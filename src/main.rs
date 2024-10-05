use anyhow::{Context, Result};
use cgroups_rs::{cgroup_builder::CgroupBuilder, hierarchies, CgroupPid, MaxValue};
use clap::{Parser, Subcommand};
use flate2::read::GzDecoder;
use nix::mount::{mount, umount, MsFlags};
use nix::sched::{clone, CloneFlags};
use nix::sys::signal::Signal;
use nix::sys::wait::waitpid;
use nix::unistd::{chdir, chroot, setgroups, sethostname, setresgid, setresuid, Gid, Uid};
use reqwest;
use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};
use tar::Archive;
use tempfile;
use tempfile::TempDir;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run {
        #[arg(required = true)]
        command: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run { command } => run(command),
    }
}

const STACK_SIZE: usize = 1024 * 1024;
fn run(command: &[String]) -> Result<()> {
    println!("Running {:?}", command);

    let mut stack = [0; STACK_SIZE];
    match unsafe {
        clone(
            Box::new(|| match child(command) {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!("Error in child process: {}", e);
                    1
                }
            }),
            &mut stack,
            CloneFlags::CLONE_NEWUTS
                | CloneFlags::CLONE_NEWUSER
                | CloneFlags::CLONE_NEWPID
                | CloneFlags::CLONE_NEWNS,
            Some(Signal::SIGCHLD as i32),
        )
    } {
        Ok(child_pid) => {
            setup_id_map(child_pid.as_raw()).context("Failed to set up id map")?;
            setup_cgroups(child_pid.as_raw()).context("Failed to set up cgroups")?;
            // Wait for the child process to finish
            waitpid(child_pid, None)?;
            Ok(())
        }
        Err(err) => Err(anyhow::anyhow!("Failed to clone: {}", err)),
    }
}

const USERNS_START: u64 = 0;
const USERNS_OFFSET: u64 = 10000;
const USERNS_COUNT: u64 = 2000;
fn setup_id_map(pid: i32) -> Result<()> {
    // Set up UID mapping
    let uid_map = format!("{} {} {}", USERNS_START, USERNS_OFFSET, USERNS_COUNT);
    File::create(format!("/proc/{}/uid_map", pid))
        .and_then(|mut f| f.write_all(uid_map.as_bytes()))
        .context("Failed to set up UID mapping")?;

    // Set up GID mapping
    let gid_map = format!("{} {} {}", USERNS_START, USERNS_OFFSET, USERNS_COUNT);
    File::create(format!("/proc/{}/gid_map", pid))
        .and_then(|mut f| f.write_all(gid_map.as_bytes()))
        .context("Failed to set up GID mapping")?;

    Ok(())
}

const KMEM_LIMIT: i64 = 1024 * 1024 * 1024;
const MEM_LIMIT: i64 = KMEM_LIMIT;
const MAX_PID: MaxValue = MaxValue::Value(64);
const CPU_SHARES: u64 = 256;
const BLKIO_WEIGHT: u16 = 50;
fn setup_cgroups(pid: i32) -> Result<()> {
    let hierarchy = Box::new(hierarchies::V1::new());
    let cgroup = CgroupBuilder::new("container")
        // cpu
        .cpu()
        .shares(CPU_SHARES)
        .done()
        // memory
        .memory()
        .kernel_memory_limit(KMEM_LIMIT)
        .memory_hard_limit(MEM_LIMIT)
        .done()
        // pid
        .pid()
        .maximum_number_of_processes(MAX_PID)
        .done()
        // blkio
        .blkio()
        .weight(BLKIO_WEIGHT)
        .done()
        // build
        .build(hierarchy)
        .context("Failed to build cgroup")?;

    // Add current process to the cgroup
    cgroup
        .add_task(CgroupPid::from(pid as u64))
        .context("Failed to add process to cgroup")?;

    Ok(())
}

fn child(command: &[String]) -> Result<()> {
    setup_container_environment().context("Failed to set up container environment")?;
    switch_user().context("Failed to switch user")?;
    mount_filesystems().context("Failed to mount filesystems")?;

    let status = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("Failed to execute command in container")?;

    status
        .success()
        .then_some(())
        .context("Command in container failed")?;

    cleanup_mounts().context("Failed to clean up mounts")?;
    Ok(())
}

fn switch_user() -> Result<()> {
    let gid = Gid::from_raw(0);
    let uid = Uid::from_raw(0);
    setgroups(&[gid]).context("Failed to set groups")?;
    setresgid(gid, gid, gid).context("Failed to set gid")?;
    setresuid(uid, uid, uid).context("Failed to switch to root user")?;
    Ok(())
}

fn setup_container_environment() -> Result<()> {
    let rootfs_path = prepare_rootfs().context("Failed to prepare rootfs")?;
    sethostname("container").context("Failed to set hostname")?;
    chroot(&rootfs_path.into_path()).context("Failed to change root")?;
    chdir("/").context("Failed to change directory to root")?;

    Ok(())
}

fn prepare_rootfs() -> Result<TempDir> {
    let tmp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;

    // Get the Alpine link for the current architecture and version
    let alpine_link = format!(
        "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/{0}/alpine-minirootfs-3.20.0-{0}.tar.gz",
        std::env::consts::ARCH
    );

    // Download Alpine base image and extract it directly
    let response =
        reqwest::blocking::get(alpine_link).context("Failed to download Alpine base image")?;
    let tar = GzDecoder::new(response);
    let mut archive = Archive::new(tar);
    println!(
        "Unpacking Alpine base image to {}",
        tmp_dir.path().display()
    );
    archive
        .unpack(&tmp_dir)
        .context("Failed to extract Alpine base image")?;

    Ok(tmp_dir)
}

fn mount_filesystems() -> Result<()> {
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::empty(),
        None as Option<&str>,
    )
    .context("Failed to mount /proc")?;

    mount(
        Some("tmp"),
        "/tmp",
        Some("tmpfs"),
        MsFlags::empty(),
        None as Option<&str>,
    )
    .context("Failed to mount /tmp")?;

    Ok(())
}

fn cleanup_mounts() -> Result<()> {
    umount("/proc").context("Failed to unmount /proc")?;
    umount("/tmp").context("Failed to unmount /tmp")?;
    Ok(())
}
