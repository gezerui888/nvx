use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use super::Transport;
use crate::hypervisor::Hypervisor;

#[cfg(all(feature = "cli", unix))]
pub(crate) use crate::host::sys::{interrupted, watch_interrupts, write_interruptibly};

/// Whether this host can run NVX microVMs.
pub const SUPPORTED: bool = false;

/// Does nothing: this host has no console interrupts to watch.
#[cfg(all(feature = "cli", not(unix)))]
pub(crate) fn watch_interrupts() -> io::Result<()> {
    Ok(())
}

/// Reports no interrupt: this host has no console interrupts to watch.
#[cfg(all(feature = "cli", not(unix)))]
pub(crate) fn interrupted() -> bool {
    false
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "the openvmm backend supports Linux and Windows hosts only",
    )
}

/// Reports every process as gone: this host runs no OpenVMM processes.
pub fn process_start_time(_pid: u32) -> io::Result<Option<u64>> {
    Ok(None)
}

/// A verified process, which this host never holds.
pub(crate) enum ProcessHandle {}

impl ProcessHandle {
    /// Never called: no handle exists.
    pub(crate) fn has_exit_event(&self) -> bool {
        match *self {}
    }

    /// Never called: no handle exists.
    pub(crate) fn wait(&self, _deadline: Instant) -> io::Result<Option<bool>> {
        match *self {}
    }

    /// Never called: no handle exists.
    pub(crate) fn kill(&self, _pid: u32) -> io::Result<()> {
        match *self {}
    }
}

/// Reports every process as gone, as [`process_start_time`] does.
pub(crate) fn open_process(_pid: u32, _start_time: u64) -> io::Result<Option<ProcessHandle>> {
    Ok(None)
}

/// Fails: this host cannot verify processes.
pub(crate) fn pin_child(_pid: u32) -> io::Result<(ProcessHandle, u64)> {
    Err(unsupported())
}

/// Fails: this host has no boot identity that NVX reads.
pub(crate) fn boot_id() -> io::Result<[u8; 16]> {
    Err(unsupported())
}

/// Fails: this host cannot export host paths.
pub fn file_identity(_path: &Path) -> io::Result<(u64, u64)> {
    Err(unsupported())
}

pub(crate) fn detach(_command: &mut Command, _breakaway_from_job: bool) {}

pub(crate) fn probe_hypervisor(_hypervisor: Hypervisor) -> Result<(), String> {
    Err(unsupported().to_string())
}

/// Creates `path` if needed.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Err(error) if error.kind() != io::ErrorKind::AlreadyExists => Err(error),
        _ => Ok(()),
    }
}

pub(crate) fn control_endpoint(_socket_path: &Path) -> io::Result<String> {
    Err(unsupported())
}

pub(crate) fn connect_endpoint(
    _endpoint: &str,
    _expected_pid: u32,
    _timeout: Duration,
) -> io::Result<Box<dyn Transport>> {
    Err(unsupported())
}

pub(crate) fn endpoint_server_pid(_endpoint: &str) -> io::Result<Option<u32>> {
    Ok(None)
}
