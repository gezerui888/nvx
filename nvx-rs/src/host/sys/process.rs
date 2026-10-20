//! Process descriptors, and the hook that detaches a spawned process from its caller.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::ptr;
use std::time::Duration;

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl, open};
use nix::libc;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::Signal;
use nix::sys::stat::Mode;
use nix::unistd::setsid;

use super::Errno;

/// A pidfd: an owned descriptor that refers to one process. Signals sent through it reach that
/// process or fail, even once another process reuses its ID.
pub(crate) struct PidFd(OwnedFd);

impl PidFd {
    /// Opens a pidfd for the process `pid`.
    ///
    /// Fails with `ESRCH` if no such process exists, with `EINVAL` if `pid` names a thread that
    /// does not lead its process, and with [`io::ErrorKind::InvalidInput`] if `pid` is not a
    /// process ID of Linux. Hosts without pidfds, Linux before 5.3 or seccomp profiles that
    /// reject them, fail with another error.
    pub(crate) fn open(pid: u32) -> io::Result<Self> {
        let pid = libc::pid_t::try_from(pid).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{pid} is not a process ID"),
            )
        })?;
        // SAFETY: pidfd_open takes a process ID and flags and returns a new descriptor or -1.
        let descriptor = Errno::result(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) })?;
        // SAFETY: the kernel returned a fresh descriptor that nothing else owns.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(descriptor as RawFd) }))
    }

    /// Waits up to `timeout` for the process to exit, and returns whether it has.
    ///
    /// The pidfd becomes readable once the whole process has exited: its last thread, not only
    /// its main one. That holds whether or not the caller is the process's parent, and whether
    /// or not the process has been reaped. A signal that interrupts the wait ends it early.
    pub(crate) fn wait_exit(&self, timeout: Duration) -> io::Result<bool> {
        // Round up, so that a wait shorter than a millisecond does not spin.
        let timeout = PollTimeout::try_from(timeout.as_nanos().div_ceil(1_000_000))
            .unwrap_or(PollTimeout::MAX);
        let mut descriptors = [PollFd::new(self.0.as_fd(), PollFlags::POLLIN)];
        match poll(&mut descriptors, timeout) {
            Ok(0) | Err(Errno::EINTR) => Ok(false),
            Ok(_) => {
                let events = descriptors[0].revents().unwrap_or(PollFlags::empty());
                // Since Linux 6.9, a pidfd also reports a hang-up once its process is reaped.
                if events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
                    Ok(true)
                } else {
                    Err(io::Error::other(format!(
                        "a pidfd reported unexpected events {events:?}"
                    )))
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Sends `SIGKILL` to the process.
    ///
    /// Fails with `ESRCH` if the process has exited.
    pub(crate) fn kill(&self) -> io::Result<()> {
        // SAFETY: the descriptor is a valid pidfd, and a null siginfo with no flags is allowed.
        Errno::result(unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.0.as_raw_fd(),
                Signal::SIGKILL as libc::c_int,
                ptr::null::<libc::siginfo_t>(),
                0,
            )
        })?;
        Ok(())
    }
}

/// Makes `command` start its process in a new session, with every descriptor of the caller
/// above standard error close-on-exec.
pub(crate) fn detach(command: &mut Command) {
    // SAFETY: the hook makes only async-signal-safe system calls and allocates nothing, as code
    // that runs between fork and exec must.
    unsafe {
        command.pre_exec(|| {
            setsid()?;
            mark_descriptors_close_on_exec()
        });
    }
}

/// Makes `command` mark only the descriptors that `/proc/self/fd` lists close-on-exec before it
/// executes, as [`detach`] does on kernels without `CLOSE_RANGE_CLOEXEC`.
#[cfg(test)]
pub(crate) fn mark_listed_descriptors_on_spawn(command: &mut Command) {
    // SAFETY: the hook makes only async-signal-safe system calls and allocates nothing, as code
    // that runs between fork and exec must.
    unsafe { command.pre_exec(mark_listed_descriptors_close_on_exec) };
}

/// Clears the close-on-exec flag of `descriptor`, as a descriptor that the caller's parent or
/// native code left inheritable lacks it.
#[cfg(test)]
pub(crate) fn clear_close_on_exec(descriptor: impl AsFd) -> io::Result<()> {
    fcntl(descriptor, FcntlArg::F_SETFD(FdFlag::empty()))?;
    Ok(())
}

/// Marks every descriptor above standard error close-on-exec.
///
/// Rust opens its own descriptors close-on-exec, but a descriptor that the caller inherited or
/// that native code opened may lack the flag, and a detached VM would hold it until it stops: a
/// pipe writer it holds, for example, keeps the reader from seeing end-of-file. Marking rather
/// than closing keeps the descriptor through which `Command::spawn` reports a failed exec.
fn mark_descriptors_close_on_exec() -> io::Result<()> {
    let first: libc::c_uint = 3;
    // SAFETY: close_range takes two descriptor bounds and flags and changes no memory.
    let marked = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            first,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if marked == 0 {
        return Ok(());
    }
    // Linux before 5.11 lacks CLOSE_RANGE_CLOEXEC, and seccomp policies may reject close_range.
    mark_listed_descriptors_close_on_exec()
}

/// Marks every descriptor above standard error that `/proc/self/fd` lists close-on-exec.
///
/// It runs only in a `pre_exec` hook, between fork and exec, where nothing may allocate, so it
/// reads the directory with getdents64 into a stack buffer rather than through `nix`'s `Dir`,
/// whose `fdopendir` allocates.
fn mark_listed_descriptors_close_on_exec() -> io::Result<()> {
    let directory = open(
        c"/proc/self/fd",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    mark_directory_entries(&directory)
}

/// Marks the descriptors enumerated by the open `/proc/self/fd` `directory` close-on-exec.
fn mark_directory_entries(directory: &OwnedFd) -> io::Result<()> {
    #[repr(C, align(8))]
    struct Records([u8; 4096]);

    let malformed = || io::Error::from(Errno::EIO);
    let mut buffer = Records([0; 4096]);
    loop {
        // SAFETY: the kernel writes at most the buffer's length into it.
        let read = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                directory.as_raw_fd(),
                buffer.0.as_mut_ptr(),
                buffer.0.len(),
            )
        };
        let Ok(read) = usize::try_from(read) else {
            return Err(io::Error::last_os_error());
        };
        if read == 0 {
            return Ok(());
        }
        let mut records = buffer.0.get(..read).ok_or_else(malformed)?;
        while !records.is_empty() {
            // A linux_dirent64 holds d_ino (8 bytes), d_off (8), d_reclen (2), d_type (1), and
            // the NUL-terminated name.
            let length = match records.get(16..18) {
                Some(&[low, high]) => usize::from(u16::from_ne_bytes([low, high])),
                _ => return Err(malformed()),
            };
            let (record, rest) = records.split_at_checked(length).ok_or_else(malformed)?;
            let name = record.get(19..).ok_or_else(malformed)?;
            if let Some(descriptor) = descriptor_number(name)
                && descriptor > 2
                && descriptor != directory.as_raw_fd()
            {
                // SAFETY: the listing shows the descriptor open, and between fork and exec only
                // this thread runs, which closes no descriptor while the borrow lasts.
                let descriptor = unsafe { BorrowedFd::borrow_raw(descriptor) };
                // F_SETFD changes only the flags of the descriptor, so a failure leaves it as is.
                let _ = fcntl(descriptor, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC));
            }
            records = rest;
        }
    }
}

/// Parses a `/proc/self/fd` entry name, which ends at its NUL terminator.
fn descriptor_number(name: &[u8]) -> Option<RawFd> {
    let digits = name.split(|&byte| byte == 0).next()?;
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0, |value: RawFd, &byte| {
        let digit = byte.checked_sub(b'0').filter(|digit| *digit < 10)?;
        value.checked_mul(10)?.checked_add(RawFd::from(digit))
    })
}
