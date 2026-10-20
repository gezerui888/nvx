//! Owned file descriptors and safe file-oriented system operations.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

pub(crate) use nix::fcntl::OFlag as OpenFlags;
use nix::fcntl::{FcntlArg, Flock, FlockArg, SealFlag, fcntl};
use nix::poll::{PollFd, PollFlags};
use nix::sys::memfd::{MFdFlags, memfd_create};
pub(crate) use nix::sys::stat::Mode;
use nix::unistd::Whence;

use super::Errno;

/// The seals that make an execution configuration immutable.
const IMMUTABLE_SEALS: SealFlag = SealFlag::F_SEAL_WRITE
    .union(SealFlag::F_SEAL_GROW)
    .union(SealFlag::F_SEAL_SHRINK)
    .union(SealFlag::F_SEAL_SEAL);

/// An owned file descriptor.
///
/// The inner [`OwnedFd`] closes the descriptor on every early-return path. [`close`](Self::close)
/// consumes the owner and reports the close error for the C code paths whose diagnostics depend
/// on it; dropping the value is the best-effort fallback where the C program ignored close.
#[derive(Debug)]
pub(crate) struct FileDescriptor(OwnedFd);

impl FileDescriptor {
    /// Takes ownership of a descriptor number that the caller validated.
    ///
    /// # Safety
    ///
    /// `descriptor` must be open and have no other owner, because the result closes it.
    pub(super) unsafe fn from_raw(descriptor: RawFd) -> Self {
        // SAFETY: the caller guarantees that the descriptor is open and has no other owner.
        Self(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }

    /// Formats the descriptor number as a NUL-terminated decimal argument.
    pub(crate) fn argument(&self) -> CString {
        CString::new(self.0.as_raw_fd().to_string()).expect("a decimal descriptor has no NUL")
    }

    /// Reads bytes once, without retrying an interrupted call.
    pub(crate) fn read(&self, bytes: &mut [u8]) -> Result<usize, Errno> {
        nix::unistd::read(&self.0, bytes)
    }

    /// Writes bytes once, without retrying an interrupted or short call.
    pub(crate) fn write(&self, bytes: &[u8]) -> Result<usize, Errno> {
        nix::unistd::write(&self.0, bytes)
    }

    /// Reads exactly `bytes.len()` bytes, retrying interruptions.
    ///
    /// End of file before the last byte is `EIO`, the status that the agent reports for it.
    pub(crate) fn read_exact(&self, mut bytes: &mut [u8]) -> Result<(), Errno> {
        while !bytes.is_empty() {
            match self.read(bytes) {
                Ok(0) => return Err(Errno::EIO),
                Ok(count) => bytes = &mut bytes[count..],
                Err(Errno::EINTR) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Writes every byte, retrying interruptions.
    ///
    /// A write that makes no progress is `EIO`, the status that the agent reports for it.
    pub(crate) fn write_all(&self, mut bytes: &[u8]) -> Result<(), Errno> {
        while !bytes.is_empty() {
            match self.write(bytes) {
                Ok(0) => return Err(Errno::EIO),
                Ok(count) => bytes = &bytes[count..],
                Err(Errno::EINTR) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Reads at `offset` once, preserving the C cast from `u64` to `off_t`.
    pub(crate) fn pread(&self, bytes: &mut [u8], offset: u64) -> Result<usize, Errno> {
        nix::sys::uio::pread(&self.0, bytes, offset as _)
    }

    /// Writes at `offset` once, preserving the C cast from `u64` to `off_t`.
    pub(crate) fn pwrite(&self, bytes: &[u8], offset: u64) -> Result<usize, Errno> {
        nix::sys::uio::pwrite(&self.0, bytes, offset as _)
    }

    /// Sets the file's size to `length` bytes, preserving the C cast from `u64` to `off_t`.
    pub(crate) fn truncate(&self, length: u64) -> Result<(), Errno> {
        nix::unistd::ftruncate(&self.0, length as _)
    }

    /// Writes the file's modified data and metadata to its storage device.
    pub(crate) fn sync(&self) -> Result<(), Errno> {
        nix::unistd::fsync(&self.0)
    }

    /// Waits at most `timeout_ms` milliseconds for data to read, with one `poll` call.
    ///
    /// Returns whether `poll` reported `POLLIN`. An interrupted call is an error, not a retry.
    pub(crate) fn wait_readable(&self, timeout_ms: u16) -> Result<bool, Errno> {
        let mut descriptors = [PollFd::new(self.0.as_fd(), PollFlags::POLLIN)];
        let ready = nix::poll::poll(&mut descriptors, timeout_ms)?;
        Ok(ready > 0
            && descriptors[0]
                .revents()
                .is_some_and(|events| events.contains(PollFlags::POLLIN)))
    }

    /// Takes ownership of a descriptor that another wrapper in this module tree, or a test,
    /// created.
    pub(crate) fn from_owned(descriptor: OwnedFd) -> Self {
        Self(descriptor)
    }

    /// Makes future reads and writes nonblocking while preserving the other status flags.
    pub(crate) fn set_nonblocking(&self) -> Result<(), Errno> {
        let flags = fcntl(&self.0, FcntlArg::F_GETFL).map(OpenFlags::from_bits_retain)?;
        fcntl(&self.0, FcntlArg::F_SETFL(flags | OpenFlags::O_NONBLOCK)).map(|_| ())
    }

    /// Rewinds this descriptor to byte zero.
    pub(crate) fn rewind(&self) -> Result<(), Errno> {
        nix::unistd::lseek(&self.0, 0, Whence::SeekSet).map(|_| ())
    }

    /// Moves this descriptor to the end of its file. On the kernel log device, it skips the
    /// records already written, so that reads return only later ones.
    pub(crate) fn seek_end(&self) -> Result<(), Errno> {
        nix::unistd::lseek(&self.0, 0, Whence::SeekEnd).map(|_| ())
    }

    /// Adds the complete immutable-file seal set used by execution configurations.
    pub(crate) fn seal_immutable(&self) -> Result<(), Errno> {
        fcntl(&self.0, FcntlArg::F_ADD_SEALS(IMMUTABLE_SEALS)).map(|_| ())
    }

    /// Returns whether this descriptor carries every seal that `seal_immutable` adds.
    #[cfg(test)]
    pub(crate) fn is_sealed_immutable(&self) -> Result<bool, Errno> {
        let seals = fcntl(&self.0, FcntlArg::F_GET_SEALS).map(SealFlag::from_bits_retain)?;
        Ok(seals.contains(IMMUTABLE_SEALS))
    }

    /// Closes this descriptor and returns an error if the kernel reports one.
    pub(crate) fn close(self) -> Result<(), Errno> {
        nix::unistd::close(self.0)
    }

    /// Borrows the descriptor for another safe wrapper in this module tree.
    pub(super) fn borrowed(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    /// Returns the raw descriptor only to the ioctl wrappers and the forked child in this module
    /// tree.
    pub(super) fn raw(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Reads through the standard library's I/O traits, so that its buffering and bounding adapters,
/// such as `BufReader` and `Read::take`, read a descriptor that this module opened while the
/// descriptor keeps its one owner.
///
/// Each call is one `read` system call, as it is for `std::fs::File`, which buffers nothing
/// either. An interrupted call is `ErrorKind::Interrupted`, which the standard library's
/// buffered and whole-input reads retry.
impl io::Read for FileDescriptor {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        FileDescriptor::read(self, bytes).map_err(io::Error::from)
    }
}

/// Gives up the descriptor to its new owner, which `crate::guest::spawn` hands to a child.
impl From<FileDescriptor> for OwnedFd {
    fn from(descriptor: FileDescriptor) -> Self {
        descriptor.0
    }
}

/// Opens `path` with typed `flags` and `mode`, returning an owned descriptor.
pub(crate) fn open(path: &CStr, flags: OpenFlags, mode: Mode) -> Result<FileDescriptor, Errno> {
    nix::fcntl::open(path, flags, mode).map(FileDescriptor)
}

/// Creates an anonymous close-on-exec file that permits seals.
pub(crate) fn create_memfd(name: &CStr) -> Result<FileDescriptor, Errno> {
    memfd_create(name, MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING).map(FileDescriptor)
}

/// Creates a close-on-exec pipe and returns its owned read and write ends.
pub(crate) fn create_pipe() -> Result<(FileDescriptor, FileDescriptor), Errno> {
    nix::unistd::pipe2(OpenFlags::O_CLOEXEC)
        .map(|(reader, writer)| (FileDescriptor(reader), FileDescriptor(writer)))
}

/// Creates `path` as a directory with `mode`.
pub(crate) fn create_directory(path: &CStr, mode: Mode) -> Result<(), Errno> {
    nix::unistd::mkdir(path, mode)
}

/// Creates `path` as a FIFO with `mode`.
///
/// The managed agent creates its sandbox launch barrier with it, and tests use it to stand for a
/// console, which keeps their system calls in this module.
pub(crate) fn create_fifo(path: &CStr, mode: Mode) -> Result<(), Errno> {
    nix::unistd::mkfifo(path, mode)
}

/// Removes a filesystem entry without following it.
pub(crate) fn unlink(path: &CStr) -> Result<(), Errno> {
    nix::unistd::unlink(path)
}

/// An exclusive advisory lock on a file. Dropping the owner releases the lock and closes the
/// file.
#[derive(Debug)]
pub(crate) struct FileLock {
    /// The locked file, which the lock holds only so that dropping it releases the lock.
    _lock: Flock<OwnedFd>,
}

/// Opens `path`, creating it with `mode` if it is missing, and waits for its exclusive lock,
/// resuming after interruptions.
pub(crate) fn lock_file(path: &CStr, mode: Mode) -> Result<FileLock, Errno> {
    let flags = OpenFlags::O_RDWR | OpenFlags::O_CREAT | OpenFlags::O_CLOEXEC;
    let mut descriptor = nix::fcntl::open(path, flags, mode)?;
    loop {
        match Flock::lock(descriptor, FlockArg::LockExclusive) {
            Ok(lock) => return Ok(FileLock { _lock: lock }),
            Err((returned, Errno::EINTR)) => descriptor = returned,
            Err((_, error)) => return Err(error),
        }
    }
}

/// A file that this process creates, which dropping the owner closes and removes unless the
/// process [keeps](Self::keep) or [renames](Self::rename) it first.
#[derive(Debug)]
pub(crate) struct CreatedFile<'a> {
    /// The file's path, until the process keeps or renames the file.
    path: Option<&'a CStr>,
    /// The file's write-only descriptor, until the file closes.
    descriptor: Option<FileDescriptor>,
}

impl<'a> CreatedFile<'a> {
    /// Creates `path` for writing with `mode`, and truncates a file that exists already, or,
    /// for an `exclusive` creation, fails with `EEXIST`.
    pub(crate) fn create(path: &'a CStr, exclusive: bool, mode: Mode) -> Result<Self, Errno> {
        let existing = if exclusive {
            OpenFlags::O_EXCL
        } else {
            OpenFlags::O_TRUNC
        };
        let flags = OpenFlags::O_WRONLY | OpenFlags::O_CREAT | OpenFlags::O_CLOEXEC | existing;
        let descriptor = open(path, flags, mode)?;
        Ok(Self {
            path: Some(path),
            descriptor: Some(descriptor),
        })
    }

    /// Writes every byte to the file; see [`FileDescriptor::write_all`].
    pub(crate) fn write_all(&self, bytes: &[u8]) -> Result<(), Errno> {
        self.descriptor
            .as_ref()
            .map_or(Err(Errno::EBADF), |descriptor| descriptor.write_all(bytes))
    }

    /// Writes the file's data and metadata to its storage device.
    pub(crate) fn sync(&self) -> Result<(), Errno> {
        self.descriptor
            .as_ref()
            .map_or(Err(Errno::EBADF), FileDescriptor::sync)
    }

    /// Closes the file and keeps it, even when closing fails, which it reports.
    pub(crate) fn keep(mut self) -> Result<(), Errno> {
        self.path = None;
        self.descriptor.take().map_or(Ok(()), FileDescriptor::close)
    }

    /// Closes the file and renames it to `destination`, which it replaces atomically. When
    /// either step fails, the file is removed.
    pub(crate) fn rename(mut self, destination: &CStr) -> Result<(), Errno> {
        if let Some(descriptor) = self.descriptor.take() {
            descriptor.close()?;
        }
        let source = self.path.ok_or(Errno::EBADF)?;
        rename(source, destination)?;
        self.path = None;
        Ok(())
    }
}

impl Drop for CreatedFile<'_> {
    /// Closes the file, and removes it unless the process kept or renamed it, best effort.
    fn drop(&mut self) {
        drop(self.descriptor.take());
        if let Some(path) = self.path {
            let _ = unlink(path);
        }
    }
}

/// Renames `source` to `destination`, which it replaces atomically.
pub(crate) fn rename(source: &CStr, destination: &CStr) -> Result<(), Errno> {
    nix::fcntl::renameat(
        nix::fcntl::AT_FDCWD,
        source,
        nix::fcntl::AT_FDCWD,
        destination,
    )
}

/// Returns the host page size when it is a positive power of two.
pub(crate) fn page_size() -> Option<usize> {
    nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .ok()
        .flatten()
        .and_then(|size| usize::try_from(size).ok())
        .filter(|size| size.is_power_of_two())
}
