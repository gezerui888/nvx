//! The fork/exec boundary of [`crate::guest::spawn`].
//!
//! [`PreparedChild::new`] checks a [`ChildSpec`] and allocates or opens everything that the child
//! uses after `fork`, and [`PreparedChild::spawn`] forks it. The child branch performs no
//! allocation, locking, formatting, or Rust cleanup: it makes direct system calls over that
//! storage, in the order of [`LaunchStage`], and ends in `execve`, `execv`, or `_exit`. It makes
//! them through `nix` where its wrappers neither allocate nor consume an owner, and through libc
//! to fill the preallocated `PWD` entry, execute, and exit. A stage that fails writes its number
//! and `errno` to the launch report, a close-on-exec pipe, and ends the child with status 125, so
//! that the report's reader reaches end of file without a report once the program runs.
//!
//! Every descriptor that the child uses after it places its standard streams has a number above
//! theirs, so that placing them replaces none of it: [`PreparedChild::new`] moves a stream source,
//! the root, the cgroup's membership file, or the report's writer that has a lower number. It also
//! makes them close-on-exec, so that the program receives them only as its standard streams.

use std::ffi::CString;
use std::os::fd::RawFd;

use nix::fcntl::{FcntlArg, FdFlag};
use nix::libc::c_char;
use nix::unistd::{ForkResult, Gid, Pid, Uid};

use super::{Errno, FileDescriptor, ProcessId};
use crate::guest::spawn::LaunchStage;

/// Prefix of the mutable physical-working-directory environment entry.
const PWD_PREFIX: &[u8] = b"PWD=";
/// Capacity of the physical working directory in its entry, with its terminating NUL: Linux's
/// `PATH_MAX`.
const PHYSICAL_PWD_CAPACITY: usize = 4096;
/// The lowest descriptor number above the standard streams'.
const FIRST_NONSTANDARD: RawFd = 3;
/// Exit status of a child whose launch stage failed.
const LAUNCH_FAILURE_STATUS: i32 = 125;
/// Length of a launch report: the stage's number and the `errno`, as native-endian 32-bit
/// integers.
pub(crate) const REPORT_LENGTH: usize = 8;

/// Everything that a caller asks of one child, as [`crate::guest::spawn::Command`] collects it.
#[derive(Debug)]
pub(crate) struct ChildSpec {
    /// Path of the program.
    pub(crate) program: CString,
    /// Arguments, argument zero first.
    pub(crate) arguments: Vec<CString>,
    /// Exact environment, or `None` to inherit the caller's.
    pub(crate) environment: Option<Vec<CString>>,
    /// Whether `PWD` receives the physical working directory.
    pub(crate) physical_pwd: bool,
    /// Directory that becomes the child's root.
    pub(crate) root: Option<FileDescriptor>,
    /// Absolute working directory, resolved in the root, or `None` to keep the current one.
    pub(crate) directory: Option<CString>,
    /// Effective user and group IDs with which the child enters `directory`.
    pub(crate) credentials: Option<(u32, u32)>,
    /// Sources of standard input, output, and error; `None` keeps the caller's.
    pub(crate) streams: [Option<FileDescriptor>; 3],
    /// Descriptors that stay open across `exec`, at their numbers.
    pub(crate) inherited: Vec<FileDescriptor>,
    /// Membership file of the cgroup that the child joins.
    pub(crate) cgroup: Option<FileDescriptor>,
    /// Whether the child leads a new process group.
    pub(crate) process_group: bool,
    /// Test-only outcome of the credential system calls, which the child then skips:
    /// `Some(None)` succeeds, and `Some(Some(error))` fails the first one with `error`.
    #[cfg(test)]
    pub(crate) simulated_credentials: Option<Option<Errno>>,
}

impl ChildSpec {
    /// Describes a child that runs `program` with `arguments` and keeps everything else of its
    /// parent's.
    pub(crate) fn new(program: CString, arguments: Vec<CString>) -> Self {
        Self {
            program,
            arguments,
            environment: None,
            physical_pwd: false,
            root: None,
            directory: None,
            credentials: None,
            streams: [None, None, None],
            inherited: Vec::new(),
            cgroup: None,
            process_group: false,
            #[cfg(test)]
            simulated_credentials: None,
        }
    }
}

/// Mutable physical-working-directory entry prepared before `fork`.
struct PhysicalPwd {
    /// Writable `PWD=` entry, with capacity for the path and its trailing NUL.
    entry: Box<[u8]>,
    /// Position of the entry in the child's environment.
    index: usize,
}

impl PhysicalPwd {
    /// Allocates the entry and removes the first `PWD` entry of `environment`, whose position it
    /// takes, or appends it.
    fn new(environment: &mut Vec<CString>) -> Self {
        let index = environment
            .iter()
            .position(|entry| entry.as_bytes().starts_with(PWD_PREFIX))
            .map_or(environment.len(), |index| {
                environment.remove(index);
                index
            });
        let mut entry = vec![0u8; PWD_PREFIX.len() + PHYSICAL_PWD_CAPACITY].into_boxed_slice();
        entry[..PWD_PREFIX.len()].copy_from_slice(PWD_PREFIX);
        Self { entry, index }
    }
}

/// Credentials of the working-directory check, and the supplementary groups that the child gives
/// back after it.
struct Credentials {
    /// Effective user ID of the check.
    uid: Uid,
    /// Effective group ID of the check.
    gid: Gid,
    /// The parent's supplementary groups, which the child shares until the check.
    groups: Vec<Gid>,
}

/// A checked child whose every input is allocated or opened, ready to fork.
pub(crate) struct PreparedChild {
    /// Path of the program.
    program: CString,
    /// Arguments, argument zero first.
    arguments: Vec<CString>,
    /// Exact environment, without the physical `PWD` entry, or `None` to inherit the caller's.
    environment: Option<Vec<CString>>,
    /// Physical `PWD` entry that the child fills.
    physical_pwd: Option<PhysicalPwd>,
    /// Directory that becomes the child's root.
    root: Option<FileDescriptor>,
    /// Absolute working directory, resolved in the root.
    directory: Option<CString>,
    /// Credentials of the working-directory check.
    credentials: Option<Credentials>,
    /// Sources of standard input, output, and error.
    streams: [Option<FileDescriptor>; 3],
    /// Descriptors that stay open across `exec`, at their numbers.
    inherited: Vec<FileDescriptor>,
    /// Membership file of the cgroup that the child joins.
    cgroup: Option<FileDescriptor>,
    /// Whether the child leads a new process group.
    process_group: bool,
    /// Reader of the launch report, which the caller receives.
    report_reader: FileDescriptor,
    /// Writer of the launch report, which only the child keeps.
    report_writer: FileDescriptor,
    /// Test-only outcome of the credential system calls.
    #[cfg(test)]
    simulated_credentials: Option<Option<Errno>>,
}

impl PreparedChild {
    /// Checks `spec` and prepares every input of its child.
    ///
    /// The working directory must be absolute, credentials need a working directory, the physical
    /// `PWD` an exact environment, and an inherited descriptor a number above the standard
    /// streams'; a command with no argument zero is invalid too. Each fails with `EINVAL`.
    pub(crate) fn new(spec: ChildSpec) -> Result<Self, Errno> {
        if spec.arguments.is_empty()
            || spec
                .directory
                .as_ref()
                .is_some_and(|directory| directory.as_bytes().first() != Some(&b'/'))
            || (spec.credentials.is_some() && spec.directory.is_none())
            || (spec.physical_pwd && spec.environment.is_none())
            || spec
                .inherited
                .iter()
                .any(|descriptor| descriptor.raw() < FIRST_NONSTANDARD)
        {
            return Err(Errno::EINVAL);
        }
        let [stdin, stdout, stderr] = spec.streams;
        let streams = [
            stdin.map(above_standard_streams).transpose()?,
            stdout.map(above_standard_streams).transpose()?,
            stderr.map(above_standard_streams).transpose()?,
        ];
        let root = spec.root.map(above_standard_streams).transpose()?;
        let cgroup = spec.cgroup.map(above_standard_streams).transpose()?;
        let (report_reader, report_writer) = super::create_pipe()?;
        let report_writer = above_standard_streams(report_writer)?;
        let credentials = match spec.credentials {
            Some((uid, gid)) => Some(Credentials {
                uid: Uid::from_raw(uid),
                gid: Gid::from_raw(gid),
                groups: nix::unistd::getgroups()?,
            }),
            None => None,
        };
        let mut environment = spec.environment;
        let physical_pwd = match (&mut environment, spec.physical_pwd) {
            (Some(environment), true) => Some(PhysicalPwd::new(environment)),
            _ => None,
        };
        Ok(Self {
            program: spec.program,
            arguments: spec.arguments,
            environment,
            physical_pwd,
            root,
            directory: spec.directory,
            credentials,
            streams,
            inherited: spec.inherited,
            cgroup,
            process_group: spec.process_group,
            report_reader,
            report_writer,
            #[cfg(test)]
            simulated_credentials: spec.simulated_credentials,
        })
    }

    /// Forks the child, which runs its launch stages and then its program, and returns its
    /// process ID and the reader of its launch report.
    ///
    /// The parent closes its copies of the child's descriptors once the child exists. This
    /// function is safe because every pointer and descriptor that the child uses belongs to this
    /// value or to this frame, which the child's copied stack keeps, and the child path never
    /// returns into Rust. `fork` may occur in a multithreaded process: the child makes only
    /// direct async-signal-safe system calls over storage allocated before the fork.
    pub(crate) fn spawn(mut self) -> Result<(ProcessId, FileDescriptor), Errno> {
        let mut argument_pointers: Vec<*const c_char> = self
            .arguments
            .iter()
            .map(|argument| argument.as_ptr())
            .collect();
        argument_pointers.push(std::ptr::null());
        // The child writes the physical `PWD` entry through one raw pointer, which also serves
        // the environment. The entry's owner leaves `self`, which the child borrows, and lives
        // in this frame, so no reference to the entry exists while the child fills it.
        let mut physical_pwd = self.physical_pwd.take();
        let physical = physical_pwd
            .as_mut()
            .map(|physical_pwd| (physical_pwd.entry.as_mut_ptr(), physical_pwd.index));
        let environment_pointers = self.environment.as_ref().map(|environment| {
            let mut pointers = Vec::with_capacity(environment.len() + 2);
            for index in 0..=environment.len() {
                if let Some((entry, position)) = physical
                    && position == index
                {
                    pointers.push(entry.cast_const().cast::<c_char>());
                }
                if let Some(entry) = environment.get(index) {
                    pointers.push(entry.as_ptr());
                }
            }
            pointers.push(std::ptr::null());
            pointers
        });

        // SAFETY: every child input and pointer vector was allocated above, and the child runs
        // only the non-returning routine below.
        match unsafe { nix::unistd::fork() }? {
            ForkResult::Child => {
                // SAFETY: this is the just-forked child, and the pointers name storage that `self`,
                // the physical `PWD` entry's owner, and the vectors above own.
                unsafe {
                    self.run_child(
                        &argument_pointers,
                        environment_pointers.as_deref(),
                        physical.map(|(entry, _)| entry),
                    )
                }
            }
            ForkResult::Parent { child } => {
                if self.process_group {
                    // The child makes the same call; whichever runs first creates the group, so
                    // that the caller may signal it at once. The child's `exec` or exit makes a
                    // failure here harmless.
                    let _ = nix::unistd::setpgid(child, child);
                }
                Ok((ProcessId::from_pid(child), self.report_reader))
            }
        }
    }

    /// Runs the child's launch stages, then its program.
    ///
    /// # Safety
    ///
    /// This must run only in the just-forked child. `arguments` and `environment` must be
    /// NUL-terminated vectors of pointers to C strings that outlive the call, and `physical_pwd`,
    /// if any, the physical `PWD` entry of this child.
    unsafe fn run_child(
        &self,
        arguments: &[*const c_char],
        environment: Option<&[*const c_char]>,
        physical_pwd: Option<*mut u8>,
    ) -> ! {
        let report = &self.report_writer;
        if self.process_group
            && let Err(error) = nix::unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0))
        {
            // SAFETY: the caller establishes that this is the post-fork child.
            unsafe { fail(report, LaunchStage::ProcessGroup, error) }
        }
        if let Err(error) = self.place_descriptors() {
            // SAFETY: as above.
            unsafe { fail(report, LaunchStage::Descriptors, error) }
        }
        if let Some(root) = &self.root
            && let Err(error) = enter_root(root)
        {
            // SAFETY: as above.
            unsafe { fail(report, LaunchStage::Root, error) }
        }
        if let Some(directory) = &self.directory {
            match &self.credentials {
                Some(credentials) => {
                    let saved = (nix::unistd::geteuid(), nix::unistd::getegid());
                    if let Err(error) = self.take_credentials(credentials) {
                        // SAFETY: as above.
                        unsafe { fail(report, LaunchStage::Credentials, error) }
                    }
                    if let Err(error) = nix::unistd::chdir(directory.as_c_str()) {
                        // SAFETY: as above.
                        unsafe { fail(report, LaunchStage::WorkingDirectory, error) }
                    }
                    if let Err(error) = self.restore_credentials(credentials, saved) {
                        // SAFETY: as above.
                        unsafe { fail(report, LaunchStage::Credentials, error) }
                    }
                }
                None => {
                    if let Err(error) = nix::unistd::chdir(directory.as_c_str()) {
                        // SAFETY: as above.
                        unsafe { fail(report, LaunchStage::WorkingDirectory, error) }
                    }
                }
            }
        }
        if let Some(entry) = physical_pwd {
            // `nix`'s `getcwd` allocates its result, so libc fills the entry in place.
            // SAFETY: the entry holds the prefix and `PHYSICAL_PWD_CAPACITY` bytes after it.
            let filled = unsafe {
                nix::libc::getcwd(
                    entry.add(PWD_PREFIX.len()).cast::<c_char>(),
                    PHYSICAL_PWD_CAPACITY,
                )
            };
            if filled.is_null() {
                // SAFETY: as above.
                unsafe { fail(report, LaunchStage::PhysicalWorkingDirectory, Errno::last()) }
            }
        }
        if let Some(cgroup) = &self.cgroup
            && let Err(error) = write_decimal(cgroup, nix::unistd::getpid().as_raw())
        {
            // SAFETY: as above.
            unsafe { fail(report, LaunchStage::Cgroup, error) }
        }
        // `nix`'s `exec` wrappers allocate their pointer vectors, so libc takes the ones that the
        // parent prepared.
        // SAFETY: the vectors are NUL-terminated, and every pointer names storage retained by the
        // copied parent stack.
        unsafe {
            match environment {
                Some(environment) => nix::libc::execve(
                    self.program.as_ptr(),
                    arguments.as_ptr(),
                    environment.as_ptr(),
                ),
                None => nix::libc::execv(self.program.as_ptr(), arguments.as_ptr()),
            };
            fail(report, LaunchStage::Exec, Errno::last())
        }
    }

    /// Places the standard streams and clears close-on-exec on the inherited descriptors.
    ///
    /// Every source has a number above the standard streams', so `dup2` replaces each stream
    /// without closing a source, and clears close-on-exec on its copy.
    fn place_descriptors(&self) -> Result<(), Errno> {
        let [stdin, stdout, stderr] = &self.streams;
        if let Some(source) = stdin {
            retry(|| nix::unistd::dup2_stdin(source.borrowed()))?;
        }
        if let Some(source) = stdout {
            retry(|| nix::unistd::dup2_stdout(source.borrowed()))?;
        }
        if let Some(source) = stderr {
            retry(|| nix::unistd::dup2_stderr(source.borrowed()))?;
        }
        for descriptor in &self.inherited {
            nix::fcntl::fcntl(descriptor.borrowed(), FcntlArg::F_SETFD(FdFlag::empty()))?;
        }
        Ok(())
    }

    /// Takes the credentials of the working-directory check: no supplementary groups, then the
    /// effective group, then the effective user.
    fn take_credentials(&self, credentials: &Credentials) -> Result<(), Errno> {
        #[cfg(test)]
        if let Some(simulated) = self.simulated_credentials {
            return simulated.map_or(Ok(()), Err);
        }
        nix::unistd::setgroups(&[])?;
        nix::unistd::setegid(credentials.gid)?;
        nix::unistd::seteuid(credentials.uid)
    }

    /// Gives back the effective user, then the effective group and the supplementary groups,
    /// that the child had before the check.
    fn restore_credentials(
        &self,
        credentials: &Credentials,
        (uid, gid): (Uid, Gid),
    ) -> Result<(), Errno> {
        #[cfg(test)]
        if self.simulated_credentials.is_some() {
            return Ok(());
        }
        nix::unistd::seteuid(uid)?;
        nix::unistd::setegid(gid)?;
        nix::unistd::setgroups(&credentials.groups)
    }

    /// Returns the prepared executable path for focused launch tests.
    #[cfg(test)]
    pub(crate) fn program(&self) -> &CString {
        &self.program
    }

    /// Returns the prepared arguments for focused launch tests.
    #[cfg(test)]
    pub(crate) fn arguments(&self) -> &[CString] {
        &self.arguments
    }

    /// Returns the prepared exact environment, without the physical `PWD` entry, for focused
    /// launch tests.
    #[cfg(test)]
    pub(crate) fn environment(&self) -> &[CString] {
        self.environment.as_deref().unwrap_or_default()
    }

    /// Returns the preallocated physical `PWD` entry for focused launch tests.
    #[cfg(test)]
    pub(crate) fn physical_pwd(&self) -> Option<&[u8]> {
        self.physical_pwd
            .as_ref()
            .map(|physical_pwd| physical_pwd.entry.as_ref())
    }

    /// Returns the environment position of the physical `PWD` entry for focused launch tests.
    #[cfg(test)]
    pub(crate) fn physical_pwd_index(&self) -> Option<usize> {
        self.physical_pwd
            .as_ref()
            .map(|physical_pwd| physical_pwd.index)
    }

    /// Returns whether the child joins a cgroup, for focused launch tests.
    #[cfg(test)]
    pub(crate) fn has_cgroup(&self) -> bool {
        self.cgroup.is_some()
    }
}

/// Returns `descriptor` with close-on-exec set and a number above the standard streams',
/// duplicating it if its number is lower.
fn above_standard_streams(descriptor: FileDescriptor) -> Result<FileDescriptor, Errno> {
    if descriptor.raw() >= FIRST_NONSTANDARD {
        nix::fcntl::fcntl(descriptor.borrowed(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        return Ok(descriptor);
    }
    let raised = nix::fcntl::fcntl(
        descriptor.borrowed(),
        FcntlArg::F_DUPFD_CLOEXEC(FIRST_NONSTANDARD),
    )?;
    // SAFETY: the kernel has just created `raised`, so it is open and nothing else owns it.
    Ok(unsafe { FileDescriptor::from_raw(raised) })
}

/// Makes `root` the calling process's root directory and working directory.
fn enter_root(root: &FileDescriptor) -> Result<(), Errno> {
    nix::unistd::fchdir(root.borrowed())?;
    nix::unistd::chroot(c".")
}

/// Repeats `call` while it is interrupted.
fn retry(mut call: impl FnMut() -> Result<(), Errno>) -> Result<(), Errno> {
    loop {
        match call() {
            Err(Errno::EINTR) => {}
            result => return result,
        }
    }
}

/// Reports a failed launch stage and ends the child at once.
///
/// # Safety
///
/// This must run only in a post-fork child, with `report` its launch report's writer.
unsafe fn fail(report: &FileDescriptor, stage: LaunchStage, error: Errno) -> ! {
    let mut bytes = [0u8; REPORT_LENGTH];
    bytes[..4].copy_from_slice(&stage.code().to_ne_bytes());
    bytes[4..].copy_from_slice(&(error as i32).to_ne_bytes());
    let _ = write_all(report, &bytes);
    // `nix` has no `_exit`, and `std::process::exit` runs cleanup.
    // SAFETY: the caller guarantees that this is the post-fork child.
    unsafe { nix::libc::_exit(LAUNCH_FAILURE_STATUS) }
}

/// Writes a decimal process ID and newline without allocation.
fn write_decimal(descriptor: &FileDescriptor, value: nix::libc::pid_t) -> Result<(), Errno> {
    let mut bytes = [0u8; 32];
    let mut position = bytes.len() - 1;
    bytes[position] = b'\n';
    let mut value = value as u32;
    loop {
        position -= 1;
        bytes[position] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    write_all(descriptor, &bytes[position..])
}

/// Writes all bytes with direct async-signal-safe calls, retrying interruptions. A write that
/// makes no progress is `EIO`.
fn write_all(descriptor: &FileDescriptor, mut bytes: &[u8]) -> Result<(), Errno> {
    while !bytes.is_empty() {
        match nix::unistd::write(descriptor.borrowed(), bytes) {
            Ok(0) => return Err(Errno::EIO),
            Ok(count) => bytes = &bytes[count..],
            Err(Errno::EINTR) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

    use super::*;
    use crate::guest::sys::{self, ChildStatus};

    /// Closes standard streams of an isolated test process, and restores them when dropped, so
    /// that the test harness can report the outcome.
    struct ClosedStreams(Vec<(RawFd, OwnedFd)>);

    impl ClosedStreams {
        /// Closes the standard streams `numbers`, keeping a copy of each.
        fn new(numbers: &[RawFd]) -> Self {
            Self(
                numbers
                    .iter()
                    .map(|&number| {
                        // SAFETY: the standard stream is open while this borrow lasts.
                        let stream = unsafe { BorrowedFd::borrow_raw(number) };
                        let copy = stream.try_clone_to_owned().unwrap();
                        // SAFETY: the isolated test process gives up the stream, which nothing
                        // else in it uses until the guard restores it.
                        drop(unsafe { OwnedFd::from_raw_fd(number) });
                        (number, copy)
                    })
                    .collect(),
            )
        }
    }

    impl Drop for ClosedStreams {
        fn drop(&mut self) {
            for (number, copy) in &self.0 {
                // SAFETY: `dup2` replaces whatever the test left at the stream's number.
                unsafe { nix::libc::dup2(copy.as_raw_fd(), *number) };
            }
        }
    }

    /// Returns one ordinary owned descriptor.
    fn descriptor() -> FileDescriptor {
        FileDescriptor::from_owned(tempfile::tempfile().unwrap().into())
    }

    /// Returns a spec that runs `/bin/sh -c script`.
    fn shell(script: &str) -> ChildSpec {
        ChildSpec::new(
            c"/bin/sh".to_owned(),
            vec![
                c"sh".to_owned(),
                c"-c".to_owned(),
                CString::new(script).unwrap(),
            ],
        )
    }

    /// Spawns `spec`, reads its launch report to the end, reaps it, and returns both.
    fn run(spec: ChildSpec) -> (Option<(i32, i32)>, Option<ChildStatus>) {
        let (process, mut reader) = PreparedChild::new(spec).unwrap().spawn().unwrap();
        let mut report = Vec::new();
        reader.read_to_end(&mut report).unwrap();
        let report = (report.len() == REPORT_LENGTH).then(|| {
            (
                i32::from_ne_bytes(report[..4].try_into().unwrap()),
                i32::from_ne_bytes(report[4..].try_into().unwrap()),
            )
        });
        (report, sys::wait(process))
    }

    #[test]
    fn the_physical_pwd_entry_takes_the_first_pwd_entry_s_place() {
        let mut environment = vec![
            c"FIRST=1".to_owned(),
            c"PWD=/old".to_owned(),
            c"PWD=/second".to_owned(),
        ];
        let physical_pwd = PhysicalPwd::new(&mut environment);
        assert_eq!(physical_pwd.index, 1);
        assert_eq!(
            environment,
            [c"FIRST=1".to_owned(), c"PWD=/second".to_owned()]
        );
        assert_eq!(&physical_pwd.entry[..PWD_PREFIX.len()], PWD_PREFIX);
        assert_eq!(
            physical_pwd.entry.len(),
            PWD_PREFIX.len() + PHYSICAL_PWD_CAPACITY
        );
        assert!(
            physical_pwd.entry[PWD_PREFIX.len()..]
                .iter()
                .all(|&byte| byte == 0)
        );

        let mut environment = vec![c"FIRST=1".to_owned()];
        assert_eq!(PhysicalPwd::new(&mut environment).index, 1);
    }

    #[test]
    fn invalid_specs_are_refused_before_forking() {
        let mut spec = shell("exit 0");
        spec.arguments.clear();
        assert_eq!(PreparedChild::new(spec).err(), Some(Errno::EINVAL));

        let mut spec = shell("exit 0");
        spec.directory = Some(c"relative".to_owned());
        assert_eq!(PreparedChild::new(spec).err(), Some(Errno::EINVAL));

        let mut spec = shell("exit 0");
        spec.credentials = Some((1000, 1000));
        assert_eq!(PreparedChild::new(spec).err(), Some(Errno::EINVAL));

        let mut spec = shell("exit 0");
        spec.physical_pwd = true;
        assert_eq!(PreparedChild::new(spec).err(), Some(Errno::EINVAL));
    }

    #[test]
    fn stream_sources_below_the_standard_streams_are_raised_and_kept_from_the_program() {
        if crate::guest::managed_agent::isolate_process_test(
            "NVX_SPAWN_LOW_STREAM_TEST_CHILD",
            "guest::sys::spawn::tests::stream_sources_below_the_standard_streams_are_raised_and_kept_from_the_program",
        ) {
            return;
        }
        let output = tempfile::NamedTempFile::new().unwrap();
        let streams = ClosedStreams::new(&[0]);
        // The file takes number 0, the lowest free one, and becomes the program's standard
        // output; the program has no standard input.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(output.path())
            .unwrap();
        assert_eq!(file.as_raw_fd(), 0);
        let mut spec = shell("printf placed; test ! -e /proc/self/fd/0");
        spec.streams[1] = Some(FileDescriptor::from_owned(file.into()));
        let outcome = run(spec);

        // An inherited descriptor keeps its number, which must not be a standard stream's.
        let file = std::fs::File::open(output.path()).unwrap();
        assert_eq!(file.as_raw_fd(), 0);
        let mut spec = shell("exit 0");
        spec.inherited
            .push(FileDescriptor::from_owned(OwnedFd::from(file)));
        let refused = PreparedChild::new(spec).err();
        drop(streams);

        assert_eq!(outcome, (None, Some(ChildStatus::Exited(0))));
        assert_eq!(std::fs::read(output.path()).unwrap(), b"placed");
        assert_eq!(refused, Some(Errno::EINVAL));
    }

    #[test]
    fn the_report_writer_is_raised_above_the_standard_streams() {
        if crate::guest::managed_agent::isolate_process_test(
            "NVX_SPAWN_LOW_REPORT_TEST_CHILD",
            "guest::sys::spawn::tests::the_report_writer_is_raised_above_the_standard_streams",
        ) {
            return;
        }
        // With standard input and output closed, the report's pipe takes their numbers, and
        // placing the child's standard output would replace a writer that kept number 1.
        let streams = ClosedStreams::new(&[0, 1]);
        let mut spec = ChildSpec::new(c"/nonexistent".to_owned(), vec![c"nonexistent".to_owned()]);
        spec.streams[1] = Some(descriptor());
        let outcome = run(spec);
        drop(streams);
        assert_eq!(
            outcome,
            (
                Some((LaunchStage::Exec.code(), Errno::ENOENT as i32)),
                Some(ChildStatus::Exited(LAUNCH_FAILURE_STATUS))
            )
        );
    }

    #[test]
    fn a_new_process_group_is_led_by_the_child() {
        for process_group in [true, false] {
            let (reader, writer) = sys::create_pipe().unwrap();
            let mut spec = shell("read -r line");
            spec.streams[0] = Some(reader);
            spec.process_group = process_group;
            let (process, _report) = PreparedChild::new(spec).unwrap().spawn().unwrap();
            let child = Pid::from_raw(process.raw());
            let expected = if process_group {
                child
            } else {
                nix::unistd::getpgrp()
            };
            let group = nix::unistd::getpgid(Some(child));
            writer.write_all(b"done\n").unwrap();
            assert_eq!(sys::wait(process), Some(ChildStatus::Exited(0)));
            assert_eq!(group, Ok(expected), "{process_group}");
        }
    }

    #[test]
    fn a_child_enters_its_root_or_reports_why_not() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("inside")).unwrap();
        let mut spec = ChildSpec::new(c"/bin/sh".to_owned(), vec![c"sh".to_owned()]);
        spec.root = Some(
            sys::open(
                &sys::path_c_string(root.path()).unwrap(),
                sys::OpenFlags::O_RDONLY | sys::OpenFlags::O_DIRECTORY | sys::OpenFlags::O_CLOEXEC,
                sys::Mode::empty(),
            )
            .unwrap(),
        );
        spec.directory = Some(c"/inside".to_owned());
        let (report, status) = run(spec);
        assert_eq!(status, Some(ChildStatus::Exited(LAUNCH_FAILURE_STATUS)));
        // Without the privilege to change its root, the child stops there. With it, the child
        // finds `/inside` in the new root, which has no `/bin/sh`.
        let (stage, error) = if nix::unistd::geteuid().is_root() {
            (LaunchStage::Exec, Errno::ENOENT)
        } else {
            (LaunchStage::Root, Errno::EPERM)
        };
        assert_eq!(report, Some((stage.code(), error as i32)));
    }

    #[test]
    fn the_check_s_credentials_keep_the_parent_s_supplementary_groups() {
        let mut spec = shell("exit 0");
        spec.directory = Some(c"/".to_owned());
        spec.credentials = Some((1000, 1001));
        let prepared = PreparedChild::new(spec).unwrap();
        let credentials = prepared.credentials.as_ref().unwrap();
        assert_eq!(credentials.groups, nix::unistd::getgroups().unwrap());
        assert_eq!(
            (credentials.uid, credentials.gid),
            (Uid::from_raw(1000), Gid::from_raw(1001))
        );
    }

    #[test]
    fn the_launch_descriptors_are_close_on_exec() {
        let mut spec = shell("exit 0");
        spec.cgroup = Some(descriptor());
        spec.streams[2] = Some(descriptor());
        let prepared = PreparedChild::new(spec).unwrap();
        for descriptor in [
            prepared.cgroup.as_ref().unwrap(),
            prepared.streams[2].as_ref().unwrap(),
            &prepared.report_reader,
            &prepared.report_writer,
        ] {
            assert!(descriptor.raw() >= FIRST_NONSTANDARD);
            let flags = nix::fcntl::fcntl(descriptor.borrowed(), FcntlArg::F_GETFD).unwrap();
            assert!(FdFlag::from_bits_retain(flags).contains(FdFlag::FD_CLOEXEC));
        }
    }
}
