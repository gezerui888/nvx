//! Starting a program in a new process, for any guest init or agent.
//!
//! A [`Command`] describes a program and how its process starts: its arguments and environment, an
//! optional root directory and a working directory in it, the descriptors of its standard streams
//! and of any others that it inherits, the cgroup that it joins, and whether it leads a new
//! process group. [`Command::spawn`] allocates and opens everything that the child needs before it
//! forks; the child then makes only system calls over that storage, in the order of
//! [`LaunchStage`], and replaces itself with the program. A caller may therefore spawn from any
//! thread.
//!
//! A command owns the descriptors that it takes, and hands each one over once: the child places
//! the standard streams and keeps the inherited descriptors open at their numbers, and the
//! caller's process closes all of them as soon as it has forked the child, so that the reader of a
//! workload's pipe sees end of file once the program and its descendants close their ends. Before
//! the fork, a command moves any descriptor that the child uses after it places its standard
//! streams above their numbers and makes it close-on-exec, so the program receives the command's
//! descriptors only as its standard streams and inherited descriptors. Descriptors that the
//! caller opened without close-on-exec stay open in the program, as across any `exec`.
//!
//! No step needs NVX's control protocol, its managed agent and helper, or its workload identity:
//! the caller chooses the program, which applies its own credentials, and the identity, if any,
//! as which the child checks its working directory. NVX's managed agent is one caller.
//!
//! The caller owns the child. [`Spawned::id`] names it, and the caller collects its status: this
//! module never waits for a process. [`LaunchReport::wait`] tells whether the program started, or
//! which stage failed and why.
//!
//! ```no_run
//! use std::fs::File;
//!
//! use nvx::guest::spawn::Command;
//!
//! # fn main() -> std::io::Result<()> {
//! let spawned = Command::new(c"/bin/echo".to_owned(), vec![c"echo".to_owned(), c"hi".to_owned()])
//!     .working_directory(c"/tmp".to_owned())
//!     .stdin(File::open("/dev/null")?)
//!     .new_process_group()
//!     .spawn()?;
//! let process = spawned.id();
//! if let Some(failure) = spawned.into_report().wait()? {
//!     eprintln!("process {process} did not start: {failure}");
//! }
//! // The caller reaps `process`.
//! # Ok(())
//! # }
//! ```

use std::ffi::CString;
use std::fmt;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use super::sys::{
    self, ChildSpec, Errno, FileDescriptor, Mode, OpenFlags, PreparedChild, ProcessId,
    REPORT_LENGTH,
};

/// A step that a child takes after it is forked and before its program runs.
///
/// The variants are in the order of the steps, and a child skips the steps that its [`Command`]
/// does not ask for. A child whose step fails reports it and exits with status 125 without
/// running its program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LaunchStage {
    /// The child makes itself the leader of a new process group.
    ProcessGroup,
    /// The child places its standard streams and keeps its inherited descriptors open.
    Descriptors,
    /// The child makes the root directory its root.
    Root,
    /// The child takes the identity of its working-directory check, or gives it back after.
    Credentials,
    /// The child enters its working directory.
    WorkingDirectory,
    /// The child records the physical path of its working directory in `PWD`.
    PhysicalWorkingDirectory,
    /// The child joins its cgroup.
    Cgroup,
    /// The child replaces itself with its program.
    Exec,
}

impl LaunchStage {
    /// Every stage, in order.
    const ALL: [Self; 8] = [
        Self::ProcessGroup,
        Self::Descriptors,
        Self::Root,
        Self::Credentials,
        Self::WorkingDirectory,
        Self::PhysicalWorkingDirectory,
        Self::Cgroup,
        Self::Exec,
    ];

    /// Returns the stage's number in a launch report: its position, from 1.
    pub(crate) fn code(self) -> i32 {
        match self {
            Self::ProcessGroup => 1,
            Self::Descriptors => 2,
            Self::Root => 3,
            Self::Credentials => 4,
            Self::WorkingDirectory => 5,
            Self::PhysicalWorkingDirectory => 6,
            Self::Cgroup => 7,
            Self::Exec => 8,
        }
    }

    /// Returns the stage that a launch report numbers `code`, if any.
    fn from_code(code: i32) -> Option<Self> {
        Self::ALL.into_iter().find(|stage| stage.code() == code)
    }
}

impl fmt::Display for LaunchStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProcessGroup => "process group",
            Self::Descriptors => "descriptors",
            Self::Root => "root directory",
            Self::Credentials => "credentials",
            Self::WorkingDirectory => "working directory",
            Self::PhysicalWorkingDirectory => "physical working directory",
            Self::Cgroup => "cgroup",
            Self::Exec => "exec",
        })
    }
}

/// The launch stage at which a child stopped, and the `errno` of the failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchFailure {
    /// The stage that failed.
    stage: LaunchStage,
    /// The `errno` with which it failed.
    error: i32,
}

impl LaunchFailure {
    /// Returns the stage that failed.
    pub fn stage(&self) -> LaunchStage {
        self.stage
    }

    /// Returns the `errno` with which the stage failed.
    pub fn raw_os_error(&self) -> i32 {
        self.error
    }
}

impl fmt::Display for LaunchFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the {} launch stage failed: {}",
            self.stage,
            io::Error::from_raw_os_error(self.error)
        )
    }
}

impl std::error::Error for LaunchFailure {}

/// A cgroup v2 that a child joins before its program runs.
#[derive(Debug)]
pub struct Cgroup {
    /// The cgroup's membership file, open for writing.
    procs: FileDescriptor,
}

impl Cgroup {
    /// Opens the membership file, `cgroup.procs`, of the cgroup v2 directory `directory`. The
    /// child writes its process ID to it.
    pub fn open(directory: &Path) -> io::Result<Self> {
        let path = sys::path_c_string(&directory.join("cgroup.procs"))?;
        let procs = sys::open(
            &path,
            OpenFlags::O_WRONLY | OpenFlags::O_CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self { procs })
    }
}

/// A program, and how a new process starts it.
///
/// By default the child keeps its parent's environment, root and working directories, standard
/// streams, process group, and cgroup, and inherits no other descriptor of the command's. Each
/// method changes one of them.
#[derive(Debug)]
pub struct Command {
    /// The child's inputs.
    spec: ChildSpec,
}

impl Command {
    /// Describes a process that runs the executable at `program`, which is not searched for in
    /// `PATH`, with `arguments`, argument zero first. A command without arguments fails to spawn.
    pub fn new(program: CString, arguments: Vec<CString>) -> Self {
        Self {
            spec: ChildSpec::new(program, arguments),
        }
    }

    /// Gives the program exactly the `NAME=value` entries of `environment`, instead of the
    /// parent's environment.
    pub fn environment(mut self, environment: Vec<CString>) -> Self {
        self.spec.environment = Some(environment);
        self
    }

    /// Makes the directory that `root` opens the child's root directory, and its working
    /// directory unless [`working_directory`](Self::working_directory) names another one. Changing
    /// the root needs the privilege to `chroot`.
    pub fn root(mut self, root: impl Into<OwnedFd>) -> Self {
        self.spec.root = Some(FileDescriptor::from_owned(root.into()));
        self
    }

    /// Makes the absolute path `directory`, which the child resolves in its root, its working
    /// directory. A relative path fails to spawn.
    pub fn working_directory(mut self, directory: CString) -> Self {
        self.spec.directory = Some(directory);
        self
    }

    /// Makes the child enter its working directory with the effective user ID `uid`, the
    /// effective group ID `gid`, and no supplementary groups, then take back its own, so that the
    /// directory's permissions apply as they will to a program that runs as `uid` and `gid`.
    ///
    /// The check needs a [working directory](Self::working_directory), without which the command
    /// fails to spawn, and the privilege to change the child's credentials.
    pub fn check_working_directory_as(mut self, uid: u32, gid: u32) -> Self {
        self.spec.credentials = Some((uid, gid));
        self
    }

    /// Sets `PWD`, in the place of the environment's first `PWD` entry or after the last entry,
    /// to the physical path of the child's working directory once the child has entered it.
    ///
    /// The path may hold 4095 bytes. The child records it without allocating, in an entry of
    /// the [environment](Self::environment), without which the command fails to spawn.
    pub fn export_physical_working_directory(mut self) -> Self {
        self.spec.physical_pwd = true;
        self
    }

    /// Makes `descriptor` the program's standard input.
    pub fn stdin(mut self, descriptor: impl Into<OwnedFd>) -> Self {
        self.spec.streams[0] = Some(FileDescriptor::from_owned(descriptor.into()));
        self
    }

    /// Makes `descriptor` the program's standard output.
    pub fn stdout(mut self, descriptor: impl Into<OwnedFd>) -> Self {
        self.spec.streams[1] = Some(FileDescriptor::from_owned(descriptor.into()));
        self
    }

    /// Makes `descriptor` the program's standard error.
    pub fn stderr(mut self, descriptor: impl Into<OwnedFd>) -> Self {
        self.spec.streams[2] = Some(FileDescriptor::from_owned(descriptor.into()));
        self
    }

    /// Keeps `descriptor` open in the program at its current number, which the caller passes to
    /// the program, for example as an argument. A descriptor numbered 0, 1, or 2, which are the
    /// standard streams', fails to spawn.
    pub fn inherit(mut self, descriptor: impl Into<OwnedFd>) -> Self {
        self.spec
            .inherited
            .push(FileDescriptor::from_owned(descriptor.into()));
        self
    }

    /// Makes the child join `cgroup` after its other stages and before its program runs, so that
    /// the program and its descendants start in it.
    pub fn cgroup(mut self, cgroup: Cgroup) -> Self {
        self.spec.cgroup = Some(cgroup.procs);
        self
    }

    /// Makes the child the leader of a new process group, whose ID is its process ID.
    pub fn new_process_group(mut self) -> Self {
        self.spec.process_group = true;
        self
    }

    /// Starts the child.
    ///
    /// The call returns once it has forked the child, before the child's launch stages finish;
    /// the child's [`LaunchReport`] tells how they end. It fails without a child if the command
    /// is invalid, or if a resource that the child needs cannot be allocated or opened.
    pub fn spawn(self) -> io::Result<Spawned> {
        let (process, report) = PreparedChild::new(self.spec)?.spawn()?;
        Ok(Spawned {
            process,
            report: LaunchReport { reader: report },
        })
    }

    /// Prepares the child without starting it, for focused launch tests.
    #[cfg(test)]
    pub(crate) fn prepare(self) -> PreparedChild {
        PreparedChild::new(self.spec).expect("the command prepares")
    }

    /// Replaces the system calls of the child's credential stage, which then succeed, or fail
    /// with `failure`, without privileges.
    #[cfg(test)]
    pub(crate) fn simulate_credentials(mut self, failure: Option<Errno>) -> Self {
        self.spec.simulated_credentials = Some(failure);
        self
    }
}

/// A child that [`Command::spawn`] started.
///
/// Dropping it neither waits for the child nor stops it.
#[derive(Debug)]
pub struct Spawned {
    /// The child's process ID.
    process: ProcessId,
    /// The report of the child's launch.
    report: LaunchReport,
}

impl Spawned {
    /// Returns the child's process ID, which is also its process group's ID when its command
    /// asked for a [new process group](Command::new_process_group).
    pub fn id(&self) -> u32 {
        self.process.raw().unsigned_abs()
    }

    /// Returns the child's process ID for the crate's own callers.
    pub(crate) fn process(&self) -> ProcessId {
        self.process
    }

    /// Returns the report of the child's launch.
    pub fn into_report(self) -> LaunchReport {
        self.report
    }
}

/// The outcome of a child's launch stages.
#[derive(Debug)]
pub struct LaunchReport {
    /// The read end of the child's report pipe, whose write end only the child holds.
    reader: FileDescriptor,
}

impl LaunchReport {
    /// Waits until the child's program runs, which returns `None`, or a launch stage fails,
    /// which returns the failure.
    ///
    /// The wait ends when the child replaces itself with its program or exits. A report that is
    /// cut short or names no stage is `EPROTO`.
    pub fn wait(self) -> io::Result<Option<LaunchFailure>> {
        let mut bytes = [0u8; REPORT_LENGTH];
        let mut length = 0;
        while length < bytes.len() {
            match self.reader.read(&mut bytes[length..]) {
                Ok(0) => break,
                Ok(count) => length += count,
                Err(Errno::EINTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if length == 0 {
            return Ok(None);
        }
        let stage = i32::from_ne_bytes(bytes[..4].try_into().expect("four bytes"));
        let error = i32::from_ne_bytes(bytes[4..].try_into().expect("four bytes"));
        match LaunchStage::from_code(stage) {
            Some(stage) if length == REPORT_LENGTH => Ok(Some(LaunchFailure { stage, error })),
            _ => Err(Errno::EPROTO.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;

    use super::*;
    use crate::guest::sys::ChildStatus;

    /// Returns a command that runs `/bin/sh -c script`, with `$0` set to `sh`.
    fn shell(script: &str) -> Command {
        Command::new(
            c"/bin/sh".to_owned(),
            vec![
                c"sh".to_owned(),
                c"-c".to_owned(),
                CString::new(script).unwrap(),
            ],
        )
    }

    /// Returns `path` as a C string.
    fn c_path(path: &Path) -> CString {
        CString::new(path.as_os_str().as_bytes()).unwrap()
    }

    /// Returns the bytes that `reader` yields until end of file.
    fn read_all(mut reader: std::io::PipeReader) -> Vec<u8> {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        bytes
    }

    /// Spawns `command` with piped standard output and error, and returns its launch failure,
    /// status, output, and error output.
    fn run(command: Command) -> (Option<LaunchFailure>, Option<ChildStatus>, Vec<u8>, Vec<u8>) {
        let (stdout, stdout_writer) = std::io::pipe().unwrap();
        let (stderr, stderr_writer) = std::io::pipe().unwrap();
        let spawned = command
            .stdout(stdout_writer)
            .stderr(stderr_writer)
            .spawn()
            .unwrap();
        let process = spawned.process();
        let failure = spawned.into_report().wait().unwrap();
        // The command took the writers, so the readers end when the child and its descendants
        // close theirs.
        let output = read_all(stdout);
        let error = read_all(stderr);
        (failure, sys::wait(process), output, error)
    }

    #[test]
    fn a_program_runs_with_its_arguments_environment_and_streams() {
        let (stdin, mut stdin_writer) = std::io::pipe().unwrap();
        stdin_writer.write_all(b"input\n").unwrap();
        drop(stdin_writer);
        let command = Command::new(
            c"/bin/sh".to_owned(),
            vec![
                c"zero".to_owned(),
                c"-c".to_owned(),
                c"read -r line; printf '%s|%s|%s|%s' \"$0\" \"$1\" \"$VALUE\" \"$line\"; printf err >&2"
                    .to_owned(),
                c"argument zero".to_owned(),
                c"one".to_owned(),
            ],
        )
        .environment(vec![c"VALUE=exact".to_owned()])
        .stdin(stdin);
        let (failure, status, output, error) = run(command);
        assert_eq!(failure, None);
        assert_eq!(status, Some(ChildStatus::Exited(0)));
        assert_eq!(output, b"argument zero|one|exact|input");
        assert_eq!(error, b"err");
    }

    #[test]
    fn a_program_without_an_environment_inherits_its_parent_s() {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let (failure, status, output, _) = run(shell("printf %s \"$PATH\""));
        assert_eq!((failure, status), (None, Some(ChildStatus::Exited(0))));
        assert_eq!(output, path.as_bytes());
    }

    #[test]
    fn inherited_descriptors_stay_open_at_their_numbers_and_others_close() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"handed over").unwrap();
        std::io::Seek::rewind(&mut file).unwrap();
        let inherited = std::os::fd::AsRawFd::as_raw_fd(&file);
        let unrelated = tempfile::tempfile().unwrap();
        let other = std::os::fd::AsRawFd::as_raw_fd(&unrelated);
        // `cat` reads the inherited descriptor through its own descriptor table, because `sh`
        // accepts only single-digit redirections.
        let (failure, status, output, _) = run(shell(&format!(
            "cat /proc/self/fd/{inherited}; test ! -e /proc/self/fd/{other} && printf ' closed'"
        ))
        .inherit(file));
        assert_eq!((failure, status), (None, Some(ChildStatus::Exited(0))));
        assert_eq!(output, b"handed over closed");
        drop(unrelated);
    }

    #[test]
    fn the_working_directory_and_physical_pwd_follow_the_command() {
        let directory = tempfile::tempdir().unwrap();
        let physical = directory.path().join("physical");
        std::fs::create_dir(&physical).unwrap();
        std::os::unix::fs::symlink(&physical, directory.path().join("link")).unwrap();
        let requested = directory.path().join("link/.");
        let (failure, status, output, _) = run(shell("printf '%s|' \"$PWD\"; pwd -P")
            .environment(vec![c"PWD=/stale".to_owned(), c"KEPT=1".to_owned()])
            .working_directory(c_path(&requested))
            .export_physical_working_directory());
        assert_eq!((failure, status), (None, Some(ChildStatus::Exited(0))));
        let physical = std::fs::canonicalize(&physical).unwrap();
        let expected = [
            physical.as_os_str().as_bytes(),
            b"|",
            physical.as_os_str().as_bytes(),
            b"\n",
        ]
        .concat();
        assert_eq!(output, expected);
    }

    #[test]
    fn launch_stage_failures_are_reported_and_run_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("file");
        std::fs::write(&file, b"").unwrap();
        let marker = directory.path().join("ran");
        let touch = |command: Command| run(command).0;
        let script = format!("touch '{}'", marker.display());
        for (path, stage, error) in [
            (
                directory.path().join("missing"),
                LaunchStage::WorkingDirectory,
                Errno::ENOENT,
            ),
            (file.clone(), LaunchStage::WorkingDirectory, Errno::ENOTDIR),
        ] {
            let failure = touch(shell(&script).working_directory(c_path(&path))).unwrap();
            assert_eq!(
                (failure.stage(), failure.raw_os_error()),
                (stage, error as i32),
                "{path:?}"
            );
        }
        let failure = touch(
            shell(&script)
                .working_directory(c_path(directory.path()))
                .check_working_directory_as(1000, 1000)
                .simulate_credentials(Some(Errno::EPERM)),
        )
        .unwrap();
        assert_eq!(
            (failure.stage(), failure.raw_os_error()),
            (LaunchStage::Credentials, Errno::EPERM as i32)
        );
        let failure = touch(Command::new(
            c_path(&directory.path().join("missing")),
            vec![c"missing".to_owned()],
        ))
        .unwrap();
        assert_eq!(
            (failure.stage(), failure.raw_os_error()),
            (LaunchStage::Exec, Errno::ENOENT as i32)
        );
        // A cgroup whose membership file is full refuses the child's process ID.
        let cgroup = directory.path().join("cgroup");
        std::fs::create_dir(&cgroup).unwrap();
        std::os::unix::fs::symlink("/dev/full", cgroup.join("cgroup.procs")).unwrap();
        let failure = touch(shell(&script).cgroup(Cgroup::open(&cgroup).unwrap())).unwrap();
        assert_eq!(
            (failure.stage(), failure.raw_os_error()),
            (LaunchStage::Cgroup, Errno::ENOSPC as i32)
        );
        assert!(!marker.exists());
        assert_eq!(
            failure.to_string(),
            format!(
                "the cgroup launch stage failed: {}",
                io::Error::from_raw_os_error(Errno::ENOSPC as i32)
            )
        );
    }

    #[test]
    fn a_child_joins_its_cgroup_and_enters_its_checked_directory() {
        let directory = tempfile::tempdir().unwrap();
        let cgroup = directory.path().join("cgroup");
        std::fs::create_dir(&cgroup).unwrap();
        std::fs::write(cgroup.join("cgroup.procs"), b"").unwrap();
        let (stdout, stdout_writer) = std::io::pipe().unwrap();
        let spawned = shell("pwd -P")
            .working_directory(c_path(directory.path()))
            .check_working_directory_as(1000, 1000)
            .simulate_credentials(None)
            .cgroup(Cgroup::open(&cgroup).unwrap())
            .stdout(stdout_writer)
            .spawn()
            .unwrap();
        let (id, process) = (spawned.id(), spawned.process());
        let failure = spawned.into_report().wait().unwrap();
        let output = read_all(stdout);
        assert_eq!(sys::wait(process), Some(ChildStatus::Exited(0)));
        assert_eq!(failure, None);
        let physical = std::fs::canonicalize(directory.path()).unwrap();
        assert_eq!(output, [physical.as_os_str().as_bytes(), b"\n"].concat());
        assert_eq!(
            std::fs::read(cgroup.join("cgroup.procs")).unwrap(),
            format!("{id}\n").into_bytes()
        );
        assert!(Cgroup::open(&directory.path().join("missing")).is_err());
    }

    #[test]
    fn invalid_commands_fail_to_spawn() {
        for command in [
            Command::new(c"/bin/true".to_owned(), Vec::new()),
            shell("exit 0").working_directory(c"relative".to_owned()),
            shell("exit 0").check_working_directory_as(1000, 1000),
            shell("exit 0").export_physical_working_directory(),
        ] {
            let error = command.spawn().unwrap_err();
            assert_eq!(error.raw_os_error(), Some(Errno::EINVAL as i32));
        }
    }

    #[test]
    fn short_and_unknown_reports_are_protocol_errors() {
        for (bytes, expected) in [
            (Vec::new(), Ok(None)),
            (
                [5i32.to_ne_bytes(), 2i32.to_ne_bytes()].concat(),
                Ok(Some(LaunchFailure {
                    stage: LaunchStage::WorkingDirectory,
                    error: 2,
                })),
            ),
            (vec![1, 0, 0], Err(Errno::EPROTO as i32)),
            (
                [9i32.to_ne_bytes(), 2i32.to_ne_bytes()].concat(),
                Err(Errno::EPROTO as i32),
            ),
            (
                [0i32.to_ne_bytes(), 2i32.to_ne_bytes()].concat(),
                Err(Errno::EPROTO as i32),
            ),
        ] {
            let (reader, writer) = sys::create_pipe().unwrap();
            writer.write_all(&bytes).unwrap();
            drop(writer);
            let report = LaunchReport { reader }.wait();
            assert_eq!(
                report.map_err(|error| error.raw_os_error().unwrap()),
                expected,
                "{bytes:?}"
            );
        }
        for stage in LaunchStage::ALL {
            assert_eq!(LaunchStage::from_code(stage.code()), Some(stage));
        }
    }
}
