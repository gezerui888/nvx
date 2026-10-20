//! Verified process references and event-driven exit waits, through the public API of
//! `nvx::host::process`, as a supervisor of VMM processes uses them.
//!
//! The processes are this test executable, run again as one of two fixtures. A VMM fixture reads
//! the capability that `nvx::host::process::spawn` passes on its standard input, as OpenVMM does,
//! and runs until a file named `exit` appears in its working directory. A launcher fixture spawns
//! a VMM fixture, prints the VMM's reference as an orchestrator would record it, and runs until
//! its standard input closes. A launcher that the test kills, or whose job object the test
//! closes, stands for an orchestrator that crashed and restarts within the same boot: the test
//! then finds the VMM again from the recorded reference, as the restarted orchestrator would.
#![cfg(all(feature = "host", any(target_os = "linux", windows)))]

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use nvx::host::process::{self, BootId, Launched, Process, ProcessRef, WaitMethod};
use nvx::protocol::CAPABILITY_LEN;

/// File whose presence in its working directory marks a VMM fixture. Without it, the fixture
/// returns at once, as it does when `cargo test -- --ignored` runs it.
const VMM_MARKER: &str = "vmm-fixture";
/// File whose appearance in its working directory ends a VMM fixture.
const EXIT_MARKER: &str = "exit";
/// Environment variable that marks a launcher fixture, and names the working directory of its
/// VMM.
const LAUNCHER_DIR: &str = "NVX_SUPERVISOR_TEST_VMM_DIR";
/// Environment variable that asks a launcher fixture to start its VMM outside its job object.
const LAUNCHER_BREAKAWAY: &str = "NVX_SUPERVISOR_TEST_BREAKAWAY";
/// Prefix of the line on which a launcher fixture prints the reference of its VMM.
const REFERENCE_PREFIX: &str = "vmm-reference ";
/// Longest wait for a process that is expected to exit, or for a launcher to answer.
const TIMEOUT: Duration = Duration::from_secs(60);
/// Longest life of a VMM fixture that nothing ends, so that a failed test leaves no process.
const VMM_LIFETIME: Duration = Duration::from_secs(180);
/// A wait that a running process outlasts.
const SHORT_WAIT: Duration = Duration::from_millis(100);

/// The VMM fixture: reads its capability as OpenVMM does, then runs until a file named
/// [`EXIT_MARKER`] appears in its working directory.
#[test]
#[ignore = "fixture that the supervision tests run as a VMM"]
fn vmm_fixture() {
    let directory = std::env::current_dir().unwrap();
    if !directory.join(VMM_MARKER).exists() {
        return;
    }
    let mut capability = [0; CAPABILITY_LEN];
    io::stdin().read_exact(&mut capability).unwrap();
    let started = Instant::now();
    while !directory.join(EXIT_MARKER).exists() && started.elapsed() < VMM_LIFETIME {
        thread::sleep(Duration::from_millis(10));
    }
}

/// The launcher fixture: when the test writes a line to its standard input, spawns a VMM fixture
/// in the directory that [`LAUNCHER_DIR`] names, prints its reference, releases it, and runs
/// until its standard input closes.
#[test]
#[ignore = "fixture that the supervision tests run as a launcher"]
fn launcher_fixture() {
    let Some(directory) = std::env::var_os(LAUNCHER_DIR) else {
        return;
    };
    let mut input = io::stdin().lock();
    input.read_line(&mut String::new()).unwrap();
    let breakaway = std::env::var_os(LAUNCHER_BREAKAWAY).is_some();
    let launched = spawn_vmm(Path::new(&directory), breakaway);
    let reference = launched.process().unwrap().reference().clone();
    println!(
        "{REFERENCE_PREFIX}{}",
        serde_json::to_string(&reference).unwrap()
    );
    process::detach_child(launched);
    io::copy(&mut input, &mut io::sink()).unwrap();
}

/// Returns the arguments that run only the fixture `name` of this test executable.
fn fixture_arguments(name: &str) -> Vec<OsString> {
    ["--exact", name, "--ignored", "--nocapture"]
        .map(OsString::from)
        .to_vec()
}

/// Spawns a VMM fixture in `directory` as OpenVMM is spawned, outside the caller's job object if
/// `breakaway`.
fn spawn_vmm(directory: &Path, breakaway: bool) -> Launched {
    File::create(directory.join(VMM_MARKER)).unwrap();
    let log = File::create(directory.join("vmm.log")).unwrap();
    process::spawn(
        &std::env::current_exe().unwrap(),
        breakaway,
        &fixture_arguments("vmm_fixture"),
        &[0x5a; CAPABILITY_LEN],
        log,
        directory,
    )
    .unwrap()
}

/// The working directory of a VMM fixture. Dropping it ends the fixture and waits for it to
/// exit, so that a failed test leaves no process behind.
struct VmmDirectory {
    /// The reference of the VMM, once the test knows it.
    reference: Option<ProcessRef>,
    /// The directory, which is removed after the VMM exits.
    directory: tempfile::TempDir,
}

impl VmmDirectory {
    /// Creates an empty directory.
    fn new() -> Self {
        Self {
            reference: None,
            directory: tempfile::tempdir().unwrap(),
        }
    }

    /// Returns the path of the directory.
    fn path(&self) -> &Path {
        self.directory.path()
    }

    /// Records the reference of the VMM that runs in the directory.
    fn record(&mut self, reference: &ProcessRef) {
        self.reference = Some(reference.clone());
    }

    /// Asks the VMM to exit.
    fn end(&self) {
        File::create(self.path().join(EXIT_MARKER)).unwrap();
    }
}

impl Drop for VmmDirectory {
    fn drop(&mut self) {
        let _ = File::create(self.path().join(EXIT_MARKER));
        if let Some(reference) = &self.reference
            && let Ok(Some(process)) = Process::open(reference)
        {
            let _ = process.wait(Instant::now() + TIMEOUT);
        }
    }
}

/// A launcher fixture, which the test drives through its standard streams.
struct Launcher {
    /// The launcher process.
    child: Child,
    /// Its standard input, which the test closes to end it.
    input: Option<ChildStdin>,
}

impl Launcher {
    /// Starts a launcher whose VMM runs in `directory`, outside the launcher's job object if
    /// `breakaway`.
    fn start(directory: &Path, breakaway: bool) -> Self {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(fixture_arguments("launcher_fixture"))
            .env(LAUNCHER_DIR, directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        if breakaway {
            command.env(LAUNCHER_BREAKAWAY, "1");
        }
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take();
        Self { child, input }
    }

    /// Asks the launcher to spawn its VMM, and returns the reference that it prints, as the
    /// launcher would record it: as JSON.
    fn launch(&mut self) -> String {
        let input = self.input.as_mut().unwrap();
        input.write_all(b"launch\n").unwrap();
        input.flush().unwrap();
        let output = self.child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut lines = BufReader::new(output).lines();
            let reference = lines
                .by_ref()
                .find_map(|line| line.ok()?.strip_prefix(REFERENCE_PREFIX).map(str::to_owned));
            let _ = sender.send(reference);
            // Read the rest, so that the launcher can still write its own output.
            lines.for_each(drop);
        });
        receiver
            .recv_timeout(TIMEOUT)
            .expect("the launcher printed no reference in time")
            .expect("the launcher exited before it printed a reference")
    }

    /// Waits for the launcher to exit, and returns its status.
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "the launcher did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Closes the launcher's input, which ends it, and waits for it to exit.
    fn finish(&mut self) {
        drop(self.input.take());
        assert!(self.wait().success());
    }
}

impl Drop for Launcher {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Opens the process that `reference` names, which must still run.
fn open_running(reference: &ProcessRef) -> Process {
    Process::open(reference)
        .unwrap()
        .unwrap_or_else(|| panic!("{reference:?} does not run"))
}

/// Checks that the process that `reference` names has exited, and that no process matches it.
fn assert_ended(process: &Process) {
    assert!(process.has_exited().unwrap());
    assert!(Process::open(process.reference()).unwrap().is_none());
}

#[test]
fn processes_can_be_shared_between_threads() {
    /// Compiles only for types that threads can share.
    fn shared<T: Send + Sync>() {}
    shared::<Process>();
    shared::<ProcessRef>();
}

#[test]
fn a_child_that_exits_wakes_its_waiter() {
    let mut vmm = VmmDirectory::new();
    let launched = spawn_vmm(vmm.path(), false);
    let process = launched.process().unwrap();
    vmm.record(process.reference());
    assert_eq!(process.reference().pid, launched.id());
    assert_eq!(process.reference().boot, BootId::current().unwrap());
    assert_eq!(process.wait_method(), WaitMethod::Event);
    assert!(!process.has_exited().unwrap());
    assert!(!process.wait(Instant::now() + SHORT_WAIT).unwrap());
    // The reference finds the same process through a handle of its own.
    let found = open_running(process.reference());
    assert_eq!(found.reference(), process.reference());

    let started = Instant::now();
    vmm.end();
    assert!(process.wait(started + TIMEOUT).unwrap());
    assert!(found.wait(started + TIMEOUT).unwrap());
    assert!(started.elapsed() < TIMEOUT);
    assert_ended(&process);
    // Ending a process that exited does nothing.
    process.kill().unwrap();
    assert!(process::kill_child(launched));
}

#[test]
fn a_process_that_is_not_a_child_wakes_its_waiters() {
    let mut vmm = VmmDirectory::new();
    let mut launcher = Launcher::start(vmm.path(), false);
    let reference: ProcessRef = serde_json::from_str(&launcher.launch()).unwrap();
    vmm.record(&reference);
    // The launcher exits, so its VMM is no child of this process.
    launcher.finish();
    let process = open_running(&reference);
    assert_eq!(process.wait_method(), WaitMethod::Event);
    assert!(!process.wait(Instant::now() + SHORT_WAIT).unwrap());

    let started = Instant::now();
    let waiters: Vec<bool> = thread::scope(|scope| {
        let waiters: Vec<_> = (0..2)
            .map(|_| scope.spawn(|| process.wait(started + TIMEOUT).unwrap()))
            .collect();
        vmm.end();
        waiters
            .into_iter()
            .map(|waiter| waiter.join().unwrap())
            .collect()
    });
    assert_eq!(waiters, [true, true]);
    assert!(started.elapsed() < TIMEOUT);
    assert_ended(&process);
}

#[test]
fn a_restarted_launcher_finds_its_vmm_again_and_ends_it() {
    let mut vmm = VmmDirectory::new();
    // On Windows, the launcher runs in a job object that terminates it when the job closes, and
    // its VMM breaks away from the job, as an orchestrator's VMMs do to survive it.
    #[cfg(windows)]
    let job = job::Job::new(true);
    let mut launcher = Launcher::start(vmm.path(), cfg!(windows));
    #[cfg(windows)]
    job.assign(&launcher.child);
    let recorded = launcher.launch();
    // The launcher crashes.
    #[cfg(windows)]
    drop(job);
    #[cfg(not(windows))]
    launcher.child.kill().unwrap();
    launcher.wait();

    // Its successor reads the recorded reference back, and finds the VMM, which survived.
    let reference: ProcessRef = serde_json::from_str(&recorded).unwrap();
    vmm.record(&reference);
    let process = open_running(&reference);
    assert_eq!(process.wait_method(), WaitMethod::Event);
    assert!(!process.wait(Instant::now() + SHORT_WAIT).unwrap());
    let started = Instant::now();
    process.kill().unwrap();
    assert!(process.wait(started + TIMEOUT).unwrap());
    assert_ended(&process);
}

#[test]
fn a_reused_process_id_is_never_signaled() {
    let mut vmm = VmmDirectory::new();
    let launched = spawn_vmm(vmm.path(), false);
    let process = launched.process().unwrap();
    let reference = process.reference().clone();
    vmm.record(&reference);
    let mut other_boot = *reference.boot.as_bytes();
    other_boot[15] ^= 1;
    // A process with the same ID and another start time is not the referenced one, and neither
    // is one of another boot: the referenced process exited, and its ID now names another.
    for impostor in [
        ProcessRef {
            start_time: reference.start_time + 1,
            ..reference.clone()
        },
        ProcessRef {
            start_time: reference.start_time - 1,
            ..reference.clone()
        },
        ProcessRef {
            boot: BootId::from_bytes(other_boot),
            ..reference.clone()
        },
    ] {
        assert!(
            Process::open(&impostor).unwrap().is_none(),
            "{impostor:?} names a running process"
        );
    }
    // The functions that take a process ID and a start time do not signal it either.
    assert!(process::kill(reference.pid, reference.start_time + 1).unwrap());
    assert!(process::wait_for_exit(
        reference.pid,
        reference.start_time + 1,
        Instant::now()
    ));

    // The process that has the ID still runs.
    assert!(!process.has_exited().unwrap());
    open_running(&reference);
    vmm.end();
    assert!(process.wait(Instant::now() + TIMEOUT).unwrap());
    assert!(process::kill_child(launched));
}

#[test]
fn references_that_name_no_process_are_never_opened() {
    let boot = BootId::current().unwrap();
    let invalid = ProcessRef {
        pid: 0,
        start_time: 1,
        boot,
    };
    let error = Process::open(&invalid).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    // Linux assigns no process ID beyond `i32::MAX`.
    #[cfg(target_os = "linux")]
    {
        let invalid = ProcessRef {
            pid: u32::MAX,
            ..invalid
        };
        let error = Process::open(&invalid).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    // A process that exited and was reaped: no process has its ID, or another one has it.
    let vmm = VmmDirectory::new();
    let launched = spawn_vmm(vmm.path(), false);
    let process = launched.process().unwrap();
    vmm.end();
    assert!(process.wait(Instant::now() + TIMEOUT).unwrap());
    assert!(process::kill_child(launched));
    assert!(Process::open(process.reference()).unwrap().is_none());
    assert!(process.has_exited().unwrap());
}

#[cfg(windows)]
#[test]
fn a_job_that_ends_its_vmm_wakes_the_waiters() {
    let mut vmm = VmmDirectory::new();
    let job = job::Job::new(false);
    let mut launcher = Launcher::start(vmm.path(), false);
    job.assign(&launcher.child);
    let reference: ProcessRef = serde_json::from_str(&launcher.launch()).unwrap();
    vmm.record(&reference);
    // The VMM did not break away, so the job holds it too, and closing the job ends it.
    let process = open_running(&reference);
    assert!(!process.wait(Instant::now() + SHORT_WAIT).unwrap());
    let started = Instant::now();
    drop(job);
    assert!(process.wait(started + TIMEOUT).unwrap());
    assert_ended(&process);
    launcher.wait();
}

/// Job objects, which Windows orchestrators run in.
#[cfg(windows)]
mod job {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::process::Child;
    use std::{io, mem, ptr};

    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };

    /// A job object that terminates its processes when the test closes it.
    pub(crate) struct Job(OwnedHandle);

    impl Job {
        /// Creates a job that terminates its processes when it closes, and that lets them start
        /// processes outside it if `breakaway`.
        pub(crate) fn new(breakaway: bool) -> Self {
            // SAFETY: creates an unnamed job object with default security.
            let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
            assert!(
                !handle.is_null(),
                "cannot create a job object: {}",
                io::Error::last_os_error()
            );
            // SAFETY: the handle is new, and nothing else owns it.
            let job = Self(unsafe { OwnedHandle::from_raw_handle(handle) });
            // SAFETY: the structure is plain data for which all-zero bytes are valid.
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | if breakaway {
                    JOB_OBJECT_LIMIT_BREAKAWAY_OK
                } else {
                    0
                };
            // SAFETY: the handle is a job object, and the information has the size given.
            let set = unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    (&raw const limits).cast(),
                    mem::size_of_val(&limits) as u32,
                )
            };
            assert_ne!(
                set,
                0,
                "cannot set the limits of a job object: {}",
                io::Error::last_os_error()
            );
            job
        }

        /// Places `child` in the job, before it starts any process of its own.
        pub(crate) fn assign(&self, child: &Child) {
            // SAFETY: both handles are open for the duration of the call.
            let assigned =
                unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), child.as_raw_handle()) };
            assert_ne!(
                assigned,
                0,
                "cannot place the launcher in a job object: {}",
                io::Error::last_os_error()
            );
        }
    }
}
