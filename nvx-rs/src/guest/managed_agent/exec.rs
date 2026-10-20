use std::time::{Duration, Instant};

use crate::guest::spawn::{LaunchReport, LaunchStage};
use crate::guest::sys::{
    self, ChildStatus, Errno, FileDescriptor, Mode, OpenFlags, ProcessId, c_string,
};
use crate::protocol::{
    self, APP_CANCEL, APP_EXIT, APP_STDERR, APP_STDOUT, BUSY, CWD_FAILED, GuestExecPayload,
    LAUNCH_FAILED, OUTER_DATA, OUTER_RESET,
};

use super::AgentConfig;
use super::cgroup;
use super::diagnostics::with_description;
use super::exec_config;
use super::launch::{self, LaunchRequest};
use super::seam::{System, path_c_string};
use super::session::{DataFailureKind, Session};
use super::tty;

/// Maximum bytes read from one output descriptor at a time.
const OUTPUT_CHUNK_BYTES: usize = 32 * 1024;
/// Readiness-poll interval, in milliseconds.
const POLL_INTERVAL_MS: u16 = 25;
/// Number of bounded attempts to open a sandbox barrier writer.
const BARRIER_ATTEMPTS: usize = 500;

/// Executes one validated workload request and streams its terminal outcome.
pub(crate) fn run(
    system: &mut impl System,
    session: &mut Session,
    config: &AgentConfig,
    request_id: u64,
    execution: &GuestExecPayload,
) -> Result<(), Errno> {
    if config.direct {
        if let Err(error) = cgroup::prepare(system) {
            super::diagnostics::error(system, "exec-cgroup", error as i32);
            return session.send_error(request_id, 125, LAUNCH_FAILED);
        }
        match cgroup::verify_empty(system) {
            Ok(false) => {}
            Ok(true) => {
                super::diagnostics::error(system, "exec-cgroup-verify", Errno::EBUSY as i32);
                return session.send_error(request_id, 125, "containment-failed");
            }
            Err(error) => {
                super::diagnostics::error(system, "exec-cgroup-verify", error as i32);
                return session.send_error(request_id, 125, "containment-failed");
            }
        }
    }
    if let Err(failure) = validate_launch_environment(system, config, execution) {
        match failure {
            EnvironmentFailure::Child(error, diagnostic) => {
                let message = with_description(diagnostic, error);
                session.send_app(APP_STDERR, request_id, 0, &message)?;
                return session.send_app(APP_EXIT, request_id, 125, b"exit");
            }
            EnvironmentFailure::Launch(error) => {
                super::diagnostics::error(system, "exec-launch", error as i32);
                return session.send_error(request_id, 125, LAUNCH_FAILED);
            }
        }
    }
    if !config.direct && create_barrier(system).is_err() {
        return session.send_error(request_id, 125, LAUNCH_FAILED);
    }

    let Ok(Launched {
        child,
        stdout,
        stderr,
        report,
    }) = launch(system, config, execution)
    else {
        unlink_barrier(system);
        return session.send_error(request_id, 125, LAUNCH_FAILED);
    };
    let mut launch_failed =
        tty::make_nonblocking(&stdout).is_err() || tty::make_nonblocking(&stderr).is_err();
    if !launch_failed && !config.direct {
        launch_failed = cgroup::write_container_pid(system, child).is_err()
            || release_barrier(system, child).is_err();
    }
    if launch_failed {
        cgroup::terminate(system, config.direct, child);
        let _ = sys::wait(child);
        unlink_barrier(system);
        return session.send_error(request_id, 125, LAUNCH_FAILED);
    }
    unlink_barrier(system);
    let mut stdout_pipe = Some(stdout);
    let mut stderr_pipe = Some(stderr);

    let started = Instant::now();
    let mut output_bytes = 0usize;
    let mut timed_out = false;
    let mut output_limited = false;
    let mut cancelled = false;
    let mut session_lost = false;
    let mut stragglers_killed = false;
    let mut wait_status = None;

    while wait_status.is_none() || stdout_pipe.is_some() || stderr_pipe.is_some() {
        let ready = match sys::readable_or_hung_up(
            [
                stdout_pipe.as_ref(),
                stderr_pipe.as_ref(),
                (!session_lost).then_some(session.descriptor()),
            ],
            POLL_INTERVAL_MS,
        ) {
            Ok(ready) => ready,
            Err(Errno::EINTR) => [false; 3],
            Err(_) => {
                cgroup::terminate(system, config.direct, child);
                [false; 3]
            }
        };
        if !session_lost && ready[2] {
            let control = match handle_control(system, session, request_id) {
                Ok(control) => control,
                Err(error) => {
                    cgroup::terminate(system, config.direct, child);
                    let _ = sys::wait(child);
                    return Err(error);
                }
            };
            match control {
                ExecControl::None => {}
                ExecControl::Cancel if wait_status.is_none() && !cancelled => {
                    cancelled = true;
                    cgroup::terminate(system, config.direct, child);
                }
                ExecControl::Cancel => {}
                ExecControl::SessionLost => {
                    session_lost = true;
                    cgroup::terminate(system, config.direct, child);
                }
            }
        }
        let mut read_output = |pipe: Option<&FileDescriptor>, readable: bool, kind: u8| match pipe {
            Some(pipe) if readable && session_lost => drain(pipe),
            Some(pipe) if readable => stream(session, request_id, pipe, kind, &mut output_bytes),
            _ => StreamResult::Open,
        };
        let stdout_result = read_output(stdout_pipe.as_ref(), ready[0], APP_STDOUT);
        let stderr_result = read_output(stderr_pipe.as_ref(), ready[1], APP_STDERR);
        if stdout_result == StreamResult::Closed {
            stdout_pipe = None;
        }
        if stderr_result == StreamResult::Closed {
            stderr_pipe = None;
        }
        if stdout_result.is_failure() || stderr_result.is_failure() {
            output_limited =
                stdout_result == StreamResult::Limited || stderr_result == StreamResult::Limited;
            cgroup::terminate(system, config.direct, child);
        }
        cgroup::reap(child, &mut wait_status);
        if wait_status.is_some()
            && config.direct
            && !stragglers_killed
            && (stdout_pipe.is_some() || stderr_pipe.is_some())
        {
            stragglers_killed = true;
            let _ = cgroup::kill(system);
        }
        if wait_status.is_none()
            && execution.timeout_ms != 0
            && started.elapsed() >= Duration::from_millis(u64::from(execution.timeout_ms))
        {
            timed_out = true;
            cgroup::terminate(system, config.direct, child);
        }
        if (timed_out || output_limited || cancelled || session_lost)
            && wait_status.is_none()
            && let Some(status) = sys::wait(child)
        {
            wait_status = Some(status);
        }
    }

    let launch_report = report.wait();
    if config.direct
        && let Err(error) = cgroup::settle(system)
    {
        super::diagnostics::error(system, "exec-cgroup-settle", error as i32);
        return if session_lost {
            Ok(())
        } else {
            session.send_error(request_id, 125, "containment-failed")
        };
    }
    if session_lost {
        return Ok(());
    }
    match launch_report {
        Ok(Some(failure)) => match failure.stage() {
            LaunchStage::WorkingDirectory => {
                return refuse_cwd(session, request_id, execution, failure.raw_os_error());
            }
            LaunchStage::Credentials
            | LaunchStage::PhysicalWorkingDirectory
            | LaunchStage::Cgroup => {
                super::diagnostics::error(system, "exec-launch", failure.raw_os_error());
                return session.send_error(request_id, 125, LAUNCH_FAILED);
            }
            // The other stages end the child with status 125 before the workload runs, which
            // the agent reports as the workload's exit status, as the C agent did.
            _ => {}
        },
        Err(error) => {
            super::diagnostics::error(system, "exec-launch-report", sys::errno_of(&error) as i32);
        }
        Ok(None) => {}
    }
    if cancelled {
        session.send_app(
            APP_EXIT,
            request_id,
            128 + sys::Signal::SIGKILL as i32,
            b"cancelled",
        )
    } else if timed_out {
        session.send_app(APP_EXIT, request_id, 124, b"timeout")
    } else if output_limited {
        session.send_app(APP_EXIT, request_id, 125, b"output-limit")
    } else {
        match wait_status {
            Some(ChildStatus::Exited(status)) => {
                session.send_app(APP_EXIT, request_id, status, b"exit")
            }
            Some(ChildStatus::Signaled(signal)) => {
                session.send_app(APP_EXIT, request_id, 128 + signal, b"signal")
            }
            Some(ChildStatus::Other) | None => {
                session.send_app(APP_EXIT, request_id, 125, b"failed")
            }
        }
    }
}

/// A spawned workload and the parent's ends of its pipes.
struct Launched {
    /// The workload process, which leads its own process group.
    child: ProcessId,
    /// Reader of the workload's standard output.
    stdout: FileDescriptor,
    /// Reader of the workload's standard error.
    stderr: FileDescriptor,
    /// Report of the workload's launch stages.
    report: LaunchReport,
}

/// Creates the workload's pipes and sealed configuration, then spawns it.
///
/// The launch command takes the configuration and the child's pipe ends, which the agent closes
/// once the child exists, as the C agent closed them after `fork`.
fn launch(
    system: &mut impl System,
    config: &AgentConfig,
    execution: &GuestExecPayload,
) -> Result<Launched, Errno> {
    let (stdout, stdout_writer) = sys::create_pipe()?;
    let (stderr, stderr_writer) = sys::create_pipe()?;
    let config_fd = exec_config::create(execution, config.direct)?;
    let command = launch::command(
        system.paths(),
        LaunchRequest {
            config,
            execution,
            config_fd,
            stdout: stdout_writer,
            stderr: stderr_writer,
        },
    )?;
    let spawned = system.spawn(command)?;
    Ok(Launched {
        child: spawned.process(),
        stdout,
        stderr,
        report: spawned.into_report(),
    })
}

/// Failure discovered before the fork boundary.
#[derive(Debug)]
enum EnvironmentFailure {
    /// Failure whose exact stderr text belongs to the would-be child.
    Child(Errno, &'static [u8]),
    /// Parent-side launch validation failure.
    Launch(Errno),
}

/// Validates all environment mutations before allocating child resources.
fn validate_launch_environment(
    system: &mut impl System,
    config: &AgentConfig,
    execution: &GuestExecPayload,
) -> Result<(), EnvironmentFailure> {
    if config.direct {
        for (name, value) in [
            (c"HOME", config.home.as_c_str()),
            (c"USER", config.user.as_c_str()),
            (c"LOGNAME", config.user.as_c_str()),
        ] {
            if let Err(error) = system.validate_environment(name, value) {
                return Err(EnvironmentFailure::Child(
                    error,
                    b"nvx-managed-agent: cannot configure workload environment: ",
                ));
            }
        }
        if execution.environment.is_none() || execution.inherit_default_env {
            let pwd = c_string(execution.cwd.as_deref().unwrap_or(b"/"))
                .map_err(EnvironmentFailure::Launch)?;
            system
                .validate_environment(c"PWD", &pwd)
                .map_err(EnvironmentFailure::Launch)?;
        }
    } else if let Err(error) = system.validate_environment(c"NVX_EXEC_CONFIG_FD", c"0") {
        return Err(EnvironmentFailure::Child(
            error,
            b"nvx-managed-agent: cannot export execution configuration: ",
        ));
    }
    Ok(())
}

/// Sends the C-compatible stderr and application error for a cwd failure.
fn refuse_cwd(
    session: &mut Session,
    request_id: u64,
    execution: &GuestExecPayload,
    status: i32,
) -> Result<(), Errno> {
    let cwd = execution.cwd.as_deref().unwrap_or(b"/");
    let prefix = [
        b"nvx-managed-agent: cannot enter working directory ".as_slice(),
        cwd,
        b": ",
    ]
    .concat();
    let diagnostic = with_description(&prefix, Errno::from_raw(status));
    session.send_app(APP_STDERR, request_id, 0, &diagnostic)?;
    session.send_error(request_id, status, CWD_FAILED)
}

/// Control action observed while a workload is active.
#[derive(Clone, Copy)]
enum ExecControl {
    /// No action applies to the active workload.
    None,
    /// The host cancelled the active workload.
    Cancel,
    /// A reset detached this workload's session.
    SessionLost,
}

/// Processes one control-console record while a workload runs.
fn handle_control(
    system: &mut impl System,
    session: &mut Session,
    exec_id: u64,
) -> Result<ExecControl, Errno> {
    let record = session.read_record().inspect_err(|error| {
        super::diagnostics::error(system, "exec-outer-read", *error as i32);
    })?;
    if record.header.record_type == OUTER_RESET {
        session.acknowledge_reset(&record)?;
        return Ok(ExecControl::SessionLost);
    }
    if record.header.record_type != OUTER_DATA {
        super::diagnostics::error(system, "exec-record", i32::from(record.header.record_type));
        return Err(Errno::EPROTO);
    }
    let request = match session.validate_data(&record) {
        Ok(request) => request,
        Err(failure) => {
            if failure.kind != DataFailureKind::Credit {
                super::diagnostics::error(
                    system,
                    "exec-record",
                    i32::from(record.header.record_type),
                );
            }
            return Err(failure.into_error());
        }
    };
    if request.kind == APP_CANCEL {
        return Ok(
            if request.payload.is_empty() && request.request_id == exec_id {
                ExecControl::Cancel
            } else {
                ExecControl::None
            },
        );
    }
    session.send_error(request.request_id, Errno::EBUSY as i32, BUSY)?;
    Ok(ExecControl::None)
}

/// Result of draining one nonblocking output descriptor.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamResult {
    /// The descriptor remains open and currently has no more data.
    Open,
    /// End of file closed the descriptor.
    Closed,
    /// Reading or forwarding output failed.
    Failed,
    /// Forwarding another chunk would exceed the output cap.
    Limited,
}

impl StreamResult {
    /// Returns whether the workload must be terminated for this result.
    fn is_failure(self) -> bool {
        matches!(self, Self::Failed | Self::Limited)
    }
}

/// Reads and forwards all currently available output from one descriptor.
fn stream(
    session: &mut Session,
    request_id: u64,
    descriptor: &FileDescriptor,
    kind: u8,
    output_bytes: &mut usize,
) -> StreamResult {
    let mut buffer = [0u8; OUTPUT_CHUNK_BYTES];
    loop {
        let count = descriptor.read(&mut buffer);
        if let Ok(count) = count
            && count > 0
        {
            if *output_bytes > protocol::MAX_OUTPUT_BYTES - count {
                return StreamResult::Limited;
            }
            *output_bytes += count;
            if session
                .send_app(kind, request_id, 0, &buffer[..count])
                .is_err()
            {
                return StreamResult::Failed;
            }
        } else if matches!(count, Ok(0)) {
            return StreamResult::Closed;
        } else {
            match count {
                Err(sys::Errno::EINTR) => {}
                Err(sys::Errno::EAGAIN) => return StreamResult::Open,
                Err(_) | Ok(_) => return StreamResult::Failed,
            }
        }
    }
}

/// Discards currently available bytes after the control session is lost.
fn drain(descriptor: &FileDescriptor) -> StreamResult {
    let mut buffer = [0u8; OUTPUT_CHUNK_BYTES];
    loop {
        match descriptor.read(&mut buffer) {
            Ok(count) if count > 0 => {}
            Ok(_) => return StreamResult::Closed,
            Err(sys::Errno::EINTR) => {}
            Err(sys::Errno::EAGAIN) => return StreamResult::Open,
            Err(_) => return StreamResult::Failed,
        }
    }
}

/// Creates a fresh launch-barrier FIFO after removing a stale entry.
fn create_barrier(system: &impl System) -> Result<(), Errno> {
    unlink_barrier(system);
    let path = path_c_string(&system.paths().barrier)?;
    sys::create_fifo(&path, Mode::from_bits_retain(0o600))
}

/// Best-effort removes the launch-barrier FIFO.
fn unlink_barrier(system: &impl System) {
    if let Ok(path) = path_c_string(&system.paths().barrier) {
        let _ = sys::unlink(&path);
    }
}

/// Opens and releases the sandbox barrier, bounded by child exit and retry count.
fn release_barrier(system: &mut impl System, child: ProcessId) -> Result<(), Errno> {
    let path = path_c_string(&system.paths().barrier)?;
    for _ in 0..BARRIER_ATTEMPTS {
        match sys::open(
            &path,
            OpenFlags::O_WRONLY | OpenFlags::O_CLOEXEC | OpenFlags::O_NONBLOCK,
            Mode::empty(),
        ) {
            Ok(descriptor) => return write_barrier(system, &descriptor),
            Err(Errno::ENXIO | Errno::EINTR) => {}
            Err(error) => return Err(error),
        }
        match sys::has_exited(child) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(error),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(Errno::ETIMEDOUT)
}

/// Writes the barrier with SIGPIPE temporarily ignored and exactly restored.
fn write_barrier(system: &mut impl System, descriptor: &FileDescriptor) -> Result<(), Errno> {
    sys::with_sigpipe_ignored(|| system.write_barrier(descriptor, b"start\n"))
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::process::Command;
    use std::thread;

    use super::super::seam::{Paths, TestSystem};
    use super::*;

    fn system() -> (tempfile::TempDir, TestSystem) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = Paths {
            barrier: temporary.path().join("managed-container-start"),
            ..Paths::default()
        };
        (temporary, TestSystem::new(paths))
    }

    #[test]
    fn parent_barrier_release_is_bounded_without_a_child_reader() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = system();
        create_barrier(&system).unwrap();
        let mut child = Command::new("/bin/true").spawn().unwrap();
        let process = ProcessId::from_child(&child);
        release_barrier(&mut system, process).unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn parent_barrier_release_handles_a_reader_closing_during_write() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = system();
        create_barrier(&system).unwrap();
        let path = path_c_string(&system.paths.barrier).unwrap();
        let reader = sys::open(
            &path,
            OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC | OpenFlags::O_NONBLOCK,
            Mode::empty(),
        )
        .unwrap();
        system.close_barrier_reader = Some(reader);
        system.fail_barrier_write = Some(Errno::EPIPE);
        let mut child = Command::new("/bin/sleep").arg("5").spawn().unwrap();
        let error = release_barrier(&mut system, ProcessId::from_child(&child)).unwrap_err();
        assert_eq!(error, Errno::EPIPE);
        child.kill().unwrap();
        let _ = child.wait();
    }

    #[test]
    fn parent_barrier_release_preserves_a_live_child_start() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = system();
        create_barrier(&system).unwrap();
        let path = system.paths.barrier.clone();
        let reader = thread::spawn(move || {
            let mut fifo = std::fs::OpenOptions::new().read(true).open(path).unwrap();
            let mut message = [0u8; 6];
            fifo.read_exact(&mut message).unwrap();
            message
        });
        let mut child = Command::new("/bin/sleep").arg("5").spawn().unwrap();
        release_barrier(&mut system, ProcessId::from_child(&child)).unwrap();
        assert_eq!(reader.join().unwrap(), *b"start\n");
        child.kill().unwrap();
        let _ = child.wait();
    }

    #[test]
    fn write_barrier_restores_the_sigpipe_disposition() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = system();
        let (left, right) = UnixStream::pair().unwrap();
        let writer = FileDescriptor::from_owned(left.into());
        let reader = FileDescriptor::from_owned(right.into());
        system.close_barrier_reader = Some(reader);
        system.fail_barrier_write = Some(Errno::EPIPE);
        let before = sys::sigpipe_disposition().unwrap();
        assert_eq!(
            write_barrier(&mut system, &writer).unwrap_err(),
            Errno::EPIPE
        );
        let after = sys::sigpipe_disposition().unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn environment_failures_stop_direct_and_sandbox_launches_before_exec() {
        let config = |direct| AgentConfig {
            rootfs: CString::new(if direct { "-" } else { "/rootfs" }).unwrap(),
            hostname: c"test".to_owned(),
            uid: c"1000".to_owned(),
            gid: c"1000".to_owned(),
            user: c"workload".to_owned(),
            home: c"/home/workload".to_owned(),
            direct,
        };
        let execution = GuestExecPayload {
            timeout_ms: 0,
            argv: vec![b"/bin/true".to_vec()],
            cwd: None,
            environment: None,
            inherit_default_env: false,
        };
        for (direct, variable, diagnostic) in [
            (
                true,
                b"HOME".as_slice(),
                b"cannot configure workload environment".as_slice(),
            ),
            (
                false,
                b"NVX_EXEC_CONFIG_FD".as_slice(),
                b"cannot export execution configuration".as_slice(),
            ),
        ] {
            let mut system = TestSystem::new(Paths::default());
            system.fail_environment = Some(variable.to_vec());
            let failure =
                validate_launch_environment(&mut system, &config(direct), &execution).unwrap_err();
            let EnvironmentFailure::Child(error, message) = failure else {
                panic!("expected a child environment failure");
            };
            assert_eq!(error, Errno::ENOMEM);
            assert!(
                message
                    .windows(diagnostic.len())
                    .any(|part| part == diagnostic),
                "{message:?}"
            );
            assert!(system.execs.is_empty());
        }

        let mut system = TestSystem::new(Paths::default());
        system.fail_environment = Some(b"PWD".to_vec());
        let failure =
            validate_launch_environment(&mut system, &config(true), &execution).unwrap_err();
        assert!(matches!(failure, EnvironmentFailure::Launch(Errno::ENOMEM)));
        assert!(system.execs.is_empty());
    }
}
