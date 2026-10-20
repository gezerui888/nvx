use crate::guest::sys::Errno;
use crate::protocol::{
    self, APP_CANCEL, APP_EXEC, APP_FEATURES, APP_MAPS, APP_PING, APP_READY, APP_STOP, APP_STOPPED,
    GuestFeatures, INVALID_REQUEST, MAPPINGS_INCOMPLETE, OUTER_DATA, OUTER_RESET,
    UNSUPPORTED_OPERATION,
};

use super::diagnostics;
use super::mappings::{HostMappings, MappingError};
use super::seam::System;
use super::session::{Record, Session};
use super::{AgentConfig, exec, tty};

/// Terminal outcome of the long-lived dispatch loop.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// The host requested and acknowledged an orderly stop.
    Stopped,
}

/// Serves control requests until STOP or a fatal session error.
pub(crate) fn run(
    system: &mut impl System,
    session: &mut Session,
    config: &AgentConfig,
    mappings: &mut HostMappings,
) -> Result<Outcome, Errno> {
    session.send_attach()?;
    loop {
        let record = session.read_record().inspect_err(|error| {
            diagnostics::error(system, "outer-read", *error as i32);
        })?;
        match record.header.record_type {
            OUTER_RESET => session.acknowledge_reset(&record).inspect_err(|error| {
                diagnostics::error(system, "reset-ack", *error as i32);
            })?,
            // As in the C agent, a DATA record that fails also reports the `data` stage, after any
            // more specific stage. Its status is the error that ends the session, which
            // `control-session` reports too: `EPROTO` where C's `errno` was incidental, as after
            // a validation failure.
            OUTER_DATA => match handle_data(system, session, config, mappings, &record) {
                Ok(Some(outcome)) => return Ok(outcome),
                Ok(None) => {}
                Err(error) => {
                    diagnostics::error(system, "data", error as i32);
                    return Err(error);
                }
            },
            record_type => {
                diagnostics::error(system, "outer-type", i32::from(record_type));
                return Err(Errno::EPROTO);
            }
        }
    }
}

/// Validates one DATA record and serves its application request, returning the outcome that
/// ends the session, if any.
fn handle_data(
    system: &mut impl System,
    session: &mut Session,
    config: &AgentConfig,
    mappings: &mut HostMappings,
    record: &Record,
) -> Result<Option<Outcome>, Errno> {
    let request = match session.validate_data(record) {
        Ok(request) => request,
        Err(failure) => {
            diagnostics::error(system, failure.kind.stage(), failure.status);
            return Err(failure.into_error());
        }
    };
    match request.kind {
        APP_PING => {
            if request.payload.is_empty() {
                session
                    .send_app(APP_READY, request.request_id, 0, &[])
                    .inspect_err(|error| {
                        diagnostics::error(system, "ping-ready", *error as i32);
                    })?;
            } else {
                diagnostics::error(system, "ping-payload", request.payload.len() as i32);
                session.send_error(request.request_id, Errno::EINVAL as i32, INVALID_REQUEST)?;
            }
        }
        APP_EXEC => {
            if mappings.applied != mappings.expected {
                session.send_error(
                    request.request_id,
                    Errno::EAGAIN as i32,
                    MAPPINGS_INCOMPLETE,
                )?;
                return Ok(None);
            }
            let execution = match protocol::decode_guest_exec_payload(request.payload) {
                Ok(execution) => execution,
                Err(_) => {
                    session.send_error(
                        request.request_id,
                        Errno::EINVAL as i32,
                        INVALID_REQUEST,
                    )?;
                    return Ok(None);
                }
            };
            exec::run(system, session, config, request.request_id, &execution)?;
        }
        APP_CANCEL => {
            // The targeted workload has already reported its outcome.
        }
        APP_FEATURES => {
            if request.payload.is_empty() {
                let features = if config.direct {
                    GuestFeatures::DIRECT_AGENT
                } else {
                    GuestFeatures::SANDBOX_AGENT
                };
                session.send_app(APP_READY, request.request_id, 0, &features.encode())?;
            } else {
                session.send_error(request.request_id, Errno::EINVAL as i32, INVALID_REQUEST)?;
            }
        }
        APP_MAPS => match super::mappings::apply_request(system, mappings, request.payload) {
            Ok(()) => session.send_app(APP_READY, request.request_id, 0, &[])?,
            Err(MappingError::Invalid) => {
                session.send_error(request.request_id, Errno::EINVAL as i32, INVALID_REQUEST)?
            }
            Err(MappingError::Mount { status, entry }) => {
                diagnostics::mapping_error(system, status, entry);
                session.send_error(request.request_id, status, protocol::MAPPING_FAILED)?;
            }
        },
        APP_STOP => {
            if !request.payload.is_empty() {
                return Err(Errno::EPROTO);
            }
            session.send_app(APP_STOPPED, request.request_id, 0, &[])?;
            tty::drain(system, session.descriptor());
            return Ok(Some(Outcome::Stopped));
        }
        _ => session.send_error(
            request.request_id,
            Errno::ENOTSUP as i32,
            std::str::from_utf8(UNSUPPORTED_OPERATION).expect("the category is ASCII"),
        )?,
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixStream;
    use std::thread;

    use crate::protocol::{
        APP_ERROR, APP_EXIT, APP_STDERR, APP_STDOUT, OUTER_ACK, OUTER_CREDIT, OUTER_GUEST_ATTACH,
        OUTER_HEADER_LEN, OUTER_RECEIVE_WINDOW, OuterHeader, Workload, WorkloadEnvironment,
        decode_ack_payload, decode_app, decode_credit_payload, decode_outer_header, encode_app,
        encode_exec_payload, encode_outer,
    };

    use super::super::seam::{Paths, TestSystem};
    use super::*;
    use crate::guest::sys::{FileDescriptor, MountFlags};

    const INSTANCE: [u8; 16] = [7; 16];

    #[derive(Debug, PartialEq, Eq)]
    struct Response {
        kind: u8,
        request_id: u64,
        status: i32,
        payload: Vec<u8>,
    }

    struct Harness {
        host: UnixStream,
        thread: thread::JoinHandle<(Result<Outcome, Errno>, TestSystem)>,
        host_sequence: u64,
        guest_sequence: u64,
    }

    impl Harness {
        fn new(direct: bool) -> Self {
            Self::with_system(direct, TestSystem::new(Paths::default()), 0)
        }

        fn with_system(direct: bool, mut system: TestSystem, expected_mappings: u32) -> Self {
            let (host, guest) = UnixStream::pair().unwrap();
            let descriptor = FileDescriptor::from_owned(guest.into());
            let thread = thread::spawn(move || {
                let config = AgentConfig {
                    rootfs: CString::new(if direct { "-" } else { "/rootfs" }).unwrap(),
                    hostname: c"test".to_owned(),
                    uid: c"1000".to_owned(),
                    gid: c"1000".to_owned(),
                    user: c"workload".to_owned(),
                    home: c"/home/workload".to_owned(),
                    direct,
                };
                let mut session = Session::new(descriptor);
                let mut mappings = HostMappings {
                    expected: expected_mappings,
                    ..HostMappings::default()
                };
                let outcome = run(&mut system, &mut session, &config, &mut mappings);
                (outcome, system)
            });
            let mut harness = Self {
                host,
                thread,
                host_sequence: 8,
                guest_sequence: 1,
            };
            let (header, payload) = harness.read_outer();
            assert_eq!(header.record_type, OUTER_GUEST_ATTACH);
            assert!(payload.is_empty());
            harness
                .host
                .write_all(&encode_outer(OUTER_RESET, &INSTANCE, 1, 7, &[]).unwrap())
                .unwrap();
            let (header, payload) = harness.read_outer();
            assert_eq!((header.record_type, header.sequence), (OUTER_ACK, 0));
            assert_eq!(decode_ack_payload(&payload).unwrap(), OUTER_RECEIVE_WINDOW);
            harness
        }

        fn request(&mut self, kind: u8, payload: &[u8]) -> Response {
            let mut responses = self.request_all(42, kind, payload);
            assert_eq!(responses.len(), 1, "{responses:?}");
            responses.pop().unwrap()
        }

        fn request_all(&mut self, request_id: u64, kind: u8, payload: &[u8]) -> Vec<Response> {
            let frame = encode_app(kind, request_id, 0, payload);
            self.host
                .write_all(
                    &encode_outer(OUTER_DATA, &INSTANCE, 1, self.host_sequence, &frame).unwrap(),
                )
                .unwrap();
            self.host_sequence += 1;
            let (credit, payload) = self.read_outer();
            assert_eq!(
                (credit.record_type, credit.sequence),
                (OUTER_CREDIT, self.guest_sequence)
            );
            assert_eq!(decode_credit_payload(&payload).unwrap(), frame.len() as u32);
            self.guest_sequence += 1;
            let mut responses = Vec::new();
            loop {
                let (data, frame) = self.read_outer();
                assert_eq!(
                    (data.record_type, data.sequence),
                    (OUTER_DATA, self.guest_sequence)
                );
                self.guest_sequence += 1;
                let frame = decode_app(&frame).unwrap();
                let terminal = matches!(frame.kind, APP_READY | APP_ERROR | APP_EXIT | APP_STOPPED);
                responses.push(Response {
                    kind: frame.kind,
                    request_id: frame.request_id,
                    status: frame.status,
                    payload: frame.payload.to_vec(),
                });
                if terminal {
                    return responses;
                }
            }
        }

        fn stop(mut self) -> TestSystem {
            let response = self.request(APP_STOP, &[]);
            assert_eq!(
                (
                    response.kind,
                    response.request_id,
                    response.status,
                    response.payload.as_slice()
                ),
                (APP_STOPPED, 42, 0, b"".as_slice())
            );
            let (outcome, system) = self.thread.join().unwrap();
            assert!(matches!(outcome, Ok(Outcome::Stopped)));
            system
        }

        fn fail(mut self, record: &[u8]) -> Vec<u8> {
            self.host.write_all(record).unwrap();
            let (outcome, system) = self.thread.join().unwrap();
            assert!(outcome.is_err());
            system.diagnostics
        }

        fn read_outer(&mut self) -> (OuterHeader, Vec<u8>) {
            let mut header = [0u8; OUTER_HEADER_LEN];
            self.host.read_exact(&mut header).unwrap();
            let header = decode_outer_header(&header).unwrap();
            let mut payload = vec![0; header.length];
            self.host.read_exact(&mut payload).unwrap();
            (header, payload)
        }
    }

    fn response(kind: u8, request_id: u64, status: i32, payload: &[u8]) -> Response {
        Response {
            kind,
            request_id,
            status,
            payload: payload.to_vec(),
        }
    }

    fn exec_payload(cwd: Option<&str>) -> Vec<u8> {
        encode_exec_payload(&Workload {
            argv: vec!["/bin/true".to_owned()],
            timeout_ms: 0,
            cwd,
            environment: WorkloadEnvironment::Default,
        })
        .unwrap()
    }

    fn direct_system() -> (tempfile::TempDir, TestSystem) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("cgroup");
        let execution = root.join("nvx-exec");
        std::fs::create_dir_all(&execution).unwrap();
        std::fs::write(root.join("cgroup.procs"), b"").unwrap();
        std::fs::write(root.join("cgroup.subtree_control"), b"").unwrap();
        std::fs::write(execution.join("pids.current"), b"0\n").unwrap();
        std::fs::write(execution.join("cgroup.kill"), b"").unwrap();
        std::fs::write(execution.join("cgroup.procs"), b"").unwrap();
        let paths = Paths {
            cgroup_root: root,
            ..Paths::default()
        };
        (temporary, TestSystem::new(paths))
    }

    fn mapping_system() -> (tempfile::TempDir, TestSystem) {
        let temporary = tempfile::tempdir().unwrap();
        let hostfs = temporary.path().join("hostfs");
        std::fs::create_dir_all(hostfs.join("root/0/src")).unwrap();
        std::fs::write(hostfs.join("root/0/notes.txt"), b"notes").unwrap();
        std::fs::create_dir(hostfs.join("root/1")).unwrap();
        let paths = Paths {
            hostfs_dir: hostfs,
            ..Paths::default()
        };
        (temporary, TestSystem::new(paths))
    }

    fn maps_payload(first: u32, entries: &[(&[u8], &[u8], u16)], count: Option<u32>) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&first.to_le_bytes());
        payload.extend_from_slice(&count.unwrap_or(entries.len() as u32).to_le_bytes());
        for (source, target, flags) in entries {
            payload.extend_from_slice(&flags.to_le_bytes());
            payload.extend_from_slice(&(source.len() as u16).to_le_bytes());
            payload.extend_from_slice(&(target.len() as u16).to_le_bytes());
            payload.extend_from_slice(source);
            payload.extend_from_slice(target);
        }
        payload
    }

    fn assert_environment_failure(mut harness: Harness, diagnostic_prefix: &[u8]) {
        let replies = harness.request_all(42, APP_EXEC, &exec_payload(None));
        assert_eq!(replies.len(), 2, "{replies:?}");
        assert_eq!(
            (replies[0].kind, replies[0].request_id, replies[0].status),
            (APP_STDERR, 42, 0)
        );
        assert!(
            replies[0].payload.starts_with(diagnostic_prefix),
            "{:?}",
            replies[0].payload
        );
        assert_eq!(replies[1], response(APP_EXIT, 42, 125, b"exit"));
        let system = harness.stop();
        assert_eq!(system.spawn_calls, 0);
    }

    #[test]
    fn agent_advertises_the_control_features_of_its_mode_and_stops() {
        for (direct, expected) in [
            (true, GuestFeatures::DIRECT_AGENT),
            (false, GuestFeatures::SANDBOX_AGENT),
        ] {
            let mut harness = Harness::new(direct);
            let response = harness.request(APP_FEATURES, &[]);
            assert_eq!(
                (response.kind, response.request_id, response.status),
                (APP_READY, 42, 0)
            );
            assert_eq!(GuestFeatures::decode(&response.payload).unwrap(), expected);
            let system = harness.stop();
            assert_eq!(system.tty_drained, 1);
        }
    }

    #[test]
    fn agent_refuses_feature_payloads_and_unannounced_mapping_tables() {
        let mut harness = Harness::new(true);
        for (kind, payload) in [
            (APP_FEATURES, b"abc".as_slice()),
            (APP_MAPS, b"\0\0\0\0\x01\0\0\0\0\0\x01\0\x02\0".as_slice()),
        ] {
            let response = harness.request(kind, payload);
            assert_eq!(
                (response.kind, response.request_id, response.status),
                (APP_ERROR, 42, Errno::EINVAL as i32)
            );
            assert_eq!(response.payload, INVALID_REQUEST.as_bytes());
        }
        harness.stop();
    }

    #[test]
    fn containment_failures_refuse_consecutive_execs_until_verified_empty() {
        if super::super::isolate_process_test(
            "NVX_DISPATCH_CONTAINMENT_TEST_CHILD",
            "guest::managed_agent::dispatch::tests::containment_failures_refuse_consecutive_execs_until_verified_empty",
        ) {
            return;
        }
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let payload = exec_payload(None);
        for state in ["missing", "directory", "malformed", "charged"] {
            let (_temporary, system) = direct_system();
            let tasks = system.paths.cgroup_root.join("nvx-exec/pids.current");
            match state {
                "missing" => std::fs::remove_file(&tasks).unwrap(),
                "directory" => {
                    std::fs::remove_file(&tasks).unwrap();
                    std::fs::create_dir(&tasks).unwrap();
                }
                "malformed" => std::fs::write(&tasks, b"max\n").unwrap(),
                "charged" => std::fs::write(&tasks, b"1\n").unwrap(),
                _ => unreachable!(),
            }
            let mut harness = Harness::with_system(true, system, 0);
            for request_id in [42, 43] {
                assert_eq!(
                    harness.request_all(request_id, APP_EXEC, &payload),
                    vec![response(APP_ERROR, request_id, 125, b"containment-failed")],
                    "{state}"
                );
            }

            if state == "directory" {
                std::fs::remove_dir(&tasks).unwrap();
            }
            std::fs::write(&tasks, b"0\n").unwrap();
            assert_eq!(
                harness.request_all(44, APP_EXEC, &payload),
                vec![response(
                    APP_ERROR,
                    44,
                    125,
                    protocol::LAUNCH_FAILED.as_bytes()
                )],
                "{state}"
            );
            let system = harness.stop();
            assert_eq!(system.spawn_calls, 1, "{state}");
        }
    }

    #[test]
    fn mappings_mount_in_order_and_unblock_workloads_through_dispatch() {
        let (temporary, system) = mapping_system();
        let export = system.paths.hostfs_dir.join("root");
        let guest = temporary.path().join("guest");
        let source = guest.join("src");
        let notes = guest.join("src/notes.txt");
        let out = guest.join("out");
        let first = maps_payload(
            0,
            &[
                (
                    b"0/src",
                    source.as_os_str().as_bytes(),
                    protocol::MAP_READ_ONLY,
                ),
                (b"0/notes.txt", notes.as_os_str().as_bytes(), 0),
            ],
            None,
        );
        let second = maps_payload(2, &[(b"1", out.as_os_str().as_bytes(), 0)], None);
        let mut harness = Harness::with_system(true, system, 3);
        let mut replies = Vec::new();
        replies.extend(harness.request_all(1, APP_EXEC, &[]));
        replies.extend(harness.request_all(2, APP_MAPS, &first));
        replies.extend(harness.request_all(3, APP_EXEC, &[]));
        replies.extend(harness.request_all(4, APP_MAPS, &second));
        replies.extend(harness.request_all(5, APP_EXEC, &[]));
        assert_eq!(
            replies,
            vec![
                response(APP_ERROR, 1, Errno::EAGAIN as i32, b"mappings-incomplete"),
                response(APP_READY, 2, 0, b""),
                response(APP_ERROR, 3, Errno::EAGAIN as i32, b"mappings-incomplete"),
                response(APP_READY, 4, 0, b""),
                response(APP_ERROR, 5, Errno::EINVAL as i32, b"invalid-request"),
            ]
        );

        let system = harness.stop();
        let remount = MountFlags::MS_BIND
            | MountFlags::MS_REMOUNT
            | MountFlags::MS_NOSUID
            | MountFlags::MS_NODEV;
        assert_eq!(
            system.mounts,
            vec![
                (
                    Some(export.join("0/src").as_os_str().as_bytes().to_vec()),
                    source.as_os_str().as_bytes().to_vec(),
                    MountFlags::MS_BIND,
                ),
                (
                    None,
                    source.as_os_str().as_bytes().to_vec(),
                    remount | MountFlags::MS_RDONLY,
                ),
                (
                    Some(export.join("0/notes.txt").as_os_str().as_bytes().to_vec()),
                    notes.as_os_str().as_bytes().to_vec(),
                    MountFlags::MS_BIND,
                ),
                (None, notes.as_os_str().as_bytes().to_vec(), remount,),
                (
                    Some(export.join("1").as_os_str().as_bytes().to_vec()),
                    out.as_os_str().as_bytes().to_vec(),
                    MountFlags::MS_BIND,
                ),
                (None, out.as_os_str().as_bytes().to_vec(), remount),
            ]
        );
        assert!(source.is_dir());
        assert!(notes.is_file());
        assert!(out.is_dir());
        assert_eq!(system.spawn_calls, 0);
    }

    #[test]
    fn mapping_sequence_errors_are_reported_through_dispatch() {
        let (temporary, system) = mapping_system();
        let target = temporary.path().join("guest/src");
        let target = target.as_os_str().as_bytes();
        let entry = [(b"0/src".as_slice(), target, 0)];
        let mut harness = Harness::with_system(true, system, 1);
        let mut replies = Vec::new();
        replies.extend(harness.request_all(1, APP_MAPS, &maps_payload(1, &entry, None)));
        replies.extend(harness.request_all(
            2,
            APP_MAPS,
            &maps_payload(0, &[(b"0/src", target, 0), (b"0/src", target, 0)], None),
        ));
        replies.extend(harness.request_all(3, APP_MAPS, &maps_payload(0, &entry, None)));
        replies.extend(harness.request_all(4, APP_MAPS, &maps_payload(1, &entry, None)));
        assert_eq!(
            replies,
            vec![
                response(APP_ERROR, 1, Errno::EINVAL as i32, b"invalid-request"),
                response(APP_ERROR, 2, Errno::EINVAL as i32, b"invalid-request"),
                response(APP_READY, 3, 0, b""),
                response(APP_ERROR, 4, Errno::EINVAL as i32, b"invalid-request"),
            ]
        );
        let system = harness.stop();
        assert_eq!(system.mounts.len(), 2);
        assert_eq!(system.spawn_calls, 0);
    }

    #[test]
    fn a_failed_mapping_keeps_refusing_workloads_through_dispatch() {
        let (temporary, system) = mapping_system();
        let target = temporary.path().join("guest/missing");
        let missing = maps_payload(0, &[(b"0/missing", target.as_os_str().as_bytes(), 0)], None);
        let valid = maps_payload(0, &[(b"0/src", target.as_os_str().as_bytes(), 0)], None);
        let mut harness = Harness::with_system(true, system, 2);
        let mut replies = Vec::new();
        replies.extend(harness.request_all(1, APP_MAPS, &missing));
        replies.extend(harness.request_all(2, APP_EXEC, &[]));
        replies.extend(harness.request_all(3, APP_MAPS, &valid));
        assert_eq!(
            replies,
            vec![
                response(APP_ERROR, 1, Errno::ENOENT as i32, b"mapping-failed"),
                response(APP_ERROR, 2, Errno::EAGAIN as i32, b"mappings-incomplete"),
                response(APP_ERROR, 3, Errno::EINVAL as i32, b"invalid-request"),
            ]
        );
        let system = harness.stop();
        assert!(system.mounts.is_empty());
        assert_eq!(system.spawn_calls, 0);
    }

    #[test]
    fn unannounced_mapping_tables_are_refused_through_dispatch() {
        let (temporary, system) = mapping_system();
        let target = temporary.path().join("guest/src");
        let mapping = maps_payload(0, &[(b"0/src", target.as_os_str().as_bytes(), 0)], None);
        let mut harness = Harness::with_system(true, system, 0);
        assert_eq!(
            harness.request_all(1, APP_MAPS, &mapping),
            vec![response(
                APP_ERROR,
                1,
                Errno::EINVAL as i32,
                b"invalid-request"
            )]
        );
        assert_eq!(
            harness.request_all(2, APP_EXEC, &[]),
            vec![response(
                APP_ERROR,
                2,
                Errno::EINVAL as i32,
                b"invalid-request"
            )]
        );
        let system = harness.stop();
        assert!(system.mounts.is_empty());
        assert_eq!(system.spawn_calls, 0);
    }

    #[test]
    fn sandbox_does_not_launch_when_descriptor_export_fails() {
        let mut system = TestSystem::new(Paths::default());
        system.fail_environment = Some(b"NVX_EXEC_CONFIG_FD".to_vec());
        assert_environment_failure(
            Harness::with_system(false, system, 0),
            b"nvx-managed-agent: cannot export execution configuration: ",
        );
    }

    #[test]
    fn direct_does_not_launch_when_identity_export_fails() {
        // Direct mode verifies the exec cgroup first, which reaps any child of this process.
        if super::super::isolate_process_test(
            "NVX_DISPATCH_HOME_EXPORT_TEST_CHILD",
            "guest::managed_agent::dispatch::tests::direct_does_not_launch_when_identity_export_fails",
        ) {
            return;
        }
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = direct_system();
        system.fail_environment = Some(b"HOME".to_vec());
        assert_environment_failure(
            Harness::with_system(true, system, 0),
            b"nvx-managed-agent: cannot configure workload environment: ",
        );
    }

    #[test]
    fn pwd_export_failures_refuse_launch_without_spawning() {
        // Direct mode verifies the exec cgroup first, which reaps any child of this process.
        if super::super::isolate_process_test(
            "NVX_DISPATCH_PWD_EXPORT_TEST_CHILD",
            "guest::managed_agent::dispatch::tests::pwd_export_failures_refuse_launch_without_spawning",
        ) {
            return;
        }
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (temporary, mut system) = direct_system();
        system.fail_environment = Some(b"PWD".to_vec());
        let mut harness = Harness::with_system(true, system, 0);
        for (request_id, cwd) in [(42, None), (43, Some(temporary.path().to_str().unwrap()))] {
            assert_eq!(
                harness.request_all(request_id, APP_EXEC, &exec_payload(cwd)),
                vec![response(
                    APP_ERROR,
                    request_id,
                    125,
                    protocol::LAUNCH_FAILED.as_bytes()
                )]
            );
        }
        let system = harness.stop();
        assert_eq!(system.spawn_calls, 0);
    }

    #[test]
    fn agent_refuses_malformed_working_directories() {
        let mut harness = Harness::new(true);
        let argument = [9u32.to_le_bytes().as_slice(), b"/bin/true"].concat();
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&2u16.to_le_bytes());
        payload.extend_from_slice(&argument);
        let response = harness.request(APP_EXEC, &payload);
        assert_eq!(
            (response.kind, response.status, response.payload.as_slice()),
            (APP_ERROR, Errno::EINVAL as i32, INVALID_REQUEST.as_bytes())
        );
        harness.stop();
    }

    #[test]
    fn data_validation_diagnostics_preserve_the_c_failure_stage_and_status() {
        let data = format!(
            "NVX-MANAGED-ERROR: stage=data status={}\n",
            Errno::EPROTO as i32
        );
        let frame = encode_app(APP_PING, 42, 0, &[]);
        let diagnostics =
            Harness::new(true).fail(&encode_outer(OUTER_DATA, &INSTANCE, 1, 9, &frame).unwrap());
        assert_eq!(
            diagnostics,
            [
                b"NVX-MANAGED-ERROR: stage=data-sequence status=9\n",
                data.as_bytes()
            ]
            .concat()
        );

        let diagnostics =
            Harness::new(true).fail(&encode_outer(OUTER_DATA, &INSTANCE, 2, 8, &frame).unwrap());
        assert_eq!(
            diagnostics,
            [
                b"NVX-MANAGED-ERROR: stage=data-identity status=2\n",
                data.as_bytes()
            ]
            .concat()
        );

        let diagnostics =
            Harness::new(true).fail(&encode_outer(OUTER_DATA, &INSTANCE, 1, 8, b"x").unwrap());
        assert_eq!(
            diagnostics,
            [
                b"NVX-MANAGED-ERROR: stage=data-application status=1\n",
                data.as_bytes()
            ]
            .concat()
        );
    }

    #[test]
    fn a_request_that_fails_after_validation_reports_the_data_stage() {
        let frame = encode_app(APP_STOP, 42, 0, b"x");
        let diagnostics =
            Harness::new(true).fail(&encode_outer(OUTER_DATA, &INSTANCE, 1, 8, &frame).unwrap());
        assert_eq!(
            diagnostics,
            format!(
                "NVX-MANAGED-ERROR: stage=data status={}\n",
                Errno::EPROTO as i32
            )
            .as_bytes()
        );
    }

    /// Returns the payload of an `EXEC` request for `argv` in `cwd`, with the default environment.
    fn workload_payload(argv: &[&str], cwd: Option<&str>) -> Vec<u8> {
        encode_exec_payload(&Workload {
            argv: argv.iter().map(|argument| (*argument).to_owned()).collect(),
            timeout_ms: 0,
            cwd,
            environment: WorkloadEnvironment::Default,
        })
        .unwrap()
    }

    /// Returns whether the tests run as root, whose credentials the directory check would bypass.
    fn is_root() -> bool {
        use std::os::unix::fs::MetadataExt;

        std::fs::metadata("/proc/self").is_ok_and(|metadata| metadata.uid() == 0)
    }

    /// Spawns a launch command with its real credential calls.
    fn spawn_with_real_credentials(
        command: crate::guest::spawn::Command,
    ) -> Result<crate::guest::spawn::Spawned, Errno> {
        command
            .spawn()
            .map_err(|error| crate::guest::sys::errno_of(&error))
    }

    #[test]
    fn direct_launch_refuses_working_directories_that_the_workload_cannot_enter() {
        if super::super::isolate_process_test(
            "NVX_DISPATCH_CWD_REFUSAL_TEST_CHILD",
            "guest::managed_agent::dispatch::tests::direct_launch_refuses_working_directories_that_the_workload_cannot_enter",
        ) {
            return;
        }
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (temporary, mut system) = direct_system();
        let root = temporary.path();
        // As root, the child takes the workload's real identity, which must reach the
        // directories; otherwise its credential calls are replaced, and the test's own identity
        // meets the same refusals.
        if is_root() {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755)).unwrap();
            system.spawner = Some(spawn_with_real_credentials);
        } else {
            system.spawner = Some(super::super::seam::spawn_as_privileged);
        }
        system.paths.setpriv = super::super::seam::setpriv_shim(root, ":");
        let file = root.join("file");
        std::fs::write(&file, b"").unwrap();
        let unsearchable = root.join("unsearchable");
        std::fs::create_dir(&unsearchable).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&unsearchable, std::fs::Permissions::from_mode(0o000))
                .unwrap();
        }
        let marker = root.join("ran");
        let marker = marker.to_str().unwrap();
        let mut harness = Harness::with_system(true, system, 0);
        for (request_id, directory, error) in [
            (42, root.join("missing"), Errno::ENOENT),
            (43, file, Errno::ENOTDIR),
            (44, unsearchable, Errno::EACCES),
        ] {
            let directory = directory.to_str().unwrap();
            let diagnostic = super::super::diagnostics::with_description(
                format!("nvx-managed-agent: cannot enter working directory {directory}: ")
                    .as_bytes(),
                error,
            );
            assert_eq!(
                harness.request_all(
                    request_id,
                    APP_EXEC,
                    &workload_payload(&["/bin/touch", marker], Some(directory)),
                ),
                vec![
                    response(APP_STDERR, request_id, 0, &diagnostic),
                    response(APP_ERROR, request_id, error as i32, b"cwd-failed"),
                ],
                "{directory}"
            );
        }
        let system = harness.stop();
        assert_eq!(system.spawn_calls, 3);
        assert!(system.diagnostics.is_empty());
        assert!(!std::path::Path::new(marker).exists());
    }

    #[test]
    fn direct_launch_refuses_a_failed_identity_change_and_runs_nothing() {
        if super::super::isolate_process_test(
            "NVX_DISPATCH_IDENTITY_FAILURE_TEST_CHILD",
            "guest::managed_agent::dispatch::tests::direct_launch_refuses_a_failed_identity_change_and_runs_nothing",
        ) {
            return;
        }
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (temporary, mut system) = direct_system();
        system.paths.setpriv = super::super::seam::setpriv_shim(temporary.path(), ":");
        system.spawner = Some(super::super::seam::spawn_with_failing_credentials);
        let marker = temporary.path().join("ran");
        let mut harness = Harness::with_system(true, system, 0);
        assert_eq!(
            harness.request_all(
                42,
                APP_EXEC,
                &workload_payload(&["/bin/touch", marker.to_str().unwrap()], None),
            ),
            vec![response(
                APP_ERROR,
                42,
                125,
                protocol::LAUNCH_FAILED.as_bytes()
            )]
        );
        let system = harness.stop();
        assert_eq!(
            system.diagnostics,
            format!(
                "NVX-MANAGED-ERROR: stage=exec-launch status={}\n",
                Errno::EPERM as i32
            )
            .as_bytes()
        );
        assert!(!marker.exists());
    }

    #[test]
    fn direct_launch_starts_the_workload_in_the_directory_that_it_checked() {
        if super::super::isolate_process_test(
            "NVX_DISPATCH_CHECKED_DIRECTORY_TEST_CHILD",
            "guest::managed_agent::dispatch::tests::direct_launch_starts_the_workload_in_the_directory_that_it_checked",
        ) {
            return;
        }
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (temporary, mut system) = direct_system();
        let root = std::fs::canonicalize(temporary.path()).unwrap();
        let checked = root.join("checked");
        let moved = root.join("moved");
        let first = root.join("first");
        let second = root.join("second");
        let link = root.join("link");
        for directory in [&checked, &first, &second] {
            std::fs::create_dir(directory).unwrap();
        }
        std::os::unix::fs::symlink(&first, &link).unwrap();
        // Between the check and the workload, the stand-in `setpriv` renames the checked
        // directory and retargets the link.
        system.paths.setpriv = super::super::seam::setpriv_shim(
            &root,
            &format!(
                "if [ -d '{checked}' ]; then mv '{checked}' '{moved}'; fi\nln -sfn '{second}' '{link}'",
                checked = checked.display(),
                moved = moved.display(),
                second = second.display(),
                link = link.display(),
            ),
        );
        system.spawner = Some(super::super::seam::spawn_as_privileged);
        let mut harness = Harness::with_system(true, system, 0);
        let renamed = harness.request_all(
            42,
            APP_EXEC,
            &workload_payload(&["/bin/sh", "-c", "pwd -P"], checked.to_str()),
        );
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&first, &link).unwrap();
        let retargeted = harness.request_all(
            43,
            APP_EXEC,
            &workload_payload(&["/bin/sh", "-c", "pwd -P"], link.to_str()),
        );
        let system = harness.stop();
        let line = |path: &std::path::Path| [path.as_os_str().as_bytes(), b"\n"].concat();
        assert_eq!(
            renamed,
            vec![
                response(APP_STDOUT, 42, 0, &line(&moved)),
                response(APP_EXIT, 42, 0, b"exit"),
            ]
        );
        assert_eq!(
            retargeted,
            vec![
                response(APP_STDOUT, 43, 0, &line(&first)),
                response(APP_EXIT, 43, 0, b"exit"),
            ]
        );
        assert!(system.diagnostics.is_empty());
    }
}
