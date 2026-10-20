use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::guest::sys::{self, Errno, FileDescriptor};
use crate::host::platform::Transport;
use crate::protocol::{
    self, OUTER_ACK, OUTER_CREDIT, OUTER_DATA, OUTER_GUEST_ATTACH, OUTER_HEADER_LEN,
    OUTER_HOST_ATTACH, OUTER_READY, OUTER_RESET, OuterHeader,
};

use super::seam::{Paths, TestSystem, setpriv_shim, spawn_as_privileged};

struct BrokerCore {
    guest: UnixStream,
    host_output: VecDeque<u8>,
    instance_id: [u8; 16],
    epoch: u64,
    initialized: bool,
    active_host: bool,
    host_receive_sequence: u64,
    host_send_sequence: u64,
    guest_send_sequence: u64,
    guest_receive_sequence: u64,
    receive_window: u32,
    receive_credit: u32,
}

impl BrokerCore {
    fn new(guest: UnixStream) -> Self {
        Self {
            guest,
            host_output: VecDeque::new(),
            instance_id: core::array::from_fn(|index| index as u8 + 1),
            epoch: 0,
            initialized: false,
            active_host: false,
            host_receive_sequence: 0,
            host_send_sequence: 0,
            guest_send_sequence: 0,
            guest_receive_sequence: 0,
            receive_window: 0,
            receive_credit: 0,
        }
    }

    fn attach_host(&mut self, header: OuterHeader, payload: &[u8]) -> io::Result<()> {
        if header.record_type != OUTER_HOST_ATTACH
            || header.instance_id != [0; 16]
            || header.epoch != 0
            || header.sequence != 0
            || payload.len() != protocol::CAPABILITY_LEN
            || self.active_host
        {
            return Err(protocol_error());
        }
        self.host_output.clear();
        self.host_receive_sequence = 0;
        self.host_send_sequence = 1;
        if !self.initialized {
            let (attach, payload) = self.read_guest(Some(Duration::from_secs(5)))?;
            if attach.record_type != OUTER_GUEST_ATTACH
                || attach.instance_id != [0; 16]
                || attach.epoch != 0
                || attach.sequence != 0
                || !payload.is_empty()
            {
                return Err(protocol_error());
            }
            self.epoch = 1;
            self.reset_guest()?;
            self.initialized = true;
        }
        self.active_host = true;
        self.queue_host(OUTER_READY, 0, &[])
    }

    fn accept_host_data(&mut self, header: OuterHeader, payload: &[u8]) -> io::Result<()> {
        if !self.active_host
            || header.record_type != OUTER_DATA
            || header.instance_id != self.instance_id
            || header.epoch != self.epoch
            || header.sequence != self.host_receive_sequence
            || payload.is_empty()
            || payload.len() > self.receive_credit as usize
        {
            return Err(protocol_error());
        }
        self.host_receive_sequence = self.host_receive_sequence.wrapping_add(1);
        self.receive_credit -= payload.len() as u32;
        let record = protocol::encode_outer(
            OUTER_DATA,
            &self.instance_id,
            self.epoch,
            self.guest_send_sequence,
            payload,
        )
        .map_err(|_| protocol_error())?;
        self.guest_send_sequence = self.guest_send_sequence.wrapping_add(1);
        self.guest.write_all(&record)
    }

    fn pump_guest(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        loop {
            let (header, payload) = self.read_guest(timeout)?;
            if header.instance_id != self.instance_id
                || header.epoch != self.epoch
                || header.sequence != self.guest_receive_sequence
            {
                return Err(protocol_error());
            }
            self.guest_receive_sequence = self.guest_receive_sequence.wrapping_add(1);
            match header.record_type {
                OUTER_CREDIT => {
                    let credit =
                        protocol::decode_credit_payload(&payload).map_err(|_| protocol_error())?;
                    let available = self
                        .receive_credit
                        .checked_add(credit)
                        .filter(|available| *available <= self.receive_window)
                        .ok_or_else(protocol_error)?;
                    self.receive_credit = available;
                }
                OUTER_DATA => {
                    self.queue_host(OUTER_DATA, self.host_send_sequence, &payload)?;
                    self.host_send_sequence = self.host_send_sequence.wrapping_add(1);
                    return Ok(());
                }
                _ => return Err(protocol_error()),
            }
        }
    }

    fn reset_active_host(&mut self) -> io::Result<()> {
        if !self.initialized {
            return Err(protocol_error());
        }
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| io::Error::from(Errno::EOVERFLOW))?;
        self.host_output.clear();
        self.receive_credit = 0;
        self.reset_guest()?;
        self.queue_host(OUTER_RESET, 0, &[])
    }

    fn reset_guest(&mut self) -> io::Result<()> {
        self.guest_send_sequence = 1;
        self.guest_receive_sequence = 0;
        let reset = protocol::encode_outer(OUTER_RESET, &self.instance_id, self.epoch, 0, &[])
            .map_err(|_| protocol_error())?;
        self.guest.write_all(&reset)?;
        loop {
            let (header, payload) = self.read_guest(Some(Duration::from_secs(5)))?;
            if header.record_type == OUTER_ACK
                && header.instance_id == self.instance_id
                && header.epoch == self.epoch
                && header.sequence == 0
            {
                let window =
                    protocol::decode_ack_payload(&payload).map_err(|_| protocol_error())?;
                self.receive_window = window;
                self.receive_credit = window;
                self.guest_receive_sequence = 1;
                return Ok(());
            }
            // The real broker discards records from the retired epoch while reset drains.
        }
    }

    fn queue_host(&mut self, record_type: u8, sequence: u64, payload: &[u8]) -> io::Result<()> {
        let record = protocol::encode_outer(
            record_type,
            &self.instance_id,
            self.epoch,
            sequence,
            payload,
        )
        .map_err(|_| protocol_error())?;
        self.host_output.extend(record);
        Ok(())
    }

    fn read_guest(&mut self, timeout: Option<Duration>) -> io::Result<(OuterHeader, Vec<u8>)> {
        self.guest.set_read_timeout(timeout)?;
        let mut header = [0u8; OUTER_HEADER_LEN];
        self.guest.read_exact(&mut header).map_err(timeout_error)?;
        let header = protocol::decode_outer_header(&header).map_err(|_| protocol_error())?;
        let mut payload = vec![0; header.length];
        self.guest.read_exact(&mut payload).map_err(timeout_error)?;
        Ok((header, payload))
    }
}

struct BrokerTransport {
    core: Arc<Mutex<BrokerCore>>,
}

impl Drop for BrokerTransport {
    fn drop(&mut self) {
        if let Ok(mut core) = self.core.lock() {
            core.active_host = false;
        }
    }
}

impl Transport for BrokerTransport {
    fn read(&mut self, buffer: &mut [u8], timeout: Option<Duration>) -> io::Result<usize> {
        let mut core = self.core.lock().unwrap();
        if core.host_output.is_empty() {
            core.pump_guest(timeout)?;
        }
        let count = buffer.len().min(core.host_output.len());
        for byte in &mut buffer[..count] {
            *byte = core.host_output.pop_front().expect("the count is bounded");
        }
        Ok(count)
    }

    fn write_all(&mut self, data: &[u8], _timeout: Option<Duration>) -> io::Result<()> {
        if data.len() < OUTER_HEADER_LEN {
            return Err(protocol_error());
        }
        let header = protocol::decode_outer_header(
            data[..OUTER_HEADER_LEN]
                .try_into()
                .map_err(|_| protocol_error())?,
        )
        .map_err(|_| protocol_error())?;
        let payload = data
            .get(OUTER_HEADER_LEN..)
            .filter(|payload| payload.len() == header.length)
            .ok_or_else(protocol_error)?;
        let mut core = self.core.lock().unwrap();
        match header.record_type {
            OUTER_HOST_ATTACH => core.attach_host(header, payload),
            OUTER_DATA => core.accept_host_data(header, payload),
            _ => Err(protocol_error()),
        }
    }
}

#[derive(Clone)]
struct BrokerHandle {
    core: Arc<Mutex<BrokerCore>>,
}

impl BrokerHandle {
    fn transport(&self) -> Box<dyn Transport> {
        Box::new(BrokerTransport {
            core: Arc::clone(&self.core),
        })
    }

    fn reset(&self) {
        self.core.lock().unwrap().reset_active_host().unwrap();
    }
}

fn protocol_error() -> io::Error {
    io::Error::from(Errno::EPROTO)
}

fn timeout_error(error: io::Error) -> io::Error {
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) {
        io::ErrorKind::TimedOut.into()
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Instant;

    use crate::host::session::{ControlSession, ExecEvent, SessionError};
    use crate::protocol::{
        CAPABILITY_LEN, ExitCategory, GuestFeatures, HostMap, Workload, WorkloadEnvironment,
    };

    use super::super::AgentConfig;
    use super::super::dispatch;
    use super::super::mappings::HostMappings;
    use super::super::session::Session;
    use super::*;

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }

    fn run_exec(
        session: &mut ControlSession,
        workload: &Workload<'_>,
    ) -> (Vec<u8>, Vec<u8>, ExecEvent) {
        let id = session.start_exec(workload, deadline()).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            match session.next_exec_event(id, Some(deadline())).unwrap() {
                ExecEvent::Stdout(bytes) => stdout.extend(bytes),
                ExecEvent::Stderr(bytes) => stderr.extend(bytes),
                event @ ExecEvent::Exit { .. } | event @ ExecEvent::Rejected { .. } => {
                    return (stdout, stderr, event);
                }
            }
        }
    }

    #[test]
    fn control_session_broker_and_real_agent_loop_back() {
        if super::super::isolate_process_test(
            "NVX_AGENT_LOOPBACK_TEST_CHILD",
            "guest::managed_agent::loopback::tests::control_session_broker_and_real_agent_loop_back",
        ) {
            return;
        }
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let cgroup = temporary.path().join("cgroup");
        std::fs::create_dir_all(cgroup.join("nvx-exec")).unwrap();
        for (path, contents) in [
            ("cgroup.procs", b"".as_slice()),
            ("cgroup.subtree_control", b""),
            ("nvx-exec/cgroup.procs", b""),
            ("nvx-exec/cgroup.kill", b""),
            ("nvx-exec/pids.current", b"0\n"),
        ] {
            std::fs::write(cgroup.join(path), contents).unwrap();
        }
        let hostfs = temporary.path().join("hostfs");
        std::fs::create_dir_all(hostfs.join("root/0/source")).unwrap();
        let target = temporary.path().join("mapped");
        // The workloads run through the agent's real direct launch, whose credential calls are
        // replaced and whose `setpriv` executes each workload unchanged.
        let paths = Paths {
            cgroup_root: cgroup,
            hostfs_dir: hostfs,
            setpriv: setpriv_shim(temporary.path(), ":"),
            ..Paths::default()
        };
        let system = TestSystem {
            spawner: Some(spawn_as_privileged),
            ..TestSystem::new(paths)
        };
        let (broker_guest, agent) = UnixStream::pair().unwrap();
        let agent_descriptor = FileDescriptor::from_owned(agent.into());
        let agent_thread = thread::spawn(move || {
            let mut system = system;
            let config = AgentConfig {
                rootfs: c"-".to_owned(),
                hostname: c"loopback".to_owned(),
                uid: c"1000".to_owned(),
                gid: c"1000".to_owned(),
                user: c"workload".to_owned(),
                home: c"/".to_owned(),
                direct: true,
            };
            let mut session = Session::new(agent_descriptor);
            let mut mappings = HostMappings {
                expected: 1,
                ..HostMappings::default()
            };
            let outcome = dispatch::run(&mut system, &mut session, &config, &mut mappings).unwrap();
            (outcome, system)
        });
        let core = Arc::new(Mutex::new(BrokerCore::new(broker_guest)));
        let broker = BrokerHandle { core };
        let capability = [0x5a; CAPABILITY_LEN];
        let mut session =
            ControlSession::attach(broker.transport(), &capability, deadline()).unwrap();

        session.ping(deadline()).unwrap();
        assert_eq!(
            session.features(deadline()).unwrap(),
            GuestFeatures::DIRECT_AGENT
        );
        session
            .map_host_paths(
                &[HostMap {
                    source: "0/source".to_owned(),
                    target: target.to_string_lossy().into_owned(),
                    read_only: true,
                }],
                deadline(),
            )
            .unwrap();

        let workload = |script: &str, timeout_ms| Workload {
            argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()],
            timeout_ms,
            cwd: None,
            environment: WorkloadEnvironment::Default,
        };
        let (stdout, stderr, exit) = run_exec(
            &mut session,
            &workload("printf out; printf err >&2; exit 7", 0),
        );
        assert_eq!((stdout, stderr), (b"out".to_vec(), b"err".to_vec()));
        assert_eq!(
            exit,
            ExecEvent::Exit {
                category: ExitCategory::Exit,
                status: 7
            }
        );

        let (_, _, signal) = run_exec(&mut session, &workload("kill -TERM $$", 0));
        assert_eq!(
            signal,
            ExecEvent::Exit {
                category: ExitCategory::Signal,
                status: 128 + sys::Signal::SIGTERM as i32
            }
        );
        let (_, _, realtime_signal) = run_exec(&mut session, &workload("kill -40 $$", 0));
        assert_eq!(
            realtime_signal,
            ExecEvent::Exit {
                category: ExitCategory::Signal,
                status: 128 + 40
            }
        );
        let (_, _, timeout) = run_exec(&mut session, &workload("sleep 10", 25));
        assert_eq!(
            timeout,
            ExecEvent::Exit {
                category: ExitCategory::Timeout,
                status: 124
            }
        );
        let (_, _, limited) = run_exec(&mut session, &workload("head -c 1048577 /dev/zero", 0));
        assert_eq!(
            limited,
            ExecEvent::Exit {
                category: ExitCategory::OutputLimit,
                status: 125
            }
        );

        let cancel_id = session
            .start_exec(&workload("sleep 10", 0), deadline())
            .unwrap();
        session.cancel_exec(cancel_id, deadline()).unwrap();
        assert_eq!(
            session
                .next_exec_event(cancel_id, Some(deadline()))
                .unwrap(),
            ExecEvent::Exit {
                category: ExitCategory::Cancelled,
                status: 128 + sys::Signal::SIGKILL as i32
            }
        );

        let reset_id = session
            .start_exec(&workload("sleep 10", 0), deadline())
            .unwrap();
        broker.reset();
        assert!(matches!(
            session.next_exec_event(reset_id, Some(deadline())),
            Err(SessionError::Reset)
        ));
        drop(session);
        let mut session =
            ControlSession::attach(broker.transport(), &capability, deadline()).unwrap();
        session.ping(deadline()).unwrap();
        session.stop(deadline()).unwrap();
        drop(session);

        let (_outcome, system) = agent_thread.join().unwrap();
        assert_eq!(system.mounts.len(), 2);
        assert!(system.diagnostics.is_empty());
    }
}
