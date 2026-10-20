//! Tests of the store's identities, records, lock, and launch bookkeeping. The launches of real
//! processes and the recovery of interrupted ones are tested in `tests/store.rs`.

use std::fs;
use std::sync::mpsc;
use std::thread;

use super::*;
use crate::ErrorKind;
use crate::contract;
use crate::host::process::{BootId, ProcessRef};

/// A launch capability.
const CAPABILITY: [u8; CAPABILITY_LEN] = [7; CAPABILITY_LEN];

/// Returns a reference to process 42, started at 4242 during the boot whose bytes are all `boot`.
fn reference(boot: u8) -> ProcessRef {
    ProcessRef {
        pid: 42,
        start_time: 4242,
        boot: BootId::from_bytes([boot; 16]),
    }
}

/// Returns the identity `sha256:` and 64 copies of `digit`.
fn artifact(digit: char) -> ArtifactIdentity {
    ArtifactIdentity::sha256(&digit.to_string().repeat(64)).unwrap()
}

/// Returns a runtime identity under this crate's contracts.
fn runtime() -> RuntimeIdentity {
    RuntimeIdentity::new(artifact('a'), artifact('b'), artifact('c'))
}

/// Returns a store in a fresh temporary directory.
fn store() -> (tempfile::TempDir, SandboxStore) {
    let directory = tempfile::tempdir().unwrap();
    let store = SandboxStore::create(directory.path().join("sandbox")).unwrap();
    (directory, store)
}

/// Writes `value` as the file `name` of `store`.
fn write(store: &SandboxStore, name: &str, value: &serde_json::Value) {
    fs::write(store.path(name), serde_json::to_vec(value).unwrap()).unwrap();
}

#[test]
fn artifact_identities_are_printable_tokens() {
    assert_eq!(
        ArtifactIdentity::new("openvmm-1.2+build.7")
            .unwrap()
            .as_str(),
        "openvmm-1.2+build.7"
    );
    for invalid in [
        String::new(),
        "with space".to_owned(),
        "tab\there".to_owned(),
        "caf\u{e9}".to_owned(),
        "x".repeat(MAX_IDENTITY_LEN + 1),
    ] {
        let error = ArtifactIdentity::new(invalid.clone()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unsupported, "{invalid:?}");
    }
    assert!(ArtifactIdentity::new("x".repeat(MAX_IDENTITY_LEN)).is_ok());

    let digest = "AB".repeat(32);
    assert_eq!(
        ArtifactIdentity::sha256(&digest).unwrap().to_string(),
        format!("sha256:{}", "ab".repeat(32))
    );
    for invalid in ["ab".repeat(31), "g".repeat(64), "ab".repeat(33)] {
        assert_eq!(
            ArtifactIdentity::sha256(&invalid).unwrap_err().kind(),
            ErrorKind::Unsupported
        );
    }
    // The serde form checks the token too.
    assert!(serde_json::from_value::<ArtifactIdentity>(serde_json::json!("a b")).is_err());
}

#[test]
fn runtime_identities_bind_this_crates_contracts() {
    let identity = runtime();
    assert_eq!(identity.boot_contract, contract::MICROVM_ABI_VERSION);
    assert_eq!(
        identity.control_contract,
        contract::CONTROL_CONTRACT_REVISION
    );
    assert_eq!(
        identity.control_session,
        contract::CONTROL_SESSION_PROTOCOL_VERSION
    );
    identity.check().unwrap();
    assert!(identity.differences(&runtime()).is_empty());

    let mut other = runtime();
    other.kernel = artifact('d');
    other.control_session += 1;
    assert_eq!(identity.differences(&other), ["kernel", "control session"]);
    other = RuntimeIdentity::new(artifact('e'), artifact('b'), artifact('f'));
    other.boot_contract += 1;
    other.control_contract = "another-revision".to_owned();
    assert_eq!(
        identity.differences(&other),
        ["OpenVMM", "initramfs", "boot contract", "control contract"]
    );
    for invalid in ["", "two words"] {
        other.control_contract = invalid.to_owned();
        assert_eq!(other.check().unwrap_err().kind(), ErrorKind::Unsupported);
    }
}

#[test]
fn records_keep_their_json_form() {
    let journal = LaunchJournal::prepared(
        LaunchId::try_from("0123456789abcdef0123456789abcdef".to_owned()).unwrap(),
        "/state/sandbox/control.sock".to_owned(),
        runtime(),
        LogClaim {
            identity: FileIdentity {
                device: 1,
                index: 2,
            },
        },
    );
    let runtime_json = serde_json::json!({
        "openvmm": format!("sha256:{}", "a".repeat(64)),
        "kernel": format!("sha256:{}", "b".repeat(64)),
        "initramfs": format!("sha256:{}", "c".repeat(64)),
        "bootContract": contract::MICROVM_ABI_VERSION,
        "controlContract": contract::CONTROL_CONTRACT_REVISION,
        "controlSession": contract::CONTROL_SESSION_PROTOCOL_VERSION,
    });
    let prepared = serde_json::json!({
        "format": 4,
        "launch": "0123456789abcdef0123456789abcdef",
        "endpoint": "/state/sandbox/control.sock",
        "runtime": runtime_json,
        "log": { "identity": { "device": 1, "index": 2 } },
    });
    assert_eq!(serde_json::to_value(&journal).unwrap(), prepared);
    assert_eq!(journal.state(), LaunchState::Prepared);

    let process = reference(0xab);
    let spawned = journal.spawned(process.clone());
    assert_eq!(spawned.state(), LaunchState::Spawned);
    let process_json = serde_json::json!({
        "pid": 42,
        "startTime": 4242,
        "boot": "ab".repeat(16),
    });
    let mut expected = prepared.clone();
    expected["process"] = process_json.clone();
    assert_eq!(serde_json::to_value(&spawned).unwrap(), expected);

    let record = RuntimeRecord::committed(&spawned, process);
    assert_eq!(
        serde_json::to_value(&record).unwrap(),
        serde_json::json!({
            "format": 4,
            "launch": "0123456789abcdef0123456789abcdef",
            "process": process_json,
            "endpoint": "/state/sandbox/control.sock",
            "runtime": runtime_json,
        })
    );
    assert_eq!(record.check_identity(&runtime()), IdentityCheck::Matches);
    let mut upgraded = runtime();
    upgraded.openvmm = artifact('9');
    assert_eq!(
        record.check_identity(&upgraded),
        IdentityCheck::Mismatched(vec!["OpenVMM"])
    );
}

#[test]
fn records_of_other_formats_fail_clearly() {
    let (_directory, store) = store();
    let unsupported = |value: serde_json::Value, format: &str| {
        write(&store, RUNTIME_NAME, &value);
        let error = store.runtime().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Io, "{error}");
        assert!(
            error
                .message()
                .contains(&format!("has the unsupported format {format};")),
            "{error}"
        );
        assert!(error.message().contains("migrates no other"), "{error}");
    };
    // The runtime records of the CLI's state directories and of `instance`.
    unsupported(
        serde_json::json!({
            "format": 1, "pid": 7, "start_time": 8, "control_endpoint": "/state/control.sock",
        }),
        "1",
    );
    unsupported(
        serde_json::json!({ "format": 3, "pid": 7, "startTime": 8, "endpoint": "e" }),
        "3",
    );
    unsupported(serde_json::json!({ "format": 5 }), "5");
    unsupported(serde_json::json!({ "format": "4" }), "\"4\"");

    let malformed = |text: &[u8], detail: &str| {
        fs::write(store.path(JOURNAL_NAME), text).unwrap();
        let error = store.journal().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Io, "{error}");
        assert!(error.message().contains("is malformed"), "{error}");
        assert!(error.message().contains(detail), "{error}");
    };
    malformed(b"{ truncated", "");
    malformed(b"[4]", "it has no format");
    malformed(b"{}", "it has no format");
    malformed(br#"{ "format": 4 }"#, "");
}

#[test]
fn records_with_invalid_fields_are_malformed() {
    let (_directory, store) = store();
    let valid = serde_json::json!({
        "format": 4,
        "launch": "0123456789abcdef0123456789abcdef",
        "process": { "pid": 42, "startTime": 4242, "boot": "ab".repeat(16) },
        "endpoint": "/state/sandbox/control.sock",
        "runtime": serde_json::to_value(runtime()).unwrap(),
    });
    write(&store, RUNTIME_NAME, &valid);
    let record = store.runtime().unwrap().unwrap();
    assert_eq!(record.process(), &reference(0xab));
    assert_eq!(record.endpoint(), "/state/sandbox/control.sock");
    assert_eq!(record.runtime(), &runtime());

    let invalid = |pointer: &str, value: serde_json::Value, detail: &str| {
        let mut record = valid.clone();
        *record.pointer_mut(pointer).unwrap() = value;
        write(&store, RUNTIME_NAME, &record);
        let error = store.runtime().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Io, "{pointer}: {error}");
        assert!(
            error.message().contains("is malformed"),
            "{pointer}: {error}"
        );
        assert!(error.message().contains(detail), "{pointer}: {error}");
    };
    invalid("/process/pid", 0.into(), "its process ID is 0");
    invalid("/process/boot", "ab".into(), "");
    invalid("/endpoint", "".into(), "its control endpoint");
    invalid("/runtime/controlContract", "a b".into(), "control contract");
    invalid("/launch", "0123".into(), "");
    invalid("/runtime/kernel", "".into(), "");
    invalid("/runtime/bootContract", (-1).into(), "");
    // Unknown fields are refused rather than ignored.
    let mut extra = valid.clone();
    extra["capability"] = "secret".into();
    write(&store, RUNTIME_NAME, &extra);
    assert_eq!(store.runtime().unwrap_err().kind(), ErrorKind::Io);
}

#[test]
fn the_lock_excludes_other_holders() {
    let (_directory, store) = store();
    let held = store.lock(None).unwrap();
    let started = Instant::now();
    let error = store
        .lock(Some(Instant::now() + Duration::from_millis(100)))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TimedOut, "{error}");
    assert!(started.elapsed() >= Duration::from_millis(100));
    // A deadline that has passed still tries once.
    assert!(store.lock(Some(Instant::now())).is_err());
    drop(held);
    drop(store.lock(Some(Instant::now())).unwrap());

    // A waiter without a deadline takes the lock once its holder releases it.
    let held = store.lock(None).unwrap();
    let (sender, receiver) = mpsc::channel();
    let waiter = thread::spawn({
        let store = store.clone();
        move || {
            let locked = store.lock(None).map(drop);
            sender.send(()).unwrap();
            locked
        }
    });
    assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());
    drop(held);
    waiter.join().unwrap().unwrap();
}

#[test]
fn a_lock_file_replaced_while_waiting_locks_nothing() {
    let (_directory, store) = store();
    let held = store.lock(None).unwrap();
    let waiter = thread::spawn({
        let store = store.clone();
        move || {
            let locked = store.lock(None).unwrap();
            // The waiter holds the lock of the file that the path names now.
            let current = platform::file_identity(&locked.path(LOCK_NAME)).unwrap();
            let held = platform::opened_file_identity(&locked._lock).unwrap();
            assert_eq!(current, held);
        }
    });
    thread::sleep(Duration::from_millis(100));
    // The lock file goes while the waiter waits for it.
    fs::remove_file(store.path(LOCK_NAME)).unwrap();
    drop(held);
    waiter.join().unwrap();
}

#[cfg(unix)]
#[test]
fn the_store_is_private_to_the_current_user() {
    use std::os::unix::fs::PermissionsExt;

    let (_directory, store) = store();
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    // An existing directory is restricted too.
    fs::set_permissions(store.dir(), fs::Permissions::from_mode(0o755)).unwrap();
    let store = SandboxStore::create(store.dir()).unwrap();
    assert_eq!(mode(store.dir()), 0o700);
    let mut locked = store.lock(None).unwrap();
    let launch = locked.begin_launch(&runtime(), &CAPABILITY).unwrap();
    drop(launch);
    for name in [LOCK_NAME, JOURNAL_NAME, CAPABILITY_NAME, LOG_NAME] {
        assert_eq!(mode(&store.path(name)), 0o600, "{name}");
    }
}

#[test]
fn stores_open_only_existing_directories() {
    let (directory, store) = store();
    assert_eq!(SandboxStore::open(store.dir()).unwrap(), store);
    let missing = SandboxStore::open(directory.path().join("missing")).unwrap_err();
    assert_eq!(missing.kind(), ErrorKind::Io);
    let file = directory.path().join("file");
    fs::write(&file, b"").unwrap();
    assert!(
        SandboxStore::open(&file)
            .unwrap_err()
            .message()
            .contains("is not a plain directory")
    );
    // A relative directory names the same store from any later working directory.
    let current = SandboxStore::open(".").unwrap();
    assert!(current.dir().is_absolute());
    assert_eq!(
        platform::file_identity(current.dir()).unwrap(),
        platform::file_identity(&std::env::current_dir().unwrap()).unwrap()
    );
}

#[test]
fn a_launch_writes_its_marker_before_its_vmm_runs() {
    let (_directory, store) = store();
    for name in [OUTCOME_NAME, CONSOLE_NAME, LOG_NAME] {
        fs::write(store.path(name), b"previous launch").unwrap();
    }
    let previous_log = platform::file_identity(&store.log_path()).unwrap();
    // Held open, the previous log keeps its inode, which the fresh log cannot then reuse.
    let previous = fs::File::open(store.log_path()).unwrap();
    let mut locked = store.lock(None).unwrap();
    let mut launch = locked.begin_launch(&runtime(), &CAPABILITY).unwrap();
    let journal = store.journal().unwrap().unwrap();
    assert_eq!(&journal, launch.journal());
    assert_eq!(journal.state(), LaunchState::Prepared);
    assert_eq!(journal.runtime(), &runtime());
    assert_eq!(launch.endpoint(), journal.endpoint());
    if cfg!(windows) {
        assert!(journal.endpoint().starts_with("//./pipe/openvmm-microvm-"));
    } else {
        assert_eq!(Path::new(journal.endpoint()), store.socket_path());
    }
    assert_eq!(store.read_capability().unwrap(), CAPABILITY);
    // The previous launch's outcome and console are gone, and its log is replaced.
    assert!(!store.outcome_path().exists());
    assert!(!store.console_path().exists());
    assert_eq!(fs::read(store.log_path()).unwrap(), b"");
    let identity = platform::file_identity(&store.log_path()).unwrap();
    assert_ne!(identity, previous_log);
    let claim = journal.log();
    assert_eq!((claim.identity.device, claim.identity.index), identity);

    // The claim lasts until every holder of the log closes it.
    let log = launch.take_log().unwrap();
    assert!(launch.take_log().is_err());
    assert!(platform::log_claim_held(&store.log_path(), identity).unwrap());
    let copy = log.try_clone().unwrap();
    drop(log);
    assert!(platform::log_claim_held(&store.log_path(), identity).unwrap());
    drop(copy);
    assert!(!platform::log_claim_held(&store.log_path(), identity).unwrap());
    // A log that is not the claimed file proves nothing.
    assert!(platform::log_claim_held(&store.log_path(), previous_log).is_err());

    // A second launch waits until the first is recovered.
    drop(launch);
    let error = locked.begin_launch(&runtime(), &CAPABILITY).unwrap_err();
    assert!(
        error.message().contains("must be recovered first"),
        "{error}"
    );
    assert_eq!(locked.recover().unwrap(), Recovery::Exited);
    assert!(store.journal().unwrap().is_none());
    assert!(store.read_capability().is_err());
    // The log outlives the launch.
    assert!(store.log_path().exists());
    assert_eq!(locked.recover().unwrap(), Recovery::Clean);
    drop(previous);
}

#[test]
fn launches_check_their_inputs() {
    let (_directory, store) = store();
    let mut locked = store.lock(None).unwrap();
    let error = locked
        .begin_launch(&runtime(), &[0; CAPABILITY_LEN])
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    let mut invalid = runtime();
    invalid.control_contract = String::new();
    assert_eq!(
        locked
            .begin_launch(&invalid, &CAPABILITY)
            .unwrap_err()
            .kind(),
        ErrorKind::Unsupported
    );
    // Nothing was written.
    assert!(store.journal().unwrap().is_none());
    assert!(!store.capability_path().exists());
    assert!(!store.log_path().exists());
}

#[test]
fn an_abandoned_launch_that_spawned_nothing_has_exited() {
    let (_directory, store) = store();
    let mut locked = store.lock(None).unwrap();
    let launch = locked.begin_launch(&runtime(), &CAPABILITY).unwrap();
    // A launch commits only once it records its VMM.
    let error = launch.commit().unwrap_err();
    assert!(error.message().contains("before it records"), "{error}");
    let error = locked.begin_launch(&runtime(), &CAPABILITY).unwrap_err();
    assert!(
        error.message().contains("must be recovered first"),
        "{error}"
    );
    assert_eq!(locked.recover().unwrap(), Recovery::Exited);
    let launch = locked.begin_launch(&runtime(), &CAPABILITY).unwrap();
    assert_eq!(launch.abandon().unwrap(), Recovery::Exited);
    assert!(store.journal().unwrap().is_none());
    assert!(!store.capability_path().exists());
}

#[test]
fn a_journal_that_its_runtime_record_supersedes_is_removed() {
    let (_directory, store) = store();
    let mut locked = store.lock(None).unwrap();
    let launch = locked.begin_launch(&runtime(), &CAPABILITY).unwrap();
    let journal = launch.journal().spawned(reference(1));
    drop(launch);
    // The launch wrote its runtime record and crashed before it removed its journal.
    let committed = RuntimeRecord::committed(&journal, journal.process().unwrap().clone());
    record::write(&store.path(RUNTIME_NAME), &committed).unwrap();
    record::write(&store.path(JOURNAL_NAME), &journal).unwrap();
    assert_eq!(locked.recover().unwrap(), Recovery::Clean);
    assert!(store.journal().unwrap().is_none());
    assert_eq!(store.runtime().unwrap(), Some(committed));
    // A runtime record of another launch makes the state inconsistent.
    let other = LaunchJournal::prepared(
        LaunchId::generate().unwrap(),
        journal.endpoint().to_owned(),
        runtime(),
        *journal.log(),
    );
    record::write(&store.path(JOURNAL_NAME), &other).unwrap();
    let error = locked.recover().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Io);
    assert!(error.message().contains("names launch"), "{error}");
    // A runtime record keeps a launch from beginning until it is cleared.
    fs::remove_file(store.path(JOURNAL_NAME)).unwrap();
    let error = locked.begin_launch(&runtime(), &CAPABILITY).unwrap_err();
    assert!(error.message().contains("already running"), "{error}");
    locked.clear_runtime().unwrap();
    assert!(store.runtime().unwrap().is_none());
    assert!(!store.capability_path().exists());
    drop(locked.begin_launch(&runtime(), &CAPABILITY).unwrap());
}

#[test]
fn launch_identities_are_fresh_hexadecimal() {
    let first = LaunchId::generate().unwrap();
    assert_eq!(first.as_str().len(), 32);
    assert_ne!(first, LaunchId::generate().unwrap());
    assert!(LaunchId::try_from(first.to_string()).is_ok());
    for invalid in [
        String::new(),
        "0123".to_owned(),
        "A".repeat(32),
        "g".repeat(32),
    ] {
        assert!(LaunchId::try_from(invalid.clone()).is_err(), "{invalid}");
    }
}

#[test]
fn an_endpoint_server_counts_only_while_the_endpoint_names_it_once_held() {
    /// Holds the endpoint server whose IDs `lookups` returns in turn, as a value that names its
    /// ID, or `None` if `hold_exits`.
    fn hold(
        lookups: Vec<io::Result<Option<u32>>>,
        hold_exits: bool,
    ) -> std::result::Result<(u32, u32), String> {
        let mut lookups = lookups.into_iter();
        vmm::hold_endpoint_server(
            || {
                lookups
                    .next()
                    .expect("the endpoint is looked up at most twice")
            },
            |pid| Ok((!hold_exits).then_some(pid)),
        )
    }
    let failed = || Err(io::Error::other("lookup failed"));

    assert_eq!(hold(vec![Ok(Some(7)), Ok(Some(7))], false), Ok((7, 7)));
    // The server exited after the first lookup, and another process reused its ID before it was
    // held: once held, the endpoint names no process, or another one.
    for again in [Ok(None), Ok(Some(8))] {
        let reason = hold(vec![Ok(Some(7)), again], false).unwrap_err();
        assert!(reason.contains("stopped serving"), "{reason}");
    }
    let reason = hold(vec![Ok(Some(7)), failed()], false).unwrap_err();
    assert!(reason.contains("cannot be examined again"), "{reason}");
    // The server exited before it was held, or no process serves the endpoint.
    let reason = hold(vec![Ok(Some(7))], true).unwrap_err();
    assert!(
        reason.contains("exited before it could be verified"),
        "{reason}"
    );
    let reason = hold(vec![Ok(None)], false).unwrap_err();
    assert!(reason.contains("no process serves"), "{reason}");
    let reason = hold(vec![failed()], false).unwrap_err();
    assert!(reason.contains("cannot be examined"), "{reason}");
}
