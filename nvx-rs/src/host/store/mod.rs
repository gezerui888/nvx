//! The store of a sandbox's runtime records, which every host that supervises the sandbox
//! shares: one private directory per sandbox, with one lock, the runtime record of its running
//! VM, and the journal of its launch, so that a VMM whose launch crashed midway is never lost.
//!
//! ```text
//! <dir>/                   one sandbox, private to the current user
//!   sandbox.lock           the lock that serializes its lifecycle transitions
//!   launch.json            the journal of a launch in progress, or of one that was interrupted
//!   runtime.json           the runtime record of its running VM
//!   control.capability     the launch capability of its VM
//!   control.sock           the control endpoint of its VM, on Linux
//!   openvmm.log            the VMM's output, claimed by the launch that created it
//!   console.log            the guest console of the latest launch, if the caller captures it
//!   outcome.json           the VMM's outcome report of the latest launch
//! ```
//!
//! The directory is private to the current user: mode 0700 on Unix, and on Windows the access
//! control list that it inherits, which is private under a user's profile. Files have mode 0600
//! on Unix, and records are replaced atomically, so readers that hold no lock, such as an
//! execution, see whole records. The store holds runtime records only: configuration belongs to
//! its caller, which may keep it in the same directory under a name of its own.
//!
//! # Records
//!
//! The [`RuntimeRecord`] and the [`LaunchJournal`] are JSON in format [`FORMAT`]. A record in any
//! other format fails with a message that names the format, and is neither read nor migrated:
//! switching from earlier formats takes one stop of every sandbox. Both records hold the
//! [`RuntimeIdentity`] of their launch, which decides whether a host may reattach to the VM; see
//! [`RuntimeRecord::check_identity`].
//!
//! # Launches
//!
//! A launch holds the sandbox's lock throughout:
//!
//! 1. [`LockedStore::begin_launch`] stores the capability, creates a fresh log and claims it, and
//!    writes the journal's marker, before anything is spawned.
//! 2. The caller spawns the VMM with [`Launch::take_log`] as its standard output and error, and
//!    [`Launch::record_process`] records the VMM's [`ProcessRef`] right after the spawn.
//! 3. Once the VM is ready, [`Launch::commit`] replaces the journal with the runtime record. A
//!    launch that fails ends with [`Launch::abandon`].
//!
//! ```no_run
//! use std::time::{Duration, Instant};
//!
//! use nvx::host::launch::LaunchSpec;
//! use nvx::host::process;
//! use nvx::host::store::{RuntimeIdentity, SandboxStore};
//! use nvx::protocol::CAPABILITY_LEN;
//!
//! fn launch(
//!     spec: &LaunchSpec,
//!     runtime: &RuntimeIdentity,
//!     capability: &[u8; CAPABILITY_LEN],
//! ) -> Result<(), Box<dyn std::error::Error>> {
//!     let store = SandboxStore::create("/var/lib/example/sandbox")?;
//!     let mut locked = store.lock(Some(Instant::now() + Duration::from_secs(10)))?;
//!     locked.recover()?;
//!     let mut launch = locked.begin_launch(runtime, capability)?;
//!     let arguments = spec.openvmm_arguments(launch.endpoint(), &store.outcome_path())?;
//!     let log = launch.take_log()?;
//!     let child = process::spawn(&spec.openvmm, false, &arguments, capability, log, store.dir())?;
//!     launch.record_process(&child)?;
//!     // Wait until the VM is ready, then commit, or else abandon the launch.
//!     launch.commit()?;
//!     process::detach_child(child);
//!     Ok(())
//! }
//! ```
//!
//! The launch borrows the locked store exclusively until it commits or is abandoned, so no other
//! transition of the sandbox overlaps it, not even through the same guard:
//!
//! ```compile_fail
//! # use nvx::host::store::{RuntimeIdentity, SandboxStore};
//! # use nvx::protocol::CAPABILITY_LEN;
//! # fn overlap(
//! #     store: &SandboxStore,
//! #     runtime: &RuntimeIdentity,
//! #     capability: &[u8; CAPABILITY_LEN],
//! # ) -> nvx::Result<()> {
//! let mut locked = store.lock(None)?;
//! let launch = locked.begin_launch(runtime, capability)?;
//! locked.recover()?; // `locked` is still borrowed by `launch`.
//! launch.commit()?;
//! # Ok(())
//! # }
//! ```
//!
//! # The log claim
//!
//! The VMM inherits its launch's claim on the log, so the claim lasts as long as any process that
//! holds the log open from the launch. On Linux it is an exclusive `flock` lock of the log's open
//! file description, which the VMM shares through its standard output and error, and which only
//! the last close of that description releases. On Windows it is the VMM's handles themselves:
//! while any process holds the log open, an open of the log that shares nothing fails. A released
//! claim proves that the launch has exited, even one that never recorded its VMM or published its
//! endpoint. The claim relies on the VMM keeping its standard output and error until it exits, as
//! OpenVMM does, and on the directory being on a local file system.
//!
//! # Recovery
//!
//! A caller that dies during a launch leaves its journal, and [`LockedStore::recover`] ends the
//! launch, signaling only a VMM that it holds through a verified [`Process`]:
//!
//! - A crash before the spawn leaves the claim released, which proves that nothing of the launch
//!   runs.
//! - After a crash between the spawn and the identity, the VMM holds the claim. Recovery finds
//!   the VMM through the control endpoint that the journal names, holds it, confirms that the
//!   endpoint still names it once held, and terminates it.
//!   On Windows the endpoint is a pipe whose name each launch draws at random, which names the
//!   VMM by itself. On Linux it is the same socket path for every launch of the sandbox, so the
//!   VMM must also hold the claimed log as its standard output. Until the VMM serves its
//!   endpoint, recovery is indeterminate and keeps the journal; once the VMM exits, the released
//!   claim proves it.
//! - After a crash between the identity and the endpoint, the recorded [`ProcessRef`] decides:
//!   the process ID, its start time, and the host's boot. [`Process::open`] holds a live VMM,
//!   which is terminated through its handle, and never another process that reuses its ID, nor
//!   any process when the reference comes from an earlier boot, whose processes have all exited.
//!   Within the current boot, a VMM that no process matches has exited once the claim is
//!   released; until then, it may still run unseen, and recovery is indeterminate.
//!
//! The runtime record of a committed launch names its running VM, and reattaching to that VM
//! belongs to its supervisor.

mod files;
mod identity;
mod record;
#[cfg(test)]
mod tests;
mod vmm;

use std::fs::{self, File, TryLockError};
use std::io;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use self::files::{io_error, remove_if_present};
pub use self::identity::{ArtifactIdentity, IdentityCheck, MAX_IDENTITY_LEN, RuntimeIdentity};
pub use self::record::{
    LaunchId, LaunchJournal, LaunchState, LogClaim, MAX_ENDPOINT_LEN, RuntimeRecord,
};
use super::filesystem::FileIdentity;
use super::platform;
use super::process::{BootId, Launched, Process, ProcessRef};
use crate::error::{Error, Result};
use crate::protocol::CAPABILITY_LEN;

/// Version of the store's records.
///
/// It follows the versions of the runtime state that the CLI and [`instance`](super::instance)
/// keep on their own, up to 3, so that a record of theirs fails as unsupported rather than being
/// read as one of the store's.
pub const FORMAT: u32 = 4;
/// Name of the sandbox's lock.
pub const LOCK_NAME: &str = "sandbox.lock";
/// Name of the launch journal.
pub const JOURNAL_NAME: &str = "launch.json";
/// Name of the runtime record.
pub const RUNTIME_NAME: &str = "runtime.json";
/// Name of the file that holds the launch capability.
pub const CAPABILITY_NAME: &str = "control.capability";
/// Name of the Linux control socket.
pub const SOCKET_NAME: &str = "control.sock";
/// Name of the VMM's log.
pub const LOG_NAME: &str = "openvmm.log";
/// Name of the guest console's log.
pub const CONSOLE_NAME: &str = "console.log";
/// Name of the VMM's outcome report.
pub const OUTCOME_NAME: &str = "outcome.json";
/// Every file that the store keeps in a sandbox's directory. Replacing a record leaves a
/// temporary file named `.NAME.NUMBER.tmp` beside it only if the replacement was interrupted.
pub const FILE_NAMES: [&str; 8] = [
    LOCK_NAME,
    JOURNAL_NAME,
    RUNTIME_NAME,
    CAPABILITY_NAME,
    SOCKET_NAME,
    LOG_NAME,
    CONSOLE_NAME,
    OUTCOME_NAME,
];

/// Interval at which a lock with a deadline is tried again.
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(25);

/// Returns `dir` as an absolute path, which a relative one names from the current directory.
fn absolute(dir: PathBuf) -> Result<PathBuf> {
    std::path::absolute(&dir).map_err(io_error(format!(
        "cannot resolve the sandbox store {}",
        dir.display()
    )))
}

/// The store of one sandbox: its private directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxStore {
    /// The sandbox's private directory.
    dir: PathBuf,
}

impl SandboxStore {
    /// Creates the directory `dir` if needed, whose parent must exist, restricts it to the current
    /// user, and opens the store in it.
    ///
    /// A relative `dir` is resolved against the current directory, so that the store's paths, and
    /// the control endpoint that a launch records, name the same files from any working directory.
    pub fn create(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = absolute(dir.into())?;
        platform::create_private_dir(&dir).map_err(io_error(format!(
            "cannot create the sandbox store {}",
            dir.display()
        )))?;
        Ok(Self { dir })
    }

    /// Opens the store in the existing directory `dir`, which a relative path names from the
    /// current directory.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = absolute(dir.into())?;
        match fs::symlink_metadata(&dir) {
            Ok(metadata) if metadata.is_dir() => Ok(Self { dir }),
            Ok(_) => Err(Error::io(format!(
                "the sandbox store {} is not a plain directory",
                dir.display()
            ))),
            Err(error) => Err(io_error(format!(
                "cannot open the sandbox store {}",
                dir.display()
            ))(error)),
        }
    }

    /// Returns the sandbox's directory, as an absolute path.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Returns the path of the store's file `name`, one of [`FILE_NAMES`].
    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Returns the path of the VMM's log.
    pub fn log_path(&self) -> PathBuf {
        self.path(LOG_NAME)
    }

    /// Returns the path of the guest console's log, which a launch whose caller captures the
    /// console points the VMM at.
    pub fn console_path(&self) -> PathBuf {
        self.path(CONSOLE_NAME)
    }

    /// Returns the path of the VMM's outcome report.
    pub fn outcome_path(&self) -> PathBuf {
        self.path(OUTCOME_NAME)
    }

    /// Returns the path of the file that holds the launch capability.
    pub fn capability_path(&self) -> PathBuf {
        self.path(CAPABILITY_NAME)
    }

    /// Returns the path of the Linux control socket.
    pub fn socket_path(&self) -> PathBuf {
        self.path(SOCKET_NAME)
    }

    /// Reads the runtime record, which names the sandbox's VM from the commit of its launch until
    /// its runtime is cleared.
    pub fn runtime(&self) -> Result<Option<RuntimeRecord>> {
        record::read(&self.path(RUNTIME_NAME))
    }

    /// Reads the journal of a launch in progress, or of one that was interrupted.
    pub fn journal(&self) -> Result<Option<LaunchJournal>> {
        record::read(&self.path(JOURNAL_NAME))
    }

    /// Reads the launch capability of the sandbox's VM.
    pub fn read_capability(&self) -> Result<[u8; CAPABILITY_LEN]> {
        let path = self.capability_path();
        let bytes = fs::read(&path).map_err(io_error(format!(
            "cannot read the sandbox control capability {}",
            path.display()
        )))?;
        match <[u8; CAPABILITY_LEN]>::try_from(bytes.as_slice()) {
            Ok(capability) if capability != [0; CAPABILITY_LEN] => Ok(capability),
            _ => Err(Error::io(format!(
                "the sandbox control capability {} is invalid",
                path.display()
            ))),
        }
    }

    /// Takes the sandbox's lock, waiting for it until `deadline`, or for as long as it takes
    /// without one.
    ///
    /// Fails with [`ErrorKind::TimedOut`](crate::ErrorKind::TimedOut) when the deadline passes
    /// first. A lock file that is removed or replaced while this waits locks nothing, so the
    /// lock is then taken again.
    pub fn lock(&self, deadline: Option<Instant>) -> Result<LockedStore> {
        let path = self.path(LOCK_NAME);
        let failed = |error| io_error(format!("cannot lock {}", path.display()))(error);
        loop {
            let file = files::private_options()
                .read(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .map_err(failed)?;
            match deadline {
                None => file.lock().map_err(failed)?,
                Some(deadline) => loop {
                    match file.try_lock() {
                        Ok(()) => break,
                        Err(TryLockError::WouldBlock) => {
                            let left = deadline.saturating_duration_since(Instant::now());
                            if left.is_zero() {
                                return Err(Error::timed_out(format!(
                                    "another lifecycle transition of the sandbox in {} is still \
                                     in progress",
                                    self.dir.display()
                                )));
                            }
                            thread::sleep(left.min(LOCK_RETRY_INTERVAL));
                        }
                        Err(TryLockError::Error(error)) => return Err(failed(error)),
                    }
                },
            }
            let locked = platform::opened_file_identity(&file).map_err(failed)?;
            match platform::file_identity(&path) {
                Ok(current) if current == locked => {
                    return Ok(LockedStore {
                        store: self.clone(),
                        _lock: file,
                    });
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(failed(error)),
            }
        }
    }
}

/// The store of a sandbox whose lock this holds, through which its lifecycle transitions change
/// its records. Dropping it releases the lock.
///
/// Every transition borrows it exclusively, and a [`Launch`] keeps it borrowed until the launch
/// commits or is abandoned, so transitions never overlap, not even through one guard that
/// threads share.
#[derive(Debug)]
pub struct LockedStore {
    /// The sandbox's store.
    store: SandboxStore,
    /// The locked file, whose lock lasts until it closes.
    _lock: File,
}

impl Deref for LockedStore {
    type Target = SandboxStore;

    fn deref(&self) -> &SandboxStore {
        &self.store
    }
}

impl LockedStore {
    /// Begins a launch of the runtime `runtime`, whose VMM receives `capability`.
    ///
    /// It stores the capability, replaces the log of the previous launch with a fresh one, which
    /// it claims, removes the outcome report, console log, and control socket of the previous
    /// launch, chooses a control endpoint, and writes the journal's marker. Nothing is spawned
    /// yet: the caller spawns the VMM with [`Launch::take_log`].
    ///
    /// Fails if the sandbox's VM runs, or a launch was interrupted and is not recovered yet, and
    /// with [`ErrorKind::Unsupported`](crate::ErrorKind::Unsupported) for an all-zero capability
    /// or an invalid runtime identity.
    pub fn begin_launch(
        &mut self,
        runtime: &RuntimeIdentity,
        capability: &[u8; CAPABILITY_LEN],
    ) -> Result<Launch<'_>> {
        runtime.check()?;
        if *capability == [0; CAPABILITY_LEN] {
            return Err(Error::unsupported(
                "a control capability cannot be all zero",
            ));
        }
        if self.journal()?.is_some() {
            return Err(Error::other(format!(
                "a launch of the sandbox in {} was interrupted and must be recovered first",
                self.dir.display()
            )));
        }
        if self.runtime()?.is_some() {
            return Err(Error::other(format!(
                "the sandbox in {} is already running",
                self.dir.display()
            )));
        }
        let socket = self.socket_path();
        for path in [&socket, &self.outcome_path(), &self.console_path()] {
            remove_if_present(path)?;
        }
        let endpoint = platform::control_endpoint(&socket)
            .map_err(|error| Error::io("cannot choose a control endpoint").with_source(error))?;
        let (log, claim) = self.create_log()?;
        files::write_private(&self.capability_path(), capability)?;
        let journal =
            LaunchJournal::prepared(LaunchId::generate()?, endpoint, runtime.clone(), claim);
        if let Err(error) = record::write(&self.path(JOURNAL_NAME), &journal) {
            let _ = remove_if_present(&self.capability_path());
            return Err(error);
        }
        Ok(Launch {
            locked: self,
            journal,
            log: Some(log),
        })
    }

    /// Replaces the log of the previous launch with a fresh file, and claims it.
    fn create_log(&self) -> Result<(File, LogClaim)> {
        let path = self.log_path();
        let failed = |error| io_error(format!("cannot create the log {}", path.display()))(error);
        remove_if_present(&path)?;
        let log = files::create_new(&path).map_err(failed)?;
        platform::claim_log(&log).map_err(failed)?;
        let (device, index) = platform::opened_file_identity(&log).map_err(failed)?;
        let claim = LogClaim {
            identity: FileIdentity { device, index },
        };
        Ok((log, claim))
    }

    /// Ends a launch that was interrupted, if its journal remains.
    ///
    /// Recovery signals only a VMM that it holds through a verified [`Process`]: the one that the
    /// journal's [`ProcessRef`] names, or the one that serves the journal's control endpoint, as
    /// the [module documentation](self#recovery) describes. Once nothing of the launch runs, it
    /// removes the launch's capability, control socket, and journal, and keeps its log. A
    /// recovery that cannot prove that is [`Recovery::Indeterminate`] and keeps them all for a
    /// later recovery.
    ///
    /// A journal that a committed runtime record of the same launch supersedes is removed. A
    /// runtime record of another launch fails as inconsistent state.
    pub fn recover(&mut self) -> Result<Recovery> {
        let Some(journal) = self.journal()? else {
            return Ok(Recovery::Clean);
        };
        match self.runtime()? {
            None => self.end_launch(&journal),
            Some(runtime) if runtime.launch() == journal.launch() => {
                remove_if_present(&self.path(JOURNAL_NAME))?;
                Ok(Recovery::Clean)
            }
            Some(runtime) => Err(Error::io(format!(
                "the launch journal of the sandbox in {} names launch {}, but its runtime record \
                 names launch {}",
                self.dir.display(),
                journal.launch(),
                runtime.launch()
            ))),
        }
    }

    /// Ends the launch that `journal` records, and removes its files once nothing of it runs.
    fn end_launch(&self, journal: &LaunchJournal) -> Result<Recovery> {
        let recovery = match journal.process() {
            Some(process) => self.end_identified(journal, process),
            None => self.end_unidentified(journal),
        };
        if !matches!(recovery, Recovery::Indeterminate(_)) {
            // The journal goes last, so that an interrupted removal leaves it for a later
            // recovery to finish.
            for name in [CAPABILITY_NAME, SOCKET_NAME, JOURNAL_NAME] {
                remove_if_present(&self.path(name))?;
            }
        }
        Ok(recovery)
    }

    /// Returns whether a process still holds the claim of the launch of `journal` on its log, or
    /// why that cannot be determined.
    fn claim_held(&self, journal: &LaunchJournal) -> std::result::Result<bool, String> {
        let path = self.log_path();
        let identity = journal.log().identity;
        platform::log_claim_held(&path, (identity.device, identity.index)).map_err(|error| {
            format!(
                "its claim on the log {} cannot be checked: {error}",
                path.display()
            )
        })
    }

    /// Ends a launch through the recorded reference to its VMM, which only the process that it
    /// names can match.
    ///
    /// A reference from an earlier boot names a process that has exited. Within the boot that it
    /// names, a VMM that no process matches may still run unseen, as one that this user may not
    /// examine, so the launch has exited only once its claim on its log is released.
    fn end_identified(&self, journal: &LaunchJournal, reference: &ProcessRef) -> Recovery {
        let pid = reference.pid;
        match BootId::current() {
            Ok(boot) if boot != reference.boot => return Recovery::Exited,
            Ok(_) => {}
            Err(error) => {
                return Recovery::Indeterminate(format!(
                    "the current boot cannot be identified: {error}"
                ));
            }
        }
        match Process::open(reference) {
            Ok(Some(process)) => end_process(&process),
            Ok(None) => match self.claim_held(journal) {
                Ok(false) => Recovery::Exited,
                Ok(true) => Recovery::Indeterminate(format!(
                    "no process matches its VMM process {pid}, but a process still holds its log"
                )),
                Err(reason) => Recovery::Indeterminate(reason),
            },
            Err(error) => Recovery::Indeterminate(format!(
                "whether its VMM process {pid} runs cannot be determined: {error}"
            )),
        }
    }

    /// Ends a launch that did not record its VMM's identity, through its claim on its log.
    fn end_unidentified(&self, journal: &LaunchJournal) -> Recovery {
        match self.claim_held(journal) {
            Ok(false) => return Recovery::Exited,
            Ok(true) => {}
            Err(reason) => return Recovery::Indeterminate(reason),
        }
        // A VMM that the launch spawned may hold the claim. Once it serves its control endpoint,
        // the endpoint names it.
        let endpoint = journal.endpoint();
        let (pid, candidate) = match vmm::hold_endpoint_server(
            || platform::endpoint_server_pid(endpoint),
            vmm::find,
        ) {
            Ok(found) => found,
            Err(reason) => return Recovery::Indeterminate(reason),
        };
        let identity = journal.log().identity;
        match vmm::serves_launch(&candidate, (identity.device, identity.index)) {
            Ok(true) => end_process(&candidate),
            Ok(false) => Recovery::Indeterminate(format!(
                "process {pid} serves its control endpoint, but does not hold its log as its \
                 standard output, so it is not signaled"
            )),
            Err(error) => Recovery::Indeterminate(format!(
                "process {pid} serves its control endpoint, and whether it is its VMM cannot be \
                 determined: {error}"
            )),
        }
    }

    /// Removes the runtime record, the launch capability, and the control socket of a VM that has
    /// exited, the runtime record last. The log, console log, and outcome report outlive the run.
    pub fn clear_runtime(&mut self) -> Result<()> {
        for name in [CAPABILITY_NAME, SOCKET_NAME, RUNTIME_NAME] {
            remove_if_present(&self.path(name))?;
        }
        Ok(())
    }
}

/// Ends a launch by terminating its verified VMM `process`.
fn end_process(process: &Process) -> Recovery {
    let pid = process.reference().pid;
    match vmm::terminate(process) {
        Ok(true) => Recovery::Terminated(process.reference().clone()),
        Ok(false) => Recovery::Indeterminate(format!(
            "its VMM process {pid} did not exit after it was terminated"
        )),
        Err(error) => Recovery::Indeterminate(format!(
            "its VMM process {pid} cannot be terminated: {error}"
        )),
    }
}

/// How [`LockedStore::recover`] or [`Launch::abandon`] ended a launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    /// No launch was interrupted.
    Clean,
    /// The launch never spawned its VMM, or its VMM has exited; its files are removed.
    Exited,
    /// Recovery terminated the launch's VMM, whose reference this holds, after verifying it; its
    /// files are removed.
    Terminated(ProcessRef),
    /// Recovery cannot prove that nothing of the launch runs, for the reason that this gives, and
    /// keeps its files for a later recovery.
    Indeterminate(String),
}

/// A launch in progress, which borrows its sandbox's locked store exclusively from its journal's
/// marker until its runtime record.
///
/// Dropping it before [`commit`](Self::commit) or [`abandon`](Self::abandon) leaves its journal,
/// as a crash would, for [`LockedStore::recover`] to end.
#[derive(Debug)]
pub struct Launch<'a> {
    /// The sandbox's locked store.
    locked: &'a mut LockedStore,
    /// The launch's journal, as written.
    journal: LaunchJournal,
    /// The claimed log, until the caller takes it for the VMM.
    log: Option<File>,
}

impl Launch<'_> {
    /// Returns the launch's journal.
    pub fn journal(&self) -> &LaunchJournal {
        &self.journal
    }

    /// Returns the control endpoint that the launch chose, on which the VMM must listen.
    pub fn endpoint(&self) -> &str {
        self.journal.endpoint()
    }

    /// Takes the claimed log, which the caller passes to the VMM as its standard output and
    /// error, as [`spawn`](super::process::spawn) does with its `log`, once.
    ///
    /// The launch keeps no copy of the log, so the claim lasts as long as the processes that hold
    /// it.
    pub fn take_log(&mut self) -> Result<File> {
        self.log
            .take()
            .ok_or_else(|| Error::other("the log of the launch was taken already"))
    }

    /// Records the reference to the VMM process `child`, which the caller spawned and has not
    /// reaped, right after the spawn, and returns the process, held through a handle of its own
    /// as [`Launched::process`] holds it.
    ///
    /// Fails if the launch has recorded its VMM already, or if the process's identity cannot be
    /// read; [`abandon`](Self::abandon) then ends the launch.
    pub fn record_process(&mut self, child: &Launched) -> Result<Process> {
        if self.journal.process().is_some() {
            return Err(Error::other(
                "the launch has recorded its VMM process already",
            ));
        }
        let process = child
            .process()
            .map_err(|error| Error::io("cannot identify the VMM process").with_source(error))?;
        let journal = self.journal.spawned(process.reference().clone());
        record::write(&self.locked.path(JOURNAL_NAME), &journal)?;
        self.journal = journal;
        Ok(process)
    }

    /// Commits the launch of a VM that is ready: writes its runtime record, which then names the
    /// VM, and removes the journal.
    ///
    /// The runtime record is the commit, so a journal that remains because its removal failed is
    /// removed by [`LockedStore::recover`]. Fails if the launch has not recorded its VMM process,
    /// or if the runtime record cannot be written; the journal then remains, as that of an
    /// interrupted launch, for [`LockedStore::recover`] to end.
    pub fn commit(self) -> Result<RuntimeRecord> {
        let Some(process) = self.journal.process() else {
            return Err(Error::other(
                "a launch cannot commit before it records its VMM process",
            ));
        };
        let runtime = RuntimeRecord::committed(&self.journal, process.clone());
        record::write(&self.locked.path(RUNTIME_NAME), &runtime)?;
        let _ = remove_if_present(&self.locked.path(JOURNAL_NAME));
        Ok(runtime)
    }

    /// Ends a launch that failed, as [`LockedStore::recover`] ends an interrupted one: it
    /// terminates the VMM if its identity is verified, and removes the launch's files once
    /// nothing of it runs.
    ///
    /// A caller that still holds the VMM's [`Launched`] process releases it as usual. If the
    /// launch never recorded that process, the caller ends it with
    /// [`kill_child`](super::process::kill_child) first: an unrecorded VMM that serves no
    /// endpoint yet holds the log's claim, so the launch would end as
    /// [`Recovery::Indeterminate`].
    pub fn abandon(mut self) -> Result<Recovery> {
        // A log that no VMM received holds no claim once it closes.
        drop(self.log.take());
        self.locked.end_launch(&self.journal)
    }
}
