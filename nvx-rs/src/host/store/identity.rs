//! The runtime identity of a VM: the identities of its VMM, kernel, and initramfs, and the
//! versions of the contracts between its host, its VMM, and its guest.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::contract;
use crate::error::{Error, Result};

/// Longest [`ArtifactIdentity`] and control contract revision, in bytes.
pub const MAX_IDENTITY_LEN: usize = 128;

/// Returns whether `text` holds 1 to [`MAX_IDENTITY_LEN`] printable ASCII characters and no space.
pub(super) fn is_token(text: &str) -> bool {
    (1..=MAX_IDENTITY_LEN).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Identity of one runtime artifact, such as the OpenVMM executable, as the metadata of its
/// install or staging records it: for example `sha256:` and the hexadecimal SHA-256 digest that
/// a release's `SHA256SUMS` lists for the file.
///
/// It is an opaque token of 1 to [`MAX_IDENTITY_LEN`] printable ASCII characters without spaces,
/// which the store only compares. Nothing here reads or hashes an artifact: a digest computed at
/// launch would cost time in proportion to the artifact's size on every start.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ArtifactIdentity(String);

impl ArtifactIdentity {
    /// Wraps `identity`.
    ///
    /// Fails with [`ErrorKind::Unsupported`](crate::ErrorKind::Unsupported) unless it holds 1 to
    /// [`MAX_IDENTITY_LEN`] printable ASCII characters and no space.
    pub fn new(identity: impl Into<String>) -> Result<Self> {
        let identity = identity.into();
        if is_token(&identity) {
            Ok(Self(identity))
        } else {
            Err(Error::unsupported(format!(
                "artifact identity {identity:?} must hold 1 to {MAX_IDENTITY_LEN} printable ASCII \
                 characters and no space"
            )))
        }
    }

    /// Returns the identity `sha256:DIGEST` of an artifact whose SHA-256 digest is `digest`, 64
    /// hexadecimal digits in either case, which the identity holds in lowercase.
    ///
    /// Fails with [`ErrorKind::Unsupported`](crate::ErrorKind::Unsupported) otherwise.
    pub fn sha256(digest: &str) -> Result<Self> {
        if digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(Self(format!("sha256:{}", digest.to_ascii_lowercase())))
        } else {
            Err(Error::unsupported(format!(
                "{digest:?} is not a SHA-256 digest of 64 hexadecimal digits"
            )))
        }
    }

    /// Returns the identity's text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ArtifactIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for ArtifactIdentity {
    type Error = Error;

    fn try_from(identity: String) -> Result<Self> {
        Self::new(identity)
    }
}

impl From<ArtifactIdentity> for String {
    fn from(identity: ArtifactIdentity) -> Self {
        identity.0
    }
}

/// Identity of the runtime that a VM was launched with: its OpenVMM executable, guest kernel, and
/// guest initramfs, and the boot and control contract versions between its host, OpenVMM, and
/// its guest.
///
/// It decides whether a host may keep managing a VM that it finds recorded, as after an
/// orchestrator restart or an upgrade of the orchestrator. Under the same runtime identity, a new
/// build of the host's own code keeps the VM running and reattaches to it. A different runtime
/// identity would drive the VM through artifacts or contracts that did not start it, so the VM
/// must be stopped instead, through its verified process identity; see
/// [`RuntimeRecord::check_identity`](super::RuntimeRecord::check_identity).
///
/// The caller takes the artifact identities from install or staging metadata, and
/// [`RuntimeIdentity::new`] adds the contract versions that this crate speaks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeIdentity {
    /// The OpenVMM executable.
    pub openvmm: ArtifactIdentity,
    /// The guest kernel.
    pub kernel: ArtifactIdentity,
    /// The guest initramfs.
    pub initramfs: ArtifactIdentity,
    /// The boot contract: the version of the microVM ABI through which OpenVMM boots and
    /// configures the guest, [`MICROVM_ABI_VERSION`](contract::MICROVM_ABI_VERSION) in this
    /// crate.
    pub boot_contract: u64,
    /// The revision of the control contract,
    /// [`CONTROL_CONTRACT_REVISION`](contract::CONTROL_CONTRACT_REVISION) in this crate: 1 to
    /// [`MAX_IDENTITY_LEN`] printable ASCII characters without spaces.
    pub control_contract: String,
    /// The version of the control session that carries the control contract,
    /// [`CONTROL_SESSION_PROTOCOL_VERSION`](contract::CONTROL_SESSION_PROTOCOL_VERSION) in this
    /// crate.
    pub control_session: u64,
}

impl RuntimeIdentity {
    /// Returns the identity of a runtime of these artifacts under the contracts that this crate
    /// speaks.
    pub fn new(
        openvmm: ArtifactIdentity,
        kernel: ArtifactIdentity,
        initramfs: ArtifactIdentity,
    ) -> Self {
        Self {
            openvmm,
            kernel,
            initramfs,
            boot_contract: contract::MICROVM_ABI_VERSION,
            control_contract: contract::CONTROL_CONTRACT_REVISION.to_owned(),
            control_session: contract::CONTROL_SESSION_PROTOCOL_VERSION,
        }
    }

    /// Fails with [`ErrorKind::Unsupported`](crate::ErrorKind::Unsupported) if the control
    /// contract revision does not hold 1 to [`MAX_IDENTITY_LEN`] printable ASCII characters and
    /// no space: the one field whose type does not ensure its form.
    pub fn check(&self) -> Result<()> {
        if is_token(&self.control_contract) {
            Ok(())
        } else {
            Err(Error::unsupported(format!(
                "control contract revision {:?} must hold 1 to {MAX_IDENTITY_LEN} printable \
                 ASCII characters and no space",
                self.control_contract
            )))
        }
    }

    /// Names the parts of this identity that differ from `other`, in the order of its fields.
    pub fn differences(&self, other: &Self) -> Vec<&'static str> {
        [
            ("OpenVMM", self.openvmm == other.openvmm),
            ("kernel", self.kernel == other.kernel),
            ("initramfs", self.initramfs == other.initramfs),
            ("boot contract", self.boot_contract == other.boot_contract),
            (
                "control contract",
                self.control_contract == other.control_contract,
            ),
            (
                "control session",
                self.control_session == other.control_session,
            ),
        ]
        .into_iter()
        .filter(|(_, equal)| !equal)
        .map(|(name, _)| name)
        .collect()
    }
}

/// How the runtime identity of a record compares with the current one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityCheck {
    /// The identities are equal: the host may reattach to the VM and keep it running.
    Matches,
    /// The identities differ in the parts that this lists, as
    /// [`RuntimeIdentity::differences`] names them: the VM must be stopped, and only through its
    /// verified process identity.
    Mismatched(Vec<&'static str>),
}
