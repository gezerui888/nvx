//! NVX mechanics: the OpenVMM control protocol, and the launch, policy lowering, and supervision
//! of NVX microVMs.
//!
//! An NVX sandbox is a microVM that OpenVMM runs with the managed lifecycle: the guest's init
//! starts a managed agent, which runs workloads that the host sends it over an authenticated
//! control console. This crate holds everything it takes to drive one:
//!
//! - [`protocol`]: the codec of the control console, the `NVXS` records that OpenVMM brokers and
//!   the `NVXC` frames of the guest agent. It has no dependencies, so the host, the guest, and
//!   test doubles share it.
//! - [`contract`]: the control-contract versions that this crate speaks, and the compatibility of
//!   NVX releases with them.
//! - [`net`]: IP networks in CIDR notation and their subtraction, and the forms of a VM's
//!   hostname and guest network address.
//! - [`Hypervisor`]: the hypervisors that run the VMs.
//! - [`host`] (feature `host`): artifact discovery, the OpenVMM command line, the lowering of
//!   network and filesystem policies, control sessions, process and platform primitives, and the
//!   supervision of VM instances: starting, reconciling, executing workloads, and stopping.
//! - `testing` (feature `testing`): a fake OpenVMM that serves the control console without
//!   running a VM.
//! - `guest` (feature `guest`, Linux): the programs that run in NVX guests, such as
//!   `nvx-console-pending`, which the crate's `nvx-*` guest binaries run, and `guest::spawn`,
//!   through which any guest init or agent starts a program in a new process.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "host")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::atomic::AtomicBool;
//! use std::time::Duration;
//!
//! use nvx::host::instance::{self, Instance};
//! use nvx::host::launch::LaunchSpec;
//! use nvx::protocol::{Workload, WorkloadEnvironment};
//! use nvx::{Artifacts, Hypervisor};
//!
//! // Locates OpenVMM, the guest kernel, and the Alpine initramfs.
//! let spec = LaunchSpec::new(Artifacts::discover()?, Hypervisor::from_env_or_default()?);
//! let directory = std::env::temp_dir().join("nvx-example");
//! instance::create_private_dir(&directory)?;
//! let instance = Instance::new(&directory, "example");
//! let started = instance.start(&spec, Duration::from_secs(60))?;
//!
//! let workload = Workload {
//!     argv: vec!["/bin/echo".to_owned(), "hello".to_owned()],
//!     timeout_ms: 0,
//!     cwd: None,
//!     environment: WorkloadEnvironment::Default,
//! };
//! let capability = instance.read_capability()?;
//! let timeout = Duration::from_secs(60);
//! let execution = instance.exec(&started.runtime, &capability, &workload, timeout, timeout)?;
//! let mut stdout = Vec::new();
//! let outcome = execution.pump(
//!     &mut |chunk: &[u8]| {
//!         stdout.extend_from_slice(chunk);
//!         Ok(())
//!     },
//!     &mut |_: &[u8]| Ok(()),
//!     &AtomicBool::new(false),
//! )?;
//! println!("{outcome:?}: {}", String::from_utf8_lossy(&stdout));
//!
//! instance.stop(&started.runtime, Duration::from_secs(30))?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "host"))]
//! # fn main() {}
//! ```
//!
//! # Features
//!
//! - `host` (default): the [`host`] module. It enables `serde`.
//! - `bundled`: stages the OpenVMM executable, guest kernel, and control initramfs at build time;
//!   see `Artifacts::bundled`. The build script downloads the release that `artifacts.json` pins,
//!   or copies the release directory that `NVX_BUNDLE_DIR` names.
//! - `testing`: the fake OpenVMM of `testing::fake_openvmm` and its `nvx-fake-openvmm` binary.
//! - `serde`: the serde form of [`Hypervisor`].
//! - `guest`: the `guest` module and the guest binaries, which the `guest` profile builds as
//!   static `x86_64-unknown-linux-musl` executables.

pub mod contract;
mod error;
mod hypervisor;
pub mod net;
pub mod protocol;

#[cfg(all(feature = "guest", target_os = "linux"))]
pub mod guest;
#[cfg(feature = "host")]
pub mod host;
#[cfg(feature = "testing")]
pub mod testing;

pub use error::{Error, ErrorKind, Result};
#[cfg(feature = "host")]
pub use host::artifacts::Artifacts;
#[cfg(feature = "host")]
pub use host::filesystem::{guest_path, resolve_guest_path};
pub use hypervisor::Hypervisor;
