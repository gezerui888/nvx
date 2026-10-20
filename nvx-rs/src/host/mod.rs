//! The host side of NVX.
//!
//! - [`artifacts`] locates the OpenVMM executable and the guest kernel and initramfs, and every
//!   artifact of the guests that `nvx.py` runs, in a repository checkout or a release.
//! - [`launch`] builds OpenVMM's command line from a [`LaunchSpec`](launch::LaunchSpec): the
//!   managed lifecycle, the workload identity, the kernel command line, and the network and
//!   filesystem options.
//! - [`network`] lowers egress rules, and the egress policy files of `nvx.py`, into OpenVMM's
//!   rules, and [`filesystem`] plans the export of host paths through OpenVMM's aggregate
//!   virtio-fs device.
//! - [`instance`] supervises one VM instance in a directory of its own: it starts OpenVMM and
//!   waits until the guest is ready, reconciles recorded state with the host, runs workloads,
//!   and stops the VM. [`report`] reads OpenVMM's outcome report.
//! - [`store`] keeps the runtime records of a sandbox in a private directory with one lock: the
//!   runtime record of its VM, with the VM's runtime identity, and the journal of its launch,
//!   through which an interrupted launch is recovered without signaling an unverified process.
//! - [`session`] speaks the authenticated control protocol, and [`platform`] holds the primitives
//!   of Linux and Windows hosts. Other hosts compile but report NVX as unavailable.
//! - [`process`] launches OpenVMM processes. Its verified process references name a process by
//!   its ID, start time, and host boot, and hold it through a pidfd or a process handle, so that
//!   waits sleep until it exits and termination reaches only it, whether or not the caller
//!   started it.
//! - [`sandbox`] is the launch profile of `nvx.py sandbox`: a container over read-only EROFS
//!   layers and a private ext4 scratch disk, with live shares, and the checks of its options.
//! - `cli` (feature `cli`) is the `nvx-rs` command-line interface, which `nvx.py` runs for the
//!   steps that it delegates: artifact lookup, egress policy compilation, and sandboxes.
//!
//! The ports of `nvx.py` code keep its Python semantics, which the private `python` module
//! provides.
//!
//! The host modules deny unsafe code. On Unix, the private `sys` module confines the system calls
//! that the standard library lacks behind documented safe functions, which call `nix`. The
//! Windows platform module, and the module of the Win32 calls that Python's filesystem queries
//! make, still call `windows-sys` directly.
#![deny(unsafe_code)]

pub mod artifacts;
#[cfg(feature = "cli")]
pub mod cli;
pub mod filesystem;
pub mod instance;
pub mod launch;
pub mod network;
pub mod platform;
pub mod process;
pub(crate) mod python;
pub mod report;
pub mod sandbox;
pub mod session;
pub mod store;
#[cfg(unix)]
#[allow(unsafe_code)]
mod sys;
