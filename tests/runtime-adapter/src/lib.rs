//! An independent adapter of the NVX runtime. NVX's CI builds it against `nvx-rs` the way an
//! adapter outside the repository would: as a path dependency with default features off, with a
//! lockfile of its own, and through the public API alone.
//!
//! Each configuration enables one side of `nvx-rs`:
//!
//! - protocol-only, without features: the control protocol, the contract versions, and the other
//!   items that `nvx-rs` has without features;
//! - host-only, with the `host` feature: the host API too, and the `runtime-adapter-host`
//!   binary;
//! - guest-only, with the `guest` feature: the guest API too, and the `runtime-adapter-guest`
//!   binary, a static `x86_64-unknown-linux-musl` executable.
//!
//! The binaries are skeletons that report the contract they were built against. Later steps give
//! the adapter its own framing over the NVXS session, fill its host and guest halves, and add the
//! scenarios that run them on a hypervisor.

/// Describes the runtime contract that this build speaks: the control contract revision, and the
/// versions of the microVM ABI, the NVXS records, and the NVXC frames.
pub fn contract() -> String {
    format!(
        "control contract {} (microVM ABI {}, NVXS v{}, NVXC v{})",
        nvx::contract::CONTROL_CONTRACT_REVISION,
        nvx::contract::MICROVM_ABI_VERSION,
        nvx::protocol::OUTER_VERSION,
        nvx::protocol::APP_VERSION,
    )
}
