//! The guest half of the runtime adapter, a static `x86_64-unknown-linux-musl` executable. This
//! skeleton reports the contract that it was built against; later steps make it serve the guest
//! role of the NVXS session with the adapter's own framing.

use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    if std::env::args_os().len() > 1 {
        eprintln!("usage: runtime-adapter-guest");
        return ExitCode::from(2);
    }
    println!("runtime-adapter-guest: {}", runtime_adapter::contract());
    ExitCode::SUCCESS
}

// The guest half runs only in Linux guests. Elsewhere this stub fails, so that every target still
// builds with every feature.
#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("runtime-adapter-guest runs only in Linux guests");
    ExitCode::FAILURE
}
