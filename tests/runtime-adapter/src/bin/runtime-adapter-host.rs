//! The host half of the runtime adapter. This skeleton reports the contract that it was built
//! against and whether `nvx-rs` supports this host; later steps make it start, reattach to, and
//! stop sandboxes through the host API.

use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args_os().len() > 1 {
        eprintln!("usage: runtime-adapter-host");
        return ExitCode::from(2);
    }
    println!(
        "runtime-adapter-host: {}; supported host: {}",
        runtime_adapter::contract(),
        nvx::host::platform::SUPPORTED,
    );
    ExitCode::SUCCESS
}
