//! The programs that run in NVX's Linux guests, which ship as `/sbin/nvx-*`, and the library
//! through which a guest init or agent starts a program.
//!
//! Each program module holds one program, and the crate's binary of the same name runs its
//! `main`. The [`spawn`] module is a library instead: it starts a program in a new process for
//! any guest init or agent, without NVX's control protocol, managed agent, or workload identity,
//! and NVX's managed agent starts its workloads through it.
//!
//! The programs keep the command lines, exit statuses, and output of the C programs that they
//! replace, except that numeric arguments are plain decimal, with a `-` sign where `nvx-time`'s
//! test hooks take negative numbers, or `0x`-prefixed hexadecimal where the C program also read
//! hexadecimal, floating-point arguments plain decimal with an optional exponent, error messages
//! describe `errno` values with `nix`'s text, and the programs read the kernel's text, such as
//! its socket tables, sysctls, rates, CPU lists, and timer list, their own records, and their
//! test fixtures only in the form in which they are written, rejecting the signed, prefixed, and
//! other lenient forms that C's `strtoul`, `strtod`, and `scanf` also read. Nor do they keep
//! what only the C programs' fixed buffers and string handling did to oversized or malformed
//! input, such as a length limit on a valid CPU list, an unknown option that a later valid one
//! masked, or a NUL byte that ended a diagnostic.
//!
//! # Conventions
//!
//! - Program and library modules deny unsafe code. Only the private `sys` module may use it,
//!   behind documented safe operations. It makes every system call through `nix`, with the
//!   enabled, default-free feature set, or through the standard library, which reads and writes
//!   whole files and the MSR devices, except the few spawn, managed-agent, and time-tool
//!   operations that neither provides, which `sys` documents, and the programs take random bytes
//!   from the `getrandom` crate. `sys` also names the kernel's and the processor's interfaces
//!   once: the procfs, sysfs, and device paths, OpenVMM's I/O ports, CPUID leaves and MSRs, and
//!   the kernel's flags, so that the programs refer to them by name.
//! - Descriptors and mappings have owners that release them when dropped. Where a C program
//!   reported a cleanup failure, a consuming `close` or `unmap` returns it instead. Raw
//!   descriptor integers never leave `sys`, and no resource is dropped by hand: where a C
//!   program released one before a later step, its scope ends there, for example in a helper
//!   function that returns what the later step needs. State that a program changes for a while,
//!   such as a lock, a signal mask, a thread's CPU affinity or scheduling policy, a mount, a
//!   created file, or a kernel setting, likewise has an owner that restores it when dropped.
//! - A descriptor stays with the library that opened it: one that `sys` opens through `nix` is
//!   read and written only through `sys`, and one that the standard library opens only through
//!   it, except that a test may hand one to `FileDescriptor::from_owned`, which takes it over
//!   whole. No descriptor thus has two owners or two buffers; a standard-library adapter such as
//!   `BufReader` may add the one buffer of a `sys` descriptor through the `std::io::Read` that
//!   `FileDescriptor` implements. `sys::Stdout` and `sys::DirectStdout` write standard output
//!   directly, past the standard library's line buffer, so the programs never print with the
//!   standard library's macros: `print!` would reorder its buffered output with theirs, and
//!   `eprint!` would bypass the error streams that the programs' tests capture. Clippy denies
//!   both here.
//! - Every program fails with the shared `CommandError`, whose kind selects the program's exit
//!   status from the shared `ExitStatus`. Every module, type, field, variant, constant, static,
//!   and function is documented, which CI enforces with `clippy::missing_docs_in_private_items`.
//! - The programs use `nix`, `getrandom`, or the standard library rather than reimplement a
//!   facility, and keep a parser of their own only for forms that no library parses.
#![deny(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr)]

mod parse;
mod status;
#[allow(unsafe_code)]
mod sys;

#[cfg(target_arch = "x86_64")]
mod kernel_text;

pub mod console_pending;
#[cfg(target_arch = "x86_64")]
pub mod device_io;
#[cfg(target_arch = "x86_64")]
pub mod exit;
pub mod ingress;
pub mod managed_agent;
#[cfg(target_arch = "x86_64")]
pub mod mmio_write;
pub mod reseed;
pub mod spawn;
#[cfg(target_arch = "x86_64")]
pub mod time;
#[cfg(target_arch = "x86_64")]
pub mod time_probe;
