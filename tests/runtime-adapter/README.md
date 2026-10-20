# Runtime adapter

The runtime adapter is an independent adapter of the NVX runtime. It lives in
this repository so that NVX's own CI builds and runs it, and it depends on
[`nvx-rs`](../../nvx-rs/README.md) the way an adapter outside the repository
does:

- as a path dependency with default features off;
- with a `Cargo.lock` of its own, outside any other workspace;
- through the public API alone, with unsafe code forbidden;
- with the minimum supported Rust version of `nvx-rs`.

[microsoft/nvx#535](https://github.com/microsoft/nvx/issues/535) sets the
contract that it proves: an adapter brings its own application framing over
the NVXS session, its own init, and its own status collector. Today its
binaries are skeletons that report the contract that they were built against.
Later steps fill its guest half
([microsoft/nvx#619](https://github.com/microsoft/nvx/issues/619)) and its host
half ([microsoft/nvx#620](https://github.com/microsoft/nvx/issues/620)), and add
the scenarios that run them on a hypervisor.

## Configurations

Each configuration enables one side of `nvx-rs`:

| Configuration | Cargo options | `nvx-rs` features | Binary |
| --- | --- | --- | --- |
| Protocol-only | none | none | none |
| Host-only | `--features host` | `host` | `runtime-adapter-host` |
| Guest-only | `--features guest --target x86_64-unknown-linux-musl` | `guest` | `runtime-adapter-guest`, a static executable |

## Tests

`tests/independent_build.rs` checks consumer-contract scenario C0 in every
configuration:

- The adapter is a workspace of its own with its own lockfile, and declares
  the minimum supported Rust version of `nvx-rs`.
- The protocol-only build depends on `nvx-rs` alone, without features. The
  host-only build enables the host side of `nvx-rs` and not its guest side. The
  guest-only build enables only the guest side, and pulls in neither Tokio nor
  a dependency that only the host side of `nvx-rs` declares. The tests read
  these dependency trees from `cargo tree`, which downloads the packages of the
  musl target the first time, on Windows too.
- Each binary runs and reports the contract that it was built against, and the
  guest binary is a static executable: it has no program interpreter, needs no
  shared library, and keeps its stack non-executable.

Run the checks of each configuration in this directory. The guest-only
configuration needs Linux and the musl target, which
`rustup target add x86_64-unknown-linux-musl` installs:

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo clippy --locked --all-targets --features host -- -D warnings
cargo test --locked --features host
cargo clippy --locked --all-targets --features guest \
  --target x86_64-unknown-linux-musl -- -D warnings
cargo test --locked --features guest --target x86_64-unknown-linux-musl
```

## CI

The [`check-nvx-rs`](../../.github/actions/check-nvx-rs/action.yml) action
runs these checks with `cargo build`, and `cargo check` with the minimum
supported Rust version, on Linux and Windows, where it skips the guest-only
configuration. A change to the adapter is a test input of CI's
[change classification](../../doc/ci.md#change-classification), so it runs the
NVX microVM tests. Their
[workflow](../../.github/workflows/run-nvx-microvm-tests.yml) runs the
adapter's hypervisor scenarios on each backend: its ignored tests in the
host-only configuration, with `NVX_HYPERVISOR` naming the backend, which
`nvx::Hypervisor::from_env_or_default` reads. There are none yet.
