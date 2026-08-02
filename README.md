# NativeMCP / core

Shared Rust crates for the NativeMCP governed server family: wire protocol, policy engine, contract schema, audit trail, host kernel.

[![CI](https://github.com/NativeMCP/core/actions/workflows/ci.yml/badge.svg)](https://github.com/NativeMCP/core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`core` is the single source of truth for every behaviour the platform servers
share. Anything a Windows, Linux and macOS server would otherwise each
implement lives here exactly once, because three implementations of one rule
is three chances to diverge from it.

## Crates

| Crate | Responsibility |
|---|---|
| `nmcp-proto` | MCP wire protocol: request and response envelopes, JSON-RPC framing, transport headers, protocol revision pinning. |
| `nmcp-policy` | Governance engine: hierarchical instruction authority, root and permission resolution, invariant enforcement, deny-by-default evaluation. |
| `nmcp-schema` | Tool contract schema, capability manifest, configuration schema and validation. |
| `nmcp-audit` | Append-only, hash-chained audit trail with a pluggable sink. Platform repos bind the sink to Event Log, journald or unified logging. |
| `nmcp-host` | Server runtime kernel: transport wiring, dispatch, tool registry. Platform daemons are thin shells over this. |

`nmcp-audit` and `nmcp-host` are in `core` rather than in each platform repo
deliberately. An audit trail that three servers implement separately is three
audit formats, and a dispatch loop that three servers implement separately is
three sets of policy bypasses waiting to be found.

## Governance

The invariants in [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md) are normative for
every repository in this organization. They are not guidance. A change that
cannot satisfy them is not merged, and there is no per-call override path.

## Status

Repository setup stage. The crates are pinned, wired and CI-green; the
protocol, policy and schema implementations are named gaps tracked as issues,
not stubs. No crate here ships a `todo!()` or a placeholder return.

## Consuming `core`

Platform repositories depend on `core` by pinned git tag:

```toml
[dependencies]
nmcp-proto = { git = "https://github.com/NativeMCP/core", tag = "v0.1.0" }
```

For local cross-repo work, override with a path patch in a git-ignored
`.cargo/config.local.toml` rather than editing `Cargo.toml`. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Build

```bash
rustup show                 # honours rust-toolchain.toml
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## License

Apache-2.0. See [LICENSE](LICENSE).
