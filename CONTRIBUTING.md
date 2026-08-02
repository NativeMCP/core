# Contributing to NativeMCP/core

## Before anything else

Read [`core/docs/GOVERNANCE.md`](https://github.com/NativeMCP/core/blob/main/docs/GOVERNANCE.md).
The invariants there are normative and are the reason most changes get
rejected. They are short.

## The bar

No stubs. No `TODO`. No `todo!()`. No placeholder implementations. No
commented-out code left "for later". Work is complete, or it is a named gap
with a stated reason and an owner, recorded in an issue.

A pull request that partially implements something and says so in the
description is welcome. A pull request that partially implements something and
looks complete is not.

## Toolchain

Pinned in `rust-toolchain.toml` (1.97.1, edition 2024). `rustup` picks it
up automatically. Do not bump it in a feature branch.

```bash
rustup show
```

## Branches

| Prefix | Use |
|---|---|
| `feat/<slug>` | new capability |
| `fix/<slug>` | defect repair |
| `docs/<slug>` | documentation only |
| `chore/<slug>` | tooling, dependencies, CI |
| `refactor/<slug>` | behaviour-preserving restructuring |

`main` is protected. It takes no direct pushes, no force pushes and no merge
without a passing CI run and an approving review.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/). The scope is the
crate or subsystem.

```
feat(policy): resolve roots before permission evaluation

Closes #12. Satisfies INV-2.
```

Every commit body cites the requirement or invariant ID it serves (INV-6).

## Local gate

Run the same checks CI runs, before you push. CI is a backstop, not a linter
you outsource to.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
```

## Pull requests

Fill in the template. The traceability and invariant sections are not optional
optional. They are what INV-6 is made of. A pull request that leaves them blank is
closed, not asked about.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
