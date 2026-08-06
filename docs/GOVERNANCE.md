# NativeMCP Governance Invariants

Status: **normative**. Applies to `core`, `WinMCP`, `LinuxMCP` and `macMCP`.

An invariant is a property that holds in every code path, in every release, on
every platform. It is not a default, not a recommended setting, and not
something a caller may relax. There is no per-request override, no
`--force` flag, and no "the user asked for it" exception. A feature that cannot
be built without violating one of these is not built.

Every invariant below carries a stable ID. Requirements, issues, tests and
architecture decision records cite these IDs, which is what makes
requirement-to-artifact traceability mechanical rather than aspirational.

---

## INV-1: No Destructive Primitive

No tool exposed by any NativeMCP server may unlink, truncate, overwrite in place
without backup, or otherwise irreversibly destroy user data.

Destructive intent is not refused, it is **redirected**. A request to delete
resolves to a move into a quarantine location inside the same governed root,
recorded in the audit trail, reversible by the user. Reclaiming that space is a
human action taken outside the server.

Consequences: no `remove_file`, `remove_dir_all`, `DeleteFile`, `unlink`,
`SHFileOperation` or equivalent in any dependency path reachable from a tool
handler. Enforced by a deny-list lint in CI, not by review vigilance.

## INV-2: Root-Scoped Path Authority

Every filesystem operation resolves against an explicitly configured root that
carries an explicit permission set. Default is deny.

A path that does not canonicalize to a location inside a granted root is
rejected before any I/O is attempted. Canonicalization happens before the check,
never after, and symlink traversal out of a root is a rejection, not a
follow. Permission sets are additive per root and never inherited from a parent
directory that was not itself granted.

## INV-3: Immutable Audit

Every request, every policy decision and every effect emits an append-only
record. The record is written and durable **before** the effect becomes
observable, not after it succeeds.

Records are hash-chained: each entry commits to the digest of its predecessor,
so removing or editing an entry is detectable. The audit sink is
platform-bound (Event Log, journald, unified logging), but the record schema
and the chain are defined once in `nmcp-audit`.

A server that cannot write audit does not serve. Audit failure is a hard stop,
never a degraded mode.

## INV-4: Hierarchical Instruction Authority

Authority flows in one direction:

```
operator policy file  >  server defaults  >  client request
```

A lower tier may **narrow** what a higher tier permits. It may never widen it. A
client request that asks for more than policy grants is rejected with the
governing rule named in the rejection, not silently clamped. Silent clamping
teaches callers that the boundary is negotiable.

## INV-5: Explicit State Machine

Every session, job and long-running operation has an enumerated state and a
declared set of legal transitions. States are data, not implied by which
variables happen to be set.

An attempted illegal transition halts the operation and emits an audit record.
It does not log a warning and continue. "Shouldn't happen" paths are the ones
that matter here.

## INV-6: Requirement Traceability

Every merged change cites at least one requirement or invariant ID. Every
requirement maps to an artifact that demonstrates it: a test, a schema, a
policy rule, or a named gap with a stated reason.

A gap is acceptable. An unstated gap is not. There are no `TODO` markers, no
`todo!()`, no placeholder returns and no silently unimplemented branches
anywhere in this organization's code. Work is complete, or it is a named gap
with a reason and an owner.

## INV-7: Reproducible Build

The toolchain is pinned in `rust-toolchain.toml`. The dependency graph is
locked. The supply chain policy in `deny.toml` is enforced in CI as a gate, not
reported as advice.

Bumping the toolchain, adding a dependency, or adding a license exception is a
reviewed change with the reason recorded in the pull request.

## INV-8: Brand Integrity

No artifact in this organization references the product's retired
predecessor names: not in sources, comments, docs, workflows, package
metadata, branch names, commit messages, or binary strings. The product has
exactly one name.

The enumeration of retired names lives in the CI brand gate, assembled from
fragments so the gate does not trip on its own definition. The normative
list resides in the private port specification (NMCP-SPEC-001, R-6), which
is itself excluded from every public tree. A hit is a build failure, not a
review comment.

---

## Enforcement

| Invariant | Enforced by |
|---|---|
| INV-1 | CI deny-list lint over the reachable dependency graph; policy engine rejects destructive verbs |
| INV-2 | `nmcp-policy` root resolution; property tests over traversal and symlink cases |
| INV-3 | `nmcp-audit` write-before-effect ordering; chain verification test |
| INV-4 | `nmcp-policy` precedence evaluation; conflict matrix tests |
| INV-5 | Typed state transitions; exhaustive match, illegal transition tests |
| INV-6 | Pull request template requires an ID; traceability matrix generated in CI |
| INV-7 | `rust-toolchain.toml`, committed lockfile, `cargo deny check` gate |
| INV-8 | CI brand gate step in the governance job; fragment-assembled pattern, required check |

## Amendment

These invariants change by pull request against this file, with the rationale in
the pull request body and an approving review from a `CODEOWNERS` owner. An
invariant is never suspended for a release.
