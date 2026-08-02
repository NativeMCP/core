## Summary

<!-- What changed and why. One paragraph. -->

## Traceability (INV-6)

<!-- Required. Cite the requirement, issue or invariant IDs this change serves.
     A change with no traceable driver does not merge. -->

- Closes #
- Satisfies:

## Invariant impact

<!-- Required. State the effect on each invariant this change touches, or
     "not touched". "Not touched" is a claim you are making, so check it. -->

| Invariant | Impact |
|---|---|
| INV-1 No Destructive Primitive | |
| INV-2 Root-Scoped Path Authority | |
| INV-3 Immutable Audit | |
| INV-4 Hierarchical Instruction Authority | |
| INV-5 Explicit State Machine | |
| INV-7 Reproducible Build | |

## Evidence

<!-- How a reviewer knows this works. Tests added, output, manual verification.
     "It compiles" is not evidence. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] `cargo deny check`

## Completeness

- [ ] No `TODO`, `todo!()`, `unimplemented!()`, stub or placeholder introduced
- [ ] Any gap left open is named below with a reason and an owner

<!-- Named gaps, if any: -->

## Rollback

<!-- How this is reverted if it turns out to be wrong. -->
