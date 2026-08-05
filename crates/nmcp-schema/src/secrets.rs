//! The resolved-secret channel carried on a call context.
//!
//! NMCP-SPEC-003 section 4.3, RATIFIED v1.1, reserves the field and states only that it is
//! private, that its accessor hands out no owned copy, and that it is empty for every call
//! with no schema-declared secret slot. NMCP-SPEC-002 owns what an entry is. G-4 records
//! that boundary so the two specifications do not both own the same field.

/// Secret material resolved for one call, on its way to the provider that performs the
/// injection.
///
/// This type is complete at zero entries, which is a different thing from unimplemented.
/// Everything NMCP-SPEC-003 decides about it is decided and expressed here: it is carried
/// by value on [`CallContext`](crate::CallContext), the field is private, and
/// [`CallContext::secrets`](crate::CallContext::secrets) hands out a borrow rather than an
/// owned copy, so material cannot be lifted out of the context and outlive the call it was
/// resolved for. What is deliberately not decided here is what an entry is: the resolution
/// stage and the lifetime rules belong to NMCP-SPEC-002, and a guess at them made on this
/// crate's own authority would be a second owner of the same field rather than a head start.
///
/// NMCP-SPEC-002 is now RATIFIED v1.0 and I-032 has landed the half of it that is a
/// vocabulary: [`SecretSlot`](crate::SecretSlot) and [`SecretRef`](crate::SecretRef) sit
/// beside this type and say what a slot and a reference are. They do not say what an entry
/// here is, and this type is unchanged, because an entry is resolved material and resolution
/// is I-033. That is the boundary rather than an oversight: a tool can declare a slot today
/// and the kernel can recognise one, and there is still nothing that opens a store.
///
/// It is empty for every call, and empty by construction rather than by omission. A call
/// whose tool declares no schema-declared secret slot has nothing to resolve, and a call whose
/// tool declares one has nothing to resolve it with until I-033 lands the store; that is every
/// call in this workspace either way. [`ResolvedSecrets::is_empty`] is therefore `true` for
/// every value of this type that can exist, which is a fact about the type's cardinality
/// rather than a body left unwritten, and the destructure in that method is what keeps the two
/// from being confused.
///
/// It exists now rather than when NMCP-SPEC-002 lands because section 4.3 freezes
/// `ToolProvider::call` at four parameters. The host does not spawn the child process,
/// `nmcp-exec` does, so material resolved in the kernel needs a way to travel and those
/// four parameters do not provide one. A fifth parameter added once implementors exist
/// inside and outside this workspace is a breaking change to every one of them. A field on
/// a type they already receive is not, and carrying it empty costs nothing.
///
/// Deliberately not `Copy`: a populated one will not be, and taking `Copy` away later is
/// itself a breaking change. `Debug` is derived on a type with nothing to print, because
/// [`CallContext`](crate::CallContext) derives `Debug` and is logged. Whether a populated
/// one may be printed at all is NMCP-SPEC-002's question, and it is named here rather than
/// answered.
#[derive(Debug, Clone, Default)]
pub struct ResolvedSecrets {}

impl ResolvedSecrets {
    /// Whether this carries no material.
    ///
    /// The destructure is load-bearing rather than decorative. It names every field there
    /// is, so on the day NMCP-SPEC-002 adds one this stops compiling, and whoever adds it
    /// answers the question here instead of inheriting a `true` that has quietly become
    /// false. That is the difference between a constant that is currently correct and a
    /// placeholder.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        let Self {} = self;
        true
    }
}

#[cfg(test)]
mod tests {
    // Tests assert on shapes, verdicts and JSON, where expect/indexing ARE the assertion:
    // a panic in a test is the failure signal, so the production rationale for the
    // workspace denies (availability plus an audit gap) does not apply. Scoped to the test
    // module, named in the PR.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::ResolvedSecrets;

    /// The type has one value and it carries nothing, so every route to one agrees. This
    /// says "complete at zero entries" out loud: the literal, `Default` and a clone are the
    /// only three ways to obtain one, and all three are empty.
    #[test]
    fn every_resolved_secrets_that_can_exist_is_empty() {
        let fresh = ResolvedSecrets::default();
        assert!(fresh.is_empty());
        assert!(fresh.clone().is_empty());
        assert!(ResolvedSecrets {}.is_empty());
    }
}
