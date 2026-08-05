//! The resolved-secret channel carried on a call context.
//!
//! NMCP-SPEC-003 section 4.3, RATIFIED v1.1, reserves the field and states only that it is
//! private, that its accessor hands out no owned copy, and that it is empty for every call
//! with no schema-declared secret slot. NMCP-SPEC-002 owns what an entry is, and I-034 is
//! where it says: an entry is one slot's resolved material, sealed in [`SealedSecret`] and
//! tagged with the [`InjectionModality`](crate::InjectionModality) the tool's contract
//! declared, so the provider that performs the injection knows where the value goes without
//! being told anything else.
//!
//! ## Why a second sealed type exists
//!
//! `nmcp-secrets` already has `Sealed<T>`, and this module deliberately does not use it. It
//! cannot: `nmcp-secrets` depends on this crate for the SB-2 grammar, so this crate
//! depending back on `nmcp-secrets` is a dependency cycle, the exact shape RC-D1 exists to
//! prevent and the same edge direction that already forced the v1.1 relocation of binding
//! evaluation. The carrier therefore lives here, with the same contract `Sealed<T>` has
//! (private bytes, zeroize on a real `Drop`, one scoped read path, manual `Debug` printing
//! `[sealed]`, no serde, no `Display`), and the ring converts one into the other at stage
//! 5b through the scoped-exposure API. Two sealed types is a known cost, paid for the
//! dependency direction; if the duplication proves annoying, `nmcp-secrets` may adopt this
//! carrier at a later issue, which is the cheap direction of the edge.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use zeroize::Zeroize;

use crate::secret_ref::InjectionModality;

/// The buffer behind [`SealedSecret`]: erased when the last handle drops.
struct SealedBytes(Vec<u8>);

impl Drop for SealedBytes {
    /// A real `Drop`, not a `Zeroize` bound with nothing calling it (SB-1).
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Secret material resolved for one call, sealed against accidental escape.
///
/// The contract is `nmcp-secrets`' `Sealed<T>` restated where the dependency direction can
/// reach it (see the module documentation for why that is a second type rather than a
/// reuse). The bytes are private, so they cannot be read by field access, printed by a
/// derived `Debug`, or matched out by a pattern; the one read path is
/// [`SealedSecret::with_exposed`], so `grep` enumerates every exposure site; and the buffer
/// is zeroized by a real `Drop` when the last handle goes away.
///
/// `Clone` exists and `Sealed<T>` deliberately has no `Clone`, which deserves a reason:
/// [`CallContext`](crate::CallContext) derives `Clone` and is cloned by providers and
/// transports that hold one, so a carrier field without `Clone` would be a breaking change
/// to a type NMCP-SPEC-003 section 4.3 moved field for field. The clone is an [`Arc`]
/// share, not a second allocation of material, so however many handles a call fans out,
/// there is exactly one plaintext buffer and it is erased once, when the last handle drops
/// at the end of the call that resolved it. That is the SB-5 lifetime with shared handles
/// rather than a copy per holder.
///
/// What is deliberately absent, same list and same reasons as `Sealed<T>`: no `Display`, no
/// serde in either direction (a context is never serialized, and material must not become
/// serializable by riding in one), no `AsRef`, no `Deref`, no `PartialEq` (a derived
/// comparison is variable-time over the bytes, which is a timing oracle for a prefix).
///
/// ```
/// use nmcp_schema::SealedSecret;
///
/// let sealed = SealedSecret::new(vec![1_u8, 2, 3]);
/// assert_eq!(sealed.with_exposed(<[u8]>::len), 3);
/// assert_eq!(format!("{sealed:?}"), "[sealed]");
/// ```
///
/// The `Display` denial is pinned as a compile failure, paired with the positive block
/// above so a rename cannot silently disarm it (`rustdoc` passes `compile_fail` on any
/// error):
///
/// ```compile_fail,E0277
/// let sealed = nmcp_schema::SealedSecret::new(vec![1_u8, 2, 3]);
/// println!("{sealed}");
/// ```
pub struct SealedSecret(Arc<SealedBytes>);

impl SealedSecret {
    /// Take ownership of material.
    ///
    /// Public because the ring in `nmcp-router` builds one at stage 5b from the store's
    /// sealed value, and a private constructor would leave the channel with nothing that
    /// can fill it. Constructing one grants nothing: the unforgeability story for secret
    /// use is the binding grant and the sealed store in `nmcp-secrets`, not this wrapper,
    /// which only keeps the bytes from escaping by accident once they are resolved.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Arc::new(SealedBytes(bytes)))
    }

    /// Run `f` with a borrow of the material.
    ///
    /// A scoped closure rather than an accessor returning a slice: a reference handed out
    /// is a reference that can be stored, and the point of the type is that the exposure
    /// surface is enumerable. The borrow cannot outlive the call, so returning the
    /// reference itself does not type-check.
    pub fn with_exposed<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.0.0)
    }
}

impl Clone for SealedSecret {
    /// Shares the one sealed buffer; no material is duplicated. See the type documentation
    /// for why `Clone` exists here and not on `nmcp-secrets`' `Sealed<T>`.
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl fmt::Debug for SealedSecret {
    /// `[sealed]` and nothing else: not the type name, not the length, not a handle count.
    /// SB-1 forbids a value derived from material as much as the value, and a length is
    /// one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[sealed]")
    }
}

/// One resolved slot: where the value goes, and the value itself.
#[derive(Debug, Clone)]
struct ResolvedEntry {
    /// The injection modality the tool's contract declared for the slot.
    modality: InjectionModality,
    /// The material, sealed.
    value: SealedSecret,
}

/// Secret material resolved for one call, keyed by the declared slot argument it was
/// resolved for, on its way to the provider that performs the injection.
///
/// Populated by ring stage 5b (NMCP-SPEC-002 SB-5) and by nothing else in production:
/// resolution happens after the approval gate and before the audit intent record, and the
/// material reaches the provider through the private `secrets` field on
/// [`CallContext`](crate::CallContext), whose accessor hands out a borrow rather than an
/// owned copy. Empty for every call whose tool declares no `secret_ref` slot, exactly as
/// NMCP-SPEC-003 section 4.3 states.
///
/// [`ResolvedSecrets::insert`] is public, which is a decision rather than an oversight: the
/// ring lives in `nmcp-router` and this crate cannot name it, so there is no visibility
/// that admits the ring and nothing else. The unforgeability story for secret use is not
/// this struct; it is the binding grant and the sealed store in `nmcp-secrets`, which are
/// the only path to material. A caller assembling one of these by hand has only bytes it
/// already held, and a provider is handed the context by the ring, which built it.
///
/// Entries are keyed by the slot's argument name because that is the one name the caller,
/// the contract and the kernel all share; the modality carries the injection-side name (the
/// environment variable for `env`, the header for `header`). The map is modality-tagged now
/// so the `header` modality (I-020, `nmcp-gateway`) attaches without touching this type
/// again.
#[derive(Debug, Clone, Default)]
pub struct ResolvedSecrets {
    entries: BTreeMap<String, ResolvedEntry>,
}

impl ResolvedSecrets {
    /// Whether this carries no material.
    ///
    /// `true` for every call whose tool declares no slot, and no longer `true` by
    /// construction: I-032's "complete at zero entries" destructure did its job, stopped
    /// compiling when the entries arrived, and the question it guarded is answered by the
    /// module documentation instead of inherited silently.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many slots resolved for this call.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Record one resolved slot.
    ///
    /// Called by the ring at stage 5b, once per declared slot whose argument carried a
    /// reference. A second insert under one slot argument replaces the first, which cannot
    /// happen from the ring (a schema object has one property per name) and is the least
    /// surprising behaviour for anyone else.
    pub fn insert(
        &mut self,
        slot_arg: impl Into<String>,
        modality: InjectionModality,
        value: SealedSecret,
    ) {
        self.entries
            .insert(slot_arg.into(), ResolvedEntry { modality, value });
    }

    /// The resolved value and declared modality for one slot argument, if that slot
    /// resolved.
    #[must_use]
    pub fn get(&self, slot_arg: &str) -> Option<(&InjectionModality, &SealedSecret)> {
        self.entries
            .get(slot_arg)
            .map(|entry| (&entry.modality, &entry.value))
    }

    /// Every resolved slot, in slot-argument order: `(slot argument, modality, value)`.
    ///
    /// Borrows, never owned copies, matching the accessor rule NMCP-SPEC-003 section 4.3
    /// fixes for the context field this type rides on.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &InjectionModality, &SealedSecret)> {
        self.entries
            .iter()
            .map(|(arg, entry)| (arg.as_str(), &entry.modality, &entry.value))
    }

    /// The `env`-modality entries as `(variable name, value)` pairs, in slot order.
    ///
    /// The shape `nmcp-exec` injects from (SB-4): the variable name is the contract's, not
    /// the caller's, because the modality was parsed out of the tool's own schema
    /// annotation and there is no caller input in it (SB-A2).
    pub fn env_entries(&self) -> impl Iterator<Item = (&str, &SealedSecret)> {
        self.entries
            .values()
            .filter_map(|entry| match &entry.modality {
                InjectionModality::Env { var } => Some((var.as_str(), &entry.value)),
                InjectionModality::Header { .. } => None,
            })
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
    use super::{ResolvedSecrets, SealedSecret};
    use crate::secret_ref::InjectionModality;

    /// Distinctive material with no English substring, so the leak assertions below cannot
    /// collide with legitimate prose such as the word "sealed".
    const MATERIAL: &[u8] = b"qx7ve-2wkzn-8rjt4-pm9hd";

    fn resolved_env(var: &str) -> ResolvedSecrets {
        let mut resolved = ResolvedSecrets::default();
        resolved.insert(
            "credential",
            InjectionModality::Env {
                var: var.to_string(),
            },
            SealedSecret::new(MATERIAL.to_vec()),
        );
        resolved
    }

    #[test]
    fn a_fresh_channel_is_empty_and_a_populated_one_is_not() {
        let fresh = ResolvedSecrets::default();
        assert!(fresh.is_empty());
        assert_eq!(fresh.len(), 0);
        assert!(fresh.get("credential").is_none());

        let populated = resolved_env("DATABASE_URL");
        assert!(!populated.is_empty());
        assert_eq!(populated.len(), 1);
    }

    #[test]
    fn the_entry_reads_back_by_slot_with_its_declared_modality() {
        let resolved = resolved_env("DATABASE_URL");
        let (modality, value) = resolved.get("credential").expect("the slot resolved");
        assert_eq!(
            modality,
            &InjectionModality::Env {
                var: "DATABASE_URL".to_string()
            }
        );
        assert_eq!(value.with_exposed(<[u8]>::to_vec), MATERIAL);

        let listed: Vec<&str> = resolved.iter().map(|(arg, _, _)| arg).collect();
        assert_eq!(listed, vec!["credential"]);
    }

    /// The shape `nmcp-exec` injects from: env entries come back as (variable, value) and a
    /// header entry does not ride along in them.
    #[test]
    fn env_entries_carry_the_contract_variable_and_skip_header_slots() {
        let mut resolved = resolved_env("DATABASE_URL");
        resolved.insert(
            "bearer",
            InjectionModality::Header {
                name: "Authorization".to_string(),
            },
            SealedSecret::new(b"h-9qz2-vk7x".to_vec()),
        );
        let env: Vec<&str> = resolved.env_entries().map(|(var, _)| var).collect();
        assert_eq!(env, vec!["DATABASE_URL"]);
        assert_eq!(resolved.len(), 2);
    }

    /// SB-1 on the carrier itself, and on the containers a log line would actually format:
    /// no byte window of the material appears in any `Debug` form, and no length either.
    #[test]
    fn debug_prints_the_marker_and_nothing_about_the_value() {
        let sealed = SealedSecret::new(MATERIAL.to_vec());
        assert_eq!(format!("{sealed:?}"), "[sealed]");

        let resolved = resolved_env("DATABASE_URL");
        let rendered = format!("{resolved:?}");
        assert!(rendered.contains("[sealed]"));
        let material = String::from_utf8_lossy(MATERIAL).to_string();
        assert!(!rendered.contains(&material));
        // MATERIAL is 23 bytes; a Debug that printed the length would leak a
        // material-derived value (SB-1).
        assert!(!rendered.contains("23"));
    }

    /// A clone shares the one sealed buffer rather than duplicating material: both handles
    /// expose the same bytes, and dropping one leaves the other whole, which is the Arc
    /// sharing doing what the type documentation claims. The `Display` denial and the
    /// scoped read path are pinned by the doc tests on [`SealedSecret`] itself, where
    /// `rustdoc` builds them as external crates, which is the population the seal is aimed
    /// at.
    #[test]
    fn a_clone_is_a_second_handle_not_a_second_buffer() {
        let first = SealedSecret::new(MATERIAL.to_vec());
        let second = first.clone();
        drop(first);
        assert_eq!(second.with_exposed(<[u8]>::to_vec), MATERIAL);
    }
}
