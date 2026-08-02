//! `nmcp-audit`
//!
//! Part of the NativeMCP `core` workspace. The governance invariants in
//! `docs/GOVERNANCE.md` are normative for every item in this crate.

/// Semantic version of this crate, taken from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate identity as it appears in audit records and capability manifests.
pub const COMPONENT: &str = "nmcp-audit";

/// Genesis link of the audit hash chain.
///
/// INV-3: every record commits to the digest of its predecessor, so an
/// entry cannot be removed or edited without breaking the chain. The
/// first record commits to this fixed value, which is what gives the
/// chain a verifiable beginning rather than an arbitrary one.
pub const CHAIN_GENESIS: [u8; 32] = [0u8; 32];

/// Ordering guarantee the audit sink must satisfy.
///
/// INV-3 requires the record to be durable *before* the effect it
/// describes becomes observable. A sink that buffers and flushes later
/// loses exactly the records that matter when a server dies mid-effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOrdering {
    /// Record is durable before the effect is applied. The only
    /// ordering this workspace permits.
    BeforeEffect,
    /// Record is written after the effect. Rejected by policy.
    AfterEffect,
}

impl WriteOrdering {
    /// Returns `true` when this ordering satisfies INV-3.
    #[must_use]
    pub fn satisfies_invariant(self) -> bool {
        matches!(self, Self::BeforeEffect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_link_is_thirty_two_zero_bytes() {
        assert_eq!(CHAIN_GENESIS.len(), 32);
        assert!(CHAIN_GENESIS.iter().all(|b| *b == 0));
    }

    #[test]
    fn only_write_before_effect_satisfies_inv3() {
        assert!(WriteOrdering::BeforeEffect.satisfies_invariant());
        assert!(!WriteOrdering::AfterEffect.satisfies_invariant());
    }
}
