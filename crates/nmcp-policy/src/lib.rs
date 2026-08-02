//! `nmcp-policy`
//!
//! Part of the NativeMCP `core` workspace. The governance invariants in
//! `docs/GOVERNANCE.md` are normative for every item in this crate.

/// Semantic version of this crate, taken from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate identity as it appears in audit records and capability manifests.
pub const COMPONENT: &str = "nmcp-policy";

/// Tiers of instruction authority, ordered least to most authoritative.
///
/// INV-4: a lower tier may narrow what a higher tier permits and may never
/// widen it. Encoding the ordering in the type system is what makes that
/// a property of the program rather than a convention reviewers enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Authority {
    /// Supplied by the calling client on a per-request basis.
    ClientRequest,
    /// Compiled-in defaults shipped with the server.
    ServerDefault,
    /// Operator-controlled policy file. Highest authority.
    OperatorPolicy,
}

impl Authority {
    /// Returns `true` when `self` may override a rule set by `other`.
    ///
    /// Strictly greater, never equal: two rules at the same tier are a
    /// configuration conflict for the caller to resolve, not something
    /// this crate silently picks a winner for.
    #[must_use]
    pub fn overrides(self, other: Self) -> bool {
        self > other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_policy_outranks_every_other_tier() {
        assert!(Authority::OperatorPolicy.overrides(Authority::ServerDefault));
        assert!(Authority::OperatorPolicy.overrides(Authority::ClientRequest));
    }

    #[test]
    fn client_request_never_widens_a_higher_tier() {
        assert!(!Authority::ClientRequest.overrides(Authority::ServerDefault));
        assert!(!Authority::ClientRequest.overrides(Authority::OperatorPolicy));
    }

    #[test]
    fn same_tier_is_a_conflict_not_an_override() {
        assert!(!Authority::ServerDefault.overrides(Authority::ServerDefault));
    }
}
