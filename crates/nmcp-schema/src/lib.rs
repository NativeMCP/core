//! `nmcp-schema`
//!
//! Part of the NativeMCP `core` workspace. The governance invariants in
//! `docs/GOVERNANCE.md` are normative for every item in this crate.

/// Semantic version of this crate, taken from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate identity as it appears in audit records and capability manifests.
pub const COMPONENT: &str = "nmcp-schema";

/// Version of the tool-contract schema this build emits and accepts.
///
/// Independent of both the crate version and the MCP protocol revision:
/// the contract shape and the wire format change on different schedules,
/// and collapsing them into one number loses the ability to say which
/// one moved.
pub const CONTRACT_SCHEMA_VERSION: u32 = 1;

/// Returns `true` when a peer advertising `version` can be understood.
///
/// Backward compatible within a major version: this build reads any
/// contract at or below its own version and refuses anything newer
/// rather than guessing at fields it does not know.
#[must_use]
pub fn accepts_contract_version(version: u32) -> bool {
    version > 0 && version <= CONTRACT_SCHEMA_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_version_is_accepted() {
        assert!(accepts_contract_version(CONTRACT_SCHEMA_VERSION));
    }

    #[test]
    fn future_version_is_refused_not_guessed_at() {
        assert!(!accepts_contract_version(CONTRACT_SCHEMA_VERSION + 1));
    }

    #[test]
    fn zero_is_not_a_version() {
        assert!(!accepts_contract_version(0));
    }
}
