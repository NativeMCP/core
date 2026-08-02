//! `nmcp-proto`
//!
//! Part of the NativeMCP `core` workspace. The governance invariants in
//! `docs/GOVERNANCE.md` are normative for every item in this crate.

/// Semantic version of this crate, taken from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate identity as it appears in audit records and capability manifests.
pub const COMPONENT: &str = "nmcp-proto";

/// MCP specification revision this workspace targets.
///
/// Pinned deliberately. The protocol revision is a contract, not a
/// runtime negotiation detail: a server that silently accepts an
/// unexpected revision is a server whose behaviour is undefined. Moving
/// this constant is a reviewed change with a migration note.
pub const PROTOCOL_REVISION: &str = "2026-07-28";

/// HTTP header carrying the protocol revision on every request.
pub const HEADER_PROTOCOL_VERSION: &str = "MCP-Protocol-Version";

/// HTTP header carrying the JSON-RPC method, so a gateway can route
/// without parsing the body.
pub const HEADER_METHOD: &str = "Mcp-Method";

/// HTTP header carrying the tool, prompt or resource name.
pub const HEADER_NAME: &str = "Mcp-Name";

/// Returns `true` when `revision` is a revision this build implements.
///
/// Exactly one revision is supported per build. Multi-revision support is
/// a named gap, not an omission: accepting two wire contracts at once
/// doubles the policy surface and is not taken on without a written
/// decision record.
#[must_use]
pub fn supports_revision(revision: &str) -> bool {
    revision == PROTOCOL_REVISION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_revision_is_supported() {
        assert!(supports_revision(PROTOCOL_REVISION));
    }

    #[test]
    fn foreign_revision_is_rejected() {
        assert!(!supports_revision("2025-06-18"));
        assert!(!supports_revision(""));
    }

    #[test]
    fn transport_headers_are_canonical() {
        assert_eq!(HEADER_PROTOCOL_VERSION, "MCP-Protocol-Version");
        assert_eq!(HEADER_METHOD, "Mcp-Method");
        assert_eq!(HEADER_NAME, "Mcp-Name");
    }
}
