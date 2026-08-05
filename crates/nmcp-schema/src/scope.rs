//! The memory scope label carried on a call context.
//!
//! NMCP-SPEC-003 RC-2.

use serde::{Deserialize, Serialize};

/// A memory scope label kept for router and audit compatibility.
///
/// Defined here rather than in `nmcp-memory`, and re-exported from there, because this
/// move is what makes RC-D1 true rather than merely stated. The kernel needed the type on
/// its call context, so the kernel had to depend on the memory crate, so the memory crate
/// could not depend on the kernel to ship its own provider: the provider had to live in
/// the server crate instead. That is the cycle. A newtype over a `String` with no tie to
/// storage does not belong on the storage side of it, and moving it here lets
/// `nmcp-memory` depend on this crate and own its provider, which is where that provider
/// always belonged.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemoryScope(pub String);

impl MemoryScope {
    /// A root-anchored scope.
    #[must_use]
    pub fn root(id: impl Into<String>) -> Self {
        Self(format!("root:{}", id.into()))
    }
    /// A session-anchored scope.
    #[must_use]
    pub fn session(id: impl Into<String>) -> Self {
        Self(format!("session:{}", id.into()))
    }
    /// A named scope, used verbatim.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

impl std::fmt::Display for MemoryScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
