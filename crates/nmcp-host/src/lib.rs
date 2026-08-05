//! `nmcp-host`
//!
//! Part of the NativeMCP `core` workspace. The governance invariants in
//! `docs/GOVERNANCE.md` are normative for every item in this crate.
//!
//! ## The tool registry
//!
//! NMCP-SPEC-003 section 4.4, RATIFIED v1.1, splits the registry in two: the `ToolRegistry`
//! trait lives in `nmcp-schema` where every provider can see it, and [`IndexedToolRegistry`]
//! implements it here because the kernel owns dispatch and owns INV-1.
//!
//! I-047c landed it unwired; I-047d put the ring on it. `nmcp_router::Router` holds an
//! `Arc<dyn ToolRegistry>` and resolves, authorizes and lists through it, and the compiled-in
//! policy table the ring used to consult is deleted. That had to be one change: dispatch cannot
//! hand a provider a `GrantedAuthority` until it produces one, and it cannot produce one until
//! it reads the declaration this index holds.

mod registry;

pub use registry::IndexedToolRegistry;

/// Semantic version of this crate, taken from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate identity as it appears in audit records and capability manifests.
pub const COMPONENT: &str = "nmcp-host";

/// Lifecycle states of a served request.
///
/// INV-5: state is data with an enumerated transition set, not something
/// inferred from which fields happen to be populated. Every terminal
/// state is reached deliberately, including the rejected one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestState {
    /// Received off the transport, nothing evaluated yet.
    Received,
    /// Passed to the policy engine for authority and root resolution.
    Authorizing,
    /// Audit record written and durable. INV-3 gate.
    Recorded,
    /// Effect applied.
    Executed,
    /// Response handed back to the transport. Terminal.
    Completed,
    /// Refused by policy. Terminal, and audited like any other outcome.
    Rejected,
}

impl RequestState {
    /// Returns `true` when `next` is a legal successor of `self`.
    ///
    /// Note that `Executed` is reachable only from `Recorded`. That edge
    /// is INV-3 expressed as a transition: there is no path to an effect
    /// that does not pass through a durable audit record.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Received, Self::Authorizing)
                | (Self::Authorizing, Self::Recorded | Self::Rejected)
                | (Self::Recorded, Self::Executed | Self::Rejected)
                | (Self::Executed, Self::Completed)
        )
    }

    /// Returns `true` when no further transition is legal.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_is_the_only_route_to_completion() {
        let path = [
            RequestState::Received,
            RequestState::Authorizing,
            RequestState::Recorded,
            RequestState::Executed,
            RequestState::Completed,
        ];
        // Pairwise by zip rather than by index: `indexing_slicing` is
        // denied workspace-wide, including in tests.
        for (from, to) in path.iter().zip(path.iter().skip(1)) {
            assert!(
                from.can_transition_to(*to),
                "{from:?} -> {to:?} must be legal"
            );
        }
    }

    #[test]
    fn no_effect_without_a_durable_audit_record() {
        // INV-3 as a graph property: Executed has exactly one predecessor.
        assert!(!RequestState::Received.can_transition_to(RequestState::Executed));
        assert!(!RequestState::Authorizing.can_transition_to(RequestState::Executed));
        assert!(RequestState::Recorded.can_transition_to(RequestState::Executed));
    }

    #[test]
    fn terminal_states_accept_no_successor() {
        for terminal in [RequestState::Completed, RequestState::Rejected] {
            assert!(terminal.is_terminal());
            for next in [
                RequestState::Received,
                RequestState::Authorizing,
                RequestState::Recorded,
                RequestState::Executed,
                RequestState::Completed,
                RequestState::Rejected,
            ] {
                assert!(!terminal.can_transition_to(next));
            }
        }
    }

    #[test]
    fn rejection_is_reachable_before_and_after_the_audit_gate() {
        assert!(RequestState::Authorizing.can_transition_to(RequestState::Rejected));
        assert!(RequestState::Recorded.can_transition_to(RequestState::Rejected));
    }
}
