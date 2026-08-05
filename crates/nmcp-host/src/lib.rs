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
//!
//! ## The request state machine
//!
//! [`RequestState`] enumerates the request lifecycle and the transitions between its states,
//! which is INV-5's "states are data" written as a type rather than inferred from which fields
//! happen to be populated. NMCP-SPEC-003 RC-15 adds the `Received -> Rejected` edge, because
//! ring stages 0 through 3 in section 4.6 refuse before `Authorizing` is entered and had no
//! legal state to move to.
//!
//! The type is defined in `nmcp-schema` and re-exported here, so `nmcp_host::RequestState`
//! still resolves and the transition tests below are the ones this crate always had. I-049 set
//! out to wire it into dispatch and found it could not be done from here: dispatch is in
//! `nmcp-router`, and `nmcp-router` cannot see this crate without inverting the
//! `nmcp-host -> nmcp-router` edge RC-D1 declares and creating the cycle at I-031 that
//! NMCP-SPEC-003 exists to prevent. That was escalated rather than decided in code, and it
//! produced v1.4: the lifecycle is part of the contract every participant in a governed call
//! must agree on, so it lives with the rest of the contract, and `nmcp-host` remains where the
//! ring is composed.
//!
//! What v1.4 also names is worse than a placement question and is recorded here because this
//! crate is where it was shipped: through v1.3 the transitions were correct, tested and inert.
//! [`RequestState::can_transition_to`] returns a `bool` that nothing was obliged to call and
//! nothing called, so INV-5 was a claim about a type rather than about the server.
//! `nmcp_schema::SettledRequest` and the guard types beside it are what closed that, and
//! `nmcp_router::Router::dispatch` walks them (RC-22).

mod registry;

pub use nmcp_schema::RequestState;
pub use registry::IndexedToolRegistry;

/// Semantic version of this crate, taken from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate identity as it appears in audit records and capability manifests.
pub const COMPONENT: &str = "nmcp-host";

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

    /// RC-15, and the whole of it: one edge added, and the rest of the row unchanged.
    ///
    /// The two illegal transitions named here are named because they are the ones that would
    /// matter. `Received -> Recorded` would let a refusal claim a durable intent record that
    /// was never written, and `Received -> Executed` is the INV-3 gate itself. The value of
    /// the new edge is that it is the only one, so this asserts the whole `Received` row
    /// rather than the single addition.
    #[test]
    fn a_pre_authorization_refusal_has_a_state_to_move_to() {
        assert!(
            RequestState::Received.can_transition_to(RequestState::Rejected),
            "ring stages 0 through 3 refuse before Authorizing is entered"
        );
        assert!(
            !RequestState::Received.can_transition_to(RequestState::Recorded),
            "a refusal never wrote an intent record, so it cannot claim one"
        );
        assert!(
            !RequestState::Received.can_transition_to(RequestState::Executed),
            "INV-3: the only predecessor of Executed is Recorded"
        );
        // The rest of the row, so "exactly one edge added" is asserted rather than described.
        assert!(RequestState::Received.can_transition_to(RequestState::Authorizing));
        assert!(!RequestState::Received.can_transition_to(RequestState::Received));
        assert!(!RequestState::Received.can_transition_to(RequestState::Completed));
    }
}
