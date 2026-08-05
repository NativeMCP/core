//! The request lifecycle: the states a governed call passes through, and the guard that walks
//! them.
//!
//! NMCP-SPEC-003 section 4.6, RATIFIED v1.4. The third column of the ring order table names a
//! state after every stage, and those transitions are INV-5. The `Recorded -> Executed` edge is
//! INV-3 expressed as a graph property: there is no route to an effect that does not pass
//! through a durable audit record.
//!
//! Two things live here rather than one, and the split is deliberate. [`RequestState`] is the
//! enumeration, with [`RequestState::can_transition_to`] as the readable statement of the edge
//! set, and it is what the tests that grade INV-5 assert against. The guard types are the same
//! edge set expressed so that dispatch cannot get it wrong: one type per state, each advance
//! consuming the previous guard and returning the next, and an advance method present only
//! where the table has an edge. `guard_edges_are_exactly_the_predicate_edges` binds the two, so
//! the pair cannot drift into disagreeing about what is legal.
//!
//! Why both, rather than the predicate alone: a `bool` is advice. Nothing is obliged to call
//! `can_transition_to`, and through spec v1.3 nothing did, which is how this workspace shipped
//! four versions of an INV-5 claim that was a property of a type and not of the server. The
//! guard is what makes it a property of the server.
//!
//! Every advance takes `self` by value and reads nothing out of it, because a guard is
//! zero-sized and carries its state in its type. That is what `clippy::unused_self` objects to
//! and what each `impl` block below allows it for: the value is consumed for its linearity, and
//! the associated function the lint suggests would hand a later guard to a caller holding no
//! earlier one, which is the whole of what these types prevent.

use crate::ToolCallResult;

/// Lifecycle states of a served request.
///
/// INV-5: state is data with an enumerated transition set, not something
/// inferred from which fields happen to be populated. Every terminal
/// state is reached deliberately, including the rejected one.
///
/// This type lived in `nmcp-host` through NMCP-SPEC-003 v1.3 and moved here at v1.4. It is not
/// a visibility workaround: the request lifecycle is part of what every participant in a
/// governed call has to agree on, which is the definition of what this crate holds, exactly
/// like [`ToolAuthority`](crate::ToolAuthority) and [`CallContext`](crate::CallContext). It is
/// re-exported from `nmcp-host`, so `nmcp_host::RequestState` still resolves.
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
    /// Note that `Executed` is reachable only from `Recorded`. That edge is INV-3 expressed as
    /// a transition: there is no path to an effect that does not pass through a durable audit
    /// record.
    ///
    /// `Received -> Rejected` is the pre-authorization refusal edge, added by NMCP-SPEC-003
    /// RC-15. Ring stages 0 through 3 in section 4.6, the delete guard, resolution, profile and
    /// allowlist visibility, and upstream admission, all refuse before `Authorizing` is
    /// entered, so without this edge four of the ring's refusals had no legal state to move to.
    ///
    /// The edge is here because it is honest, not because it is convenient. A call the delete
    /// guard refused genuinely did not authorize: no permission was read, no root resolved, no
    /// grant consulted, and the registry was not asked whether the tool exists. The alternative
    /// that needs no new edge is to enter `Authorizing` at stage 0 so the existing
    /// `Authorizing -> Rejected` edge carries every refusal, and that alternative is worse than
    /// carrying no state at all: it would make every record of a pre-authorization refusal
    /// assert an authorization attempt that never happened, and a state that misdescribes what
    /// the server did is a worse audit artifact than an absent one. INV-5 asks for state that
    /// is data rather than inference, and data that is wrong buys nothing over inference.
    ///
    /// It is exactly one edge, and that is the point. `Received` still reaches neither
    /// `Recorded` nor `Executed`, so nothing about this widens the route to an effect; the edge
    /// added reaches a terminal refusal and stops there.
    ///
    /// `Recorded -> Rejected` is legal and no dispatch path takes it today, because nothing
    /// currently refuses after the intent record is durable. It is kept rather than deleted to
    /// tidy the guard, because NMCP-SPEC-002's stage 5b failure path is what will take it.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Received, Self::Authorizing | Self::Rejected)
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

    /// Every state, so a test can quantify over the whole enumeration rather than a list some
    /// author kept up to date by hand.
    ///
    /// Written as an array literal over named variants so adding a variant without adding it
    /// here is caught by `every_state_appears_in_all`, which destructures the enum.
    pub const ALL: [Self; 6] = [
        Self::Received,
        Self::Authorizing,
        Self::Recorded,
        Self::Executed,
        Self::Completed,
        Self::Rejected,
    ];
}

/// A request off the transport, before any stage has run. Ring stage 0 is next.
///
/// This is the only guard with a public constructor, because a walk has to start somewhere and
/// [`Router::dispatch`](../nmcp_router/struct.Router.html#method.dispatch) is where it starts.
/// The consequence, stated rather than hidden: nothing in the type system prevents a second
/// walk being started in the middle of a first one. What the types do prevent is reaching a
/// later state without having walked to it, which is the property the ring needs.
///
/// The full legal walk, which is also the paired positive test the `compile_fail` blocks below
/// depend on. `rustdoc` passes a `compile_fail` block on any compilation error, so a
/// `compile_fail` block alone would stay green if the type or the method were renamed out from
/// under it. This names every guard type and every advance method, so a rename turns the suite
/// red here rather than silently disarming twenty-nine assertions.
///
/// ```
/// use nmcp_schema::{
///     RequestAuthorizing, RequestCompleted, RequestExecuted, RequestReceived, RequestRecorded,
///     RequestRejected, RequestState, SettledRequest, ToolCallResult,
/// };
///
/// let received: RequestReceived = RequestReceived::new();
/// assert_eq!(received.state(), RequestState::Received);
///
/// // Stages 0 through 3 refuse from here: Received -> Rejected, RC-15.
/// let refused: RequestRejected = RequestReceived::new().rejected();
/// assert_eq!(refused.state(), RequestState::Rejected);
/// let settled: SettledRequest = refused.settle(ToolCallResult::ok(serde_json::json!({})));
/// let _: ToolCallResult = settled.into_inner();
///
/// // Stage 4 enters Authorizing, and refuses from there on a Denial.
/// let authorizing: RequestAuthorizing = RequestReceived::new().authorizing();
/// assert_eq!(authorizing.state(), RequestState::Authorizing);
/// let _: RequestRejected = RequestReceived::new().authorizing().rejected();
///
/// // Stage 6 records, and Recorded -> Rejected stays legal for stage 5b.
/// let recorded: RequestRecorded = authorizing.recorded();
/// assert_eq!(recorded.state(), RequestState::Recorded);
/// let _: RequestRejected = RequestReceived::new().authorizing().recorded().rejected();
///
/// // Stages 7 and 8.
/// let executed: RequestExecuted = recorded.executed();
/// assert_eq!(executed.state(), RequestState::Executed);
/// let completed: RequestCompleted = executed.completed();
/// assert_eq!(completed.state(), RequestState::Completed);
/// let _: SettledRequest = completed.settle(ToolCallResult::ok(serde_json::json!({})));
/// ```
///
/// Legal successors are [`RequestAuthorizing`] and [`RequestRejected`]. The three illegal
/// targets are absent from the type, one block each.
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new();
/// let _ = g.recorded();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new();
/// let _ = g.executed();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new();
/// let _ = g.completed();
/// ```
///
/// And `Received -> Received`: no advance method anywhere produces a [`RequestReceived`], which
/// is the same fact for all six sources and is asserted once per source.
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new();
/// let _ = g.received();
/// ```
#[derive(Debug)]
#[must_use = "a guard that is dropped is a ring stage that never reached a terminal state"]
pub struct RequestReceived {
    _seal: (),
}

// `clippy::unused_self` fires on every method below and is allowed on each `impl`, with the
// reason stated in the module doc's last paragraph: `self` is taken by value for its linearity
// rather than for its data. A guard is zero-sized, so nothing reads it; consuming it is the
// entire mechanism, and the associated function the lint suggests would let a stage advance
// without holding the guard it is advancing from, which is the property being bought.
#[allow(clippy::unused_self)]
impl RequestReceived {
    /// Start a walk. Ring stage 0 has not run yet.
    pub const fn new() -> Self {
        Self { _seal: () }
    }

    /// The state this guard holds. Takes `&self`: reading a state is not a transition, so it
    /// must not consume the guard that is mid-walk.
    #[must_use]
    pub const fn state(&self) -> RequestState {
        RequestState::Received
    }

    /// Stage 4: enter authorization.
    pub const fn authorizing(self) -> RequestAuthorizing {
        RequestAuthorizing { _seal: () }
    }

    /// Stages 0 through 3: refuse before authorization began (RC-15).
    pub const fn rejected(self) -> RequestRejected {
        RequestRejected { _seal: () }
    }
}

impl Default for RequestReceived {
    fn default() -> Self {
        Self::new()
    }
}

/// Stage 4 has been entered: the ring is resolving authority and roots.
///
/// Legal successors are [`RequestRecorded`], at stage 6, and [`RequestRejected`], which is
/// taken by a [`Denial`](crate::Denial) at stage 4 and by every stage 5 refusal.
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing();
/// let _ = g.authorizing();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing();
/// let _ = g.executed();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing();
/// let _ = g.completed();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing();
/// let _ = g.received();
/// ```
#[derive(Debug)]
#[must_use = "a guard that is dropped is a ring stage that never reached a terminal state"]
pub struct RequestAuthorizing {
    _seal: (),
}

#[allow(clippy::unused_self)]
impl RequestAuthorizing {
    /// The state this guard holds. Takes `&self`: reading a state is not a transition, so it
    /// must not consume the guard that is mid-walk.
    #[must_use]
    pub const fn state(&self) -> RequestState {
        RequestState::Authorizing
    }

    /// Stage 6: the intent record is written. INV-3's gate.
    pub const fn recorded(self) -> RequestRecorded {
        RequestRecorded { _seal: () }
    }

    /// Stage 4 on a `Denial`, or any stage 5 refusal.
    pub const fn rejected(self) -> RequestRejected {
        RequestRejected { _seal: () }
    }
}

/// Stage 6 is done: the intent record is durable, and only now may an effect run.
///
/// Legal successors are [`RequestExecuted`] and [`RequestRejected`]. The second is legal and
/// unused by dispatch today; NMCP-SPEC-002's stage 5b failure path is what will take it, and it
/// is kept for that rather than deleted to make this type tidier.
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded();
/// let _ = g.authorizing();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded();
/// let _ = g.recorded();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded();
/// let _ = g.completed();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded();
/// let _ = g.received();
/// ```
#[derive(Debug)]
#[must_use = "a guard that is dropped is a ring stage that never reached a terminal state"]
pub struct RequestRecorded {
    _seal: (),
}

#[allow(clippy::unused_self)]
impl RequestRecorded {
    /// The state this guard holds. Takes `&self`: reading a state is not a transition, so it
    /// must not consume the guard that is mid-walk.
    #[must_use]
    pub const fn state(&self) -> RequestState {
        RequestState::Recorded
    }

    /// Stage 7: the provider ran.
    pub const fn executed(self) -> RequestExecuted {
        RequestExecuted { _seal: () }
    }

    /// Reserved for stage 5b, per NMCP-SPEC-002. No dispatch path takes this edge today.
    pub const fn rejected(self) -> RequestRejected {
        RequestRejected { _seal: () }
    }
}

/// Stage 7 is done: the provider returned, whatever it returned.
///
/// The single legal successor is [`RequestCompleted`]. A provider that answers with an error is
/// still a call the ring executed and completed, so there is no `Executed -> Rejected` edge and
/// this type has no `rejected`: a refusal is something the ring decided, and by stage 7 the
/// ring has decided to allow.
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded().executed();
/// let _ = g.authorizing();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded().executed();
/// let _ = g.recorded();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded().executed();
/// let _ = g.executed();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded().executed();
/// let _ = g.rejected();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded().executed();
/// let _ = g.received();
/// ```
#[derive(Debug)]
#[must_use = "a guard that is dropped is a ring stage that never reached a terminal state"]
pub struct RequestExecuted {
    _seal: (),
}

#[allow(clippy::unused_self)]
impl RequestExecuted {
    /// The state this guard holds. Takes `&self`: reading a state is not a transition, so it
    /// must not consume the guard that is mid-walk.
    #[must_use]
    pub const fn state(&self) -> RequestState {
        RequestState::Executed
    }

    /// Stage 8: the outcome record is written and the response goes back.
    pub const fn completed(self) -> RequestCompleted {
        RequestCompleted { _seal: () }
    }
}

/// Terminal: refused, and audited like any other outcome.
///
/// No advance method exists, which is [`RequestState::is_terminal`] as a property of the type.
/// The only thing left to do is [`settle`](Self::settle) the result the caller sees.
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().rejected();
/// let _ = g.authorizing();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().rejected();
/// let _ = g.recorded();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().rejected();
/// let _ = g.executed();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().rejected();
/// let _ = g.completed();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().rejected();
/// let _ = g.rejected();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().rejected();
/// let _ = g.received();
/// ```
#[derive(Debug)]
#[must_use = "a terminal guard that is dropped is a ring exit that produced no settled result"]
pub struct RequestRejected {
    _seal: (),
}

#[allow(clippy::unused_self)]
impl RequestRejected {
    /// The state this guard holds. Takes `&self`: reading a state is not a transition, so it
    /// must not consume the guard that is mid-walk.
    #[must_use]
    pub const fn state(&self) -> RequestState {
        RequestState::Rejected
    }

    /// Hand back the refusal the caller sees, sealed so the ring's exit is provably terminal.
    pub fn settle(self, result: ToolCallResult) -> SettledRequest {
        SettledRequest { _seal: (), result }
    }
}

/// Terminal: the response is on its way back to the transport.
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded().executed().completed();
/// let _ = g.authorizing();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded().executed().completed();
/// let _ = g.recorded();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded().executed().completed();
/// let _ = g.executed();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded().executed().completed();
/// let _ = g.completed();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded().executed().completed();
/// let _ = g.rejected();
/// ```
///
/// ```compile_fail,E0599
/// let g = nmcp_schema::RequestReceived::new().authorizing().recorded().executed().completed();
/// let _ = g.received();
/// ```
#[derive(Debug)]
#[must_use = "a terminal guard that is dropped is a ring exit that produced no settled result"]
pub struct RequestCompleted {
    _seal: (),
}

#[allow(clippy::unused_self)]
impl RequestCompleted {
    /// The state this guard holds. Takes `&self`: reading a state is not a transition, so it
    /// must not consume the guard that is mid-walk.
    #[must_use]
    pub const fn state(&self) -> RequestState {
        RequestState::Completed
    }

    /// Hand back the response the caller sees, sealed so the ring's exit is provably terminal.
    pub fn settle(self, result: ToolCallResult) -> SettledRequest {
        SettledRequest { _seal: (), result }
    }
}

/// A [`ToolCallResult`] that reached a terminal lifecycle state before it was returned.
///
/// This is the piece that makes the walk unskippable rather than merely well-formed. The
/// private field means no other crate can build one, and the only constructors are
/// [`RequestRejected::settle`] and [`RequestCompleted::settle`]. A dispatch function whose
/// return type is `SettledRequest` therefore cannot exit on any path that did not walk from
/// [`RequestReceived`] to a terminal guard through methods that exist only where NMCP-SPEC-003
/// section 4.6 has an edge. Adding an early return that skips a stage is a compile error at the
/// `return`, not a defect a reviewer has to notice.
///
/// It carries the result untouched. Sealing the exit is the whole job: nothing here inspects,
/// rewrites or reorders what the ring decided, which is RC-22's no-behaviour-change line held
/// at the one point where a state machine would be most tempted to cross it.
#[derive(Debug)]
#[must_use = "the settled result is what the caller receives"]
pub struct SettledRequest {
    _seal: (),
    result: ToolCallResult,
}

impl SettledRequest {
    /// Unwrap the result for the transport.
    #[must_use]
    pub fn into_inner(self) -> ToolCallResult {
        self.result
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// The enumeration and the guard are two expressions of one edge set, so they are bound
    /// mechanically rather than by the author of each remembering the other.
    ///
    /// What this covers, measured by seeding each failure rather than reasoned about. Walking
    /// every advance and checking its `(before, after)` pair against `can_transition_to` catches
    /// a predicate that stops calling a walked edge legal: deleting RC-15's
    /// `Received -> Rejected` from the predicate fails here naming that pair. Comparing the
    /// counts catches a predicate edge with no advance method, which the walk alone cannot see.
    ///
    /// What it does not cover, and what does. An advance method added for a transition the
    /// predicate calls illegal changes neither the walked list nor either count, so this test
    /// stays green; the `compile_fail` block for that transition is what goes red, and seeding
    /// a `Received -> Recorded` advance was checked to do exactly that. The two instruments are
    /// complementary rather than redundant, which is why both are here.
    #[test]
    fn guard_edges_are_exactly_the_predicate_edges() {
        let walked = [
            (
                RequestReceived::new().state(),
                RequestReceived::new().authorizing().state(),
            ),
            (
                RequestReceived::new().state(),
                RequestReceived::new().rejected().state(),
            ),
            (
                RequestReceived::new().authorizing().state(),
                RequestReceived::new().authorizing().recorded().state(),
            ),
            (
                RequestReceived::new().authorizing().state(),
                RequestReceived::new().authorizing().rejected().state(),
            ),
            (
                RequestReceived::new().authorizing().recorded().state(),
                RequestReceived::new()
                    .authorizing()
                    .recorded()
                    .executed()
                    .state(),
            ),
            (
                RequestReceived::new().authorizing().recorded().state(),
                RequestReceived::new()
                    .authorizing()
                    .recorded()
                    .rejected()
                    .state(),
            ),
            (
                RequestReceived::new()
                    .authorizing()
                    .recorded()
                    .executed()
                    .state(),
                RequestReceived::new()
                    .authorizing()
                    .recorded()
                    .executed()
                    .completed()
                    .state(),
            ),
        ];
        for (from, to) in walked {
            assert!(
                from.can_transition_to(to),
                "the guard offers {from:?} -> {to:?}, which the predicate calls illegal"
            );
        }

        let legal = RequestState::ALL
            .iter()
            .flat_map(|from| RequestState::ALL.iter().map(move |to| (*from, *to)))
            .filter(|(from, to)| from.can_transition_to(*to))
            .count();
        assert_eq!(
            legal,
            walked.len(),
            "the predicate has {legal} edges and the guard offers {}; every predicate edge needs \
             an advance method or the guard is narrower than INV-5 says the machine is",
            walked.len()
        );
    }

    /// `ALL` is a hand-written list, so this is what stops it drifting from the enum.
    ///
    /// The destructure is the mechanism: adding a variant makes this match non-exhaustive and
    /// the crate stops compiling, which is a louder failure than a test that counts to six.
    #[test]
    fn every_state_appears_in_all() {
        for state in RequestState::ALL {
            match state {
                RequestState::Received
                | RequestState::Authorizing
                | RequestState::Recorded
                | RequestState::Executed
                | RequestState::Completed
                | RequestState::Rejected => {}
            }
        }
        assert_eq!(RequestState::ALL.len(), 6);
        let mut seen = RequestState::ALL.to_vec();
        seen.sort_by_key(|state| format!("{state:?}"));
        seen.dedup();
        assert_eq!(seen.len(), 6, "ALL lists a state twice");
    }

    /// The seal, from the outside. A settled result is the only thing a ring exit can produce,
    /// and the only way to produce one is to have reached a terminal guard.
    #[test]
    fn a_settled_result_carries_the_result_untouched() {
        let result = ToolCallResult::ok(serde_json::json!({"answer": 41}));
        let expected = result.content.clone();
        let settled = RequestReceived::new().rejected().settle(result);
        assert_eq!(settled.into_inner().content, expected);
    }

    /// Both terminal guards settle, and neither offers anything else, which is
    /// [`RequestState::is_terminal`] and the type agreeing.
    #[test]
    fn both_terminals_are_terminal_in_the_enumeration_too() {
        let rejected = RequestReceived::new().rejected();
        let completed = RequestReceived::new()
            .authorizing()
            .recorded()
            .executed()
            .completed();
        assert!(rejected.state().is_terminal());
        assert!(completed.state().is_terminal());
        for state in RequestState::ALL {
            assert!(
                !rejected.state().can_transition_to(state),
                "Rejected is terminal, so {state:?} is unreachable from it"
            );
            assert!(!completed.state().can_transition_to(state));
        }
    }
}
