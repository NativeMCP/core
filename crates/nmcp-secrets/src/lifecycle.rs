//! The key lifecycle: the states a stored version passes through, and the guard that walks
//! them.
//!
//! NMCP-SPEC-002 SB-14, RATIFIED v1.0, and INV-5. The state set and its edges are normative;
//! the rotation overlap window and its default are operator decision 3 in section 8.
//!
//! ## Why an enumeration and a guarded transition rather than a typestate
//!
//! The workspace precedent is `nmcp_schema::lifecycle`, landed at I-049, which is a
//! `RequestState` enumeration with `can_transition_to` as the readable statement of the edge
//! set, plus one zero-sized guard type per state so that dispatch cannot get the walk wrong.
//! The shape here is deliberately the first half of that and deliberately not the second, and
//! the reason is that these two lifecycles differ in the one property the typestate depends on.
//!
//! A request lifecycle is walked once, forwards, inside one call, in memory. A guard can be
//! consumed by each stage because there is a stack frame holding it from `Received` to
//! `Completed`. A key lifecycle is **persisted**. Its state is written to a file, survives the
//! process, and is read back by a later process that holds no guard from the transition that
//! produced it. Deserialising a typestate means writing a function that hands out a
//! `KeyActive` on the strength of some bytes, and that function is exactly the forging
//! constructor the typestate exists to prevent: the linearity would be reintroduced at the one
//! place it is not enforceable. Worse, the state has to be *matched on* at resolution to decide
//! whether this version answers, and a typestate cannot be matched on, so the store would carry
//! an enumeration beside the guards anyway and the two could disagree.
//!
//! So the property is bought a different way, and the way matters. In `nmcp-schema` the
//! predicate alone is advice: `RequestState` is a public enum with public variants and nothing
//! is obliged to consult `can_transition_to`, which is why the guards exist. Here the state is
//! a private field of a private record inside [`SealedStore`](crate::SealedStore), and
//! [`KeyLifecycle::advance`] is the only function in the crate that writes it. There is no
//! public constructor for a version record and no setter, so a caller cannot reach the field to
//! set it without going through the check, and an illegal transition is a returned
//! [`IllegalTransition`] rather than a `false` somebody may ignore. Encapsulation replaces
//! linearity because linearity is what the persistence broke.
//!
//! ## Rotation is not revocation
//!
//! The two look alike and behave oppositely, which is why they are separate edges. Rotation is
//! the benign case: the operator replaces a value on schedule, the new version becomes
//! [`KeyState::Active`], and the prior one becomes [`KeyState::Superseded`] and keeps resolving
//! for a bounded window so calls already in flight and durable jobs that resume do not fail in
//! a burst. After the window it is [`KeyState::Retained`]: usable never, restorable by the
//! operator. Revocation is the hostile case: [`KeyState::Quarantined`] is immediate, has no
//! window, and in-flight calls fail closed, which is the entire point of revoking.

use serde::{Deserialize, Serialize};

/// The lifecycle state of one stored version of one secret.
///
/// INV-5: state is data with an enumerated transition set, not something inferred from which
/// fields happen to be populated. The state is per version rather than per key because rotation
/// leaves two versions of one key in different states at the same time, which a per-key state
/// cannot represent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    /// Sealed and recorded, not yet in service.
    ///
    /// Walked through in memory by [`SealedStore::set`](crate::SealedStore::set) and
    /// [`SealedStore::rotate`](crate::SealedStore::rotate), which advance to [`Self::Active`]
    /// before the document is written, so it is not a state this crate persists. It is a real
    /// state rather than a formality: it is what makes "a version exists" and "a version
    /// answers" two different facts, and a record read back in it resolves nothing, which is
    /// the fail-closed reading of a store some other writer left half finished.
    Created,

    /// In service. Resolves.
    ///
    /// At most one version of a key is in this state, which is the invariant that makes
    /// "the current version" a well defined thing to issue a grant against.
    Active,

    /// Withdrawn from service, reversibly, without being revoked.
    ///
    /// Where SB-9's tripwire puts a key on a trip (owned by I-035) and where an operator puts
    /// one they are unsure about. Does not resolve. `Suspended -> Active` returns it.
    Suspended,

    /// Revoked. Does not resolve, and stopped resolving the instant the operator said so.
    ///
    /// The tombstone INV-1 requires: quarantine is how this store expresses removal, the value
    /// is still there, and [`SealedStore::restore`](crate::SealedStore::restore) reverses it.
    /// Nothing deletes it.
    Quarantined,

    /// Replaced by a newer version, and still resolving until the overlap window closes.
    ///
    /// The state that makes rotation a drain rather than a cliff (SB-14, T8).
    Superseded,

    /// Replaced by a newer version and past the overlap window. Usable never.
    ///
    /// Kept rather than deleted, for INV-1 and because an auditor reading a record that names
    /// version three should be able to establish that version three existed. Restorable by the
    /// operator.
    Retained,
}

impl KeyState {
    /// Every state, so a test can quantify over the whole enumeration rather than a list some
    /// author kept up to date by hand.
    ///
    /// Written as an array literal over named variants so adding a variant without adding it
    /// here is caught by `every_state_appears_in_all`, which destructures the enum.
    pub const ALL: [Self; 6] = [
        Self::Created,
        Self::Active,
        Self::Suspended,
        Self::Quarantined,
        Self::Superseded,
        Self::Retained,
    ];

    /// Returns `true` when `next` is a legal successor of `self`.
    ///
    /// The readable statement of SB-14's edge set, and the one [`KeyLifecycle::advance`]
    /// consults. Three groups of edges, and the third is where this specification revised
    /// itself, so each is named.
    ///
    /// **The states SB-14 lists literally.** `Created -> Active`; `Active -> Suspended` and
    /// back; `Active -> Quarantined`; and `Quarantined -> Active`, which is SB-14's
    /// `Restored(Active)` and is operator-only.
    ///
    /// **Revocation reaches every state that resolves or could resolve again.**
    /// `Suspended -> Quarantined` and `Superseded -> Quarantined` are not in SB-14's literal
    /// list and are required by the sentence that follows it: revocation is immediate and
    /// in-flight calls fail closed. A `Superseded` version resolves during the overlap window,
    /// so without that edge an operator revoking a compromised key would leave it answering for
    /// up to the window, which is the exact failure quarantine exists to prevent.
    /// `Retained -> Quarantined` is admitted for a different reason: a `Retained` version does
    /// not resolve, but it is restorable, and an operator revoking a key should not have to
    /// revoke it again after somebody restores it.
    ///
    /// **Reversal returns a version to where it was, not to `Active`.**
    /// `Quarantined -> Suspended`, `Quarantined -> Superseded` and `Quarantined -> Retained`
    /// exist because [`SealedStore::quarantine`](crate::SealedStore::quarantine) acts on every
    /// version of a key at once and [`SealedStore::restore`](crate::SealedStore::restore)
    /// reverses it. A version that was `Superseded` or `Suspended` when the operator revoked
    /// comes back exactly there, not `Active`. That is narrower than SB-14's
    /// `Restored(Active)` and it is narrower in the safe direction: restoring a suspended
    /// version to service, or two versions to `Active` at once, would hand revocation-plus-
    /// restore a wider result than the operator ever had, and every quarantinable state must
    /// have its return edge or a quarantine of it is a revocation no restore can reverse,
    /// which turns INV-5's halt into a trap on a legal operator sequence.
    ///
    /// `Retained -> Active` is the operator rollback SB-14 means by "restorable by operator".
    ///
    /// There is no edge into `Created` from anywhere. A version is created once.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        // `Suspended` and `Retained` share one arm because they happen to share successor
        // sets, not because they are the same idea; the readable one-edge-per-line statement
        // of this set is the `LEGAL` table in this module's tests, which grades this
        // predicate over every ordered pair.
        matches!(
            (self, next),
            (Self::Created, Self::Active)
                | (
                    Self::Active,
                    Self::Suspended | Self::Quarantined | Self::Superseded
                )
                | (
                    Self::Suspended | Self::Retained,
                    Self::Active | Self::Quarantined
                )
                | (Self::Superseded, Self::Retained | Self::Quarantined)
                | (
                    Self::Quarantined,
                    Self::Active | Self::Suspended | Self::Superseded | Self::Retained
                )
        )
    }

    /// Whether a version in this state answers a resolution.
    ///
    /// Exactly two states do. `Superseded` is the overlap window (SB-14) and it is the reason
    /// this is a predicate rather than an equality test against `Active`.
    ///
    /// Written as an exhaustive `match` rather than a `matches!`, so a state added later cannot
    /// default into the non-resolving arm without somebody deciding it should. The safe default
    /// is the right one and it should still be a decision.
    #[must_use]
    pub const fn resolves(self) -> bool {
        match self {
            Self::Active | Self::Superseded => true,
            Self::Created | Self::Suspended | Self::Quarantined | Self::Retained => false,
        }
    }

    /// The state's stable name, for an audit record and an operator message.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Quarantined => "quarantined",
            Self::Superseded => "superseded",
            Self::Retained => "retained",
        }
    }
}

impl std::fmt::Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The one place in this crate that writes a version's state.
///
/// A newtype rather than a free function so that the state it holds is private and the only
/// route to a new one is through [`KeyLifecycle::advance`]. `Deserialize` reads the state back
/// from the store document, which is the point at which persistence removes the option of a
/// typestate and is the reason the module documentation says so out loud: a store written by an
/// earlier run is trusted for what state it recorded, and every transition after that is
/// checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyLifecycle {
    state: KeyState,
}

impl KeyLifecycle {
    /// A newly sealed version, before it enters service.
    #[must_use]
    pub const fn created() -> Self {
        Self {
            state: KeyState::Created,
        }
    }

    /// The state this version is in.
    #[must_use]
    pub const fn state(self) -> KeyState {
        self.state
    }

    /// Whether this version answers a resolution.
    #[must_use]
    pub const fn resolves(self) -> bool {
        self.state.resolves()
    }

    /// Move to `next`, or refuse and say what was attempted.
    ///
    /// INV-5's "an attempted illegal transition halts the operation and emits an audit record"
    /// is split at the crate boundary, and the split is named rather than left to be discovered.
    /// The halt is here: the transition does not happen, nothing is written, and the caller
    /// gets an error rather than a `false` it may ignore. The audit record is not here, because
    /// this crate holds no audit sink and adding one would put a second chain writer in the
    /// workspace beside `nmcp-audit`'s. [`IllegalTransition`] carries exactly the fields SB-7's
    /// record needs, and emitting it is I-034's, which is the issue that wires resolution into
    /// the ring at stage 5b and therefore the first code with an `AuditSink` in scope.
    ///
    /// # Errors
    ///
    /// [`IllegalTransition`] when [`KeyState::can_transition_to`] refuses the edge.
    pub const fn advance(self, next: KeyState) -> Result<Self, IllegalTransition> {
        if self.state.can_transition_to(next) {
            Ok(Self { state: next })
        } else {
            Err(IllegalTransition {
                from: self.state,
                to: next,
            })
        }
    }
}

/// An attempted transition the key lifecycle does not permit.
///
/// Carries the two states and nothing else. Not the name, not the version, not the value:
/// the store adds the name and version when it turns this into a
/// [`StoreError`](crate::StoreError), and SB-1 forbids the third.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("key lifecycle has no {from} to {to} transition")]
pub struct IllegalTransition {
    /// The state the version is in.
    pub from: KeyState,
    /// The state something tried to move it to.
    pub to: KeyState,
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
    use super::{IllegalTransition, KeyLifecycle, KeyState};

    /// The whole edge set, written out once so the exhaustive test below grades the predicate
    /// against a list a reader can check against SB-14 rather than against the predicate
    /// restated in different syntax.
    const LEGAL: &[(KeyState, KeyState)] = &[
        (KeyState::Created, KeyState::Active),
        (KeyState::Active, KeyState::Suspended),
        (KeyState::Active, KeyState::Quarantined),
        (KeyState::Active, KeyState::Superseded),
        (KeyState::Suspended, KeyState::Active),
        (KeyState::Suspended, KeyState::Quarantined),
        (KeyState::Superseded, KeyState::Retained),
        (KeyState::Superseded, KeyState::Quarantined),
        (KeyState::Retained, KeyState::Active),
        (KeyState::Retained, KeyState::Quarantined),
        (KeyState::Quarantined, KeyState::Active),
        (KeyState::Quarantined, KeyState::Suspended),
        (KeyState::Quarantined, KeyState::Superseded),
        (KeyState::Quarantined, KeyState::Retained),
    ];

    #[test]
    fn every_state_appears_in_all() {
        // Destructured so a variant added without being added to `ALL` fails to compile here
        // rather than silently shrinking every exhaustive test in this module.
        for state in KeyState::ALL {
            match state {
                KeyState::Created
                | KeyState::Active
                | KeyState::Suspended
                | KeyState::Quarantined
                | KeyState::Superseded
                | KeyState::Retained => {}
            }
        }
        assert_eq!(KeyState::ALL.len(), 6);
        let mut seen = KeyState::ALL.to_vec();
        seen.dedup();
        assert_eq!(seen.len(), 6, "no state is listed twice");
    }

    /// Exhaustive over all thirty-six ordered pairs, graded against `LEGAL`. This is the test
    /// INV-5 is enforced by: an edge added to the predicate and not to the specification's
    /// reading of SB-14 fails here, and so does one removed.
    #[test]
    fn the_predicate_admits_exactly_the_declared_edges() {
        for from in KeyState::ALL {
            for to in KeyState::ALL {
                let declared = LEGAL.contains(&(from, to));
                assert_eq!(
                    from.can_transition_to(to),
                    declared,
                    "edge {from} -> {to} disagrees with the declared set"
                );
            }
        }
    }

    /// The guard and the predicate are two expressions of one edge set, so they are bound
    /// mechanically rather than by the author of each remembering the other.
    #[test]
    fn advance_admits_exactly_the_predicate_edges() {
        for from in KeyState::ALL {
            for to in KeyState::ALL {
                let held = KeyLifecycle { state: from };
                match held.advance(to) {
                    Ok(moved) => {
                        assert!(
                            from.can_transition_to(to),
                            "{from} -> {to} should have been refused"
                        );
                        assert_eq!(moved.state(), to);
                    }
                    Err(IllegalTransition { from: f, to: t }) => {
                        assert!(
                            !from.can_transition_to(to),
                            "{from} -> {to} should have been allowed"
                        );
                        assert_eq!((f, t), (from, to), "the refusal names what was attempted");
                    }
                }
            }
        }
    }

    #[test]
    fn a_refused_transition_does_not_move_the_state() {
        let active = KeyLifecycle::created().advance(KeyState::Active).unwrap();
        let refused = active.advance(KeyState::Created).unwrap_err();
        assert_eq!(refused.from, KeyState::Active);
        assert_eq!(refused.to, KeyState::Created);
        // The value is `Copy` and the refusal returned no new one, so the caller still holds
        // the state it had. That is the halt: nothing moved.
        assert_eq!(active.state(), KeyState::Active);
    }

    #[test]
    fn nothing_transitions_into_created() {
        for from in KeyState::ALL {
            assert!(
                !from.can_transition_to(KeyState::Created),
                "{from} must not reach Created: a version is created once"
            );
        }
    }

    #[test]
    fn exactly_active_and_superseded_resolve() {
        for state in KeyState::ALL {
            let expected = matches!(state, KeyState::Active | KeyState::Superseded);
            assert_eq!(state.resolves(), expected, "{state} resolvability");
            assert_eq!(KeyLifecycle { state }.resolves(), expected);
        }
    }

    /// Revocation is immediate, which means it has to be reachable from every state the store
    /// persists. Asserted directly because it is the property SB-14's literal state list does
    /// not state and the sentence after it requires.
    ///
    /// Two states are excluded, and each exclusion is itself pinned so it stays a decision.
    /// `Created` is walked through in memory by `set` and `rotate` and never persisted with
    /// anything in service behind it; a version in it resolves nothing, so there is nothing
    /// revocation would stop, and an edge from it would let a half-written record be moved by
    /// an operator action that its own writer never finished. `Quarantined` is the destination:
    /// revoking a revoked version is refused as already done, not modelled as a self-edge.
    #[test]
    fn quarantine_is_reachable_from_every_persisted_state() {
        for from in KeyState::ALL {
            let excluded = matches!(from, KeyState::Created | KeyState::Quarantined);
            assert_eq!(
                from.can_transition_to(KeyState::Quarantined),
                !excluded,
                "{from} -> quarantined must be {}",
                if excluded { "refused" } else { "legal" }
            );
        }
    }

    #[test]
    fn a_state_round_trips_through_the_store_encoding() {
        for state in KeyState::ALL {
            let held = KeyLifecycle { state };
            let text = serde_json::to_string(&held).unwrap();
            assert_eq!(text, format!("\"{}\"", state.as_str()));
            let back: KeyLifecycle = serde_json::from_str(&text).unwrap();
            assert_eq!(back.state(), state);
        }
    }

    #[test]
    fn the_refusal_message_names_both_states_and_carries_nothing_else() {
        let refused = KeyLifecycle::created()
            .advance(KeyState::Quarantined)
            .unwrap_err();
        let rendered = refused.to_string();
        assert_eq!(
            rendered,
            "key lifecycle has no created to quarantined transition"
        );
    }
}
