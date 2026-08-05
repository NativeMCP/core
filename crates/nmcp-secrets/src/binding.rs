//! The binding model: what may use a key, evaluated where the key lives.
//!
//! NMCP-SPEC-002 SB-6 and SB-R4, RATIFIED v1.1, and the v1.1 revision is load-bearing for
//! everything here: v1.0 placed binding evaluation in `nmcp-policy`, I-033 proved that
//! placement a dependency cycle (`nmcp-policy -> nmcp-secrets -> nmcp-schema -> nmcp-policy`,
//! confirmed with cargo tree), and section 9's ruling moved it into this crate. Bindings are
//! written only through the operator surface, per key (SB-13), so they are per-key store
//! metadata, and the crate that owns the store owns the evaluator. That is what keeps
//! [`BindingGrant`](crate::BindingGrant) unforgeable at no cost: the grant's constructor never
//! crosses a crate boundary. `nmcp-policy` retains no binding role; INV-4 remains the model
//! the evaluator follows, deny by default and narrowing only, but a model is not a location.
//! The host wires the two at ring stage 5b (I-034): it reads nothing secret, holds the store
//! handle, and passes the request context in.
//!
//! The evaluator itself is [`SealedStore::evaluate`](crate::SealedStore::evaluate), because
//! evaluation reads the binding off the key's own document and spends its budget there; this
//! module holds the types, the pure gates it applies, and the decisions that shape them.
//!
//! ## Deny by default, both halves
//!
//! Deny by default is structural, not a configuration default, and it has two halves, each
//! stated because assuming either from the other is how a gap ships:
//!
//! - **An absent binding means no use.** A key with no binding refuses evaluation with the
//!   governing rule named: no binding exists for the key. Storing a secret grants nothing;
//!   the operator must also say what may use it
//!   ([`SealedStore::bind`](crate::SealedStore::bind)).
//! - **An empty allowlist in a present binding means nothing satisfies it.** There is no
//!   wildcard, no "empty means any", and no way to write one. A binding whose tool allowlist
//!   is empty admits no tool, and one whose caller allowlist is empty admits no caller.
//!
//! ## The dimensions, and which of them a request carries
//!
//! [`KeyBinding`] carries four allowlists (tools, program basenames, root ids, caller
//! identities), an optional expiry and an optional use budget (SB-6). A [`BindingRequest`]
//! always carries the tool and the caller, so those two allowlists are on trial for every
//! evaluation. It carries a program basename only when the slot's modality is `env`, and a
//! root id only when the call resolved one, so those two are on trial exactly when the
//! request carries them.
//!
//! A dimension the request does not carry is not consulted, and that is not a widening a
//! caller can reach (INV-4): the caller does not choose whether a program or a root is
//! carried, the tool's contract does. The modality is contract-declared (SB-A2), and a tool
//! whose contract declares path arguments has its root resolved by the kernel before stage 5b
//! or refused at authorization, so by the time evaluation runs a rootless request means a
//! rootless tool, and which tools may reach the key at all is the tool allowlist's decision.
//! The program allowlist for the `env` modality is enforced at its point of use: an
//! `env`-slot request against an empty program allowlist refuses, which is SB-4's
//! "structurally non-empty for `env`" applied where the store can see it. The bind-time half
//! of SB-4, refusing to write such a binding for a key an `env` slot names, needs the slot
//! declaration, which lives in the tool contract and not in this store; it belongs to the
//! surfaces that see both, the stage 5b wiring (I-034) and the operator command surface
//! (I-038).
//!
//! ## Evaluation order, which is what a conflicting refusal names (SB-8)
//!
//! Every refusal names exactly one governing rule, and when a request fails several gates the
//! rule named is the first refusing gate in this order:
//!
//! 1. the store can read the key (a damaged document refuses, fail closed);
//! 2. the key exists;
//! 3. a binding exists (deny by default made visible);
//! 4. the tool allowlist;
//! 5. the program allowlist, when the request carries a program;
//! 6. the root allowlist, when the request carries a root;
//! 7. the caller allowlist;
//! 8. expiry, against the store's injected clock;
//! 9. key state: a version must be in service, so a quarantined, suspended or drained key
//!    refuses here and no grant is minted for a key that resolution would refuse;
//! 10. the use budget, the only gate that writes.
//!
//! The allowlists precede expiry and key state so that a refusal discloses no more than it
//! must: a request the binding would never admit learns that it is not admitted, not whether
//! the key is revoked. Key state precedes the budget so that a refused use never spends one:
//! the budget is the last gate, reached only by a request everything else admitted.
//!
//! ## The use budget: where the counter lives and how the window advances (G-2)
//!
//! NMCP-SPEC-002 G-2 records that SB-6's count per window had no stated home and owns the
//! decision to I-036. Decided here:
//!
//! **The counter lives in the store document beside the binding, and it is persisted.** The
//! spend state is written into the key's own document under the same atomic-rename discipline
//! as every other write, so a restart does not reset it: a counter that survived only in
//! memory would be a budget any crash refills, and a counter that resets is silent widening,
//! the direction INV-4 forbids. The operator writes the terms and the evaluator writes the
//! spend state; [`SealedStore::bind`](crate::SealedStore::bind) replaces both, so re-binding
//! opens a fresh regime, which is an operator action and therefore not a widening a caller
//! can reach.
//!
//! **The window is fixed and opens at first use.** The alternatives were a sliding window,
//! which needs a timestamp per use and turns a two-integer counter into an unbounded log
//! inside a per-secret document, and a fixed window anchored at bind time, which ticks while
//! the key is idle and hands the first user a partially elapsed window for no reason an
//! operator could predict. Anchoring at first use keeps the state two integers, gives an idle
//! key its whole budget the moment it is needed, and makes the arithmetic the same shape as
//! the rotation overlap: elapsed time measured against the store's injected clock, compared
//! with `>=`, testable at the boundary without a sleep.
//!
//! **The boundary belongs to the closed side, in both directions.** A window of `w` seconds
//! opened at `t` meters its budgeted uses until `t + w`; at exactly `t + w` the window has
//! closed and the next use opens a fresh one. A budget of zero uses admits nothing, ever,
//! which is the empty-allowlist rule applied to a count. A window of zero seconds is closed
//! the instant it opens, so every use opens a fresh window and only a zero-use budget
//! refuses; that is the general rule evaluated at its boundary, the same reading the rotation
//! overlap gives a zero window, and an operator wanting "never replenish" writes a long
//! window rather than a zero one. Two residuals are named rather than hidden: a burst
//! straddling a window boundary can spend up to twice the budget across the two adjacent
//! windows, the known cost of any fixed window; and a clock that runs backwards reads as
//! elapsed zero, which holds the current window open longer rather than replenishing early,
//! the fail-closed direction.
//!
//! ## The budget decrements at mint, not at resolution
//!
//! The natural sequence at stage 5b is evaluate, which mints the grant, then resolve, which
//! consumes it and unseals. The budget could decrement at either end, and the difference is
//! what happens when the host crashes between the two: a grant minted and never resolved.
//! Decided: **the decrement happens at mint, atomically with it**, under the same lock and
//! persisted before the grant exists, argued from SB-8's fail-closed posture. A grant is
//! authority to unseal, so the budget bounds authorizations rather than completed unseals,
//! and an outcome the store cannot observe (the crash window) counts as an exposure rather
//! than as a refund. The check and the spend are one step under one lock, so two concurrent
//! evaluations cannot both pass on a last remaining use, which decrement-at-resolution
//! reintroduces as minted grants outnumbering the budget. The grant stays what SB-15 calls
//! it, proof, rather than a claim resolution re-adjudicates. And the cost is bounded by the
//! grant's own shape: a grant is single use by value, so a crashed host burns exactly the one
//! use it was authorized, and the operator finds an intent record with no outcome record at
//! the point the audit story already marks. A grant minted and then refused by `resolve` (the
//! key was quarantined in between, or the blob does not open) has likewise spent its use:
//! the authorization happened, and refunding on failure would let a failing key be probed
//! without bound inside one window. When the spend cannot be persisted the evaluation
//! refuses, because an unrecorded use does not proceed, mirroring INV-3's rule that a server
//! that cannot write audit does not serve.

use serde::{Deserialize, Serialize};

use crate::grant::BindingRuleId;
use crate::lifecycle::KeyState;
use crate::name::SecretName;
use crate::store::StoreError;

/// The schema version of the binding block inside a secret's document.
///
/// Versioned separately from [`STORE_SCHEMA_VERSION`](crate::STORE_SCHEMA_VERSION) so that a
/// binding-shape revision does not orphan every store written before it: the document schema
/// says how the document is laid out, this says how the binding block is, and a block
/// declaring a version this build does not know refuses the open exactly as a newer document
/// schema does, because it is a store written by a newer build rather than corruption.
pub const BINDING_SCHEMA_VERSION: u32 = 1;

/// What may use one key: SB-6's per-key binding, written only by the operator (SB-13).
///
/// Four allowlists, an optional expiry and an optional use budget. Store metadata rather than
/// material, which is why it has serde at all: it travels in the key's own document, and
/// nothing in it is secret (SB-R2 lets the agent see a binding summary).
///
/// Deny by default is structural in both directions. A key with no `KeyBinding` refuses every
/// evaluation, and an empty allowlist here admits nothing: there is no wildcard and no way to
/// write one. All four lists are always serialized, even empty, and none has a serde default,
/// so a binding block missing one is refused as unreadable rather than read as unrestricted;
/// a field somebody omitted is a field somebody may believe means "any", and NMCP-SPEC-002
/// G-3 records where tolerating that leads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBinding {
    /// Tool names that may use the key. Empty admits no tool.
    pub tools: Vec<String>,
    /// Program basenames the `env` modality may inject into (SB-4). Empty admits no program,
    /// which is "structurally non-empty for `env`" enforced at the point of use; requests
    /// without a program (the `header` modality) do not consult this list.
    pub programs: Vec<String>,
    /// Root identifiers the key may be used under. Empty admits no root; requests that
    /// resolved no root (a rootless tool, by contract) do not consult this list.
    pub roots: Vec<String>,
    /// Caller identities that may use the key. Empty admits no caller.
    pub callers: Vec<String>,
    /// When the binding stops admitting anything, in milliseconds since the Unix epoch,
    /// measured against the store's injected clock. At exactly this instant the binding is
    /// expired: the boundary belongs to the closed side, like every window in this crate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<u64>,
    /// The use budget, a count per window. Absent means unmetered; the module documentation
    /// records where the counter lives and how the window advances (G-2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<UseBudget>,
}

/// A count of uses per fixed window (SB-6).
///
/// The window opens at first use and closes `window_secs` later; the module documentation
/// argues the choice and names the boundary and the residuals. A `uses` of zero admits
/// nothing, which is the empty-allowlist rule applied to a count. A `window_secs` of zero is
/// closed the instant it opens, so every use opens a fresh window and only a zero-use budget
/// refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UseBudget {
    /// How many grants may be minted inside one window.
    pub uses: u32,
    /// The window's length, in seconds, matching the overlap window's unit: a drain time an
    /// operator reasons about in seconds.
    pub window_secs: u64,
}

/// The spend state of a use budget: the window currently open and the uses minted inside it.
///
/// Written by the evaluator, never by the operator: [`SealedStore::bind`](crate::SealedStore::bind)
/// takes a [`KeyBinding`] and not one of these, so no caller of the operator surface can hand
/// the store a refilled counter. Persisted in the key's document beside the binding so a
/// restart does not reset it (G-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BudgetSpent {
    /// When the open window started, in milliseconds since the Unix epoch.
    pub(crate) window_started_at_unix_ms: u64,
    /// Grants minted inside it.
    pub(crate) used: u32,
}

/// The binding block as it sits in a secret's document: a schema version, the terms the
/// operator wrote, and the spend state the evaluator writes.
///
/// The split matters: `terms` is replaced whole by [`SealedStore::bind`](crate::SealedStore::bind)
/// and `spent` is written only at mint, so the two writers never hold the same field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindingRecord {
    /// [`BINDING_SCHEMA_VERSION`] at write; checked at read before the typed parse.
    pub(crate) schema: u32,
    /// The operator-written binding.
    pub(crate) terms: KeyBinding,
    /// The evaluator-written spend state, absent until a budgeted use happens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) spent: Option<BudgetSpent>,
}

/// The request context binding evaluation runs against, assembled by the host at stage 5b.
///
/// The tool and the caller are always present: every governed call has both, so those two
/// allowlists are on trial for every evaluation. The program basename is present exactly when
/// the slot's modality is `env` (it is the basename of the program `nmcp-exec` would hand the
/// value to), and the root exactly when the call resolved one; the module documentation
/// argues why a dimension the request does not carry is not consulted and why that is not a
/// widening a caller can reach (INV-4).
///
/// Carries no material and no reference: evaluation decides whether a use may happen, and the
/// value stays sealed until [`SealedStore::resolve`](crate::SealedStore::resolve) consumes
/// the grant this request earns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRequest {
    tool: String,
    caller: String,
    program: Option<String>,
    root: Option<String>,
}

impl BindingRequest {
    /// A request from `caller` to use a key through `tool`, with no program and no root.
    #[must_use]
    pub fn new(tool: impl Into<String>, caller: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            caller: caller.into(),
            program: None,
            root: None,
        }
    }

    /// The same request with the `env` modality's program basename attached.
    #[must_use]
    pub fn with_program(mut self, program: impl Into<String>) -> Self {
        self.program = Some(program.into());
        self
    }

    /// The same request with the resolved root attached.
    #[must_use]
    pub fn with_root(mut self, root: impl Into<String>) -> Self {
        self.root = Some(root.into());
        self
    }

    /// The tool named in the call.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// The caller's identity.
    #[must_use]
    pub fn caller(&self) -> &str {
        &self.caller
    }

    /// The program basename the `env` modality would inject into, when the slot is `env`.
    #[must_use]
    pub fn program(&self) -> Option<&str> {
        self.program.as_deref()
    }

    /// The root the call resolved, when it resolved one.
    #[must_use]
    pub fn root(&self) -> Option<&str> {
        self.root.as_deref()
    }
}

/// Why binding evaluation refused to mint a grant.
///
/// Every variant names the governing rule (SB-8), both in its `Display` text and as the
/// stable identifier [`BindingDenial::rule`] returns, and exactly one rule governs: when a
/// request fails several gates the variant is the first refusing gate in the order the module
/// documentation fixes. No variant carries material or any value derived from material,
/// including a length or a digest (SB-1); names, tools, programs, roots, callers, states and
/// timestamps are all metadata the refusal is about, not contents of the key.
///
/// Exhaustive rather than `#[non_exhaustive]`, for the reason the store's errors give: this
/// enum is owned by NMCP-SPEC-002 rather than frozen by a ratified contract another crate
/// matches on, and a new way for evaluation to refuse should break every `match` on it
/// loudly.
#[derive(Debug, thiserror::Error)]
pub enum BindingDenial {
    /// The name's file exists and could not be read, so nothing about it is evaluated.
    #[error(
        "secret {name} sits in a document this build could not read and is not evaluated (rule damaged-entry)"
    )]
    DamagedEntry {
        /// The name.
        name: String,
    },

    /// No secret of that name.
    #[error("binding evaluation found no secret named {name} (rule unknown-secret)")]
    UnknownSecret {
        /// The name the request asked for.
        name: String,
    },

    /// The key exists and no binding exists for it, which is deny by default made visible:
    /// storing a secret grants nothing until the operator says what may use it (SB-6).
    #[error(
        "no binding exists for secret {name}, and a key with no binding is usable by nothing (rule no-binding)"
    )]
    NoBinding {
        /// The name.
        name: String,
    },

    /// The tool allowlist does not admit the requested tool. An empty allowlist admits none.
    #[error(
        "the binding for secret {name} does not admit tool {tool}: the tool allowlist is the governing rule"
    )]
    ToolNotAllowed {
        /// The name.
        name: String,
        /// The tool the request named.
        tool: String,
    },

    /// The program allowlist does not admit the program the `env` modality would inject
    /// into. An empty allowlist admits none, which is SB-4's structurally non-empty
    /// requirement enforced at the point of use.
    #[error(
        "the binding for secret {name} does not admit program {program} for the env modality: the program allowlist is the governing rule"
    )]
    ProgramNotAllowed {
        /// The name.
        name: String,
        /// The program basename the request carried.
        program: String,
    },

    /// The root allowlist does not admit the root the call resolved. An empty allowlist
    /// admits none.
    #[error(
        "the binding for secret {name} does not admit root {root}: the root allowlist is the governing rule"
    )]
    RootNotAllowed {
        /// The name.
        name: String,
        /// The root the call resolved.
        root: String,
    },

    /// The caller allowlist does not admit the caller. An empty allowlist admits none.
    #[error(
        "the binding for secret {name} does not admit caller {caller}: the caller allowlist is the governing rule"
    )]
    CallerNotAllowed {
        /// The name.
        name: String,
        /// The caller the request carried.
        caller: String,
    },

    /// The binding has expired. The boundary belongs to the closed side: a binding expiring
    /// at `t` refuses at exactly `t`.
    #[error(
        "the binding for secret {name} expired at {expires_at_unix_ms} and the clock reads {now_unix_ms}: expiry is the governing rule"
    )]
    Expired {
        /// The name.
        name: String,
        /// When the binding expired, in milliseconds since the Unix epoch.
        expires_at_unix_ms: u64,
        /// The store clock's reading at evaluation.
        now_unix_ms: u64,
    },

    /// No version of the key is in service, so no grant is minted: a grant for a key that
    /// resolution would refuse is a use that was authorized and could never happen, and the
    /// refusal happens at the earliest point that knows.
    #[error("secret {name} is {state} and mints no grant: key state is the governing rule")]
    NotInService {
        /// The name.
        name: String,
        /// The state that refused: the current version's, or the highest version's when
        /// nothing is in service.
        state: KeyState,
    },

    /// The use budget is spent for the window currently open (SB-6, G-2).
    #[error(
        "the binding for secret {name} has spent its budget of {uses} uses in the window opened at {window_started_at_unix_ms} ({window_secs}s): the use budget is the governing rule"
    )]
    BudgetExhausted {
        /// The name.
        name: String,
        /// The budgeted uses per window.
        uses: u32,
        /// The window length, in seconds.
        window_secs: u64,
        /// When the refusing window opened, in milliseconds since the Unix epoch; a budget
        /// of zero uses refuses before any window opens and reports the clock's reading.
        window_started_at_unix_ms: u64,
    },

    /// The spend could not be persisted, so the use does not proceed (SB-8): a budget whose
    /// decrement is lost to a failed write is a budget a crash refills, and the fail-closed
    /// posture here mirrors INV-3's rule that a server that cannot write audit does not
    /// serve.
    #[error(
        "a use of secret {name} could not be recorded and an unrecorded use does not proceed (rule use-not-recorded): {source}"
    )]
    UseNotRecorded {
        /// The name.
        name: String,
        /// What the store write refused with, boxed to keep the denial small.
        #[source]
        source: Box<StoreError>,
    },
}

impl BindingDenial {
    /// The stable name of the governing rule, for a refusal record (SB-8) and for the
    /// `rule` field the host's `Denial::SecretUnavailable` carries at I-034.
    ///
    /// One rule per refusal: evaluation stops at the first refusing gate, so this is the
    /// name of the gate that governed rather than one of several that might have.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        match self {
            Self::DamagedEntry { .. } => "damaged-entry",
            Self::UnknownSecret { .. } => "unknown-secret",
            Self::NoBinding { .. } => "no-binding",
            Self::ToolNotAllowed { .. } => "tool-allowlist",
            Self::ProgramNotAllowed { .. } => "program-allowlist",
            Self::RootNotAllowed { .. } => "root-allowlist",
            Self::CallerNotAllowed { .. } => "caller-allowlist",
            Self::Expired { .. } => "expiry",
            Self::NotInService { .. } => "key-state",
            Self::BudgetExhausted { .. } => "use-budget",
            Self::UseNotRecorded { .. } => "use-not-recorded",
        }
    }
}

/// The rule identifier a successful evaluation stamps on the grant it mints.
///
/// Bindings are per key (SB-6 at v1.1), so the rule that authorizes a resolution is the
/// key's own binding, named `binding.<name>`. Stable and derivable, so an auditor reading a
/// record that carries it can find the binding it names without a lookup table.
pub(crate) fn rule_for(name: &SecretName) -> BindingRuleId {
    BindingRuleId::new(format!("binding.{name}"))
}

/// Gates 4 through 8: the four allowlists in their fixed order, then expiry.
///
/// Read-only on purpose: everything that can refuse without spending anything runs here, so
/// the budget, the one gate that writes, is reached only by a request every other rule
/// admitted. Key existence, binding presence and key state are the store's gates, because
/// they are questions about the document rather than about the terms.
pub(crate) fn admit(
    terms: &KeyBinding,
    request: &BindingRequest,
    name: &SecretName,
    now_ms: u64,
) -> Result<(), BindingDenial> {
    if !terms.tools.iter().any(|tool| tool == request.tool()) {
        return Err(BindingDenial::ToolNotAllowed {
            name: name.to_string(),
            tool: request.tool().to_string(),
        });
    }
    if let Some(program) = request.program()
        && !terms.programs.iter().any(|allowed| allowed == program)
    {
        return Err(BindingDenial::ProgramNotAllowed {
            name: name.to_string(),
            program: program.to_string(),
        });
    }
    if let Some(root) = request.root()
        && !terms.roots.iter().any(|allowed| allowed == root)
    {
        return Err(BindingDenial::RootNotAllowed {
            name: name.to_string(),
            root: root.to_string(),
        });
    }
    if !terms
        .callers
        .iter()
        .any(|caller| caller == request.caller())
    {
        return Err(BindingDenial::CallerNotAllowed {
            name: name.to_string(),
            caller: request.caller().to_string(),
        });
    }
    if let Some(expires_at_unix_ms) = terms.expires_at_unix_ms
        && now_ms >= expires_at_unix_ms
    {
        return Err(BindingDenial::Expired {
            name: name.to_string(),
            expires_at_unix_ms,
            now_unix_ms: now_ms,
        });
    }
    Ok(())
}

/// Gate 10: spend one use, or refuse with the budget named.
///
/// Pure arithmetic over the injected clock's reading; the caller persists the returned state
/// before minting, which is the decrement-at-mint decision the module documentation argues.
/// The window opens at first use and the comparison is `elapsed >= window`, so at exactly the
/// boundary the window has closed and a fresh one opens; a zero-use budget refuses before any
/// window opens; and a clock reading earlier than the window's start saturates to elapsed
/// zero, which holds the window open rather than replenishing early.
pub(crate) fn spend(
    budget: UseBudget,
    prior: Option<BudgetSpent>,
    name: &SecretName,
    now_ms: u64,
) -> Result<BudgetSpent, BindingDenial> {
    let exhausted = |window_started_at_unix_ms: u64| BindingDenial::BudgetExhausted {
        name: name.to_string(),
        uses: budget.uses,
        window_secs: budget.window_secs,
        window_started_at_unix_ms,
    };
    if budget.uses == 0 {
        // A budget of zero admits nothing and opens no window; the report carries the
        // clock's reading so the refusal is still anchored in time.
        return Err(exhausted(
            prior.map_or(now_ms, |spent| spent.window_started_at_unix_ms),
        ));
    }
    let window_ms = budget.window_secs.saturating_mul(1_000);
    match prior {
        Some(spent) if now_ms.saturating_sub(spent.window_started_at_unix_ms) < window_ms => {
            if spent.used < budget.uses {
                Ok(BudgetSpent {
                    window_started_at_unix_ms: spent.window_started_at_unix_ms,
                    used: spent.used.saturating_add(1),
                })
            } else {
                Err(exhausted(spent.window_started_at_unix_ms))
            }
        }
        // No window open, or the open window has closed: this use opens a fresh one.
        _ => Ok(BudgetSpent {
            window_started_at_unix_ms: now_ms,
            used: 1,
        }),
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
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{BindingDenial, BindingRequest, KeyBinding, UseBudget};
    use crate::file_sealer::FileSealer;
    use crate::lifecycle::KeyState;
    use crate::name::{SecretName, Version};
    use crate::sealed::Sealed;
    use crate::store::{SealedStore, StoreError, UnreadableReason};
    use crate::testdir::TempDir;

    // - Fixtures -

    /// Distinctive material with no English substring, so the leak assertions below cannot
    /// collide with legitimate error prose such as the word "binding".
    const MATERIAL: &[u8] = b"wm4qk8-zv2xr6-np9jt3-bh7cd5";

    /// The clock every store below starts at.
    const T0: u64 = 1_000_000;

    fn name(text: &str) -> SecretName {
        SecretName::parse(text).unwrap()
    }

    fn sealed(bytes: &[u8]) -> Sealed<Vec<u8>> {
        Sealed::new(bytes.to_vec())
    }

    fn exposed(value: &Sealed<Vec<u8>>) -> Vec<u8> {
        value.with_exposed(Vec::clone)
    }

    /// A binding allowing exactly one entry on every dimension, unexpired and unmetered.
    fn full_binding() -> KeyBinding {
        KeyBinding {
            tools: vec!["exec.run".to_string()],
            programs: vec!["deployctl".to_string()],
            roots: vec!["workspace.alpha".to_string()],
            callers: vec!["operator.local".to_string()],
            expires_at_unix_ms: None,
            budget: None,
        }
    }

    /// The request `full_binding` admits on every dimension.
    fn ok_request() -> BindingRequest {
        BindingRequest::new("exec.run", "operator.local")
            .with_program("deployctl")
            .with_root("workspace.alpha")
    }

    /// An ephemeral store whose clock is a shared counter, walked rather than slept through.
    fn ephemeral_with_clock() -> (SealedStore, Arc<AtomicU64>) {
        let time = Arc::new(AtomicU64::new(T0));
        let handle = Arc::clone(&time);
        let store = SealedStore::ephemeral_with_clock(move || handle.load(Ordering::SeqCst));
        (store, time)
    }

    /// A disk store in `dir`, with the same shared-counter clock.
    fn open_with_clock(dir: &TempDir) -> (SealedStore, Arc<AtomicU64>) {
        let time = Arc::new(AtomicU64::new(T0));
        let handle = Arc::clone(&time);
        let store = SealedStore::open_with_clock(
            &dir.path().join("store"),
            Box::new(FileSealer::open(&dir.path().join("keys")).unwrap()),
            move || handle.load(Ordering::SeqCst),
        )
        .unwrap();
        (store, time)
    }

    /// Rewrite one field inside a stored document, keeping it valid JSON.
    fn tamper(store_dir: &Path, file: &str, edit: impl FnOnce(&mut serde_json::Value)) {
        let path = store_dir.join("secrets").join(file);
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        edit(&mut value);
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    /// No byte window of `material` four bytes or longer appears in `rendered` (SB-1: not
    /// the value, and nothing derived from it that could reconstruct part of it).
    fn assert_material_absent(rendered: &str, material: &[u8]) {
        let bytes = rendered.as_bytes();
        for width in 4..=material.len() {
            for window in material.windows(width) {
                assert!(
                    !bytes.windows(width).any(|candidate| candidate == window),
                    "a {width}-byte window of the material appears in: {rendered}"
                );
            }
        }
    }

    // - The precedence matrix (NMCP-SPEC-002 section 5): narrow ok, widen rejected,
    //   conflict names the governing rule -

    #[test]
    fn narrow_ok_a_request_within_every_allowlist_mints_a_grant_that_resolves() {
        let (store, _time) = ephemeral_with_clock();
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();
        store.bind(&key, full_binding()).unwrap();

        let grant = store.evaluate(&key, &ok_request()).unwrap();
        assert_eq!(grant.name(), &key);
        assert_eq!(grant.version(), Version::first());
        assert_eq!(
            grant.rule().as_str(),
            "binding.api.token",
            "the rule a grant carries names the key's own binding"
        );
        let resolved = store.resolve(grant).unwrap();
        assert_eq!(exposed(&resolved), MATERIAL.to_vec());
    }

    #[test]
    fn narrow_ok_a_request_may_use_less_than_the_binding_allows() {
        // Wider allowlists than the request needs: the request narrows, which INV-4 permits.
        let (store, _time) = ephemeral_with_clock();
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();
        let mut binding = full_binding();
        binding.tools.push("web.fetch".to_string());
        binding.programs.push("archivectl".to_string());
        binding.roots.push("workspace.beta".to_string());
        binding.callers.push("operator.remote".to_string());
        store.bind(&key, binding).unwrap();
        assert!(store.evaluate(&key, &ok_request()).is_ok());
    }

    #[test]
    fn widen_rejected_each_allowlist_dimension_refuses_independently() {
        let (store, _time) = ephemeral_with_clock();
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();
        store.bind(&key, full_binding()).unwrap();

        // One dimension deviates at a time; the other three match, and the refusal names
        // exactly the one that does not.
        let wrong_tool = BindingRequest::new("web.fetch", "operator.local")
            .with_program("deployctl")
            .with_root("workspace.alpha");
        let refused = store.evaluate(&key, &wrong_tool).unwrap_err();
        assert!(
            matches!(&refused, BindingDenial::ToolNotAllowed { tool, .. } if tool == "web.fetch"),
            "{refused:?}"
        );
        assert_eq!(refused.rule(), "tool-allowlist");
        assert!(
            refused
                .to_string()
                .contains("tool allowlist is the governing rule"),
            "{refused}"
        );

        let wrong_program = ok_request().with_program("sh");
        let refused = store.evaluate(&key, &wrong_program).unwrap_err();
        assert!(
            matches!(&refused, BindingDenial::ProgramNotAllowed { program, .. } if program == "sh"),
            "{refused:?}"
        );
        assert_eq!(refused.rule(), "program-allowlist");

        let wrong_root = ok_request().with_root("workspace.beta");
        let refused = store.evaluate(&key, &wrong_root).unwrap_err();
        assert!(
            matches!(&refused, BindingDenial::RootNotAllowed { root, .. } if root == "workspace.beta"),
            "{refused:?}"
        );
        assert_eq!(refused.rule(), "root-allowlist");

        let wrong_caller = BindingRequest::new("exec.run", "visitor.remote")
            .with_program("deployctl")
            .with_root("workspace.alpha");
        let refused = store.evaluate(&key, &wrong_caller).unwrap_err();
        assert!(
            matches!(&refused, BindingDenial::CallerNotAllowed { caller, .. } if caller == "visitor.remote"),
            "{refused:?}"
        );
        assert_eq!(refused.rule(), "caller-allowlist");
    }

    /// The documented order, walked as a staircase: a request failing every gate names the
    /// first, and fixing gates one at a time surfaces each next governing rule in turn.
    /// This is the "conflict names the governing rule" row of the matrix, graded over the
    /// whole order rather than one pair.
    #[test]
    fn conflict_names_the_first_governing_rule_in_the_documented_order() {
        let (store, _time) = ephemeral_with_clock();
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();
        let mut binding = full_binding();
        binding.expires_at_unix_ms = Some(T0); // now >= T0: already expired
        binding.budget = Some(UseBudget {
            uses: 0,
            window_secs: 60,
        }); // and a budget that admits nothing
        store.bind(&key, binding.clone()).unwrap();
        store.quarantine(&key).unwrap(); // and a key out of service

        // Every gate would refuse; the tool allowlist governs.
        let all_wrong = BindingRequest::new("web.fetch", "visitor.remote")
            .with_program("sh")
            .with_root("workspace.beta");
        assert_eq!(
            store.evaluate(&key, &all_wrong).unwrap_err().rule(),
            "tool-allowlist"
        );

        // Fix the tool: the program allowlist governs.
        let fixed_tool = BindingRequest::new("exec.run", "visitor.remote")
            .with_program("sh")
            .with_root("workspace.beta");
        assert_eq!(
            store.evaluate(&key, &fixed_tool).unwrap_err().rule(),
            "program-allowlist"
        );

        // Fix the program: the root allowlist governs.
        let fixed_program = BindingRequest::new("exec.run", "visitor.remote")
            .with_program("deployctl")
            .with_root("workspace.beta");
        assert_eq!(
            store.evaluate(&key, &fixed_program).unwrap_err().rule(),
            "root-allowlist"
        );

        // Fix the root: the caller allowlist governs.
        let fixed_root = BindingRequest::new("exec.run", "visitor.remote")
            .with_program("deployctl")
            .with_root("workspace.alpha");
        assert_eq!(
            store.evaluate(&key, &fixed_root).unwrap_err().rule(),
            "caller-allowlist"
        );

        // Fix the caller: expiry governs.
        assert_eq!(
            store.evaluate(&key, &ok_request()).unwrap_err().rule(),
            "expiry"
        );

        // Lift the expiry (an operator rewrite): key state governs.
        binding.expires_at_unix_ms = None;
        store.bind(&key, binding.clone()).unwrap();
        let refused = store.evaluate(&key, &ok_request()).unwrap_err();
        assert_eq!(refused.rule(), "key-state");
        assert!(
            matches!(
                &refused,
                BindingDenial::NotInService {
                    state: KeyState::Quarantined,
                    ..
                }
            ),
            "{refused:?}"
        );

        // Restore the key: the zero-use budget governs.
        store.restore(&key).unwrap();
        assert_eq!(
            store.evaluate(&key, &ok_request()).unwrap_err().rule(),
            "use-budget"
        );

        // Lift the budget: nothing refuses, and the staircase ends in a grant.
        binding.budget = None;
        store.bind(&key, binding).unwrap();
        assert!(store.evaluate(&key, &ok_request()).is_ok());
    }

    // - Deny by default, both halves -

    #[test]
    fn an_unbound_key_refuses_at_evaluation_naming_the_rule() {
        let (store, _time) = ephemeral_with_clock();
        let key = name("unbound.token");
        store.set(&key, sealed(MATERIAL)).unwrap();

        let refused = store.evaluate(&key, &ok_request()).unwrap_err();
        assert!(
            matches!(&refused, BindingDenial::NoBinding { .. }),
            "{refused:?}"
        );
        assert_eq!(refused.rule(), "no-binding");
        assert!(
            refused.to_string().contains("no binding exists"),
            "deny by default is named, not silent: {refused}"
        );
    }

    #[test]
    fn an_empty_allowlist_in_a_present_binding_admits_nothing() {
        let (store, _time) = ephemeral_with_clock();
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();

        // An empty tool allowlist: no tool satisfies it, so every request refuses there.
        let mut binding = full_binding();
        binding.tools = Vec::new();
        store.bind(&key, binding).unwrap();
        assert_eq!(
            store.evaluate(&key, &ok_request()).unwrap_err().rule(),
            "tool-allowlist"
        );

        // An empty program allowlist refuses every env-modality request, which is SB-4's
        // "structurally non-empty for env" at the point of use.
        let mut binding = full_binding();
        binding.programs = Vec::new();
        store.bind(&key, binding).unwrap();
        assert_eq!(
            store.evaluate(&key, &ok_request()).unwrap_err().rule(),
            "program-allowlist"
        );

        // An empty caller allowlist admits no caller.
        let mut binding = full_binding();
        binding.callers = Vec::new();
        store.bind(&key, binding).unwrap();
        assert_eq!(
            store.evaluate(&key, &ok_request()).unwrap_err().rule(),
            "caller-allowlist"
        );
    }

    #[test]
    fn a_dimension_the_request_does_not_carry_is_not_consulted() {
        // The vacuity rule, and why it is not a widening: the caller does not choose whether
        // a program or a root is carried, the tool's contract does, and the tool allowlist
        // gates which contracts reach the key at all. A header-modality request carries no
        // program, a rootless tool resolves no root, and both must be bindable or the header
        // modality could never be used at all.
        let (store, _time) = ephemeral_with_clock();
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();
        store.bind(&key, full_binding()).unwrap();

        let header_shaped =
            BindingRequest::new("exec.run", "operator.local").with_root("workspace.alpha");
        assert!(
            store.evaluate(&key, &header_shaped).is_ok(),
            "no program carried: the program allowlist is not on trial"
        );
        let rootless = BindingRequest::new("exec.run", "operator.local").with_program("deployctl");
        assert!(
            store.evaluate(&key, &rootless).is_ok(),
            "no root resolved: the root allowlist is not on trial"
        );
    }

    // - Expiry, on the injected clock, boundary on the closed side -

    #[test]
    fn expiry_admits_before_the_boundary_and_refuses_at_and_after_it() {
        let (store, time) = ephemeral_with_clock();
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();
        let mut binding = full_binding();
        binding.expires_at_unix_ms = Some(T0 + 5_000);
        store.bind(&key, binding).unwrap();

        // Well before, and one millisecond before: the binding admits.
        assert!(store.evaluate(&key, &ok_request()).is_ok());
        time.store(T0 + 4_999, Ordering::SeqCst);
        assert!(store.evaluate(&key, &ok_request()).is_ok());

        // At exactly the boundary: expired. The boundary belongs to the closed side.
        time.store(T0 + 5_000, Ordering::SeqCst);
        let refused = store.evaluate(&key, &ok_request()).unwrap_err();
        assert!(
            matches!(
                &refused,
                BindingDenial::Expired {
                    expires_at_unix_ms: 1_005_000,
                    now_unix_ms: 1_005_000,
                    ..
                }
            ),
            "{refused:?}"
        );
        assert_eq!(refused.rule(), "expiry");

        // Long after: still expired.
        time.store(T0 + 3_600_000, Ordering::SeqCst);
        assert_eq!(
            store.evaluate(&key, &ok_request()).unwrap_err().rule(),
            "expiry"
        );
    }

    // - The use budget (G-2): counted at mint, boundary walked, zero and absent pinned -

    #[test]
    fn the_budget_meters_within_a_window_and_replenishes_at_its_boundary() {
        let (store, time) = ephemeral_with_clock();
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();
        let mut binding = full_binding();
        binding.budget = Some(UseBudget {
            uses: 2,
            window_secs: 60,
        });
        store.bind(&key, binding).unwrap();

        // Two uses inside the window that opens at first use.
        assert!(store.evaluate(&key, &ok_request()).is_ok());
        assert!(store.evaluate(&key, &ok_request()).is_ok());

        // The third refuses, naming the budget and the window it is metering.
        let refused = store.evaluate(&key, &ok_request()).unwrap_err();
        assert!(
            matches!(
                &refused,
                BindingDenial::BudgetExhausted {
                    uses: 2,
                    window_secs: 60,
                    window_started_at_unix_ms: T0,
                    ..
                }
            ),
            "{refused:?}"
        );
        assert_eq!(refused.rule(), "use-budget");

        // One millisecond before the window closes: still exhausted.
        time.store(T0 + 59_999, Ordering::SeqCst);
        assert_eq!(
            store.evaluate(&key, &ok_request()).unwrap_err().rule(),
            "use-budget"
        );

        // At exactly the boundary the window has closed and the next use opens a fresh one,
        // anchored at the new instant.
        time.store(T0 + 60_000, Ordering::SeqCst);
        assert!(store.evaluate(&key, &ok_request()).is_ok());
        assert!(store.evaluate(&key, &ok_request()).is_ok());
        let refused = store.evaluate(&key, &ok_request()).unwrap_err();
        assert!(
            matches!(
                &refused,
                BindingDenial::BudgetExhausted {
                    window_started_at_unix_ms: 1_060_000,
                    ..
                }
            ),
            "the fresh window is anchored at first use, not at the old window's end: {refused:?}"
        );

        // Far past: replenished again.
        time.store(T0 + 7_200_000, Ordering::SeqCst);
        assert!(store.evaluate(&key, &ok_request()).is_ok());
    }

    #[test]
    fn a_zero_budget_admits_nothing_and_an_absent_budget_is_unmetered() {
        let (store, _time) = ephemeral_with_clock();
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();

        // Zero uses: the empty-allowlist rule applied to a count. Refused on the first use,
        // before any window opens.
        let mut binding = full_binding();
        binding.budget = Some(UseBudget {
            uses: 0,
            window_secs: 60,
        });
        store.bind(&key, binding).unwrap();
        let refused = store.evaluate(&key, &ok_request()).unwrap_err();
        assert!(
            matches!(&refused, BindingDenial::BudgetExhausted { uses: 0, .. }),
            "{refused:?}"
        );

        // Absent budget: unmetered.
        store.bind(&key, full_binding()).unwrap();
        for _ in 0..5 {
            assert!(store.evaluate(&key, &ok_request()).is_ok());
        }
    }

    #[test]
    fn a_zero_window_closes_the_instant_it_opens() {
        // The general rule evaluated at its boundary, as the module documentation records:
        // every use opens a window that has already closed, so only a zero-use budget
        // refuses. An operator wanting "never replenish" writes a long window instead.
        let (store, _time) = ephemeral_with_clock();
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();
        let mut binding = full_binding();
        binding.budget = Some(UseBudget {
            uses: 1,
            window_secs: 0,
        });
        store.bind(&key, binding).unwrap();
        for _ in 0..3 {
            assert!(store.evaluate(&key, &ok_request()).is_ok());
        }
    }

    #[test]
    fn a_refused_request_spends_no_budget() {
        // The budget is the last gate: a request refused on any other rule never reaches it,
        // so probing with inadmissible requests cannot drain the operator's budget.
        let (store, _time) = ephemeral_with_clock();
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();
        let mut binding = full_binding();
        binding.budget = Some(UseBudget {
            uses: 1,
            window_secs: 3_600,
        });
        store.bind(&key, binding).unwrap();

        let wrong_caller = BindingRequest::new("exec.run", "visitor.remote")
            .with_program("deployctl")
            .with_root("workspace.alpha");
        assert_eq!(
            store.evaluate(&key, &wrong_caller).unwrap_err().rule(),
            "caller-allowlist"
        );

        // The one budgeted use is still there, and it is the only one.
        assert!(store.evaluate(&key, &ok_request()).is_ok());
        assert_eq!(
            store.evaluate(&key, &ok_request()).unwrap_err().rule(),
            "use-budget"
        );
    }

    #[test]
    fn a_key_out_of_service_refuses_before_the_budget_spends() {
        // A quarantined key refuses at evaluation, at the earliest point that knows, and the
        // refusal burns nothing: no grant is minted for a key resolution would refuse, and
        // no budget is spent on a use that could never happen.
        let (store, _time) = ephemeral_with_clock();
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();
        let mut binding = full_binding();
        binding.budget = Some(UseBudget {
            uses: 1,
            window_secs: 3_600,
        });
        store.bind(&key, binding).unwrap();
        store.quarantine(&key).unwrap();

        let refused = store.evaluate(&key, &ok_request()).unwrap_err();
        assert!(
            matches!(
                &refused,
                BindingDenial::NotInService {
                    state: KeyState::Quarantined,
                    ..
                }
            ),
            "{refused:?}"
        );
        assert_eq!(refused.rule(), "key-state");
        assert!(refused.to_string().contains("quarantined"), "{refused}");

        // Restored, the whole budget is intact: the refusal above spent nothing.
        store.restore(&key).unwrap();
        assert!(store.evaluate(&key, &ok_request()).is_ok());
        assert_eq!(
            store.evaluate(&key, &ok_request()).unwrap_err().rule(),
            "use-budget"
        );
    }

    #[test]
    fn the_spend_state_persists_across_reopen() {
        // G-2's decision measured: the counter lives in the document, so a restart does not
        // refill a budget. Three processes, one budget of two.
        let dir = TempDir::new("binding-spend-persists");
        let key = name("api.token");
        {
            let (store, _time) = open_with_clock(&dir);
            store.set(&key, sealed(MATERIAL)).unwrap();
            let mut binding = full_binding();
            binding.budget = Some(UseBudget {
                uses: 2,
                window_secs: 3_600,
            });
            store.bind(&key, binding).unwrap();
            assert!(store.evaluate(&key, &ok_request()).is_ok());
        }
        {
            let (store, _time) = open_with_clock(&dir);
            assert!(store.evaluate(&key, &ok_request()).is_ok());
        }
        let (store, _time) = open_with_clock(&dir);
        let refused = store.evaluate(&key, &ok_request()).unwrap_err();
        assert!(
            matches!(&refused, BindingDenial::BudgetExhausted { uses: 2, .. }),
            "two uses were spent across two prior processes: {refused:?}"
        );
    }

    // - Composition with the store: versions, rotation, the write surface -

    #[test]
    fn evaluation_mints_against_the_current_version_and_a_grant_pins_its_own() {
        let (store, _time) = ephemeral_with_clock();
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();
        store.bind(&key, full_binding()).unwrap();

        // A grant minted before rotation carries version one, and still resolves version
        // one afterwards: the version was chosen at mint, and the overlap window is what
        // lets the call that already holds the grant finish (SB-14).
        let before = store.evaluate(&key, &ok_request()).unwrap();
        assert_eq!(before.version(), Version::first());
        store.rotate(&key, sealed(b"rt5xp1-vv7qn2-kd8mz4")).unwrap();
        let resolved = store.resolve(before).unwrap();
        assert_eq!(exposed(&resolved), MATERIAL.to_vec());

        // A fresh evaluation mints against the rotated current version, never the
        // superseded one: the window drains old calls, it does not feed new ones.
        let after = store.evaluate(&key, &ok_request()).unwrap();
        assert_eq!(after.version(), Version::first().next());
        assert_eq!(
            exposed(&store.resolve(after).unwrap()),
            b"rt5xp1-vv7qn2-kd8mz4".to_vec()
        );
    }

    #[test]
    fn rebinding_replaces_the_terms_whole_and_opens_a_fresh_budget_regime() {
        let (store, _time) = ephemeral_with_clock();
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();
        let mut binding = full_binding();
        binding.budget = Some(UseBudget {
            uses: 1,
            window_secs: 3_600,
        });
        store.bind(&key, binding.clone()).unwrap();
        assert!(store.evaluate(&key, &ok_request()).is_ok());
        assert_eq!(
            store.evaluate(&key, &ok_request()).unwrap_err().rule(),
            "use-budget"
        );

        // The operator rewrites the binding: a new regime, spend state reset. An operator
        // action, so INV-4's "nothing a caller supplies can widen" is not in play.
        store.bind(&key, binding).unwrap();
        assert!(store.evaluate(&key, &ok_request()).is_ok());
    }

    #[test]
    fn bind_refuses_what_the_store_cannot_hold_and_accepts_a_quarantined_key() {
        let (store, _time) = ephemeral_with_clock();
        let ghost = name("ghost.token");
        let refused = store.bind(&ghost, full_binding()).unwrap_err();
        assert!(
            matches!(&refused, StoreError::UnknownSecret { .. }),
            "{refused:?}"
        );

        // Binding a quarantined key is legal: the binding is authorization metadata that
        // takes effect when the key returns to service, and evaluation refuses on state
        // either way.
        let key = name("api.token");
        store.set(&key, sealed(MATERIAL)).unwrap();
        store.quarantine(&key).unwrap();
        store.bind(&key, full_binding()).unwrap();
        assert_eq!(
            store.evaluate(&key, &ok_request()).unwrap_err().rule(),
            "key-state"
        );
        store.restore(&key).unwrap();
        assert!(store.evaluate(&key, &ok_request()).is_ok());
    }

    #[test]
    fn evaluation_refuses_an_unknown_key_and_a_damaged_one_with_the_rule_named() {
        let dir = TempDir::new("binding-damaged");
        let key = name("api.token");
        {
            let (store, _time) = open_with_clock(&dir);
            store.set(&key, sealed(MATERIAL)).unwrap();
            store.bind(&key, full_binding()).unwrap();

            let ghost = store
                .evaluate(&name("ghost.token"), &ok_request())
                .unwrap_err();
            assert!(
                matches!(&ghost, BindingDenial::UnknownSecret { .. }),
                "{ghost:?}"
            );
            assert_eq!(ghost.rule(), "unknown-secret");
        }
        // The document is damaged on disk: evaluation fails closed with the damage named,
        // and both bind and evaluate refuse to touch it.
        let file = dir
            .path()
            .join("store")
            .join("secrets")
            .join("api.token.json");
        std::fs::write(&file, b"not json at all \x7f\x03").unwrap();
        let (store, _time) = open_with_clock(&dir);
        let refused = store.evaluate(&key, &ok_request()).unwrap_err();
        assert!(
            matches!(&refused, BindingDenial::DamagedEntry { .. }),
            "{refused:?}"
        );
        assert_eq!(refused.rule(), "damaged-entry");
        assert!(matches!(
            store.bind(&key, full_binding()).unwrap_err(),
            StoreError::DamagedEntry { .. }
        ));
    }

    // - The document format: schema, round trip, foreign shapes -

    #[test]
    fn the_binding_block_round_trips_through_the_document_and_records_its_spend() {
        let dir = TempDir::new("binding-roundtrip");
        let key = name("api.token");
        let read_doc = || -> serde_json::Value {
            serde_json::from_str(
                &std::fs::read_to_string(
                    dir.path()
                        .join("store")
                        .join("secrets")
                        .join("api.token.json"),
                )
                .unwrap(),
            )
            .unwrap()
        };
        {
            let (store, _time) = open_with_clock(&dir);
            store.set(&key, sealed(MATERIAL)).unwrap();
            // Unbound: the document carries no binding block at all, which is exactly the
            // shape of every document written before bindings existed.
            assert!(read_doc().get("binding").is_none());

            let mut binding = full_binding();
            binding.roots = Vec::new(); // an empty list is serialized, not omitted
            binding.expires_at_unix_ms = Some(T0 + 3_600_000);
            binding.budget = Some(UseBudget {
                uses: 3,
                window_secs: 600,
            });
            store.bind(&key, binding).unwrap();
            let doc = read_doc();
            assert_eq!(doc["binding"]["schema"], 1);
            assert_eq!(doc["binding"]["terms"]["tools"][0], "exec.run");
            assert_eq!(doc["binding"]["terms"]["roots"], serde_json::json!([]));
            assert_eq!(
                doc["binding"]["terms"]["expires_at_unix_ms"],
                1_000_000 + 3_600_000
            );
            assert_eq!(doc["binding"]["terms"]["budget"]["uses"], 3);
            assert!(
                doc["binding"].get("spent").is_none(),
                "no spend state until a budgeted use happens"
            );

            // One budgeted use (the request carries no root, which the empty list permits
            // by not being consulted): the spend state lands in the document.
            let rootless =
                BindingRequest::new("exec.run", "operator.local").with_program("deployctl");
            assert!(store.evaluate(&key, &rootless).is_ok());
            let doc = read_doc();
            assert_eq!(doc["binding"]["spent"]["used"], 1);
            assert_eq!(doc["binding"]["spent"]["window_started_at_unix_ms"], T0);
        }
        // A second process reads the same terms back and enforces them.
        let (store, _time) = open_with_clock(&dir);
        assert_eq!(
            store
                .evaluate(&key, &ok_request().with_root("workspace.alpha"))
                .unwrap_err()
                .rule(),
            "root-allowlist",
            "the reopened store enforces the persisted empty root allowlist"
        );
    }

    #[test]
    fn foreign_fields_and_missing_lists_in_a_binding_block_isolate_the_document() {
        let dir = TempDir::new("binding-foreign");
        let store_dir = dir.path().join("store");
        let keys = ["extra.block", "extra.terms", "missing.list"];
        {
            let (store, _time) = open_with_clock(&dir);
            for key in keys {
                store.set(&name(key), sealed(MATERIAL)).unwrap();
                store.bind(&name(key), full_binding()).unwrap();
            }
        }
        // An unknown field beside the binding's own, an unknown field inside the terms, and
        // an allowlist somebody deleted: each is a foreign document, isolated whole rather
        // than half-read, because a tolerated unknown is a rule somebody believes is in
        // force (G-3) and an absent list would otherwise read as "any".
        tamper(&store_dir, "extra.block.json", |value| {
            value["binding"]["surprise"] = serde_json::json!(true);
        });
        tamper(&store_dir, "extra.terms.json", |value| {
            value["binding"]["terms"]["wildcard"] = serde_json::json!("*");
        });
        tamper(&store_dir, "missing.list.json", |value| {
            value["binding"]["terms"]
                .as_object_mut()
                .unwrap()
                .remove("callers");
        });

        let (store, _time) = open_with_clock(&dir);
        assert!(
            store.names().is_empty(),
            "all three documents are set aside"
        );
        let unreadable = store.unreadable();
        assert_eq!(unreadable.len(), 3);
        assert!(
            unreadable
                .iter()
                .all(|entry| entry.reason == UnreadableReason::NotASecretDocument)
        );
        for key in keys {
            assert_eq!(
                store
                    .evaluate(&name(key), &ok_request())
                    .unwrap_err()
                    .rule(),
                "damaged-entry"
            );
        }
    }

    #[test]
    fn a_newer_binding_schema_refuses_the_open_rather_than_being_guessed_at() {
        let dir = TempDir::new("binding-newer-schema");
        let key = name("api.token");
        {
            let (store, _time) = open_with_clock(&dir);
            store.set(&key, sealed(MATERIAL)).unwrap();
            store.bind(&key, full_binding()).unwrap();
        }
        tamper(&dir.path().join("store"), "api.token.json", |value| {
            value["binding"]["schema"] = serde_json::json!(2);
        });
        let refused = SealedStore::open(
            &dir.path().join("store"),
            Box::new(FileSealer::open(&dir.path().join("keys")).unwrap()),
        )
        .unwrap_err();
        match &refused {
            StoreError::UnknownBindingSchema { found, known, .. } => {
                assert_eq!(*found, 2);
                assert_eq!(*known, 1);
            }
            other => panic!("expected UnknownBindingSchema, got {other:?}"),
        }
        assert!(
            refused.to_string().contains("refused rather than guessed"),
            "{refused}"
        );
    }

    // - SB-1: the leak discipline, extended to BindingDenial -

    /// Every denial reachable from a key that holds material renders, in both `Display` and
    /// `Debug`, with no byte subsequence of that material: SB-1's rule as a measurement,
    /// extended to the binding evaluator's refusals.
    #[test]
    fn no_denial_reachable_from_material_describes_it() {
        let dir = TempDir::new("binding-leak");
        let key = name("api.token");
        let mut rendered: Vec<String> = Vec::new();
        let mut push = |denial: &BindingDenial| {
            rendered.push(denial.to_string());
            rendered.push(format!("{denial:?}"));
        };
        {
            let (store, _time) = open_with_clock(&dir);
            store.set(&key, sealed(MATERIAL)).unwrap();

            // Unbound, then each allowlist, then expiry, budget and state.
            push(&store.evaluate(&key, &ok_request()).unwrap_err());
            store.bind(&key, full_binding()).unwrap();
            push(
                &store
                    .evaluate(&key, &ok_request().with_program("sh"))
                    .unwrap_err(),
            );
            push(
                &store
                    .evaluate(&key, &ok_request().with_root("workspace.beta"))
                    .unwrap_err(),
            );
            push(
                &store
                    .evaluate(&key, &BindingRequest::new("web.fetch", "operator.local"))
                    .unwrap_err(),
            );
            push(
                &store
                    .evaluate(
                        &key,
                        &BindingRequest::new("exec.run", "visitor.remote")
                            .with_program("deployctl")
                            .with_root("workspace.alpha"),
                    )
                    .unwrap_err(),
            );
            let mut expired = full_binding();
            expired.expires_at_unix_ms = Some(T0);
            store.bind(&key, expired).unwrap();
            push(&store.evaluate(&key, &ok_request()).unwrap_err());
            let mut metered = full_binding();
            metered.budget = Some(UseBudget {
                uses: 0,
                window_secs: 60,
            });
            store.bind(&key, metered).unwrap();
            push(&store.evaluate(&key, &ok_request()).unwrap_err());
            store.bind(&key, full_binding()).unwrap();
            store.quarantine(&key).unwrap();
            push(&store.evaluate(&key, &ok_request()).unwrap_err());
            push(
                &store
                    .evaluate(&name("ghost.token"), &ok_request())
                    .unwrap_err(),
            );

            // The write-refusal variant, constructed where it is built in production, so
            // its rendering is measured even though provoking a mid-evaluation write
            // failure portably is not worth a platform-conditional test.
            push(&BindingDenial::UseNotRecorded {
                name: key.to_string(),
                source: Box::new(StoreError::Unwritable {
                    path: "store/secrets/api.token.json".to_string(),
                    reason: "permission denied".to_string(),
                }),
            });
        }
        // A damaged document whose bytes still hold the sealed blob of the material.
        let file = dir
            .path()
            .join("store")
            .join("secrets")
            .join("api.token.json");
        std::fs::write(&file, b"{ broken \x7f").unwrap();
        let (store, _time) = open_with_clock(&dir);
        let damaged = store.evaluate(&key, &ok_request()).unwrap_err();
        rendered.push(damaged.to_string());
        rendered.push(format!("{damaged:?}"));

        assert_eq!(rendered.len(), 22, "eleven denials, two renderings each");
        for text in &rendered {
            assert_material_absent(text, MATERIAL);
        }
    }
}
