//! Model Context Platform - tool router and middleware ring.
//!
//! ## Architecture
//!
//! [`Router::dispatch`] is the ring, and its stage order is frozen by NMCP-SPEC-003
//! section 4.6. No stage may be reordered without a spec revision.
//!
//! ```text
//! MCP client request                                        RequestState
//!   - Router::dispatch()                                    Received
//!       0  DeleteGuard              (INV-1, before the registry is consulted)
//!       1  resolve                  (one hash lookup in the ToolRegistry)
//!       2  profile visibility       (after resolution: the public name is lossy)
//!       3  upstream admission       (provider_id != "" only)
//!                                   any of 0..3 refusing:   -> Rejected
//!       4  authorize                (the declaration becomes a GrantedAuthority)
//!                                                           Authorizing
//!       5  approval gate, ABAC, HITL                        -> Rejected on deny
//!       5b secret resolution       (NMCP-SPEC-002 SB-5)     -> Rejected on refusal
//!       6  audit intent record      (INV-3 gate, durable before any effect)
//!                                                           Recorded
//!       7  provider.call(.., granted)                       Executed
//!       8  audit outcome record                             Completed
//!   - ToolCallResult - JSON-RPC response
//! ```
//!
//! Providers implement [`ToolProvider`] and are registered through [`Router::register`],
//! which delegates to the injected [`ToolRegistry`]. The ring applies identically to local and
//! proxied (gateway) calls.
//!
//! ## How the stage order is held
//!
//! By the compiler, for the transitions, and by a test for the rest. The right-hand column
//! above is [`nmcp_schema::RequestState`], and the ring walks it through the linear typestate
//! guard beside it: one type per state, each advance consuming the previous guard, and an
//! advance method present only where section 4.6 has an edge. The ring's body returns a
//! [`nmcp_schema::SettledRequest`], which no crate outside `nmcp-schema` can construct and
//! which only a terminal guard produces, so an exit that skipped or reordered a transition does
//! not compile at the `return` rather than failing a test somebody has to have written (RC-22).
//!
//! Two limits, stated here because a guard that oversells itself is worse than none. Stages 0
//! through 3 all sit in `Received` and are indistinguishable to a guard keyed on state, so
//! their relative order is `the_ring_refuses_in_the_frozen_stage_order`'s job and the guard does
//! not claim it. And the guard constrains the order of transitions, not that the side effect
//! each stage names succeeded: `audit_intent` warns and continues if the sink refuses, so
//! `Recorded` means stage 6 ran, not that the record is on disk. Binding those would change
//! what the server does, which RC-22 forbids, and `the_intent_record_is_durable_before_the_provider_runs`
//! is what grades the durability.
//!
//! ## What the ring knows about a tool, and where it learns it
//!
//! From the tool's own declaration, except where trusting the declaration would let the
//! declarer widen its own authority. Until I-047d this crate carried a compiled-in table of
//! about forty first-party tool names deciding required permission, path arguments and the
//! Windows API grant, plus a name-keyed mutation classifier. NMCP-SPEC-003 RC-D3 makes those
//! derived rather than authoritative and RC-A1 requires their deletion; the ring now reads
//! [`nmcp_schema::ToolAuthority`] out of the registry and hands it to
//! [`nmcp_schema::authorize`].
//!
//! The exception is stage 5, and it is half the design rather than a caveat. A declaration
//! from a non-empty `provider_id` is built from a remote server's `tools/list` response, which
//! is attacker-controlled data, so the approval gate reads
//! `!auto_approve && (third_party || effect == Mutate)` with `third_party` first and not
//! conditional on anything declared (RC-D4, RC-13, M6).

use nmcp_audit::{AuditEvent, AuditSink};
use nmcp_policy::{Permission, PolicyConfig};
use nmcp_schema::{
    CapabilityGrant, CatalogView, Denial, GrantedAuthority, HeldAuthority, InjectionModality,
    RegistrationError, RequestReceived, ResolvedSecrets, SECRET_SLOT_MARKER, SealedSecret,
    SecretRef, SecretSlotCatalog, SettledRequest, ToolAuthority, ToolEffect, ToolRegistry,
    authorize,
};
use nmcp_secrets::{BindingRequest, SealedStore, SecretName};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

// - CallContext and ToolCallResult -

/// The per-call context and the per-call result, re-exported from `nmcp-schema`.
///
/// Both moved there under NMCP-SPEC-003 section 4.3, RATIFIED v1.1, which puts them in the
/// contract crate alongside the `ToolProvider` trait that names both in one signature. They
/// are re-exported here so every existing `use nmcp_router::{CallContext, ToolCallResult}`
/// keeps compiling; `the_re_export_is_the_same_type_the_contract_crate_defines` below is
/// what keeps that true once this workspace's own dependents stop going through it.
///
/// `CallContext` took the two changes 4.3 requires and no others. `matched_root` is private
/// with a `matched_root()` reader, and its one setter takes a [`GrantedAuthority`] rather
/// than a bare root, so nothing can decide what a call resolved to without having asked.
/// And a private `secrets: ResolvedSecrets` appears with a reader, carried empty until
/// I-034 wired stage 5b, because adding a fifth parameter to a frozen trait method after
/// implementors exist is a breaking change to every one of them. `ToolCallResult` is
/// unchanged.
pub use nmcp_schema::{CallContext, ToolCallResult};

/// The public tool name derivation and its validator, re-exported from `nmcp-schema`.
///
/// Both moved there under NMCP-SPEC-003 RC-D6, because the registry that owns the
/// local-to-public mapping lives in the contract crate and a name derived in two places is
/// the defect that spec's section 1 measures. Behaviour is unchanged, which is what
/// `public_tool_names_are_claude_safe` below asserts on the same table it always did.
pub use nmcp_schema::{is_valid_public_tool_name, public_tool_name};

// - ToolProvider -

/// The provider trait, re-exported from `nmcp-schema`.
///
/// It moved there under NMCP-SPEC-003 section 4.3 for RC-D1's reason: a provider crate depends
/// on the contract and never on the kernel, which is what makes the open-core split hold at the
/// dependency level rather than by convention. Re-exported here so every existing
/// `use nmcp_router::ToolProvider` keeps compiling.
///
/// I-047d put it in 4.3's frozen shape. `call` takes `granted: &GrantedAuthority`, which is
/// what makes RC-A2 a property of the type system rather than of this ring's good behaviour,
/// and the transitional `tool_names` and `tool_list` are deleted in favour of
/// [`contracts`](ToolProvider::contracts).
pub use nmcp_schema::ToolProvider;
// - AbacCheck trait -

/// Decision returned by the ABAC stage.
#[derive(Debug, Clone)]
pub enum AbacDecision {
    /// The `Allow` case.
    Allow,
    /// The `Deny` case.
    Deny(String),
    /// Caller must await human approval; the concrete handler blocks.
    RequireApproval,
}

/// Synchronous pre-call check. Implement in `nmcp-abac`; inject via `Router::set_abac`.
///
/// `evaluate` is sync so it does not introduce async complexity at the ring boundary.
/// The HITL async wait happens in `nmcp_abac::AbacStage::register_hitl`, called by the
/// router after this method returns `RequireApproval`.
pub trait AbacCheck: Send + Sync {
    /// Evaluate ABAC rules for a pending call.
    /// Called after authorization, before the provider call.
    fn evaluate(&self, ctx: &CallContext, tool_name: &str, args: &Value) -> AbacDecision;

    /// Block until the call is approved or denied/timed-out.
    /// Called only when `evaluate` returns `RequireApproval`.
    /// Must fail CLOSED on timeout.
    fn wait_for_approval<'a>(
        &'a self,
        ctx: &'a CallContext,
        tool_name: &'a str,
        args: &'a Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>;
}

// - DeleteGuard -

/// The INV-1 denylist and its predicate, imported from `nmcp-schema`.
///
/// Both moved there with the registry, which refuses a delete-denied name at registration
/// (`RegistrationError::DeleteDeniedName`, RC-A3) and does not live in this crate. A private
/// import rather than a re-export: this crate's public surface is unchanged, and the point of
/// the move is that the dispatch-time guard below and the registration-time refusal compare
/// against one table instead of two that can drift.
use nmcp_schema::contains_delete_intent;

/// Unconditional first stage of the ring. Applied to every call - local, proxied, OS, memory.
///
/// Stage 0, before the registry is consulted, so an unknown or misdeclared provider cannot
/// reach it (RC-A3). INV-1 is not delegable: a provider that declares itself non-destructive is
/// a provider grading its own homework, so this compares against a kernel-owned list of
/// forbidden verbs and consults no declaration.
fn delete_guard_check(tool_name: &str) -> Option<ToolCallResult> {
    if contains_delete_intent(tool_name) {
        warn!(tool = tool_name, "DeleteGuard: delete-named tool denied");
        Some(ToolCallResult::err(format!(
            "Tool '{tool_name}' is denied: the Model Context Platform enforces a \
             no-delete invariant. Use backup + rename for safe file replacement, \
             or TTL expiry for memory facts."
        )))
    } else {
        None
    }
}

// - Authorization -

/// What the caller actually holds, assembled from effective policy and the call context.
///
/// The other half of every [`authorize`] call, and the half a provider never sees or supplies.
/// `grants` is the union of the permissions granted on any root, which is exactly the rule the
/// deleted `has_windows_api_grant` and `has_windows_api_write_grant` applied: a capability is
/// held when some root grants it, independent of which root a path resolves to.
fn held_authority(policy: &PolicyConfig, ctx: &CallContext) -> HeldAuthority {
    HeldAuthority {
        roots: policy.roots.clone(),
        grants: policy
            .roots
            .iter()
            .flat_map(|root| root.permissions.iter())
            .map(|permission| CapabilityGrant::new(permission.as_str()))
            .collect(),
        agent_id: ctx.agent_id.clone(),
    }
}

/// Turn a refusal into the governed error a caller sees.
///
/// The message is the `Denial`'s own, which is why the six variants do not overlap: the audit
/// record and the caller both get the reason rather than a category. The `Policy denied:` prefix
/// and the `policy_denied` error kind are the ones the ring has always used, so nothing
/// downstream has to learn a new shape.
///
/// The remediation is chosen from the declared permission first for
/// [`Permission::GitPublish`], because that is the one capability whose remediation is a
/// deliberate operator decision rather than a path correction, and telling somebody to widen a
/// root when what they need is to approve outbound publishing sends them to the wrong place.
/// That special case is the deleted policy ring's, kept verbatim.
fn denial_result(declared: &ToolAuthority, denial: &Denial) -> ToolCallResult {
    let remediation = match denial {
        Denial::UnknownGrant(_) => {
            "This tool requires a capability no permission in this build defines. It cannot be \
             authorized by any policy; report it to whoever ships the provider."
        }
        Denial::MissingGrant(_) => {
            "Grant the required capability on a policy root chosen for it, or use a tool that \
             does not need it."
        }
        Denial::MissingPathArgument { .. } => {
            "Provide the required governed path argument for this tool."
        }
        Denial::UndeclaredPathUse { .. } => {
            "This tool declares no path authority, so it cannot be pointed at a path. Use a tool \
             that does."
        }
        Denial::SecretUnavailable { .. } => {
            "Store the referenced secret and bind it to this tool, program, root and caller \
             through the operator surface, or correct the reference this call carries. No policy \
             root change can grant it."
        }
        _ => match declared.permission {
            Some(Permission::GitPublish) => {
                "Grant the explicit git.publish permission on the repository root only after \
                 outbound git publishing is approved."
            }
            _ => {
                "Adjust the NativeMCP policy root permissions or use a path inside an approved \
                 root."
            }
        },
    };
    ToolCallResult::err_with_metadata(
        format!("Policy denied: {denial}"),
        "policy_denied",
        Some(remediation),
    )
}

// - Stage 5b: secret resolution (NMCP-SPEC-002 SB-5, I-034) -

/// The stage 5b wiring: the sealed store and the slot catalog, injected together.
///
/// Injected as one value on purpose, so the ring cannot be wired to resolve without being
/// able to read declarations or the other way around. The composer must pass the same
/// object behind [`SecretSlotCatalog`] that it passed to [`Router::new`] as the
/// [`ToolRegistry`]; `nmcp_host::IndexedToolRegistry` implements both, and two indexes is
/// how the slots the stage reads and the tool that resolves come to disagree.
///
/// A router with no [`SecretResolution`] wired treats stage 5b as inert: references stay
/// literal text in the arguments, which is what they are everywhere resolution does not
/// exist (SB-2, T3: a reference is a name, not material, and with no store in the process
/// there is no material anywhere to protect). SB-8's fail-closed rule governs a wired store
/// that refuses, not a composition that never had one; the composition that registers
/// slot-declaring tools and serves callers owes them this wiring, and I-031 is where that
/// composition lives.
#[derive(Clone)]
pub struct SecretResolution {
    store: Arc<SealedStore>,
    slots: Arc<dyn SecretSlotCatalog>,
}

impl SecretResolution {
    /// Wire a sealed store and the slot catalog the ring reads declarations from.
    #[must_use]
    pub fn new(store: Arc<SealedStore>, slots: Arc<dyn SecretSlotCatalog>) -> Self {
        Self { store, slots }
    }
}

/// What stage 5b hands the two post-resolution audit records (SB-7).
///
/// Names, versions and rules only, never material or a material-derived value (SB-1). On a
/// call that resolved several slots each field is comma-joined in slot order, aligned index
/// for index; the SB-2 grammar admits no comma, so the join is unambiguous. On a refusal
/// the version is absent when the stage refused before a version was chosen.
struct SecretUseStamp {
    name: Option<String>,
    version: Option<String>,
    rule: Option<String>,
}

/// Everything one successful stage 5b run produces: the channel for the provider and the
/// stamp for the audit pair.
struct ResolvedForCall {
    secrets: ResolvedSecrets,
    stamp: SecretUseStamp,
}

/// A stage 5b refusal: the denial the caller sees and the stamp the denied record carries.
struct SecretRefusal {
    denial: Denial,
    stamp: SecretUseStamp,
}

impl SecretRefusal {
    /// A refusal with the governing rule named (SB-8), about `name` when one was parsed.
    fn new(rule: impl Into<String>, name: Option<&SecretName>) -> Self {
        let rule = rule.into();
        Self {
            denial: Denial::SecretUnavailable { rule: rule.clone() },
            stamp: SecretUseStamp {
                name: name.map(ToString::to_string),
                version: None,
                rule: Some(rule),
            },
        }
    }
}

/// Resolve every declared `secret_ref` slot whose argument carries a reference, replacing
/// each consumed reference with [`SECRET_SLOT_MARKER`] in the arguments the provider will
/// see.
///
/// The mechanics of stage 5b, called from exactly one place in [`Router::walk_the_ring`],
/// which keeps the stage's position, refusal path and state walk inline in the ring the way
/// stage 0 does with `delete_guard_check`. Per slot, in the declaration's argument order:
///
/// - an absent argument fires nothing: a slot the schema marks optional and the caller did
///   not use is no use, and nothing is evaluated or spent for it;
/// - a present argument that does not parse as a reference is refused,
///   `slot-requires-reference:<argument>`, because a declared slot receiving a non-reference
///   is a caller error the tool should not see: passing it through would run the tool with a
///   credential-shaped string where the tool was promised injected material, which fails
///   open in exactly the direction `RegistrationError::UndeclaredSecretSlot` exists to
///   refuse;
/// - a reference is evaluated (`SealedStore::evaluate`, which mints the single-use
///   `BindingGrant` and spends the budget at mint), resolved (consuming the grant),
///   converted to the schema carrier through the scoped-exposure API, and recorded in the
///   channel under its slot with its declared modality.
///
/// The binding request carries exactly what the call carries (I-036's vacuity rule): the
/// tool dimension is always the **derived public name**, whichever alias the caller
/// dispatched under, so an operator writes each binding against one stable name; the caller
/// dimension is `ctx.agent_id`, or the literal `local` for the population that has none,
/// matching the audit chain's own convention for the same callers; the program dimension is
/// carried only for an `env` slot whose arguments carry a `program` string, as its basename,
/// which is the name `nmcp-exec` allowlists; and the root dimension is carried only when
/// authorization resolved one, read from the proof.
///
/// # Errors
///
/// A [`SecretRefusal`] whose denial is [`Denial::SecretUnavailable`] with the governing
/// rule named (SB-8): the rule from `BindingDenial::rule()` or `ResolveError::rule()`, or
/// one of the stage's own for a malformed slot argument or an unreadable declaration.
fn resolve_secret_slots(
    stage: &SecretResolution,
    public_name: &str,
    granted: &GrantedAuthority,
    ctx: &CallContext,
    args: &mut Value,
) -> Result<Option<ResolvedForCall>, SecretRefusal> {
    let Some(slots) = stage.slots.secret_slots_of(public_name) else {
        // Resolved at stage 1 and gone from the catalog now: the declaration cannot be
        // read, so nothing proves the reference-shaped argument below is not a declared
        // slot. Fail closed on the evidence (SB-8) rather than letting a possible slot's
        // reference travel to the provider; with no reference present there is nothing a
        // slot could have asked for, and the call proceeds.
        if let Some(object) = args.as_object()
            && object
                .values()
                .filter_map(Value::as_str)
                .any(|text| SecretRef::parse(text).is_ok())
        {
            return Err(SecretRefusal::new("slots-unreadable", None));
        }
        return Ok(None);
    };

    let mut secrets = ResolvedSecrets::default();
    let mut names: Vec<String> = Vec::new();
    let mut versions: Vec<String> = Vec::new();
    let mut rules: Vec<String> = Vec::new();

    for slot in slots {
        let Some(supplied) = args.get(&slot.arg) else {
            continue;
        };
        let reference = supplied
            .as_str()
            .and_then(|text| SecretRef::parse(text).ok());
        let Some(reference) = reference else {
            return Err(SecretRefusal::new(
                format!("slot-requires-reference:{}", slot.arg),
                None,
            ));
        };
        let name = SecretName::from(&reference);

        let mut request = BindingRequest::new(
            public_name,
            ctx.agent_id.clone().unwrap_or_else(|| "local".to_string()),
        );
        if matches!(slot.modality, InjectionModality::Env { .. })
            && let Some(program) = args.get("program").and_then(Value::as_str)
            && let Some(basename) = std::path::Path::new(program).file_name()
        {
            request = request.with_program(basename.to_string_lossy());
        }
        if let Some(root) = granted.matched_root() {
            request = request.with_root(&root.id);
        }

        let grant = stage
            .store
            .evaluate(&name, &request)
            .map_err(|denial| SecretRefusal::new(denial.rule(), Some(&name)))?;
        // Read off the grant before `resolve` consumes it: the record must name the
        // version that was authorized, not one looked up again afterwards (SB-R5).
        names.push(grant.name().to_string());
        versions.push(grant.version().to_string());
        rules.push(grant.rule().to_string());

        let sealed = stage
            .store
            .resolve(grant)
            .map_err(|refused| SecretRefusal::new(refused.rule(), Some(&name)))?;
        // The one conversion between the two sealed types, through the scoped API. The
        // copy is the price of the dependency direction the carrier's documentation
        // argues; both allocations zeroize on their own drop, and the store's drops here.
        let carrier = sealed.with_exposed(|bytes| SealedSecret::new(bytes.clone()));
        drop(sealed);
        secrets.insert(slot.arg.clone(), slot.modality, carrier);

        // The reference is removed from the arguments the provider sees: material travels
        // through the context channel, and a reference reaching a child process's argv via
        // a confused provider is the exposure SB-A2 exists to prevent. `as_object_mut`
        // succeeds because `args.get` above just read this same object.
        if let Some(object) = args.as_object_mut() {
            object.insert(slot.arg, Value::String(SECRET_SLOT_MARKER.to_string()));
        }
    }

    if secrets.is_empty() {
        return Ok(None);
    }
    Ok(Some(ResolvedForCall {
        secrets,
        stamp: SecretUseStamp {
            name: Some(names.join(",")),
            version: Some(versions.join(",")),
            rule: Some(rules.join(",")),
        },
    }))
}

// - AuditRing -

/// Write the ring's pre-effect record for a call that passed every gate (RC-16).
///
/// Stage 6, and the INV-3 gate expressed in the ring rather than only in the crate that
/// performs the effect. It is written after authorization, ABAC and any human approval have all
/// said yes and before [`ToolProvider::call`] is reached, so an effect that begins and never
/// returns still left a durable record saying it was about to begin. `AuditSink::append` syncs,
/// so "written" and "durable" are the same moment.
///
/// It carries no verdict and no duration: the verdict is the outcome record's to state and the
/// clock has not stopped. `nmcp_audit::INTENT_DECISION` is deliberately not an authorization
/// decision, so nothing that counts allowed calls counts this one twice. The two records share
/// one `call_id`, which is how a reader pairs them and how it finds an intent with no outcome.
fn audit_intent(
    sink: &AuditSink,
    tool_name: &str,
    ctx: &CallContext,
    permission: Option<Permission>,
    secret_use: Option<&SecretUseStamp>,
) {
    let mut event = AuditEvent::new(tool_name, format!("intent tool={tool_name}"));
    event.decision = nmcp_audit::INTENT_DECISION.to_string();
    stamp_caller(&mut event, ctx);
    event.permission = permission.map(|p| p.as_str().to_string());
    stamp_secret_use(&mut event, secret_use);
    if let Some(root) = ctx.matched_root() {
        event.normalized_path = Some(root.path.display().to_string());
    }
    if let Err(e) = sink.append(&event) {
        warn!(call_id = %ctx.call_id, "AuditRing: failed to write intent event: {e}");
    }
}

/// Copy what stage 5b decided onto a record, the same way for every record that carries it.
///
/// SB-7: the intent record and the outcome record of a resolving call both name the key,
/// version and binding rule, and the denied record of a refused one names the key when it
/// was parsed and the rule that refused. One function so the pair cannot disagree, exactly
/// as [`stamp_caller`] argues for the caller's identity. Names and rules only, never
/// material (SB-1).
fn stamp_secret_use(event: &mut AuditEvent, secret_use: Option<&SecretUseStamp>) {
    if let Some(stamp) = secret_use {
        event.secret_name.clone_from(&stamp.name);
        event.secret_version.clone_from(&stamp.version);
        event.secret_rule.clone_from(&stamp.rule);
    }
}

/// Copy the caller's identity onto a record, the same way for both records a call writes.
///
/// One function rather than two copies, because the intent record and the outcome record have
/// to agree about who called: a pair that disagreed would be worse than either record alone.
fn stamp_caller(event: &mut AuditEvent, ctx: &CallContext) {
    // G3-15 AF-7. `client` is overloaded: it is the session id when there is one, and a
    // literal otherwise, and session replay filters on it. So the session id stays exactly
    // where it was, and only the "local" FALLBACK changes. On the 2026-07-28 revision the
    // session is deliberately None, which is why a call arriving through the tunnel used to
    // claim to be local; it now names the network it came from. A caller with no transport at
    // all, which is every CLI and test path, still reads "local".
    event.client = ctx
        .session_id
        .clone()
        .unwrap_or_else(|| ctx.peer.clone().unwrap_or_else(|| "local".to_string()));
    event.peer.clone_from(&ctx.peer);
    event.credential_path = ctx.credential_path.map(str::to_string);
    event.agent_id.clone_from(&ctx.agent_id);
    event.client_info.clone_from(&ctx.client_info);
    // The half of G4-26 nobody had noticed was missing. `AuditEvent::call_id` and
    // `CallContext::call_id` have both existed for a long time and were never connected, so
    // every authorization record ever written carries none. Without this the effect side has
    // nothing to join to, and after RC-16 it is also what pairs the intent record with its
    // outcome.
    event.call_id = Some(ctx.call_id);
}

/// Write the authorization record for a completed or denied call.
///
/// Stage 8, and one of the records a governed call produces (ADR-0005). This is the one
/// carrying the verdict, the duration and the caller. It does not carry the content hashes,
/// because the ring never sees the bytes; the effect record written where the effect happened
/// does.
///
/// `started` is the top of `dispatch`, not the provider call, so the recorded duration is
/// what the client actually waited: delete guard, resolution, authorization, ABAC, any human
/// approval wait, and the provider. A denial that took three seconds is then as visible as a
/// slow provider, and an operator sitting on approvals shows up in the latency history
/// rather than hiding behind a fast provider.
fn audit_record(
    sink: &AuditSink,
    tool_name: &str,
    ctx: &CallContext,
    result: &ToolCallResult,
    permission: Option<Permission>,
    secret_use: Option<&SecretUseStamp>,
    started: Instant,
) {
    let decision = if result.is_error {
        nmcp_audit::DENIED_DECISION
    } else {
        nmcp_audit::ALLOWED_DECISION
    };
    let summary = result
        .audit_payload
        .as_ref()
        .map_or_else(|| format!("tool={tool_name}"), ToString::to_string);

    let mut event = AuditEvent::new(tool_name, &summary);
    event.decision = decision.to_string();
    stamp_caller(&mut event, ctx);
    stamp_secret_use(&mut event, secret_use);
    // M4-1. The capability the ring required, taken from the tool's own declaration rather
    // than from anything the caller sent, so the Event Log mirror can give a read and an
    // execution different Event IDs and a SIEM rule can tell them apart without parsing a
    // body. Absent for a call refused before its declaration was read, which is the delete
    // guard and an unknown tool, and for any tool that declares no root-scoped permission.
    //
    // It used to come from a compiled-in table keyed by tool name, which meant it was absent
    // for every upstream tool. It now names whatever an upstream declared, which is accurate:
    // RC-D4 makes a declaration an additional precondition, so a declared permission is one
    // the ring genuinely required. The upstream's own admission capability is a separate
    // question answered at stage 3.
    event.permission = permission.map(|p| p.as_str().to_string());

    if let Some(root) = ctx.matched_root() {
        event.normalized_path = Some(root.path.display().to_string());
    }
    // Saturating rather than wrapping: a duration past u64 milliseconds is not real, and a
    // wrapped value would read as a suspiciously fast call rather than an obviously broken
    // one.
    event.duration_ms = Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));

    if let Err(e) = sink.append(&event) {
        warn!(call_id = %ctx.call_id, "AuditRing: failed to write audit event: {e}");
    }
}

// - Router -

/// The central dispatch point for all tool calls on the platform.
///
/// Register providers with [`Router::register`], which delegates to the [`ToolRegistry`] the
/// router was built with. The registry owns the local-to-public name mapping, refuses a
/// duplicate rather than shadowing it, and answers resolution in one hash lookup; the router
/// owns the ring order and nothing else about a tool.
///
/// The registry arrives as a `dyn` handle rather than a concrete type because the index lives
/// in `nmcp-host`, and NMCP-SPEC-003 RC-D1 fixes the edge between these two crates as
/// `nmcp-host -> nmcp-router`. That edge does not exist yet: `nmcp-host` currently depends on
/// `nmcp-schema` and `nmcp-policy` only, and it takes the router edge at I-031, when the server
/// runtime is extracted into it. Naming the direction rather than asserting the edge matters
/// here, because it is the direction and not the presence that does the work: it keeps a
/// provider crate off the kernel, and it means this crate names the contract and never the
/// implementation. I-049 is what made the distinction load-bearing, since the reverse edge
/// would have been the cheap way to reach `RequestState` and would have made I-031 a cycle.
pub struct Router {
    registry: Arc<dyn ToolRegistry>,
    policy: Arc<parking_lot::RwLock<PolicyConfig>>,
    audit: AuditSink,
    /// The ABAC stage, behind a lock so RC-D7's one mutability rule holds for it too.
    ///
    /// `dispatch` clones the handle out and drops the guard **before** any `await`.
    /// `parking_lot::RwLockReadGuard` is `!Send`, `wait_for_approval` is awaited inside
    /// `dispatch`, and `dispatch` is served from an axum handler, so a guard held across that
    /// await makes the future `!Send` and does not compile. `dispatch_future_is_send` below is
    /// the compile-time assertion (RC-10).
    abac: parking_lot::RwLock<Option<Arc<dyn AbacCheck>>>,
    /// The stage 5b wiring, behind the same lock discipline as `abac` and for the same
    /// reasons: wired through `&self` after the router is shared (RC-D7), cloned out of the
    /// guard before any `await`. `None` leaves stage 5b inert; see [`SecretResolution`].
    secrets: parking_lot::RwLock<Option<SecretResolution>>,
}

impl Router {
    /// Build a router over a policy handle, an audit sink and a tool registry.
    pub fn new(
        policy: Arc<parking_lot::RwLock<PolicyConfig>>,
        audit: AuditSink,
        registry: Arc<dyn ToolRegistry>,
    ) -> Self {
        Self {
            registry,
            policy,
            audit,
            abac: parking_lot::RwLock::new(None),
            secrets: parking_lot::RwLock::new(None),
        }
    }

    /// Remove a provider and all its tools. `true` if one was present.
    ///
    /// Delegates to the registry, which removes every name form the provider contributed rather
    /// than the ones a caller can guess.
    pub fn unregister_provider(&self, provider_id: &str) -> bool {
        self.registry.unregister_provider(provider_id)
    }

    /// Register a tool provider, or refuse it with a reason.
    ///
    /// All-or-nothing (RC-D5): a provider whose third tool duplicates a public name registers
    /// none of its tools. Safe to call on a `SharedRouter` at runtime, because every registry
    /// method takes `&self` (RC-D7).
    ///
    /// Returning a `Result` is the point rather than a side effect. Registration used to return
    /// `()` and push onto a `Vec`, so a duplicate public name shadowed by registration order and
    /// an operator learned about it when a caller got the wrong tool.
    ///
    /// # Errors
    ///
    /// Returns the [`RegistrationError`] naming what was refused and what an operator has to
    /// change.
    pub fn register(&self, provider: Arc<dyn ToolProvider>) -> Result<(), RegistrationError> {
        let provider_id = provider.provider_id().to_string();
        self.registry.register(provider)?;
        info!(provider = provider_id, "Router: registered provider");
        Ok(())
    }

    /// Inject an ABAC stage into the router.
    ///
    /// `&self` per RC-D7: wire-up has one mutability rule, so a router already behind an `Arc`
    /// is still a router an approval workflow can be attached to. The asymmetry this replaces,
    /// where `register` took `&self` and `set_abac` took `&mut self`, was defensible as an
    /// accident and not as a design.
    ///
    /// The stage runs after authorization and before the provider call, on the single dispatch
    /// path.
    pub fn set_abac(&self, stage: Arc<dyn AbacCheck>) {
        *self.abac.write() = Some(stage);
    }

    /// Wire secret resolution into ring stage 5b (NMCP-SPEC-002 SB-5, I-034).
    ///
    /// `&self` per RC-D7, like every other wire-up method. Until this is called the stage
    /// is inert and references stay literal text; see [`SecretResolution`] for what the
    /// wiring carries and for the one-object rule its two halves must satisfy.
    pub fn set_secrets(&self, resolution: SecretResolution) {
        *self.secrets.write() = Some(resolution);
    }

    /// Merged, Claude-safe tool list for `tools/list` responses.
    /// NOT FOR A REQUEST PATH (G6-11).
    ///
    /// This is every tool of every registered provider, ignoring gateway profiles and caller
    /// allowlists, and it exists for the callers that legitimately have no session to scope to:
    /// readiness, doctor, and the no-delete sweep, which are asking about this process rather
    /// than about a caller. Answering a request with it hands a scoped session the full upstream
    /// and tool inventory the profile exists to hide.
    ///
    /// Every method that answers a caller must call [`Router::merged_tool_list_for`] with that
    /// session's profile and caller.
    #[must_use]
    pub fn merged_tool_list(&self) -> Vec<Value> {
        self.merged_tool_list_for(None, None)
    }

    /// The same list, scoped to one session's gateway profile and caller (G6-8, RC-D8).
    ///
    /// Delegates to [`ToolRegistry::list_for`], which is the point: the filter here and the
    /// check in `dispatch` are one implementation rather than two copies of a rule. A session
    /// that can see a tool it cannot call, or call one it cannot see, is worse than either
    /// restriction on its own.
    ///
    /// `agent_id` is a parameter because `CallerToolAllowlist` filtering is unconditional at
    /// list time (RC-D8) and inexpressible without knowing who is asking. It was already a
    /// call-time deny, so applying it here is a pure narrowing that closes G6-8's gap: a
    /// restricted caller used to see every tool and find out at the call.
    ///
    /// Permission-based filtering stays off (`filter_by: None`). RC-D8's second part is
    /// available and opt-in: a tool that vanishes from the catalogue is indistinguishable from
    /// a tool that does not exist, and the refusal path already gives a precise reason.
    #[must_use]
    pub fn merged_tool_list_for(
        &self,
        profile: Option<&str>,
        agent_id: Option<&str>,
    ) -> Vec<Value> {
        self.registry.list_for(&CatalogView {
            profile: profile.map(str::to_string),
            agent_id: agent_id.map(str::to_string),
            filter_by: None,
        })
    }

    /// Dispatch a tool call through the full middleware ring.
    ///
    /// The stage order is NMCP-SPEC-003 section 4.6, frozen at ratification. The ordering IS
    /// the governance; splitting it into helpers would scatter one decision procedure and
    /// invite a stage being skipped.
    ///
    /// This body unwraps the seal and nothing else. The decision procedure stays in one
    /// function, [`Router::walk_the_ring`], whose return type is a [`SettledRequest`] that only
    /// a terminal lifecycle guard can produce (RC-22). Splitting the *seal* off is what makes
    /// the ring's exits provable; splitting the *stages* off is what the paragraph above
    /// refuses, and this does not do that.
    pub async fn dispatch(&self, tool_name: &str, args: Value, ctx: CallContext) -> ToolCallResult {
        self.walk_the_ring(tool_name, args, ctx).await.into_inner()
    }

    /// The ring, from stage 0 to stage 8, with the lifecycle guard walked alongside it.
    ///
    /// Returning a [`SettledRequest`] rather than a [`ToolCallResult`] is the enforcement.
    /// `SettledRequest` has a private field in `nmcp-schema` and two constructors,
    /// `RequestRejected::settle` and `RequestCompleted::settle`, so every `return` below has to
    /// name a terminal guard, and a terminal guard is reachable only by advance methods that
    /// exist where section 4.6 has an edge. A stage that skipped a transition, took one out of
    /// order, or added an exit that walked nothing is a compile error at that `return`.
    ///
    /// Nothing here reads the guard. It is walked and never consulted, which is deliberate: the
    /// guard observes and constrains the sequence, and a state machine that changed a refusal
    /// reason, a decision or an audit record would not be observing the server.
    #[allow(clippy::too_many_lines)]
    async fn walk_the_ring(
        &self,
        tool_name: &str,
        args: Value,
        ctx: CallContext,
    ) -> SettledRequest {
        // Every exit from this function audits, and every audit records how long the client
        // waited to reach it.
        let started = Instant::now();

        // Off the transport, nothing evaluated. Stages 0 through 3 can only refuse from here,
        // which is the `Received -> Rejected` edge RC-15 added and the reason it had to exist.
        let state = RequestReceived::new();

        // - Stage 0: DeleteGuard -
        //
        // Before resolution, so an unknown or misdeclared provider cannot reach it (RC-A3).
        // INV-1 is enforced twice and this is the later of the two: the registry refuses a
        // delete-denied name at registration, so an operator wiring the server learns it
        // rather than a caller being denied forever.
        if let Some(denied) = delete_guard_check(tool_name) {
            audit_record(&self.audit, tool_name, &ctx, &denied, None, None, started);
            return state.rejected().settle(denied);
        }

        // - Stage 1: resolve -
        //
        // One hash lookup. `authority_of` is a second lookup rather than a field of the first
        // because authorization must be able to read the declaration without thereby obtaining
        // the ability to call. Both are populated by one insertion, so the only way the pair
        // disagrees is a provider unregistered between the two calls, which is an unknown tool
        // by the time the second lookup runs and is answered as one.
        let resolved = self
            .registry
            .resolve(tool_name)
            .zip(self.registry.authority_of(tool_name));
        let Some(((provider, local_name), declared)) = resolved else {
            let result = ToolCallResult::err_with_metadata(
                format!("Unknown tool: {tool_name}"),
                "command_not_found",
                Some("Call tools/list and retry with a registered tool name."),
            );
            audit_record(&self.audit, tool_name, &ctx, &result, None, None, started);
            return state.rejected().settle(result);
        };
        let permission = declared.permission;

        let policy = self.policy.read().clone();

        // - Stage 2: profile and allowlist visibility (G6-8) -
        //
        // After resolution, because the public tool name is lossy and not invertible, so the
        // only reliable way to know which upstream a call lands on is to have resolved the
        // provider. Before authorization because it is a visibility question rather than a
        // permission one: if this session cannot reach the server at all, nothing about the
        // tool's own declaration matters.
        //
        // The allowlist half of this stage is `AbacRule::CallerToolAllowlist`, and it is
        // evaluated once rather than twice. At list time `ToolRegistry::list_for` applies it
        // unconditionally (RC-D8), which is what closed G6-8; at call time the ABAC stage below
        // applies it, which is where the base put it and where its refusal names the rule that
        // refused. A second evaluation here would reach the identical verdict by a different
        // path and would replace that reason with a vaguer one, and two copies of a rule is how
        // list and call come to disagree.
        if !policy.provider_visible_to_session(ctx.profile.as_deref(), provider.provider_id()) {
            let denied = ToolCallResult::err_with_metadata(
                format!("Tool '{tool_name}' is not in this session's gateway profile"),
                "policy_denied",
                Some(
                    "Call tools/list to see what this session can reach, or connect with a client bound to a profile that includes this server.",
                ),
            );
            audit_record(
                &self.audit,
                tool_name,
                &ctx,
                &denied,
                permission,
                None,
                started,
            );
            return state.rejected().settle(denied);
        }

        // - Stage 3: upstream admission (G4-28) -
        //
        // The ring cannot govern what an admitted upstream does. A stdio or container upstream
        // is a child process of the daemon, an HTTP one is somebody else's server, and neither
        // goes through nmcp-fs, so no root permission constrains it. What the ring can govern is
        // whether its tools are reachable, and that is what this asks.
        //
        // Before authorization for the same reason the profile check is: if the caller may not
        // reach this upstream at all, nothing about an individual tool matters.
        if !provider.provider_id().is_empty() {
            let denied = match policy.upstream_admission(provider.provider_id()) {
                nmcp_policy::UpstreamAdmission::Granted { .. } => None,
                nmcp_policy::UpstreamAdmission::MissingGrant { permission } => {
                    let remediation = format!(
                        "Grant {permission} on a policy root chosen for this upstream, or disable the upstream."
                    );
                    Some(ToolCallResult::err_with_metadata(
                        format!(
                            "Policy denied: upstream '{}' requires the {permission} capability",
                            provider.provider_id()
                        ),
                        "policy_denied",
                        Some(remediation.as_str()),
                    ))
                }
                // Both of the remaining cases mean the policy in memory says less than
                // validate_semantics requires, so the safe reading is that it was never
                // validated. Refuse rather than infer an intent nobody wrote down.
                nmcp_policy::UpstreamAdmission::Undeclared => {
                    Some(ToolCallResult::err_with_metadata(
                        format!(
                            "Policy denied: upstream '{}' declares no required_permission",
                            provider.provider_id()
                        ),
                        "policy_denied",
                        Some(
                            "Set required_permission on this upstream. A validated policy cannot enable an upstream without one.",
                        ),
                    ))
                }
                nmcp_policy::UpstreamAdmission::NotAdmitted => {
                    Some(ToolCallResult::err_with_metadata(
                        format!(
                            "Policy denied: no upstream named '{}' is admitted by policy",
                            provider.provider_id()
                        ),
                        "policy_denied",
                        Some("Add this upstream to the policy, or unregister the provider."),
                    ))
                }
            };
            if let Some(denied) = denied {
                audit_record(
                    &self.audit,
                    tool_name,
                    &ctx,
                    &denied,
                    permission,
                    None,
                    started,
                );
                return state.rejected().settle(denied);
            }
        }

        // - Stage 4: authorize -
        //
        // The only consumer of `ToolAuthority`, and the only producer of `GrantedAuthority`.
        // The declaration is an additional precondition and never a grant (RC-D4): a tool
        // declaring `Read` is still refused when the caller lacks Read, still refused when the
        // path resolves outside every root, and a tool declaring no permission is restricted to
        // operations needing none rather than exempted from the question.
        //
        // This is also where RC-20 lands. The kernel used to resolve a root from the first
        // present of a compiled-in list of argument names that included `repo`, `repo_path`,
        // `repository`, `repository_path` and `cwd`, while the dev tools read `path` and their
        // schemas defined none of the others. The declaration is filtered to the tool's own
        // schema by RC-D5, so the argument the ring authorizes and the argument the tool reads
        // are the same argument by construction, which is what made deleting the provider-side
        // re-check safe rather than merely tidy.
        //
        // The state advances here rather than after `authorize` returns, because the table's
        // third column reads "`Authorizing`, then `Rejected` on `Denial`": a call that was
        // refused by authorization did enter authorization, and that is the difference this
        // state carries against stages 0 through 3.
        let state = state.authorizing();
        let held = held_authority(&policy, &ctx);
        let granted = match authorize(&declared, &held, &args) {
            Ok(granted) => granted,
            Err(denial) => {
                warn!(tool = tool_name, "PolicyRing: denied - {denial}");
                let denied = denial_result(&declared, &denial);
                audit_record(
                    &self.audit,
                    tool_name,
                    &ctx,
                    &denied,
                    permission,
                    None,
                    started,
                );
                return state.rejected().settle(denied);
            }
        };
        // The resolved root reaches the context only through the proof that it was resolved.
        let ctx = ctx.with_granted(&granted);

        // - Stage 5: approval gate, then ABAC, then HITL -
        //
        // RC-13, and the one line in this function where trusting a declaration would be a
        // vulnerability rather than a bug. `third_party` is first and is not conditional on
        // anything the provider declared: an upstream's `ToolContract` is built from a remote
        // server's `tools/list` response, so `effect` is attacker-controlled, and an
        // implementation that read `effect == Mutate` alone would hand a remote server the
        // ability to switch off its own approval gate by declaring `Observe`.
        //
        // For a third-party tool the honest answer to "does this mutate" is that nobody here
        // knows, and unknown belongs on the gated side (M6). Keyed off the resolved provider
        // rather than the tool name, because the name carries no information here. Inert while
        // auto_approve is true, which is the default and what the live policy runs.
        let third_party = !provider.provider_id().is_empty();
        let mut require_approval =
            !policy.auto_approve && (third_party || declared.effect == ToolEffect::Mutate);

        // Cloned out of the lock, and the guard dropped at the end of this statement, BEFORE
        // the `await` below. `parking_lot::RwLockReadGuard` is `!Send` and `dispatch` is served
        // from an axum handler, so a guard alive across the await makes this future `!Send`
        // (RC-D7, RC-10).
        let abac = self.abac.read().clone();
        if let Some(ref abac) = abac {
            match abac.evaluate(&ctx, tool_name, &args) {
                AbacDecision::Deny(reason) => {
                    let denied = ToolCallResult::err_with_metadata(
                        format!("ABAC denied: {reason}"),
                        "policy_denied",
                        Some(
                            "Review ABAC policy constraints or request approval through the configured workflow.",
                        ),
                    );
                    audit_record(
                        &self.audit,
                        tool_name,
                        &ctx,
                        &denied,
                        permission,
                        None,
                        started,
                    );
                    return state.rejected().settle(denied);
                }
                AbacDecision::RequireApproval => {
                    require_approval = true;
                }
                AbacDecision::Allow => {}
            }
        }
        if require_approval {
            // No approval workflow configured is a refusal, not a pass: this is
            // the fail-closed half of the gate and it must stay first.
            let Some(abac) = abac.as_ref() else {
                let denied = ToolCallResult::err_with_metadata(
                    "Approval required (auto_approve is disabled) but no approval workflow is configured".to_string(),
                    "policy_denied",
                    Some("Enable auto_approve or configure an ABAC approval workflow before invoking mutating tools."),
                );
                audit_record(
                    &self.audit,
                    tool_name,
                    &ctx,
                    &denied,
                    permission,
                    None,
                    started,
                );
                return state.rejected().settle(denied);
            };
            // Block until human approves or timeout fires (fail closed).
            let approved = abac.wait_for_approval(&ctx, tool_name, &args).await;
            if !approved {
                let denied = ToolCallResult::err_with_metadata(
                    "Approval denied: call rejected by operator or timed out".to_string(),
                    "approval_denied",
                    Some("Retry only after operator approval or adjust the HITL policy."),
                );
                audit_record(
                    &self.audit,
                    tool_name,
                    &ctx,
                    &denied,
                    permission,
                    None,
                    started,
                );
                return state.rejected().settle(denied);
            }
        }

        // - Stage 5b: secret resolution (NMCP-SPEC-002 SB-5, I-034) -
        //
        // Its position is NMCP-SPEC-003 section 4.6's two frozen constraints, honoured
        // exactly: after the approval gate, because resolving a credential for a call a human
        // then refuses is a use that should never have happened, and before the intent record
        // below, because that record names the key, version and binding decision, and a record
        // written ahead of the decision it describes asserts an outcome that could not have
        // been known. SPEC-002's architecture block says "nmcp-host: stage 5b resolution"; the
        // ring is one function and it lives here until I-031 moves composition, and 4.6, the
        // governing frozen text, constrains position rather than crate.
        //
        // Fires only when the resolved tool's contract declares `secret_ref` slots AND the
        // slot's argument parses as a reference; a reference in any other parameter is
        // literal text (SB-2), which `a_tool_with_no_slots_passes_a_reference_through_inert`
        // holds the ring to. A refusal is `Denial::SecretUnavailable` with the governing rule
        // named (SB-8), taking the `rejected()` path exactly as a stage 5 deny does: the
        // guard's `Authorizing -> Rejected` edge, no new edge needed, because 5b refusals
        // happen before `recorded()`. Resolved material reaches the provider only through
        // `CallContext::secrets`, and the consumed reference is replaced in the arguments by
        // `SECRET_SLOT_MARKER` (SB-A2). The material's lifetime runs from here to the end of
        // the call: the context is dropped when dispatch returns, and the tripwire scan that
        // extends the stated window to the scrub is I-035's.
        let stage5b = self.secrets.read().clone();
        let mut args = args;
        let resolved_use = match stage5b.as_ref() {
            None => None,
            Some(resolution) => {
                // Bindings name tools by the derived public name, whichever alias the
                // caller dispatched under, so one binding governs every name form.
                let public_name = public_tool_name(provider.provider_id(), &local_name);
                match resolve_secret_slots(resolution, &public_name, &granted, &ctx, &mut args) {
                    Ok(resolved) => resolved,
                    Err(refusal) => {
                        warn!(tool = tool_name, "SecretRing: denied - {}", refusal.denial);
                        let denied = denial_result(&declared, &refusal.denial);
                        audit_record(
                            &self.audit,
                            tool_name,
                            &ctx,
                            &denied,
                            permission,
                            Some(&refusal.stamp),
                            started,
                        );
                        return state.rejected().settle(denied);
                    }
                }
            }
        };
        let (ctx, secret_use) = match resolved_use {
            Some(resolved) => (ctx.with_secrets(resolved.secrets), Some(resolved.stamp)),
            None => (ctx, None),
        };

        // - Stage 6: audit intent record -
        //
        // INV-3's gate in the ring (RC-16). Durable before any effect, and written only once
        // every gate above has said yes, so an intent record is a statement that this call was
        // about to run rather than that somebody asked for it. For a call that resolved
        // secrets it names the key, version and binding rule (SB-7), which stage 5b has
        // decided by now; that ordering is the whole reason 5b sits above this line.
        audit_intent(
            &self.audit,
            tool_name,
            &ctx,
            permission,
            secret_use.as_ref(),
        );
        let state = state.recorded();

        // - Stage 7: provider call -
        //
        // The provider sees arguments, context and proof, and nothing else. `granted` is
        // unforgeable outside `nmcp-schema`, so there is no expression that reaches this line
        // without stage 4 having returned `Ok` (RC-A2).
        let result = provider.call(&local_name, args, &ctx, &granted).await;
        // Whatever the provider answered, including an error of its own, the ring executed the
        // call. A provider-level failure is not a refusal, which is why there is no
        // `Executed -> Rejected` edge to take here.
        let state = state.executed();

        // - Stage 8: audit outcome record -
        //
        // The other half of SB-7's pair: the outcome record of a call that resolved secrets
        // carries the same key, version and rule as its intent record, on one call_id.
        audit_record(
            &self.audit,
            tool_name,
            &ctx,
            &result,
            permission,
            secret_use.as_ref(),
            started,
        );

        state.completed().settle(result)
    }
}

/// RC-10, the compile-time half, and the reason the ABAC handle is cloned out of its lock.
///
/// Never called. It exists so the compiler refuses a `dispatch` whose future is `!Send`, which
/// is what a `parking_lot` guard held across the `wait_for_approval` await produces. The failure
/// this pins is not hypothetical: NMCP-SPEC-003 RC-D7 records it as one of the compile-level
/// defects an adversarial review found in the v0.1 signatures, and an axum handler is where it
/// would surface, one crate away from the code that caused it.
///
/// `assert_send::<T>()` is reached through a reference so the opaque future type can be
/// inferred; there is no way to name it directly.
#[allow(dead_code)]
fn dispatch_future_is_send(router: &Router, args: Value, ctx: CallContext) {
    fn assert_send<T: Send>() {}
    fn over<T: Send>(_: &T) {
        assert_send::<T>();
    }
    over(&router.dispatch("tool", args, ctx));
}

// - Shared handle -

/// Clone-cheap handle to the router.
/// `register()` goes through the registry's own lock so providers can be added at runtime
/// without restarting the daemon.
pub type SharedRouter = Arc<Router>;

/// Build a shared router over a policy handle, an audit sink and a tool registry.
pub fn make_router(
    policy: Arc<parking_lot::RwLock<PolicyConfig>>,
    audit: AuditSink,
    registry: Arc<dyn ToolRegistry>,
) -> SharedRouter {
    Arc::new(Router::new(policy, audit, registry))
}

// - Tests -

#[cfg(test)]
mod tests {
    // The test ToolProvider impls return &str because the trait says so; they
    // cannot narrow to &'static str one impl at a time.
    #![allow(clippy::unnecessary_literal_bound)]
    // Tests assert on shapes and outcomes, where unwrap/expect/indexing
    // ARE the assertion: a panic in a test is the failure signal, so the
    // production rationale for the workspace denies does not apply.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    // Three tests here drive a whole ring or a whole grid and are long because the thing they
    // measure is long: the frozen stage order is nine stages, and RC-6's oracle is the deleted
    // table. Splitting either into helpers would put the ordering somewhere other than where it
    // is read, which is the same argument `dispatch` itself carries.
    #![allow(clippy::too_many_lines)]
    use super::*;
    // The trait moved to `nmcp-schema` and the ring no longer names the attribute, but the
    // test providers below still implement an async trait method and so still need it.
    use async_trait::async_trait;
    use nmcp_host::IndexedToolRegistry;
    use nmcp_policy::RootRule;
    use nmcp_schema::{GrantedAuthority, ToolContract, ToolReach};
    use serde_json::json;
    use std::sync::Arc;

    /// M4-1. The Event Log class comes from the permission the ring required, and the mapping
    /// from permission name to class lives in `mcp-audit`, which cannot depend on `mcp-policy`.
    /// This crate depends on both, so this is where the two are held together.
    ///
    /// The match has no wildcard on purpose. Adding a `Permission` variant stops this test
    /// compiling until somebody decides which class it belongs to, which is the whole point: a
    /// new capability that silently classified as Unclassified would be a new capability a SOC
    /// cannot see, and it would ship green.
    #[test]
    fn every_permission_has_an_event_log_class_a_soc_can_filter_on() {
        use nmcp_audit::EventLogClass;
        use nmcp_policy::Permission;

        let expectations = [
            (Permission::List, EventLogClass::Read),
            (Permission::Read, EventLogClass::Read),
            (Permission::Search, EventLogClass::Read),
            (Permission::Scan, EventLogClass::Read),
            (Permission::Report, EventLogClass::Read),
            (Permission::MemoryRead, EventLogClass::Read),
            (Permission::WindowsApi, EventLogClass::Read),
            (Permission::Create, EventLogClass::Change),
            (Permission::Write, EventLogClass::Change),
            (Permission::Modify, EventLogClass::Change),
            (Permission::Rename, EventLogClass::Change),
            (Permission::Move, EventLogClass::Change),
            (Permission::Backup, EventLogClass::Change),
            (Permission::MemoryWrite, EventLogClass::Change),
            (Permission::WindowsApiWrite, EventLogClass::Change),
            (Permission::Execute, EventLogClass::Execute),
            (Permission::GitPublish, EventLogClass::Egress),
            (Permission::UpstreamCall, EventLogClass::Egress),
        ];

        for (permission, expected) in expectations {
            let mut event = AuditEvent::new("tool", "summary");
            event.decision = nmcp_audit::ALLOWED_DECISION.into();
            event.permission = Some(permission.as_str().to_string());
            assert_eq!(
                nmcp_audit::event_log_class(&event),
                expected,
                "{} classified wrongly",
                permission.as_str()
            );
        }

        // The forcing function. No wildcard, so a new variant is a compile error here, and the
        // author has to add it to `expectations` above and to the mapping in `mcp-audit`.
        for (permission, _) in expectations {
            match permission {
                Permission::List
                | Permission::Read
                | Permission::Search
                | Permission::Scan
                | Permission::Report
                | Permission::MemoryRead
                | Permission::WindowsApi
                | Permission::Create
                | Permission::Write
                | Permission::Modify
                | Permission::Rename
                | Permission::Move
                | Permission::Backup
                | Permission::MemoryWrite
                | Permission::WindowsApiWrite
                | Permission::Execute
                | Permission::GitPublish
                | Permission::UpstreamCall => {}
            }
        }
    }

    /// A router over a fresh audit file, the default policy and a real registry.
    ///
    /// The registry is `nmcp_host::IndexedToolRegistry`, the one the kernel ships, rather than
    /// a stand-in. NMCP-SPEC-003 RC-D1 puts the index in `nmcp-host` and `nmcp-host` will
    /// depend on this crate, so reaching it from here is a dev-dependency; a second index
    /// written to make these tests compile would mean every ring assertion below was measured
    /// against a fake, which is the one thing they must not be.
    fn make_test_router() -> Router {
        router_with(PolicyConfig::default(), None)
    }

    /// The registry and the router read one policy handle, not two copies.
    ///
    /// `list_for` answers profile scoping and caller allowlists from policy, and `dispatch`
    /// answers the same questions from the same place. Two handles is how a session comes to
    /// see a tool it cannot call.
    fn router_over(policy: PolicyConfig, audit: AuditSink) -> Router {
        let policy = Arc::new(parking_lot::RwLock::new(policy));
        let registry = Arc::new(IndexedToolRegistry::new(Arc::clone(&policy)));
        Router::new(policy, audit, registry)
    }

    fn temp_audit(label: &str) -> (std::path::PathBuf, AuditSink) {
        let path = std::env::temp_dir().join(format!(
            "nmcp-router-{label}-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let sink = AuditSink::open(&path).unwrap();
        (path, sink)
    }

    /// One declared tool for a test provider, needing no root-scoped authority.
    ///
    /// The shape a first-party tool with no entry in the deleted policy table had: the ring
    /// asked nothing of it then and asks nothing of it now, so `echo` and the namespaced
    /// fixtures below still reach their provider on an empty policy exactly as they did.
    fn test_contract(name: &str, effect: ToolEffect) -> ToolContract {
        ToolContract {
            name: name.to_string(),
            description: name.to_string(),
            input_schema: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
            authority: ToolAuthority {
                permission: None,
                path_args: Vec::new(),
                grants: Vec::new(),
                effect,
                reach: ToolReach::Local,
            },
            // Every fixture in this module is first-party or is an upstream that publishes
            // nothing, and RC-21 refuses a first-party tool that carries this at all.
            published_annotations: None,
        }
    }

    /// The same, declaring what the deleted `tool_policy_spec` said about this tool.
    ///
    /// The two fixtures that had a table entry, `write_text_file` and `dev.git_publish`, now
    /// declare it. That is a change of setup and not of assertion: the ring required `write` on
    /// the path argument before this commit and requires it after, and the tests that drive
    /// them measure the same thing at the same policy. Without the declaration those tools
    /// would ask for nothing, and the tests would keep passing while measuring less, which is
    /// the failure mode this whole PR is written against.
    fn specced_contract(name: &str, permission: Permission, effect: ToolEffect) -> ToolContract {
        let mut contract = test_contract(name, effect);
        contract.authority.permission = Some(permission);
        contract.authority.path_args = vec!["path".to_string()];
        contract
    }

    struct EchoProvider;

    #[async_trait]
    impl ToolProvider for EchoProvider {
        fn contract_version(&self) -> u32 {
            1
        }
        fn provider_id(&self) -> &str {
            ""
        }
        fn contracts(&self) -> Vec<ToolContract> {
            vec![test_contract("echo", ToolEffect::Observe)]
        }
        async fn call(
            &self,
            _name: &str,
            args: Value,
            _ctx: &CallContext,
            _granted: &GrantedAuthority,
        ) -> ToolCallResult {
            ToolCallResult::ok(args)
        }
    }

    // Provider whose tool declares a mutating permission (Write) on `path`, which is what
    // the deleted table said about `write_text_file`. Used to exercise the auto_approve gate.
    struct WriteProvider;

    #[async_trait]
    impl ToolProvider for WriteProvider {
        fn contract_version(&self) -> u32 {
            1
        }
        fn provider_id(&self) -> &str {
            ""
        }
        fn contracts(&self) -> Vec<ToolContract> {
            vec![specced_contract(
                "write_text_file",
                Permission::Write,
                ToolEffect::Mutate,
            )]
        }
        async fn call(
            &self,
            _name: &str,
            args: Value,
            _ctx: &CallContext,
            _granted: &GrantedAuthority,
        ) -> ToolCallResult {
            ToolCallResult::ok(args)
        }
    }

    #[derive(Clone, Copy)]
    enum StubMode {
        Allow,
        Deny,
        RequireApproval,
    }

    struct StubAbac {
        mode: StubMode,
        approve: bool,
    }

    impl AbacCheck for StubAbac {
        fn evaluate(&self, _ctx: &CallContext, _tool: &str, _args: &Value) -> AbacDecision {
            match self.mode {
                StubMode::Allow => AbacDecision::Allow,
                StubMode::Deny => AbacDecision::Deny("stub deny".into()),
                StubMode::RequireApproval => AbacDecision::RequireApproval,
            }
        }
        fn wait_for_approval<'a>(
            &'a self,
            _ctx: &'a CallContext,
            _tool: &'a str,
            _args: &'a Value,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
            let approve = self.approve;
            Box::pin(async move { approve })
        }
    }

    fn router_with(policy: PolicyConfig, abac: Option<Arc<dyn AbacCheck>>) -> Router {
        let (_, audit) = temp_audit("test");
        let router = router_over(policy, audit);
        if let Some(stage) = abac {
            // `&self`, per RC-D7. This used to need `let mut router` and had to happen before
            // the handle was shared; the asymmetry was defensible as an accident, not a design.
            router.set_abac(stage);
        }
        router
    }

    #[tokio::test]
    async fn abac_require_approval_runs_only_when_approved() {
        let router = router_with(
            PolicyConfig::default(),
            Some(Arc::new(StubAbac {
                mode: StubMode::RequireApproval,
                approve: true,
            })),
        );
        router.register(Arc::new(EchoProvider)).expect("register");
        let ok = router
            .dispatch("echo", json!({}), CallContext::new(None))
            .await;
        assert!(!ok.is_error);

        let router = router_with(
            PolicyConfig::default(),
            Some(Arc::new(StubAbac {
                mode: StubMode::RequireApproval,
                approve: false,
            })),
        );
        router.register(Arc::new(EchoProvider)).expect("register");
        let denied = router
            .dispatch("echo", json!({}), CallContext::new(None))
            .await;
        assert!(denied.is_error);
        assert_eq!(
            denied.structured_content.unwrap()["error_kind"],
            "approval_denied"
        );
    }

    #[tokio::test]
    async fn abac_deny_short_circuits_dispatch() {
        let router = router_with(
            PolicyConfig::default(),
            Some(Arc::new(StubAbac {
                mode: StubMode::Deny,
                approve: true,
            })),
        );
        router.register(Arc::new(EchoProvider)).expect("register");
        let denied = router
            .dispatch("echo", json!({}), CallContext::new(None))
            .await;
        assert!(denied.is_error);
        assert_eq!(
            denied.structured_content.unwrap()["error_kind"],
            "policy_denied"
        );
    }

    // Provider whose tool name has no compiled-in policy spec, which is every tool from
    // every admitted upstream. Namespaced the way the gateway namespaces them.
    struct ThirdPartyProvider;

    #[async_trait]
    impl ToolProvider for ThirdPartyProvider {
        fn contract_version(&self) -> u32 {
            1
        }
        fn provider_id(&self) -> &str {
            "vendor"
        }
        fn contracts(&self) -> Vec<ToolContract> {
            vec![test_contract("do_something", ToolEffect::Observe)]
        }
        async fn call(
            &self,
            _name: &str,
            args: Value,
            _ctx: &CallContext,
            _granted: &GrantedAuthority,
        ) -> ToolCallResult {
            ToolCallResult::ok(args)
        }
    }

    struct UngovernableUpstream;
    #[async_trait]
    impl ToolProvider for UngovernableUpstream {
        fn contract_version(&self) -> u32 {
            1
        }
        fn provider_id(&self) -> &str {
            "vendor"
        }
        fn contracts(&self) -> Vec<ToolContract> {
            // Declares a permission no default root grants, so stage 4 would refuse it too.
            vec![specced_contract(
                "reach",
                Permission::GitPublish,
                ToolEffect::Mutate,
            )]
        }
        async fn call(
            &self,
            _name: &str,
            args: Value,
            _ctx: &CallContext,
            _granted: &GrantedAuthority,
        ) -> ToolCallResult {
            ToolCallResult::ok(args)
        }
    }

    /// G3-15 AF-7, the acceptance criterion. An OAuth caller and a static-token caller sharing
    /// one `agent_id` used to produce byte-identical records, so an operator asking whether a
    /// destructive call came from the console or from the internet could not answer it.
    #[test]
    fn two_callers_sharing_an_agent_id_are_told_apart_by_their_credential_path() {
        let oauth = CallContext::with_agent(None, Some("chatgpt".to_string()))
            .with_provenance(Some("203.0.113.0/24".to_string()), Some("oauth"));
        let static_token = CallContext::with_agent(None, Some("chatgpt".to_string()))
            .with_provenance(Some("loopback".to_string()), Some("static"));

        assert_eq!(oauth.agent_id, static_token.agent_id);
        assert_ne!(oauth.credential_path, static_token.credential_path);
        assert_ne!(oauth.peer, static_token.peer);
    }

    /// G3-15 AF-7. On the 2026-07-28 revision the session is deliberately None, and `client`
    /// was derived from session presence, so a call arriving through the tunnel claimed to be
    /// local. It now names the network it came from.
    #[test]
    fn a_sessionless_remote_call_no_longer_claims_to_be_local() {
        let remote = CallContext::with_agent(None, Some("chatgpt".to_string()))
            .with_provenance(Some("203.0.113.0/24".to_string()), Some("oauth"));
        assert_eq!(remote.session_id, None, "the revision forces this");

        let client = remote
            .session_id
            .clone()
            .unwrap_or_else(|| remote.peer.clone().unwrap_or_else(|| "local".to_string()));
        assert_eq!(client, "203.0.113.0/24");
        assert_ne!(client, "local");
    }

    /// G3-15 AF-7. A caller with no transport at all, which is every CLI and test path, still
    /// reads `local`, so nothing changes for them.
    #[test]
    fn a_caller_with_no_transport_still_reads_as_local() {
        let ctx = CallContext::new(None);
        assert_eq!(ctx.peer, None);
        let client = ctx
            .session_id
            .clone()
            .unwrap_or_else(|| ctx.peer.clone().unwrap_or_else(|| "local".to_string()));
        assert_eq!(client, "local");
    }

    /// G3-15 AF-7. A session id still wins, because session replay filters on `client` and
    /// putting a peer where a session id belongs would make every replay query miss.
    #[test]
    fn a_session_id_still_wins_so_replay_keeps_working() {
        let ctx = CallContext::new(Some("sess-42".to_string()))
            .with_provenance(Some("203.0.113.0/24".to_string()), Some("oauth"));
        let client = ctx
            .session_id
            .clone()
            .unwrap_or_else(|| ctx.peer.clone().unwrap_or_else(|| "local".to_string()));
        assert_eq!(client, "sess-42");
    }

    /// NMCP-SPEC-003 section 4.3 requires that `nmcp-router` re-export both moved types so
    /// no `use` path breaks. I-047b re-points this workspace's three dependents at
    /// `nmcp-schema` directly, which leaves nothing outside this crate going through the
    /// re-export, and a re-export nothing uses is one that can be deleted with every gate
    /// still green. This names both through the re-export path and pins each to the type
    /// `nmcp-schema` defines, so deleting either line fails the build rather than a
    /// downstream consumer nobody in this workspace has yet.
    ///
    /// `a_call_context_has_no_field_a_caller_credential_could_travel_in` moved to
    /// `nmcp-schema` with the type it pins. It could not stay: two of the fields its
    /// exhaustive pattern names are now private to the module that defines them, and a
    /// pattern rewritten with `..` would compile here and assert nothing, which is the one
    /// thing that test exists to prevent.
    #[test]
    fn the_re_export_is_the_same_type_the_contract_crate_defines() {
        fn contract_context(_: nmcp_schema::CallContext) {}
        fn contract_result(_: nmcp_schema::ToolCallResult) {}
        contract_context(CallContext::new(None));
        contract_result(ToolCallResult::ok(json!({})));
    }

    /// The same claim as the test above, for the trait I-047c moved. `ToolProvider` is defined
    /// in `nmcp-schema` and re-exported here, so a provider crate can keep its
    /// `use nmcp_router::ToolProvider` while depending only on the contract. Written as a
    /// function taking the contract crate's trait object and handed one built through the
    /// re-export, so the two are pinned to the same type rather than merely to the same name.
    #[test]
    fn the_re_exported_provider_trait_is_the_one_the_contract_crate_defines() {
        fn contract_provider(provider: &Arc<dyn nmcp_schema::ToolProvider>) -> String {
            provider.provider_id().to_string()
        }
        let provider: Arc<dyn ToolProvider> = Arc::new(EchoProvider);
        assert_eq!(contract_provider(&provider), "");
    }

    #[tokio::test]
    async fn an_unspecced_third_party_tool_is_treated_as_mutating_rather_than_trusted() {
        // M6, first leg. The kernel's compiled-in table held first-party tool names only, so
        // every tool from an admitted upstream fell through it to "not mutating", which meant
        // an operator who disabled auto_approve gated their own write_text_file and waved
        // through a third party's do_something. The gate reads the resolved provider, so
        // unknown provenance means unknown effect. Nothing about that changed when the table
        // was deleted: `third_party` never consulted it.
        //
        // This policy admits no upstream, so stage 3 refuses before the gate is reached and
        // this test asserts the outcome rather than the mechanism. RC-13's own test,
        // `a_third_party_tool_declaring_observe_still_requires_approval`, admits the upstream
        // so the gate is the only thing left that can refuse.
        let policy = PolicyConfig {
            auto_approve: false,
            ..PolicyConfig::default()
        };
        let router = router_with(policy, None);
        router
            .register(Arc::new(ThirdPartyProvider))
            .expect("register");
        let denied = router
            .dispatch("vendor_do_something", json!({}), CallContext::new(None))
            .await;
        assert!(
            denied.is_error,
            "an unknown tool must be gated when auto_approve is off: {denied:?}"
        );
    }

    #[tokio::test]
    async fn a_specless_first_party_tool_is_not_swept_up_by_the_third_party_gate() {
        // The over-reach the first attempt at this shipped, caught by nmcp-abac's suite: keying
        // the rule off "has no policy spec" sent list_roots, scan_repo and the memory tools to
        // the approval wait, because they are first-party and legitimately specless. The rule
        // is about provenance, not about the spec table.
        let policy = PolicyConfig {
            auto_approve: false,
            ..PolicyConfig::default()
        };
        let router = router_with(policy, None);
        router.register(Arc::new(EchoProvider)).expect("register");
        let ok = router
            .dispatch("echo", json!({"a": 1}), CallContext::new(None))
            .await;
        assert!(
            !ok.is_error,
            "a first-party tool with no spec still reads as non-mutating: {ok:?}"
        );
    }

    #[tokio::test]
    async fn auto_approve_on_leaves_a_third_party_tool_reachable() {
        // The other side of the same change, and the reason it is safe to ship: with the
        // default auto_approve the gate is inert, so an admitted upstream keeps working.
        let router = router_with(
            admitting(PolicyConfig::default(), &["vendor"], Permission::Execute),
            None,
        );
        router
            .register(Arc::new(ThirdPartyProvider))
            .expect("register");
        let ok = router
            .dispatch("vendor_do_something", json!({}), CallContext::new(None))
            .await;
        assert!(!ok.is_error, "{ok:?}");
    }

    /// Admit these upstream ids under one granted capability (G4-28).
    ///
    /// Every fixture that registers a namespaced provider needs this now. Before G4-28 a
    /// provider could be registered and dispatched against a policy that had never heard of
    /// it, which is precisely what the item closed.
    fn admitting(policy: PolicyConfig, ids: &[&str], permission: Permission) -> PolicyConfig {
        let mut policy = policy;
        for id in ids {
            let mut config = nmcp_policy::UpstreamConfig::new(*id, "http://127.0.0.1:9/mcp");
            config.required_permission = Some(permission);
            policy.upstreams.push(config);
        }
        policy.roots.push(nmcp_policy::RootRule {
            id: format!("admits-{permission}"),
            path: std::env::temp_dir(),
            permissions: [permission].into_iter().collect(),
        });
        policy
    }

    fn upstream(id: &str, permission: Option<Permission>) -> nmcp_policy::UpstreamConfig {
        let mut config = nmcp_policy::UpstreamConfig::new(id, "http://127.0.0.1:9/mcp");
        config.required_permission = permission;
        config
    }

    fn policy_admitting(
        upstream_permission: Option<Permission>,
        granted: &[Permission],
    ) -> PolicyConfig {
        PolicyConfig {
            upstreams: vec![upstream("vendor", upstream_permission)],
            roots: if granted.is_empty() {
                Vec::new()
            } else {
                vec![nmcp_policy::RootRule {
                    id: "root".into(),
                    path: std::env::temp_dir(),
                    permissions: granted.iter().copied().collect(),
                }]
            },
            ..PolicyConfig::default()
        }
    }

    #[tokio::test]
    async fn an_upstream_tool_is_refused_until_its_capability_is_granted() {
        // G4-28, and the test it replaces asserted the opposite: that an upstream tool ran
        // against a policy granting nothing. That was the gap, pinned so closing it would be
        // a visible change to a test rather than a silent one. This is that change.
        let router = router_with(policy_admitting(Some(Permission::Execute), &[]), None);
        router
            .register(Arc::new(ThirdPartyProvider))
            .expect("register");
        let denied = router
            .dispatch("vendor_do_something", json!({}), CallContext::new(None))
            .await;
        assert!(denied.is_error, "{denied:?}");
        let rendered = format!("{denied:?}");
        assert!(
            rendered.contains("execute") && rendered.contains("vendor"),
            "the denial names the capability and the upstream: {rendered}"
        );
    }

    #[tokio::test]
    async fn granting_the_capability_admits_the_upstream() {
        let router = router_with(
            policy_admitting(Some(Permission::Execute), &[Permission::Execute]),
            None,
        );
        router
            .register(Arc::new(ThirdPartyProvider))
            .expect("register");
        let ok = router
            .dispatch("vendor_do_something", json!({}), CallContext::new(None))
            .await;
        assert!(!ok.is_error, "{ok:?}");
    }

    #[tokio::test]
    async fn the_capability_is_the_declared_one_and_not_any_capability() {
        // Granting something is not granting this. A root full of read and write does not
        // admit an upstream that declared execute.
        let router = router_with(
            policy_admitting(
                Some(Permission::Execute),
                &[Permission::Read, Permission::Write, Permission::List],
            ),
            None,
        );
        router
            .register(Arc::new(ThirdPartyProvider))
            .expect("register");
        let denied = router
            .dispatch("vendor_do_something", json!({}), CallContext::new(None))
            .await;
        assert!(denied.is_error, "{denied:?}");
    }

    #[tokio::test]
    async fn an_undeclared_or_unknown_upstream_fails_closed_at_dispatch() {
        // validate_semantics refuses an enabled upstream with no declaration, so reaching
        // dispatch in that state means a policy arrived by a route that did not validate.
        // Refuse rather than infer an intent nobody wrote down.
        let router = router_with(policy_admitting(None, &[Permission::Execute]), None);
        router
            .register(Arc::new(ThirdPartyProvider))
            .expect("register");
        let undeclared = router
            .dispatch("vendor_do_something", json!({}), CallContext::new(None))
            .await;
        assert!(
            undeclared.is_error,
            "undeclared must refuse: {undeclared:?}"
        );

        // And a provider whose id policy has never heard of is not a provider policy admitted.
        let router = router_with(PolicyConfig::default(), None);
        router
            .register(Arc::new(ThirdPartyProvider))
            .expect("register");
        let unknown = router
            .dispatch("vendor_do_something", json!({}), CallContext::new(None))
            .await;
        assert!(unknown.is_error, "unknown must refuse: {unknown:?}");
    }

    #[tokio::test]
    async fn upstream_admission_does_not_touch_first_party_tools() {
        // The local provider has an empty provider_id and is not an admitted upstream, so a
        // policy with no upstreams at all must leave it exactly as it was.
        let router = router_with(PolicyConfig::default(), None);
        router.register(Arc::new(EchoProvider)).expect("register");
        let ok = router
            .dispatch("echo", json!({"a": 1}), CallContext::new(None))
            .await;
        assert!(!ok.is_error, "{ok:?}");
    }

    #[tokio::test]
    async fn auto_approve_off_gates_mutating_tools() {
        let policy = PolicyConfig {
            auto_approve: false,
            ..PolicyConfig::default()
        };
        // No approval workflow configured: mutating call fails closed.
        let router = router_with(policy.clone(), None);
        router.register(Arc::new(WriteProvider)).expect("register");
        let denied = router
            .dispatch(
                "write_text_file",
                json!({"path": "."}),
                CallContext::new(None),
            )
            .await;
        assert!(
            denied.is_error,
            "mutating tool must be gated when auto_approve is off and no approver exists"
        );

        // With an approver that approves, the call runs.
        let router = router_with(
            policy,
            Some(Arc::new(StubAbac {
                mode: StubMode::Allow,
                approve: true,
            })),
        );
        router.register(Arc::new(WriteProvider)).expect("register");
        let ok = router
            .dispatch(
                "write_text_file",
                json!({"path": "."}),
                CallContext::new(None),
            )
            .await;
        assert!(!ok.is_error, "approved mutating call should run");
    }

    #[tokio::test]
    async fn auto_approve_on_does_not_gate_mutating_tools() {
        let router = router_with(PolicyConfig::default(), None);
        router.register(Arc::new(WriteProvider)).expect("register");
        let ok = router
            .dispatch(
                "write_text_file",
                json!({"path": "."}),
                CallContext::new(None),
            )
            .await;
        assert!(!ok.is_error);
    }

    struct PublishProvider;

    #[async_trait]
    impl ToolProvider for PublishProvider {
        fn contract_version(&self) -> u32 {
            1
        }
        fn provider_id(&self) -> &str {
            ""
        }
        fn contracts(&self) -> Vec<ToolContract> {
            vec![specced_contract(
                "dev.git_publish",
                Permission::GitPublish,
                ToolEffect::Mutate,
            )]
        }
        async fn call(
            &self,
            _name: &str,
            args: Value,
            _ctx: &CallContext,
            _granted: &GrantedAuthority,
        ) -> ToolCallResult {
            ToolCallResult::ok(args)
        }
    }

    struct NamespacedProvider;

    #[async_trait]
    impl ToolProvider for NamespacedProvider {
        fn contract_version(&self) -> u32 {
            1
        }
        fn provider_id(&self) -> &str {
            "upstream"
        }
        fn contracts(&self) -> Vec<ToolContract> {
            vec![test_contract("ping", ToolEffect::Observe)]
        }
        async fn call(
            &self,
            _name: &str,
            _args: Value,
            _ctx: &CallContext,
            _granted: &GrantedAuthority,
        ) -> ToolCallResult {
            ToolCallResult::ok(json!("pong"))
        }
    }

    /// A second namespaced provider, so a profile has something to include and something to
    /// leave out.
    struct OtherUpstreamProvider;

    #[async_trait]
    impl ToolProvider for OtherUpstreamProvider {
        fn contract_version(&self) -> u32 {
            1
        }
        fn provider_id(&self) -> &str {
            "partner"
        }
        fn contracts(&self) -> Vec<ToolContract> {
            vec![test_contract("fetch", ToolEffect::Observe)]
        }
        async fn call(
            &self,
            _name: &str,
            _args: Value,
            _ctx: &CallContext,
            _granted: &GrantedAuthority,
        ) -> ToolCallResult {
            ToolCallResult::ok(json!("fetched"))
        }
    }

    fn policy_with_reading_profile() -> PolicyConfig {
        let mut policy = PolicyConfig::default();
        policy.gateway_profiles.insert(
            "reading".to_string(),
            nmcp_policy::GatewayProfile {
                label: "Reading".into(),
                servers: std::collections::BTreeMap::from([("upstream".to_string(), true)]),
            },
        );
        policy
    }

    /// G6-8, and the invariant the whole item rests on: listing and calling answer the same
    /// question. A session that can see a tool it cannot call, or call one it cannot see, is
    /// worse than either restriction on its own, so both paths go through
    /// `provider_visible_to_session` and this test drives both.
    #[tokio::test]
    async fn a_scoped_session_lists_and_calls_the_same_set() {
        // Both upstreams are admitted with the same capability, so this test keeps measuring
        // what it was written to measure: the profile, not the G4-28 gate.
        let router = router_with(
            admitting(
                policy_with_reading_profile(),
                &["upstream", "partner"],
                Permission::Read,
            ),
            None,
        );
        router
            .register(Arc::new(NamespacedProvider))
            .expect("register");
        router
            .register(Arc::new(OtherUpstreamProvider))
            .expect("register");
        router.register(Arc::new(EchoProvider)).expect("register");

        let names = |profile: Option<&str>| -> Vec<String> {
            let mut names: Vec<String> = router
                .merged_tool_list_for(profile, None)
                .iter()
                .filter_map(|tool| tool["name"].as_str().map(String::from))
                .collect();
            names.sort();
            names
        };

        // Unscoped is the behaviour every build before G6-8 had.
        assert_eq!(names(None), ["echo", "partner_fetch", "upstream_ping"]);

        // Scoped drops the upstream the profile does not name, and keeps the local provider,
        // because a profile selects among proxied servers rather than taking away the tools
        // this service implements itself.
        assert_eq!(names(Some("reading")), ["echo", "upstream_ping"]);

        let scoped = || CallContext::new(None).with_profile(Some("reading".to_string()));

        let allowed = router.dispatch("upstream_ping", json!({}), scoped()).await;
        assert!(!allowed.is_error, "a listed tool must be callable");

        let refused = router.dispatch("partner_fetch", json!({}), scoped()).await;
        assert!(
            refused.is_error,
            "a tool the profile does not include must not be callable"
        );
        let text = refused.content[0]["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("gateway profile"),
            "the refusal must say why, not look like a missing tool: {text}"
        );

        // And the same call with no profile still works, so the scope is the only thing that
        // refused it.
        let unscoped = router
            .dispatch("partner_fetch", json!({}), CallContext::new(None))
            .await;
        assert!(!unscoped.is_error, "an unscoped session must be unaffected");
    }

    #[test]
    fn public_tool_names_are_claude_safe() {
        for (provider, local, expected) in [
            ("", "mem.write", "mem_write"),
            ("", "win.eventlog_query", "win_eventlog_query"),
            ("dev", "git_log", "dev_git_log"),
            ("", "dev.git_publish", "dev_git_publish"),
            ("upstream", "ping", "upstream_ping"),
        ] {
            let name = public_tool_name(provider, local);
            assert_eq!(name, expected);
            assert!(is_valid_public_tool_name(&name));
        }
    }

    #[tokio::test]
    async fn local_provider_dispatches() {
        let router = make_test_router();
        router.register(Arc::new(EchoProvider)).expect("register");
        let ctx = CallContext::new(None);
        let result = router.dispatch("echo", json!({"msg": "hi"}), ctx).await;
        assert!(!result.is_error);
    }

    #[tokio::test]
    async fn namespaced_provider_dispatches() {
        let router = router_with(
            admitting(PolicyConfig::default(), &["upstream"], Permission::Read),
            None,
        );
        router
            .register(Arc::new(NamespacedProvider))
            .expect("register");
        let ctx = CallContext::new(None);
        let result = router.dispatch("upstream_ping", json!({}), ctx).await;
        assert!(!result.is_error);
    }

    /// Read every audit record written to a sink's file.
    fn audit_lines(path: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("audit line is JSON"))
            .collect()
    }

    #[tokio::test]
    async fn every_dispatch_records_a_measured_duration() {
        // The latency history, buckets, slowest list, and timeout-like detection all read
        // AuditEvent::duration_ms. Before this, nothing on the real path ever set it: the
        // field was written only by tests, so every one of those surfaces reported on an
        // empty set while looking healthy. This test is on the producer side on purpose.
        let (path, audit) = temp_audit("duration");
        let router = router_over(PolicyConfig::default(), audit);
        router.register(Arc::new(EchoProvider)).expect("register");

        // A successful provider call.
        let ok = router
            .dispatch("echo", json!({"msg": "hi"}), CallContext::new(None))
            .await;
        assert!(!ok.is_error);

        // A denial that never reaches a provider still has to be timed, because a slow
        // denial is exactly as interesting as a slow success.
        let denied = router
            .dispatch("nonexistent", json!({}), CallContext::new(None))
            .await;
        assert!(denied.is_error);

        let events = audit_lines(&path);
        // Three records for two calls, and the count is the RC-16 behaviour change made
        // visible rather than absorbed. The permitted call writes the ring's intent record at
        // stage 6 and its outcome record at stage 8; the refused call never reaches stage 6 and
        // writes one. This test used to assert two, which was the whole chain when the ring
        // audited only on the way out.
        assert_eq!(events.len(), 3, "both calls must be audited");
        let outcomes: Vec<&serde_json::Value> = events
            .iter()
            .filter(|event| {
                event["decision"]
                    .as_str()
                    .is_some_and(nmcp_audit::is_authorization_decision)
            })
            .collect();
        assert_eq!(
            outcomes.len(),
            2,
            "one verdict per call, no more and no fewer"
        );
        // The assertion this test exists for, unchanged: every record that reached a verdict
        // carries the duration the client actually waited.
        for event in &outcomes {
            assert!(
                event.get("duration_ms").is_some(),
                "audit record is missing duration_ms: {event}"
            );
            assert!(
                event["duration_ms"].is_u64(),
                "duration_ms must be a number: {event}"
            );
        }
        // And the intent record deliberately carries neither a verdict nor a duration: the
        // verdict is the outcome record's to state and the clock has not stopped.
        let intents: Vec<&serde_json::Value> = events
            .iter()
            .filter(|event| event["decision"] == nmcp_audit::INTENT_DECISION)
            .collect();
        assert_eq!(intents.len(), 1, "only the permitted call reached stage 6");
        assert!(intents[0]["duration_ms"].is_null());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn unknown_tool_returns_error() {
        let router = make_test_router();
        let ctx = CallContext::new(None);
        let result = router.dispatch("nonexistent", json!({}), ctx).await;
        assert!(result.is_error);
        let structured = result
            .structured_content
            .expect("structured error metadata");
        assert_eq!(structured["ok"], false);
        assert_eq!(structured["error_kind"], "command_not_found");
        assert!(
            structured["message"]
                .as_str()
                .unwrap_or("")
                .contains("Unknown tool")
        );
        assert!(
            structured["remediation"]
                .as_str()
                .unwrap_or("")
                .contains("tools/list")
        );
    }

    #[tokio::test]
    async fn git_publish_denial_has_specific_remediation() {
        let router = make_test_router();
        router
            .register(Arc::new(PublishProvider))
            .expect("register");
        let ctx = CallContext::new(None);
        let result = router
            .dispatch("dev_git_publish", json!({"path":"."}), ctx)
            .await;
        assert!(result.is_error);
        let structured = result
            .structured_content
            .expect("structured error metadata");
        assert_eq!(structured["error_kind"], "policy_denied");
        assert!(
            structured["remediation"]
                .as_str()
                .unwrap_or("")
                .contains("git.publish")
        );
    }

    #[tokio::test]
    async fn delete_guard_blocks_delete_named_tools() {
        let router = make_test_router();
        router.register(Arc::new(EchoProvider)).expect("register");
        let ctx = CallContext::new(None);
        let result = router.dispatch("delete_file", json!({}), ctx).await;
        assert!(result.is_error);
        assert!(
            result.content[0]["text"]
                .as_str()
                .unwrap_or("")
                .contains("no-delete invariant")
        );
    }

    #[tokio::test]
    async fn merged_tool_list_namespaces_upstream() {
        let router = make_test_router();
        router.register(Arc::new(EchoProvider)).expect("register");
        router
            .register(Arc::new(NamespacedProvider))
            .expect("register");
        let list = router.merged_tool_list();
        let names: Vec<&str> = list.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"echo"));
        assert!(names.contains(&"upstream_ping"));
        assert!(names.iter().all(|name| is_valid_public_tool_name(name)));
    }

    #[tokio::test]
    async fn first_party_tools_get_annotations_and_upstream_tools_do_not() {
        // G2-8. The annotation says destructiveHint is false, which is a claim about this
        // product's guarantee. A proxied upstream is somebody else's software and this
        // server is in no position to make that claim on its behalf, so the boundary
        // matters as much as the annotation does.
        let router = make_test_router();
        router.register(Arc::new(EchoProvider)).expect("register");
        router
            .register(Arc::new(NamespacedProvider))
            .expect("register");
        let list = router.merged_tool_list();

        let local = list
            .iter()
            .find(|t| t["name"] == "echo")
            .expect("local tool");
        assert_eq!(
            local["annotations"]["destructiveHint"], false,
            "a first-party tool must carry the guarantee in its annotations"
        );

        let upstream = list
            .iter()
            .find(|t| t["name"] == "upstream_ping")
            .expect("upstream tool");
        assert!(
            upstream.get("annotations").is_none(),
            "this server must not invent annotations for a proxied upstream tool"
        );
    }

    #[test]
    fn delete_intent_detection() {
        assert!(contains_delete_intent("delete_file"));
        assert!(contains_delete_intent("remove_root"));
        assert!(contains_delete_intent("DROP_TABLE"));
        assert!(!contains_delete_intent("list_roots"));
        assert!(!contains_delete_intent("write_text_file"));
        assert!(!contains_delete_intent("execute_start"));
    }

    // - RC-13: the approval gate, and the one line where trusting a declaration is a hole -

    /// RC-13's specific requirement, and the M6 regression guard the spec calls not optional.
    ///
    /// A third-party provider declaring `ToolEffect::Observe` still requires approval when
    /// `auto_approve` is false. This is the assertion that fails if somebody rewrites the gate
    /// as `!auto_approve && effect == Mutate` and drops the `third_party` disjunct as
    /// redundant, which is the obvious tidy-up and which would hand a remote MCP server the
    /// ability to switch off its own approval gate by declaring itself harmless: an upstream's
    /// `ToolContract` is built from that server's `tools/list` response, so `effect` is
    /// attacker-controlled data (RC-D4).
    ///
    /// `an_unspecced_third_party_tool_is_treated_as_mutating_rather_than_trusted` is the older
    /// test for the same rule and it stays, but it cannot carry this claim on its own: its
    /// policy admits no upstream, so it is refused at stage 3 and never reaches the gate. This
    /// one admits the upstream properly, so stage 5 is the only thing left that can refuse it.
    #[tokio::test]
    async fn a_third_party_tool_declaring_observe_still_requires_approval() {
        let admitted = admitting(
            PolicyConfig {
                auto_approve: false,
                ..PolicyConfig::default()
            },
            &["vendor"],
            Permission::Execute,
        );

        // The declaration says Observe. Nothing else about this call is refusable: the
        // upstream is admitted, the tool needs no root-scoped authority, and no ABAC rule
        // matches. With no approval workflow configured the gate fails closed.
        let router = router_with(admitted.clone(), None);
        router
            .register(Arc::new(ThirdPartyProvider))
            .expect("register");
        assert_eq!(
            router
                .registry
                .authority_of("vendor_do_something")
                .expect("the declaration is indexed")
                .effect,
            ToolEffect::Observe,
            "the fixture must declare Observe or this test is measuring nothing"
        );
        let denied = router
            .dispatch("vendor_do_something", json!({}), CallContext::new(None))
            .await;
        assert!(
            denied.is_error,
            "a third party declaring Observe must still be gated: {denied:?}"
        );
        assert_eq!(
            denied.structured_content.clone().unwrap()["error_kind"],
            "policy_denied",
            "the refusal is the approval gate failing closed, not a policy denial elsewhere"
        );
        assert!(
            denied.content[0]["text"]
                .as_str()
                .unwrap_or_default()
                .contains("Approval required"),
            "the refusal must name the gate that refused: {denied:?}"
        );

        // And with an approver attached, the same call is put to a human rather than run.
        // Denying at the prompt refuses it, which is the other half of the gate having fired.
        let router = router_with(
            admitted,
            Some(Arc::new(StubAbac {
                mode: StubMode::Allow,
                approve: false,
            })),
        );
        router
            .register(Arc::new(ThirdPartyProvider))
            .expect("register");
        let refused = router
            .dispatch("vendor_do_something", json!({}), CallContext::new(None))
            .await;
        assert_eq!(
            refused.structured_content.unwrap()["error_kind"],
            "approval_denied",
            "the call reached the human gate, which is what `third_party` being first buys"
        );
    }

    /// The same rule read from the other side: a first-party tool declaring `Observe` is not
    /// gated, so the disjunct above is doing work rather than gating everything.
    ///
    /// Without this, an implementation that gated every call when `auto_approve` is off would
    /// pass the test above and be indistinguishable from a correct one.
    #[tokio::test]
    async fn a_first_party_tool_declaring_observe_is_not_gated() {
        let router = router_with(
            PolicyConfig {
                auto_approve: false,
                ..PolicyConfig::default()
            },
            None,
        );
        router.register(Arc::new(EchoProvider)).expect("register");
        let ok = router
            .dispatch("echo", json!({"a": 1}), CallContext::new(None))
            .await;
        assert!(!ok.is_error, "{ok:?}");
    }

    /// The gate reads the declaration for a first-party tool, which is what replaced the
    /// name-keyed `tool_is_mutating`. Declared `Mutate` is gated; the same provider declaring
    /// `Observe` is not. Both at one policy, so the declaration is the only variable.
    #[tokio::test]
    async fn the_first_party_half_of_the_gate_reads_the_declared_effect() {
        struct Declaring(ToolEffect);
        #[async_trait]
        impl ToolProvider for Declaring {
            fn contract_version(&self) -> u32 {
                1
            }
            fn provider_id(&self) -> &str {
                ""
            }
            fn contracts(&self) -> Vec<ToolContract> {
                vec![test_contract("thing", self.0)]
            }
            async fn call(
                &self,
                _name: &str,
                args: Value,
                _ctx: &CallContext,
                _granted: &GrantedAuthority,
            ) -> ToolCallResult {
                ToolCallResult::ok(args)
            }
        }

        for (effect, gated) in [(ToolEffect::Observe, false), (ToolEffect::Mutate, true)] {
            let router = router_with(
                PolicyConfig {
                    auto_approve: false,
                    ..PolicyConfig::default()
                },
                None,
            );
            router
                .register(Arc::new(Declaring(effect)))
                .expect("register");
            let result = router
                .dispatch("thing", json!({}), CallContext::new(None))
                .await;
            assert_eq!(
                result.is_error,
                gated,
                "{effect:?} must {} be gated when auto_approve is off",
                if gated { "" } else { "not" }
            );
        }
    }

    // - RC-16 and the ring order -

    /// NMCP-SPEC-003 section 4.6, observed rather than asserted from the source.
    ///
    /// Each stage is made to refuse in turn, and the stage that answers is identified by the
    /// reason it gives. The order is frozen, so this is what fails if somebody moves the
    /// upstream admission check above the profile check, or authorization above either.
    ///
    /// The delete guard is first and is checked against a name no provider registered, which is
    /// the property RC-A3 states: it does not depend on the registry having resolved anything.
    #[tokio::test]
    async fn the_ring_refuses_in_the_frozen_stage_order() {
        fn kind(result: &ToolCallResult) -> String {
            result
                .structured_content
                .as_ref()
                .and_then(|value| value["error_kind"].as_str())
                .unwrap_or_default()
                .to_string()
        }
        fn text(result: &ToolCallResult) -> String {
            result.content[0]["text"].as_str().unwrap_or("").to_string()
        }

        // Stage 0 beats stage 1: a delete-named tool nothing registered is refused by the
        // guard, not reported as unknown.
        let router = make_test_router();
        let refused = router
            .dispatch("delete_file", json!({}), CallContext::new(None))
            .await;
        assert!(text(&refused).contains("no-delete invariant"));

        // Stage 1: an unknown name is refused before anything reads policy.
        let unknown = router
            .dispatch("nonexistent", json!({}), CallContext::new(None))
            .await;
        assert_eq!(kind(&unknown), "command_not_found");

        // Stage 2 beats stage 3: an upstream outside the session profile is refused for the
        // profile even though policy also admits no upstream by that name, which is the
        // stage-3 refusal waiting behind it.
        let router = router_with(policy_with_reading_profile(), None);
        router
            .register(Arc::new(OtherUpstreamProvider))
            .expect("register");
        let scoped = CallContext::new(None).with_profile(Some("reading".to_string()));
        let profile_refusal = router.dispatch("partner_fetch", json!({}), scoped).await;
        assert!(
            text(&profile_refusal).contains("gateway profile"),
            "stage 2 answers before stage 3: {}",
            text(&profile_refusal)
        );
        let admission_refusal = router
            .dispatch("partner_fetch", json!({}), CallContext::new(None))
            .await;
        assert!(
            text(&admission_refusal).contains("no upstream named"),
            "and with the profile satisfied, stage 3 is what refuses: {}",
            text(&admission_refusal)
        );

        // Stage 3 beats stage 4: an unadmitted upstream is refused for admission even when its
        // declaration would also fail authorization.
        let router = router_with(PolicyConfig::default(), None);
        router
            .register(Arc::new(UngovernableUpstream))
            .expect("register");
        let admission = router
            .dispatch("vendor_reach", json!({}), CallContext::new(None))
            .await;
        assert!(
            text(&admission).contains("no upstream named"),
            "stage 3 answers before stage 4: {}",
            text(&admission)
        );

        // Stage 4 beats stage 5: a call that fails authorization is refused there rather than
        // being put to a human, even with auto_approve off and an approver that would say yes.
        let router = router_with(
            PolicyConfig {
                auto_approve: false,
                ..PolicyConfig::default()
            },
            // An approver that refuses. If stage 5 ran before stage 4 the answer would be
            // `approval_denied`; it is `policy_denied` naming the declared permission, so
            // authorization answered first.
            Some(Arc::new(StubAbac {
                mode: StubMode::RequireApproval,
                approve: false,
            })),
        );
        router
            .register(Arc::new(PublishProvider))
            .expect("register");
        let authorization = router
            .dispatch(
                "dev_git_publish",
                json!({"path": "."}),
                CallContext::new(None),
            )
            .await;
        assert_eq!(
            kind(&authorization),
            "policy_denied",
            "stage 4 answered, not stage 5, whose approver would have said no: {}",
            text(&authorization)
        );
        assert!(
            authorization
                .structured_content
                .as_ref()
                .is_some_and(|value| {
                    value["remediation"]
                        .as_str()
                        .is_some_and(|remediation| remediation.contains("git.publish"))
                }),
            "and it refused on the declared permission: {authorization:?}"
        );
    }

    /// RC-16, and INV-3 expressed in the ring: the intent record is durable before the provider
    /// is reached, and no effect is observable before it.
    ///
    /// Asserted from inside the provider, which is the only place that can see the ordering:
    /// the provider reads the audit file it is about to be recorded in, and finds its own
    /// intent record already there. A ring that wrote the record after the call, which is what
    /// both trees did before this commit, fails here rather than passing on a comment.
    #[tokio::test]
    async fn the_intent_record_is_durable_before_the_provider_runs() {
        struct Observing {
            audit_path: std::path::PathBuf,
            seen: std::sync::Mutex<Vec<serde_json::Value>>,
        }
        #[async_trait]
        impl ToolProvider for Observing {
            fn contract_version(&self) -> u32 {
                1
            }
            fn provider_id(&self) -> &str {
                ""
            }
            fn contracts(&self) -> Vec<ToolContract> {
                vec![test_contract("observe", ToolEffect::Observe)]
            }
            async fn call(
                &self,
                _name: &str,
                args: Value,
                _ctx: &CallContext,
                _granted: &GrantedAuthority,
            ) -> ToolCallResult {
                // The effect, such as it is, has not happened yet. What is on disk at this
                // instant is what INV-3 requires to be there before it does.
                *self.seen.lock().unwrap() = audit_lines(&self.audit_path);
                ToolCallResult::ok(args)
            }
        }

        let (path, audit) = temp_audit("intent");
        let router = router_over(PolicyConfig::default(), audit);
        let provider = Arc::new(Observing {
            audit_path: path.clone(),
            seen: std::sync::Mutex::new(Vec::new()),
        });
        router
            .register(Arc::clone(&provider) as Arc<dyn ToolProvider>)
            .expect("register");

        let ok = router
            .dispatch("observe", json!({}), CallContext::new(None))
            .await;
        assert!(!ok.is_error);

        let before_the_effect = provider.seen.lock().unwrap().clone();
        assert_eq!(
            before_the_effect.len(),
            1,
            "exactly the intent record is durable when the provider is entered"
        );
        assert_eq!(
            before_the_effect[0]["decision"],
            nmcp_audit::INTENT_DECISION
        );

        // And the pair shares one call_id, which is what lets a reader join an intent to its
        // outcome and find an intent that never got one.
        let all = audit_lines(&path);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0]["call_id"], all[1]["call_id"]);
        assert_ne!(all[0]["call_id"], serde_json::Value::Null);
        assert_eq!(all[1]["decision"], nmcp_audit::ALLOWED_DECISION);
        let _ = std::fs::remove_file(path);
    }

    /// A refused call writes no intent record, because it never intended to act.
    ///
    /// The other half of the gate ordering: stage 6 sits below every refusal, so an intent with
    /// no outcome means a call that started and did not finish rather than a call that was
    /// denied.
    #[tokio::test]
    async fn a_refused_call_writes_no_intent_record() {
        let (path, audit) = temp_audit("refused-intent");
        let router = router_over(PolicyConfig::default(), audit);
        router
            .register(Arc::new(PublishProvider))
            .expect("register");

        let denied = router
            .dispatch(
                "dev_git_publish",
                json!({"path": "."}),
                CallContext::new(None),
            )
            .await;
        assert!(denied.is_error);

        let events = audit_lines(&path);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["decision"], nmcp_audit::DENIED_DECISION);
        let _ = std::fs::remove_file(path);
    }

    /// M4-1, carried forward from `the_authorization_record_names_the_capability_the_ring_
    /// required`, which read the deleted table directly.
    ///
    /// The claim is unchanged: the record names the capability the ring required, taken from
    /// the tool rather than from anything the caller sent, so a SIEM rule can separate a read
    /// from an execution without parsing a body. Only the source moved, from a compiled-in
    /// table keyed by tool name to the declaration the ring actually authorized against, which
    /// is the point of the whole commit.
    #[tokio::test]
    async fn the_authorization_record_names_the_capability_the_ring_required() {
        let (path, audit) = temp_audit("permission");
        let router = router_over(PolicyConfig::default(), audit);
        router.register(Arc::new(WriteProvider)).expect("register");
        router.register(Arc::new(EchoProvider)).expect("register");

        let ok = router
            .dispatch(
                "write_text_file",
                json!({"path": "."}),
                CallContext::new(None),
            )
            .await;
        assert!(!ok.is_error, "{ok:?}");

        // A tool that declares no root-scoped permission carries none rather than a guessed
        // one, which is what every specless tool did under the table too.
        let ok = router
            .dispatch("echo", json!({}), CallContext::new(None))
            .await;
        assert!(!ok.is_error);

        // And a call refused before its declaration was read carries none either.
        let unknown = router
            .dispatch("nonexistent", json!({}), CallContext::new(None))
            .await;
        assert!(unknown.is_error);

        let events = audit_lines(&path);
        let permission_of = |action: &str| -> Option<String> {
            events
                .iter()
                .find(|event| {
                    event["action"] == action
                        && event["decision"]
                            .as_str()
                            .is_some_and(nmcp_audit::is_authorization_decision)
                })
                .and_then(|event| event["permission"].as_str().map(String::from))
        };
        assert_eq!(
            permission_of("write_text_file").as_deref(),
            Some("write"),
            "the name on the record is the name policy serializes, or a policy file and an \
             audit record disagree about the same capability"
        );
        assert_eq!(Permission::Write.as_str(), "write");
        assert_eq!(permission_of("echo"), None);
        assert_eq!(permission_of("nonexistent"), None);
        let _ = std::fs::remove_file(path);
    }

    // - RC-10: the mutability rule and the Send property -

    /// RC-10. Every wire-up method takes `&self`, so a router already behind an `Arc` is still
    /// a router an upstream and an approval workflow can be attached to. Asserted by doing it:
    /// none of these compile against a `&mut self` receiver.
    #[tokio::test]
    async fn every_wire_up_method_is_callable_through_a_shared_handle() {
        let shared: SharedRouter = Arc::new(router_with(
            admitting(PolicyConfig::default(), &["upstream"], Permission::Read),
            None,
        ));
        let handle = Arc::clone(&shared);
        handle
            .register(Arc::new(NamespacedProvider))
            .expect("register through an Arc");
        handle.set_abac(Arc::new(StubAbac {
            mode: StubMode::Allow,
            approve: true,
        }));
        let ok = handle
            .dispatch("upstream_ping", json!({}), CallContext::new(None))
            .await;
        assert!(!ok.is_error, "{ok:?}");
        assert!(handle.unregister_provider("upstream"));
        let gone = handle
            .dispatch("upstream_ping", json!({}), CallContext::new(None))
            .await;
        assert!(gone.is_error, "an unregistered provider resolves nothing");
    }

    /// RC-10's other half, at run time rather than compile time.
    ///
    /// `dispatch_future_is_send` in this crate's production code is the compile-time assertion
    /// and is the one that matters; this drives the future across a `tokio::spawn`, which is
    /// where an axum handler would put it, so the property is exercised as well as asserted.
    #[tokio::test]
    async fn the_dispatch_future_crosses_a_spawn() {
        let router: SharedRouter = Arc::new(router_with(
            PolicyConfig::default(),
            Some(Arc::new(StubAbac {
                mode: StubMode::RequireApproval,
                approve: true,
            })),
        ));
        router.register(Arc::new(EchoProvider)).expect("register");
        // RequireApproval forces the `wait_for_approval` await, which is the await a guard held
        // across would make this future `!Send`.
        let handle = tokio::spawn(async move {
            router
                .dispatch("echo", json!({}), CallContext::new(None))
                .await
        });
        let ok = handle.await.expect("the spawned dispatch completes");
        assert!(!ok.is_error);
    }

    /// RC-9 through the ring rather than through the registry alone: dispatch resolves without
    /// asking any provider to enumerate anything.
    #[tokio::test]
    async fn dispatch_never_asks_a_provider_to_enumerate() {
        struct Counting(std::sync::atomic::AtomicUsize);
        #[async_trait]
        impl ToolProvider for Counting {
            fn contract_version(&self) -> u32 {
                1
            }
            fn provider_id(&self) -> &str {
                ""
            }
            fn contracts(&self) -> Vec<ToolContract> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                vec![test_contract("counted", ToolEffect::Observe)]
            }
            async fn call(
                &self,
                _name: &str,
                args: Value,
                _ctx: &CallContext,
                _granted: &GrantedAuthority,
            ) -> ToolCallResult {
                ToolCallResult::ok(args)
            }
        }

        let router = make_test_router();
        let provider = Arc::new(Counting(std::sync::atomic::AtomicUsize::new(0)));
        router
            .register(Arc::clone(&provider) as Arc<dyn ToolProvider>)
            .expect("register");
        assert_eq!(provider.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        for _ in 0..500 {
            let ok = router
                .dispatch("counted", json!({}), CallContext::new(None))
                .await;
            assert!(!ok.is_error);
        }
        assert_eq!(
            provider.0.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "five hundred dispatches asked the provider to enumerate again"
        );
    }

    // - RC-6: the full oracle -

    /// One entry of the deleted `tool_policy_spec` table, captured as test data.
    ///
    /// Copied out of `nmcp-router` at the commit before this one, verbatim: the names after the
    /// `.` to `_` fold that function applied, the permission it required, the path arguments it
    /// tried in order, and whether it demanded the Windows API grant. RC-6 grades the new
    /// authorization path against these semantics in both directions, so the table has to
    /// survive its own deletion as data or there is nothing to grade against.
    struct OldSpec {
        names: &'static [&'static str],
        permission: Permission,
        path_args: &'static [&'static str],
        require_windows_api: bool,
        /// The subset of `path_args` the tool's own input schema defines, which is what RC-D5
        /// forces a declaration to carry and what RC-20 makes load-bearing.
        ///
        /// Grounded rather than asserted: `the_oracle_schema_subsets_match_the_shipped_catalogue`
        /// below recomputes it from `nmcp_proto::tool_list` for every name that catalogue
        /// carries. The dev tools are graded against their real schemas in `nmcp-devtools`'
        /// `the_ring_authorizes_the_argument_the_provider_reads`, and the Windows entry declares
        /// no path argument at all, so the filter is a no-op there.
        declared_path_args: &'static [&'static str],
    }

    const PATH_ARG_REPO: &[&str] = &["repo", "repo_path", "repository", "repository_path", "path"];
    const PATH_ARG_DEV: &[&str] = &["path", "repo", "repo_path", "cwd"];

    /// The whole of the deleted table. Fourteen entries, about forty names.
    const OLD_TOOL_POLICY_SPEC: &[OldSpec] = &[
        OldSpec {
            names: &["execute", "execute_start"],
            permission: Permission::Execute,
            path_args: &["cwd"],
            require_windows_api: false,
            declared_path_args: &["cwd"],
        },
        OldSpec {
            names: &["execute_resolve_program"],
            permission: Permission::Execute,
            path_args: &["program"],
            require_windows_api: false,
            declared_path_args: &["program"],
        },
        OldSpec {
            names: &[
                "read_text_file",
                "fs_read_text_file",
                "read_file_window_report",
                "inspect_file_integrity",
            ],
            permission: Permission::Read,
            path_args: &["path"],
            require_windows_api: false,
            declared_path_args: &["path"],
        },
        OldSpec {
            names: &["create_text_file"],
            permission: Permission::Create,
            path_args: &["path"],
            require_windows_api: false,
            declared_path_args: &["path"],
        },
        OldSpec {
            names: &[
                "write_text_file",
                "patch_text_file",
                "fs_write_text_file",
                "fs_patch_text_file",
            ],
            permission: Permission::Write,
            path_args: &["path"],
            require_windows_api: false,
            declared_path_args: &["path"],
        },
        OldSpec {
            names: &["list_directory", "fs_list_directory"],
            permission: Permission::List,
            path_args: &["path"],
            require_windows_api: false,
            declared_path_args: &["path"],
        },
        OldSpec {
            names: &["rename", "fs_rename", "rename_file"],
            permission: Permission::Rename,
            path_args: &["from"],
            require_windows_api: false,
            declared_path_args: &["from"],
        },
        OldSpec {
            names: &["move", "fs_move", "move_file"],
            permission: Permission::Move,
            path_args: &["from"],
            require_windows_api: false,
            declared_path_args: &["from"],
        },
        OldSpec {
            names: &["backup", "fs_backup", "backup_file"],
            permission: Permission::Backup,
            path_args: &["path"],
            require_windows_api: false,
            declared_path_args: &["path"],
        },
        OldSpec {
            names: &[
                "search_repo",
                "scan_repo",
                "dev_search_repo",
                "dev_scan_repo",
            ],
            permission: Permission::Search,
            path_args: PATH_ARG_DEV,
            require_windows_api: false,
            declared_path_args: &["path"],
        },
        OldSpec {
            names: &[
                "git_status",
                "git_diff",
                "git_log",
                "dev_git_status",
                "dev_git_diff",
                "dev_git_log",
                "git_blame",
                "dev_git_blame",
                "git_stash_list",
                "dev_git_stash_list",
            ],
            permission: Permission::Read,
            path_args: PATH_ARG_REPO,
            require_windows_api: false,
            declared_path_args: &["path"],
        },
        OldSpec {
            names: &["git_publish", "dev_git_publish"],
            permission: Permission::GitPublish,
            path_args: PATH_ARG_REPO,
            require_windows_api: false,
            declared_path_args: &["path"],
        },
        OldSpec {
            names: &["test_run", "dev_test_run", "dep_graph", "dev_dep_graph"],
            permission: Permission::Execute,
            path_args: PATH_ARG_DEV,
            require_windows_api: false,
            declared_path_args: &["path"],
        },
        OldSpec {
            names: &[
                "win_registry_read",
                "win_registry_write",
                "win_eventlog_query",
                "win_services_query",
                "win_wmi_query",
            ],
            permission: Permission::Read,
            path_args: &[],
            require_windows_api: true,
            declared_path_args: &[],
        },
    ];

    /// The deleted `policy_check`, reproduced as the RC-6 oracle.
    ///
    /// Every branch of it, in its order: the `win_registry_write` special case that demanded
    /// two grants and then returned without checking anything else, the `require_windows_api`
    /// flag, the early return on an empty `path_args`, the first-present path argument lookup,
    /// and `PolicyConfig::require`. Copied from the source it replaces rather than paraphrased,
    /// because a paraphrased oracle grades the paraphrase.
    fn old_policy_allows(spec: &OldSpec, name: &str, policy: &PolicyConfig, args: &Value) -> bool {
        fn holds(policy: &PolicyConfig, permission: Permission) -> bool {
            policy
                .roots
                .iter()
                .any(|root| root.permissions.contains(&permission))
        }
        if name == "win_registry_write" {
            return holds(policy, Permission::WindowsApi)
                && holds(policy, Permission::WindowsApiWrite);
        }
        if spec.require_windows_api && !holds(policy, Permission::WindowsApi) {
            return false;
        }
        if spec.path_args.is_empty() {
            return true;
        }
        let Some(path) = first_present(args, spec.path_args) else {
            return false;
        };
        policy.require(spec.permission, path).is_ok()
    }

    fn first_present<'a>(args: &'a Value, names: &[&str]) -> Option<&'a str> {
        names
            .iter()
            .find_map(|name| args.get(*name).and_then(Value::as_str))
    }

    /// The declaration a provider migrating off `spec` makes, derived by the documented rule.
    ///
    /// `permission` unchanged, `path_args` filtered to the tool's own schema (RC-D5, RC-20),
    /// and the `require_windows_api` flag becoming declared capability grants. `effect` and
    /// `reach` are excluded from RC-6 because `authorize` does not consume them; RC-8 and RC-13
    /// cover those.
    fn declaration_for(spec: &OldSpec, name: &str) -> ToolAuthority {
        let grants = if name == "win_registry_write" {
            vec![
                nmcp_schema::CapabilityGrant::new(Permission::WindowsApi.as_str()),
                nmcp_schema::CapabilityGrant::new(Permission::WindowsApiWrite.as_str()),
            ]
        } else if spec.require_windows_api {
            vec![nmcp_schema::CapabilityGrant::new(
                Permission::WindowsApi.as_str(),
            )]
        } else {
            Vec::new()
        };
        ToolAuthority {
            permission: Some(spec.permission),
            path_args: spec
                .declared_path_args
                .iter()
                .map(|arg| (*arg).to_string())
                .collect(),
            grants,
            effect: ToolEffect::Observe,
            reach: ToolReach::Local,
        }
    }

    /// The oracle's schema subsets are the shipped catalogue's, not somebody's recollection.
    ///
    /// For every table name `nmcp_proto::tool_list` carries, `declared_path_args` must equal
    /// `path_args` filtered to that tool's real input schema properties, in the table's order.
    /// Twenty-one of the forty names are graded here; the seven dev tools are graded against
    /// their own schemas by `nmcp-devtools`, and the five Windows names declare no path
    /// argument, so there is nothing left to filter.
    #[test]
    fn the_oracle_schema_subsets_match_the_shipped_catalogue() {
        let catalogue = nmcp_proto::tool_list();
        let mut checked = 0usize;
        for spec in OLD_TOOL_POLICY_SPEC {
            for name in spec.names {
                let Some(tool) = catalogue.iter().find(|tool| tool.name == *name) else {
                    continue;
                };
                let expected: Vec<&str> = spec
                    .path_args
                    .iter()
                    .copied()
                    .filter(|arg| {
                        tool.input_schema
                            .get("properties")
                            .and_then(Value::as_object)
                            .is_some_and(|properties| properties.contains_key(*arg))
                    })
                    .collect();
                assert_eq!(
                    spec.declared_path_args,
                    expected.as_slice(),
                    "{name}: the oracle's schema subset disagrees with the shipped input schema"
                );
                checked += 1;
            }
        }
        // Fourteen: execute, execute_start, execute_resolve_program, read_file_window_report,
        // inspect_file_integrity, create_text_file, write_text_file, patch_text_file,
        // list_directory, rename_file, move_file, backup_file, search_repo, scan_repo. The rest
        // of the table's names are provider-internal aliases, the seven dev tools and the five
        // Windows tools, none of which the shipped first-party catalogue carries. Pinned
        // exactly, so a table entry renamed out from under this check fails rather than
        // silently grounding fewer.
        assert_eq!(
            checked, 14,
            "the catalogue grounded {checked} of the oracle's names, not the 14 it carries"
        );
    }

    /// A divergence RC-6 declares deliberate. Anything else is a behaviour change hiding in a
    /// refactor and fails the test.
    #[derive(Debug, PartialEq, Eq)]
    enum Divergence {
        /// NMCP-SPEC-003 section 4.1: `permission: Some(p)` with `path_args: []` means the
        /// caller must hold `p` on some root and no root is resolved. The deleted
        /// `policy_check` returned early on an empty `path_args` and never enforced the
        /// declared permission at all, so the contract narrows here on purpose. Five Windows
        /// tools are exactly this shape.
        EmptyPathArgsNowEnforcesThePermission,
        /// RC-20: the table's path-argument lists named arguments the tools' own schemas do not
        /// define, so the kernel resolved a root from one argument while the tool operated on
        /// another. The declaration is filtered to the schema, so the argument authorized and
        /// the argument used are the same argument. Disagreements are exactly the calls where
        /// the two lists picked different arguments.
        SchemaFilteredToTheArgumentTheToolReads,
    }

    /// RC-6, the full oracle, in both directions.
    ///
    /// Every entry of the deleted table, crossed with every `Permission` as the held set plus
    /// the empty and the universal holder, crossed with every shape a call's path arguments can
    /// take: absent, present and inside the governed root, present and outside it, and the two
    /// two-argument shapes where the table's first choice and the schema's disagree. Roughly
    /// nine thousand cases.
    ///
    /// Both directions are graded. No input may produce an allow the old path refused, and no
    /// input may produce a deny the old path allowed, **except** where one of the two
    /// [`Divergence`] variants applies, and each disagreement is attributed to one of them by a
    /// predicate rather than by being tolerated. A disagreement matching neither fails with the
    /// case printed.
    #[test]
    fn authorize_agrees_with_the_deleted_table_except_where_the_contract_says_otherwise() {
        let governed = std::env::temp_dir().join("nmcp-rc6-governed");
        let elsewhere = std::env::temp_dir().join("nmcp-rc6-elsewhere");
        let inside = governed.join("file.txt").display().to_string();
        let outside = elsewhere.join("file.txt").display().to_string();

        // Every holder shape: nothing, exactly one permission, and everything. "Exactly one"
        // is what makes the grid grade a permission rather than a policy: a tool requiring
        // Write is refused under a root granting only Read, and the oracle has to agree.
        let mut holders: Vec<PolicyConfig> = vec![PolicyConfig {
            roots: Vec::new(),
            ..PolicyConfig::default()
        }];
        for permission in Permission::ALL {
            holders.push(PolicyConfig {
                roots: vec![RootRule {
                    id: format!("grants-{permission}"),
                    path: governed.clone(),
                    permissions: [permission].into_iter().collect(),
                }],
                ..PolicyConfig::default()
            });
        }
        holders.push(PolicyConfig {
            roots: vec![RootRule {
                id: "grants-everything".into(),
                path: governed.clone(),
                permissions: Permission::ALL.into_iter().collect(),
            }],
            ..PolicyConfig::default()
        });
        // The Windows pair, which is the only holder shape that satisfies the registry-write
        // special case, plus the same grant without the write half so the escalation the base
        // guarded against stays guarded.
        for permissions in [
            vec![Permission::WindowsApi],
            vec![Permission::WindowsApi, Permission::WindowsApiWrite],
            vec![Permission::WindowsApi, Permission::Read],
            vec![
                Permission::WindowsApi,
                Permission::WindowsApiWrite,
                Permission::Read,
            ],
        ] {
            holders.push(PolicyConfig {
                roots: vec![RootRule {
                    id: "grants-windows".into(),
                    path: governed.clone(),
                    permissions: permissions.into_iter().collect(),
                }],
                ..PolicyConfig::default()
            });
        }

        let mut cases = 0usize;
        let mut divergences: std::collections::BTreeSet<(String, &'static str)> =
            std::collections::BTreeSet::new();

        for spec in OLD_TOOL_POLICY_SPEC {
            // Argument shapes, built from this entry's own path-argument list so a tool that
            // names `from` or `cwd` is exercised on `from` and `cwd` rather than on `path`.
            let mut shapes: Vec<Value> = vec![json!({}), json!({"unrelated": "value"})];
            for arg in spec.path_args {
                shapes.push(json!({ *arg: inside.clone() }));
                shapes.push(json!({ *arg: outside.clone() }));
            }
            // The confused-deputy shapes: the table's first choice and the schema's choice
            // present together, pointing at different places. These are the calls RC-20 exists
            // for, and the ones where the two paths must disagree.
            if let (Some(first), Some(declared)) =
                (spec.path_args.first(), spec.declared_path_args.first())
                && first != declared
            {
                shapes.push(json!({ *first: inside.clone(), *declared: outside.clone() }));
                shapes.push(json!({ *first: outside.clone(), *declared: inside.clone() }));
            }

            for name in spec.names {
                let declared = declaration_for(spec, name);
                for policy in &holders {
                    let held = held_authority(policy, &CallContext::new(None));
                    for args in &shapes {
                        cases += 1;
                        let old = old_policy_allows(spec, name, policy, args);
                        let new = authorize(&declared, &held, args).is_ok();
                        if old == new {
                            continue;
                        }

                        let divergence = if spec.path_args.is_empty() {
                            assert!(
                                old && !new,
                                "{name}: an empty path_args entry may only narrow, and this \
                                 widened. args={args} roots={:?}",
                                policy.roots
                            );
                            Divergence::EmptyPathArgsNowEnforcesThePermission
                        } else {
                            assert_ne!(
                                spec.path_args, spec.declared_path_args,
                                "{name}: the two paths disagreed on a tool whose declaration is \
                                 the table's list unchanged, which is an unexplained behaviour \
                                 change. old={old} new={new} args={args} roots={:?}",
                                policy.roots
                            );
                            // Attribution, not tolerance: the disagreement has to be the two
                            // lists choosing different arguments out of this call.
                            let old_arg = spec
                                .path_args
                                .iter()
                                .find(|arg| args.get(**arg).and_then(Value::as_str).is_some());
                            let new_arg = spec
                                .declared_path_args
                                .iter()
                                .find(|arg| args.get(**arg).and_then(Value::as_str).is_some());
                            assert_ne!(
                                old_arg, new_arg,
                                "{name}: the two paths disagreed while resolving the same \
                                 argument, which the schema filter cannot explain. old={old} \
                                 new={new} args={args} roots={:?}",
                                policy.roots
                            );
                            Divergence::SchemaFilteredToTheArgumentTheToolReads
                        };
                        divergences.insert((
                            (*name).to_string(),
                            match divergence {
                                Divergence::EmptyPathArgsNowEnforcesThePermission => {
                                    "path_args: [] now enforces the declared permission (4.1)"
                                }
                                Divergence::SchemaFilteredToTheArgumentTheToolReads => {
                                    "path_args filtered to the schema (RC-20)"
                                }
                            },
                        ));
                    }
                }
            }
        }

        assert!(
            cases > 8_000,
            "the grid collapsed to {cases} cases; RC-6 is not being graded"
        );
        // Both divergences must actually occur, or the test is passing because the grid never
        // reached them.
        assert!(
            divergences.iter().any(|(name, _)| name.starts_with("win_")),
            "the empty path_args narrowing was never exercised"
        );
        assert!(
            divergences
                .iter()
                .any(|(_, reason)| reason.contains("RC-20")),
            "the schema filtering divergence was never exercised"
        );
        // Every tool that diverges at all is one of the two families the contract names. This
        // is the assertion that fails if a third divergence appears.
        for (name, reason) in &divergences {
            let expected_empty = name.starts_with("win_");
            assert_eq!(
                expected_empty,
                reason.contains("4.1"),
                "{name} diverged for {reason}, which is not the family it belongs to"
            );
        }
    }

    /// RC-20, stated as the property rather than as an example, at the ring rather than at one
    /// provider.
    ///
    /// The confused deputy the deleted table made possible: a call carrying a repository
    /// argument pointing somewhere the caller may read and a `path` pointing somewhere it may
    /// not. The old ring resolved the root from `repo` and authorized it; the tool then read
    /// `path`. The new ring authorizes `path`, which is the argument the tool reads, so the
    /// call is refused.
    #[test]
    fn the_ring_authorizes_the_argument_the_tool_reads_not_the_first_one_offered() {
        let governed = std::env::temp_dir().join("nmcp-rc20-governed");
        let ungoverned = std::env::temp_dir().join("nmcp-rc20-ungoverned");
        let policy = PolicyConfig {
            roots: vec![RootRule {
                id: "repo".into(),
                path: governed.clone(),
                permissions: [Permission::Read].into_iter().collect(),
            }],
            ..PolicyConfig::default()
        };
        let held = held_authority(&policy, &CallContext::new(None));

        let git_log = OLD_TOOL_POLICY_SPEC
            .iter()
            .find(|spec| spec.names.contains(&"dev_git_log"))
            .expect("the oracle carries the git family");
        let declared = declaration_for(git_log, "dev_git_log");
        assert_eq!(declared.path_args, vec!["path".to_string()]);

        let confused = json!({
            "repo": governed.join("readable").display().to_string(),
            "path": ungoverned.join("secret").display().to_string(),
        });

        // The old table resolved the root from `repo` and allowed it.
        assert!(
            old_policy_allows(git_log, "dev_git_log", &policy, &confused),
            "this is the call the old table allowed, or the test is not measuring the defect"
        );
        // The ring refuses it, naming the argument the tool actually reads.
        let denial = authorize(&declared, &held, &confused)
            .expect_err("the argument the tool reads is outside every root");
        assert!(
            matches!(&denial, Denial::OutsideRoots { arg } if arg == "path"),
            "the refusal must name `path`, which is what git_log reads: {denial:?}"
        );

        // And the mirror image, which is the direction that looks like a widening and is not:
        // the old table refused because `repo` was ungoverned while the effect was always going
        // to run on `path`, which is inside a root the caller holds Read on.
        let mirrored = json!({
            "repo": ungoverned.join("elsewhere").display().to_string(),
            "path": governed.join("readable").display().to_string(),
        });
        assert!(!old_policy_allows(
            git_log,
            "dev_git_log",
            &policy,
            &mirrored
        ));
        let granted = authorize(&declared, &held, &mirrored)
            .expect("the argument the tool reads is inside a root granting Read");
        assert_eq!(
            granted.matched_root().map(|root| root.id.as_str()),
            Some("repo"),
            "the resolved root is the one containing the argument the tool reads"
        );
    }

    // - NMCP-SPEC-002 stage 5b: secret resolution in the ring (I-034) -

    use nmcp_schema::{SECRET_SLOT_ANNOTATION, SECRET_SLOT_MARKER};
    use nmcp_secrets::{KeyBinding, Sealed, SealedStore, SecretName, UseBudget};

    /// Distinctive material with no English substring, so the leak assertions below cannot
    /// collide with legitimate prose such as the word "secret".
    const SECRET_MATERIAL: &[u8] = b"xq4vw-7zr9t-8kn2m-hp5jd";

    /// The reference the fixtures dispatch, naming the key the fixtures bind.
    const DEPLOY_REF: &str = "nmcp://secret/deploy.db";

    /// What the keyed provider saw when the ring reached it.
    #[derive(Clone)]
    struct SlotObservation {
        args: Value,
        channel_empty: bool,
        /// The declared env variable and the exposed bytes, when the slot resolved. Exposed
        /// through `with_exposed` because that is the only read path, which is itself half
        /// of what the test asserts.
        resolved: Option<(String, Vec<u8>)>,
    }

    /// A first-party tool declaring one `env` secret slot on `credential`, beside a free
    /// `program` argument (the basename source for the binding's program dimension) and a
    /// free `message` argument (the SB-2 inertness control inside the same call).
    struct KeyedProvider {
        observed: std::sync::Mutex<Option<SlotObservation>>,
    }

    impl KeyedProvider {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                observed: std::sync::Mutex::new(None),
            })
        }
    }

    #[async_trait]
    impl ToolProvider for KeyedProvider {
        fn contract_version(&self) -> u32 {
            1
        }
        fn provider_id(&self) -> &str {
            ""
        }
        fn contracts(&self) -> Vec<ToolContract> {
            let mut contract = test_contract("keyed_run", ToolEffect::Observe);
            contract.input_schema = json!({
                "type": "object",
                "properties": {
                    "credential": {
                        "type": "string",
                        SECRET_SLOT_ANNOTATION: {"inject": "env", "var": "DATABASE_URL"},
                    },
                    "program": {"type": "string"},
                    "message": {"type": "string"},
                },
            });
            vec![contract]
        }
        async fn call(
            &self,
            _name: &str,
            args: Value,
            ctx: &CallContext,
            _granted: &GrantedAuthority,
        ) -> ToolCallResult {
            let resolved = ctx.secrets().get("credential").map(|(modality, value)| {
                (
                    modality.declared_name().to_string(),
                    value.with_exposed(<[u8]>::to_vec),
                )
            });
            *self.observed.lock().unwrap() = Some(SlotObservation {
                args: args.clone(),
                channel_empty: ctx.secrets().is_empty(),
                resolved,
            });
            ToolCallResult::ok(args)
        }
    }

    /// A store holding `deploy.db` bound to the keyed tool: callers `local` (the audit
    /// convention for the CLI and test population, which is what an anonymous `agent_id`
    /// maps to), program `deployctl`, no roots because the tool resolves none and an
    /// uncarried dimension is not consulted (I-036), and a budget of `uses` per hour.
    fn bound_store(uses: u32) -> Arc<SealedStore> {
        let store = Arc::new(SealedStore::ephemeral());
        let key = SecretName::parse("deploy.db").unwrap();
        store
            .set(&key, Sealed::new(SECRET_MATERIAL.to_vec()))
            .unwrap();
        store
            .bind(
                &key,
                KeyBinding {
                    tools: vec!["keyed_run".to_string()],
                    programs: vec!["deployctl".to_string()],
                    roots: Vec::new(),
                    callers: vec!["local".to_string()],
                    expires_at_unix_ms: None,
                    budget: Some(UseBudget {
                        uses,
                        window_secs: 3_600,
                    }),
                },
            )
            .unwrap();
        store
    }

    /// A router whose stage 5b is wired: the registry serves as both the `ToolRegistry` and
    /// the `SecretSlotCatalog`, which is the one-object rule `SecretResolution` documents.
    fn keyed_router(store: &Arc<SealedStore>) -> (std::path::PathBuf, Router, Arc<KeyedProvider>) {
        let (path, audit) = temp_audit("stage5b");
        let policy = Arc::new(parking_lot::RwLock::new(PolicyConfig::default()));
        let registry = Arc::new(IndexedToolRegistry::new(Arc::clone(&policy)));
        let router = Router::new(
            policy,
            audit,
            Arc::clone(&registry) as Arc<dyn ToolRegistry>,
        );
        router.set_secrets(SecretResolution::new(Arc::clone(store), registry));
        let provider = KeyedProvider::new();
        router
            .register(Arc::clone(&provider) as Arc<dyn ToolProvider>)
            .expect("the keyed tool registers");
        (path, router, provider)
    }

    fn keyed_args() -> Value {
        json!({
            "credential": DEPLOY_REF,
            "program": "deployctl",
            "message": format!("see {DEPLOY_REF} for the key"),
        })
    }

    /// The I-034 acceptance walk, end to end at the ring: a declared slot resolves through
    /// evaluation and the store, the provider receives the marker and the channel rather
    /// than the reference, the SB-7 pair names key, version and rule, and no serialized
    /// record or result carries any byte window of the material (the SB-1 measurement
    /// discipline). Then the budget arithmetic: two dispatches spend two uses, the third
    /// names the budget, and after quarantine the refusal names key state, because state
    /// precedes budget in the evaluator's gate order.
    #[tokio::test]
    async fn the_ring_resolves_a_declared_slot_end_to_end() {
        let store = bound_store(2);
        let (path, router, provider) = keyed_router(&store);

        let result = router
            .dispatch("keyed_run", keyed_args(), CallContext::new(None))
            .await;
        assert!(!result.is_error, "{result:?}");

        // What the provider saw: the marker where the reference was, the free-text
        // reference untouched (SB-2 inertness inside the same call), and the material in
        // the channel under the declared variable.
        let observed = provider.observed.lock().unwrap().clone().expect("called");
        assert_eq!(observed.args["credential"], SECRET_SLOT_MARKER);
        assert_eq!(observed.args["program"], "deployctl");
        assert_eq!(
            observed.args["message"],
            format!("see {DEPLOY_REF} for the key"),
            "a reference in a free-text argument is literal text (SB-2)"
        );
        assert!(!observed.channel_empty);
        let (variable, bytes) = observed.resolved.expect("the slot resolved");
        assert_eq!(variable, "DATABASE_URL");
        assert_eq!(bytes, SECRET_MATERIAL);

        // The SB-7 pair: intent then outcome, one call_id, both naming key, version and
        // rule.
        let events = audit_lines(&path);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["decision"], nmcp_audit::INTENT_DECISION);
        assert_eq!(events[1]["decision"], nmcp_audit::ALLOWED_DECISION);
        assert_eq!(events[0]["call_id"], events[1]["call_id"]);
        for event in &events {
            assert_eq!(event["secret_name"], "deploy.db");
            assert_eq!(event["secret_version"], "1");
            assert_eq!(event["secret_rule"], "binding.deploy.db");
        }

        // SB-1, measured rather than asserted: no byte window of the material in any
        // serialized audit record or in the result.
        let material = String::from_utf8_lossy(SECRET_MATERIAL).to_string();
        let chain = std::fs::read_to_string(&path).expect("chain");
        assert!(!chain.contains(&material), "material reached the chain");
        let rendered = serde_json::to_string(&result.content).expect("content");
        assert!(!rendered.contains(&material), "material reached the result");
        assert!(
            rendered.contains(SECRET_SLOT_MARKER),
            "the echoed arguments carry the marker, which proves the provider echoed what \
             it was given rather than what the caller sent"
        );

        // The budget decremented exactly once per dispatch: the second use of a
        // two-per-window budget succeeds, the third is refused naming the budget.
        let second = router
            .dispatch("keyed_run", keyed_args(), CallContext::new(None))
            .await;
        assert!(!second.is_error, "a double decrement would refuse here");
        let third = router
            .dispatch("keyed_run", keyed_args(), CallContext::new(None))
            .await;
        assert!(third.is_error);
        let third_text = third.content[0]["text"].as_str().unwrap_or_default();
        assert!(third_text.contains("use-budget"), "{third_text}");

        // Quarantine, then dispatch again: refused with key state named, which precedes
        // the budget in the evaluator's gate order, and the denied record carries the rule.
        store
            .quarantine(&SecretName::parse("deploy.db").unwrap())
            .unwrap();
        let fourth = router
            .dispatch("keyed_run", keyed_args(), CallContext::new(None))
            .await;
        assert!(fourth.is_error);
        let fourth_text = fourth.content[0]["text"].as_str().unwrap_or_default();
        assert!(fourth_text.contains("key-state"), "{fourth_text}");
        let events = audit_lines(&path);
        let last = events.last().expect("denied record");
        assert_eq!(last["decision"], nmcp_audit::DENIED_DECISION);
        assert_eq!(last["secret_name"], "deploy.db");
        assert_eq!(last["secret_rule"], "key-state");
        assert_eq!(
            last["secret_version"],
            serde_json::Value::Null,
            "no version was chosen for a refused resolution"
        );
        let _ = std::fs::remove_file(path);
    }

    /// Deny by default at the ring: a key the operator stored and never bound refuses with
    /// the rule named, before the intent record, so the chain shows one denied record and
    /// no intent that never got an outcome.
    #[tokio::test]
    async fn an_unbound_key_refuses_with_the_rule_named() {
        let store = bound_store(2);
        store
            .set(
                &SecretName::parse("unbound.key").unwrap(),
                Sealed::new(b"vv2qk-8mzt3-unbound".to_vec()),
            )
            .unwrap();
        let (path, router, provider) = keyed_router(&store);

        let result = router
            .dispatch(
                "keyed_run",
                json!({"credential": "nmcp://secret/unbound.key", "program": "deployctl"}),
                CallContext::new(None),
            )
            .await;
        assert!(result.is_error);
        let text = result.content[0]["text"].as_str().unwrap_or_default();
        assert!(text.contains("no-binding"), "{text}");
        assert!(
            provider.observed.lock().unwrap().is_none(),
            "a stage 5b refusal never reaches the provider"
        );

        let events = audit_lines(&path);
        assert_eq!(events.len(), 1, "a refused call writes no intent record");
        assert_eq!(events[0]["decision"], nmcp_audit::DENIED_DECISION);
        assert_eq!(events[0]["secret_name"], "unbound.key");
        assert_eq!(events[0]["secret_rule"], "no-binding");
        let _ = std::fs::remove_file(path);
    }

    /// SB-2 at dispatch, with resolution wired and armed: a tool with no declared slots
    /// passes a well-formed reference through as literal text, untouched, and nothing is
    /// evaluated or stamped for it. This is the I-032 inertness property held at the ring
    /// rather than at the extractor.
    #[tokio::test]
    async fn a_tool_with_no_slots_passes_a_reference_through_inert() {
        let store = bound_store(2);
        let (path, router, _provider) = keyed_router(&store);
        router.register(Arc::new(EchoProvider)).expect("register");

        let result = router
            .dispatch("echo", json!({"path": DEPLOY_REF}), CallContext::new(None))
            .await;
        assert!(!result.is_error, "{result:?}");
        let rendered = serde_json::to_string(&result.content).expect("content");
        assert!(
            rendered.contains(DEPLOY_REF),
            "the reference reaches the tool as the literal text the caller sent: {rendered}"
        );
        let events = audit_lines(&path);
        for event in &events {
            assert_eq!(
                event["secret_name"],
                serde_json::Value::Null,
                "nothing was resolved, so nothing is stamped"
            );
        }
        let _ = std::fs::remove_file(path);
    }

    /// The declared-slot-without-a-reference ruling, decided and held: a plain string in a
    /// declared slot is a caller error the tool must not see, refused naming the slot,
    /// because passing it through would run the tool with a credential-shaped string where
    /// the contract promised injected material, which fails open in the direction
    /// `UndeclaredSecretSlot` exists to refuse. An absent optional slot is the other half
    /// of the ruling and is a separate test below.
    #[tokio::test]
    async fn a_declared_slot_with_a_plain_string_refuses_naming_the_slot() {
        let store = bound_store(2);
        let (path, router, provider) = keyed_router(&store);

        let result = router
            .dispatch(
                "keyed_run",
                json!({"credential": "hunter2-plain-text", "program": "deployctl"}),
                CallContext::new(None),
            )
            .await;
        assert!(result.is_error);
        let text = result.content[0]["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("slot-requires-reference:credential"),
            "{text}"
        );
        assert!(provider.observed.lock().unwrap().is_none());
        let _ = std::fs::remove_file(path);
    }

    /// A declared slot whose argument is absent fires nothing: no evaluation, no spend, no
    /// stamp, an empty channel, and the arguments reach the provider without the slot key
    /// being invented. Proven with a one-use budget: the slotless dispatch spends nothing,
    /// so the reference-carrying dispatch after it still finds its use available.
    #[tokio::test]
    async fn an_absent_optional_slot_fires_nothing_and_spends_nothing() {
        let store = bound_store(1);
        let (path, router, provider) = keyed_router(&store);

        let without = router
            .dispatch(
                "keyed_run",
                json!({"program": "deployctl"}),
                CallContext::new(None),
            )
            .await;
        assert!(!without.is_error, "{without:?}");
        let observed = provider.observed.lock().unwrap().clone().expect("called");
        assert!(observed.channel_empty);
        assert!(observed.resolved.is_none());
        assert_eq!(
            observed.args.get("credential"),
            None,
            "an absent slot argument is not invented"
        );

        let with = router
            .dispatch("keyed_run", keyed_args(), CallContext::new(None))
            .await;
        assert!(
            !with.is_error,
            "the one budgeted use is still available, so the absent slot spent nothing: {with:?}"
        );
        let _ = std::fs::remove_file(path);
    }

    /// The unwired composition, documented as a decision: a router with no
    /// `SecretResolution` treats stage 5b as inert, so a reference stays literal text and
    /// the channel stays empty. There is no store in the process, so there is no material
    /// anywhere to protect, and a reference is a name (SB-2, T3); SB-8's fail-closed rule
    /// governs a wired store that refuses, which the tests above hold.
    #[tokio::test]
    async fn an_unwired_ring_leaves_references_as_text() {
        let (path, audit) = temp_audit("stage5b-unwired");
        let router = router_over(PolicyConfig::default(), audit);
        let provider = KeyedProvider::new();
        router
            .register(Arc::clone(&provider) as Arc<dyn ToolProvider>)
            .expect("register");

        let result = router
            .dispatch("keyed_run", keyed_args(), CallContext::new(None))
            .await;
        assert!(!result.is_error, "{result:?}");
        let observed = provider.observed.lock().unwrap().clone().expect("called");
        assert!(observed.channel_empty);
        assert_eq!(observed.args["credential"], DEPLOY_REF);
        let _ = std::fs::remove_file(path);
    }
}
