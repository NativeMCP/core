//! Attribute-based access control (ABAC) ring stage.
//!
//! ## Ring position
//!
//! ```text
//! base permission check (nmcp-policy)
//!   -> ABAC stage (this crate)         <- here
//!       time-of-day / caller-identity / command-content / signature-verified-at-load
//!       risk score >= threshold -> HITL gate (pause, fail-closed)
//!   -> provider.call()
//! ```
//!
//! ABAC runs **after** base permission and **before** the provider. It cannot be
//! bypassed -- it sits on the single `dispatch` path established by the GW router.
//!
//! ## Invariants
//!
//! - ABAC rules can never override the no-delete code invariant (`DeleteGuard` runs first).
//! - Daemon loads only the **public** verification key; private key is never held here.
//! - Key material and HITL argument payloads are redacted before any audit write.
//! - HITL timeout always fails **closed** (deny, never approve on timeout).
//! - Rules are read from the **live** policy arc on every call -- never from a default.

use chrono::{DateTime, Local, Timelike, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use nmcp_audit::{AuditEvent, AuditSink};
use nmcp_policy::AbacRule;
use nmcp_schema::CallContext;
use parking_lot::Mutex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::oneshot;
use tracing::{info, warn};
use uuid::Uuid;

// AbacDecision

/// The outcome of ABAC evaluation for a single tool call.
#[derive(Debug, Clone)]
pub enum AbacDecision {
    /// Allow the call to proceed to the provider.
    Allow,
    /// Deny the call immediately with a reason.
    Deny(String),
    /// Pause the call for human approval. Returns the risk context for the HITL gate.
    RequireApproval(RiskContext),
}

/// Context attached to a paused call waiting for human approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskContext {
    /// Stable identifier.
    pub id: Uuid,
    /// The `tool` field.
    pub tool: String,
    /// The `args_redacted` field.
    pub args_redacted: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    /// The `args_for_approval` field.
    pub args_for_approval: Value,
    /// The `session_id` field.
    pub session_id: Option<String>,
    /// The `caller` field.
    pub caller: Option<String>,
    /// The `risk_reasons` field.
    pub risk_reasons: Vec<String>,
    /// The `created_at` field.
    pub created_at: DateTime<Utc>,
    /// Seconds until automatic denial.
    pub timeout_secs: u64,
}

// AbacStage

/// The ABAC ring stage. Holds the live policy arc and the HITL pending-approval registry.
///
/// Clone-cheap via inner `Arc`.
#[derive(Clone)]
pub struct AbacStage {
    inner: Arc<AbacInner>,
}

struct AbacInner {
    audit: AuditSink,
    hitl: HitlRegistry,
    /// Default timeout for HITL approvals in seconds.
    hitl_timeout_secs: AtomicU64,
    /// Live policy -- ABAC reads rules from here on every call.
    policy: Arc<parking_lot::RwLock<nmcp_policy::PolicyConfig>>,
}

impl AbacStage {
    /// Construct with the live policy arc. Rules are read from the arc on every call.
    pub fn new(
        audit: AuditSink,
        policy: Arc<parking_lot::RwLock<nmcp_policy::PolicyConfig>>,
    ) -> Self {
        Self {
            inner: Arc::new(AbacInner {
                audit,
                hitl: HitlRegistry::default(),
                hitl_timeout_secs: AtomicU64::new(120),
                policy,
            }),
        }
    }

    #[must_use]
    /// `with_timeout`.
    pub fn with_timeout(self, secs: u64) -> Self {
        self.inner.hitl_timeout_secs.store(secs, Ordering::Relaxed);
        self
    }

    /// Evaluate ABAC rules for a call. Returns `AbacDecision`.
    ///
    /// Rules are evaluated in order; first match wins. If no rule matches the
    /// call is allowed.
    #[must_use]
    pub fn evaluate(
        &self,
        ctx: &CallContext,
        tool_name: &str,
        args: &Value,
        rules: &[AbacRule],
    ) -> AbacDecision {
        let mut risk_reasons: Vec<String> = Vec::new();
        let mut requires_approval = false;

        for rule in rules {
            match self.evaluate_rule(rule, ctx, tool_name, args) {
                RuleOutcome::NoMatch => {}
                RuleOutcome::Deny(reason) => {
                    self.record_abac_denied(tool_name, ctx, &reason);
                    return AbacDecision::Deny(reason);
                }
                RuleOutcome::Escalate(reason) => {
                    risk_reasons.push(reason);
                    requires_approval = true;
                }
            }
        }

        if requires_approval {
            let ctx_id = Uuid::new_v4();
            let risk = RiskContext {
                id: ctx_id,
                tool: tool_name.to_string(),
                args_redacted: redact_args(args),
                args_for_approval: args.clone(),
                session_id: ctx.session_id.clone(),
                caller: ctx.agent_id.clone(),
                risk_reasons,
                created_at: Utc::now(),
                timeout_secs: self.inner.hitl_timeout_secs.load(Ordering::Relaxed),
            };
            AbacDecision::RequireApproval(risk)
        } else {
            AbacDecision::Allow
        }
    }

    // Takes &self so every rule kind is evaluated through the stage, which is
    // where rule state will live as kinds are added; the current kinds happen
    // not to need it.
    #[allow(clippy::unused_self)]
    fn evaluate_rule(
        &self,
        rule: &AbacRule,
        ctx: &CallContext,
        tool_name: &str,
        args: &Value,
    ) -> RuleOutcome {
        match rule {
            AbacRule::TimeOfDay {
                tools,
                allow_start_hour,
                allow_end_hour,
                action,
            } => {
                if !tool_matches(tool_name, tools.as_ref()) {
                    return RuleOutcome::NoMatch;
                }
                let Some(in_window) =
                    hour_in_window(Local::now().hour(), *allow_start_hour, *allow_end_hour)
                else {
                    return RuleOutcome::Deny(format!(
                        "invalid ABAC time window for tool '{tool_name}': {allow_start_hour:02}:00-{allow_end_hour:02}:00"
                    ));
                };
                if !in_window {
                    let reason = format!(
                        "tool '{tool_name}' is not allowed outside \
                         {allow_start_hour:02}:00-{allow_end_hour:02}:00 local"
                    );
                    return rule_action_outcome(action, reason);
                }
                RuleOutcome::NoMatch
            }

            AbacRule::CallerIdentity {
                allowed_callers,
                tools,
                action,
            } => {
                if !tool_matches(tool_name, tools.as_ref()) {
                    return RuleOutcome::NoMatch;
                }
                let caller = ctx.agent_id.as_deref().unwrap_or("");
                if !allowed_callers.iter().any(|c| c == caller || c == "*") {
                    let reason = format!(
                        "caller '{caller}' is not in the allowed list for tool '{tool_name}'"
                    );
                    return rule_action_outcome(action, reason);
                }
                RuleOutcome::NoMatch
            }

            AbacRule::CallerToolAllowlist {
                caller,
                allowed_tools,
                action,
            } => {
                // Applies to one identity only. Anyone else falls straight through, so this
                // cannot accidentally restrict the operator's own client.
                if ctx.agent_id.as_deref() != Some(caller.as_str()) {
                    return RuleOutcome::NoMatch;
                }
                if allowed_tools.iter().any(|allowed| allowed == tool_name) {
                    return RuleOutcome::NoMatch;
                }
                let reason = format!(
                    "caller '{caller}' is restricted to an explicit tool allowlist and \
                     '{tool_name}' is not on it"
                );
                rule_action_outcome(action, reason)
            }

            AbacRule::CommandContent {
                pattern,
                tools,
                action,
            } => {
                if !tool_matches(tool_name, tools.as_ref()) {
                    return RuleOutcome::NoMatch;
                }
                let args_str = args.to_string().to_lowercase();
                let re = match Regex::new(&pattern.to_lowercase()) {
                    Ok(re) => re,
                    Err(err) => {
                        return RuleOutcome::Deny(format!(
                            "invalid ABAC command-content regex for tool '{tool_name}': {pattern}: {err}"
                        ));
                    }
                };
                if re.is_match(&args_str) {
                    let reason =
                        format!("tool '{tool_name}' args match content rule pattern '{pattern}'");
                    return rule_action_outcome(action, reason);
                }
                RuleOutcome::NoMatch
            }
        }
    }

    fn record_abac_denied(&self, tool: &str, ctx: &CallContext, reason: &str) {
        let mut event = AuditEvent::new(tool, reason);
        event.decision = nmcp_audit::ABAC_DENIED_DECISION.into();
        event.client = ctx.session_id.clone().unwrap_or_else(|| "local".into());
        event.call_id = Some(ctx.call_id);
        if let Err(e) = self.inner.audit.append(&event) {
            warn!(call_id = %ctx.call_id, "ABAC: failed to write audit: {e}");
        }
    }

    /// Register a pending HITL item and write `hitl_pending` audit event.
    /// Blocks until human approves or timeout fires (always fails closed on timeout).
    pub async fn register_hitl(&self, risk: RiskContext, ctx: &CallContext) -> HitlOutcome {
        let id = risk.id;
        let timeout = risk.timeout_secs;
        let (tx, rx) = oneshot::channel::<bool>();

        let summary = serde_json::to_string(&serde_json::json!({
            "id": risk.id,
            "tool": risk.tool,
            "args_redacted": risk.args_redacted,
            "session_id": risk.session_id,
            "caller": risk.caller,
            "risk_reasons": risk.risk_reasons,
            "created_at": risk.created_at,
            "timeout_secs": risk.timeout_secs,
        }))
        .unwrap_or_else(|_| "<redacted>".into());
        let mut event = AuditEvent::new(&risk.tool, &summary);
        event.decision = nmcp_audit::HITL_PENDING_DECISION.into();
        event.client = ctx.session_id.clone().unwrap_or_else(|| "local".into());
        event.call_id = Some(ctx.call_id);
        if let Err(e) = self.inner.audit.append(&event) {
            warn!("ABAC HITL: failed to write hitl_pending audit: {e}");
        }

        self.inner.hitl.insert(id, risk, tx);

        let timeout_dur = tokio::time::Duration::from_secs(timeout);
        let outcome = match tokio::time::timeout(timeout_dur, rx).await {
            Ok(Ok(true)) => {
                info!(hitl_id = %id, "ABAC HITL: approved");
                HitlOutcome::Approved
            }
            Ok(Ok(false) | Err(_)) => {
                info!(hitl_id = %id, "ABAC HITL: denied by operator");
                HitlOutcome::Denied("denied by operator".into())
            }
            Err(_) => {
                warn!(hitl_id = %id, "ABAC HITL: timed out -- failing closed");
                let mut event = AuditEvent::new("hitl_timeout", "<redacted>");
                event.decision = nmcp_audit::HITL_DENIED_TIMEOUT_DECISION.into();
                event.call_id = Some(ctx.call_id);
                let _ = self.inner.audit.append(&event);
                HitlOutcome::Denied("approval timed out -- fail closed".into())
            }
        };

        self.inner.hitl.remove(id);
        outcome
    }

    /// Resolve a pending HITL item. Called by the admin approve/deny routes.
    #[must_use]
    pub fn resolve_hitl(&self, id: Uuid, approved: bool) -> bool {
        self.inner.hitl.resolve(id, approved)
    }

    /// List all currently pending HITL items for the admin UI.
    #[must_use]
    pub fn pending_hitl(&self) -> Vec<RiskContext> {
        self.inner.hitl.list()
    }
}

// HitlOutcome

#[derive(Debug)]
/// The `HitlOutcome` enumeration.
pub enum HitlOutcome {
    /// The `Approved` case.
    Approved,
    /// The `Denied` case.
    Denied(String),
}

// HitlRegistry

#[derive(Default)]
struct HitlRegistry {
    pending: Mutex<HashMap<Uuid, (RiskContext, oneshot::Sender<bool>)>>,
}

impl HitlRegistry {
    fn insert(&self, id: Uuid, risk: RiskContext, tx: oneshot::Sender<bool>) {
        self.pending.lock().insert(id, (risk, tx));
    }

    fn remove(&self, id: Uuid) {
        self.pending.lock().remove(&id);
    }

    fn resolve(&self, id: Uuid, approved: bool) -> bool {
        if let Some((_, tx)) = self.pending.lock().remove(&id) {
            let _ = tx.send(approved);
            true
        } else {
            false
        }
    }

    fn list(&self) -> Vec<RiskContext> {
        self.pending
            .lock()
            .values()
            .map(|(r, _)| r.clone())
            .collect()
    }
}

// Helpers

enum RuleOutcome {
    NoMatch,
    Deny(String),
    Escalate(String),
}

fn hour_in_window(hour: u32, start: u32, end: u32) -> Option<bool> {
    if hour > 23 || start > 23 || end > 24 || start == end {
        return None;
    }
    if start < end {
        Some(hour >= start && hour < end)
    } else {
        Some(hour >= start || hour < end)
    }
}

fn tool_matches(tool: &str, filter: Option<&Vec<String>>) -> bool {
    match filter {
        None => true,
        Some(list) => list.iter().any(|t| t == tool || t == "*"),
    }
}

fn rule_action_outcome(action: &nmcp_policy::AbacAction, reason: String) -> RuleOutcome {
    match action {
        nmcp_policy::AbacAction::Deny => RuleOutcome::Deny(reason),
        nmcp_policy::AbacAction::RequireApproval => RuleOutcome::Escalate(reason),
    }
}

/// Redact argument values before storing in HITL or audit.
/// Preserves keys but replaces string values > 20 chars with `<redacted>`.
fn redact_args(args: &Value) -> Value {
    match args {
        Value::Object(map) => {
            let redacted = map
                .iter()
                .map(|(k, v)| {
                    let rv = match v {
                        Value::String(s) if s.len() > 20 => Value::String("<redacted>".into()),
                        other => other.clone(),
                    };
                    (k.clone(), rv)
                })
                .collect();
            Value::Object(redacted)
        }
        _ => Value::String("<redacted>".into()),
    }
}

// Manifest signature verification (ABAC-3)

/// Verify that a tool descriptor manifest has a valid Ed25519 signature.
/// The daemon **never** holds a private key; only the public key is passed here.
///
/// Signature format: a `"_sig"` field in the manifest JSON containing
/// a hex-encoded Ed25519 signature over the canonical JSON (with `"_sig"` removed).
///
/// # Errors
///
/// Returns the error this operation can fail with.
pub fn verify_manifest_signature(
    manifest: &Value,
    public_key_bytes: &[u8; 32],
) -> Result<(), String> {
    let sig_hex = manifest
        .get("_sig")
        .and_then(Value::as_str)
        .ok_or_else(|| "manifest has no `_sig` field -- unsigned manifest rejected".to_string())?;

    let sig_bytes =
        hex::decode(sig_hex).map_err(|_| "manifest `_sig` is not valid hex".to_string())?;

    if sig_bytes.len() != 64 {
        return Err(format!(
            "manifest `_sig` has wrong length {} (expected 64 bytes)",
            sig_bytes.len()
        ));
    }

    let mut payload_map = manifest
        .as_object()
        .ok_or("manifest is not a JSON object")?
        .clone();
    payload_map.remove("_sig");
    let payload = serde_json::to_string(&Value::Object(payload_map))
        .map_err(|e| format!("manifest serialization error: {e}"))?;

    let vk = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|e| format!("invalid public key: {e}"))?;
    // The length was checked above, so this conversion cannot fail; it is
    // written as a refusal rather than an unwrap because this is signature
    // verification, and a panic here would take the process down on
    // attacker-supplied input rather than rejecting the manifest.
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "manifest `_sig` is not 64 bytes".to_string())?;
    let sig = Signature::from_bytes(&sig_array);
    vk.verify(payload.as_bytes(), &sig).map_err(|_| {
        "manifest signature verification failed -- manifest may be tampered".to_string()
    })
}

// AbacCheck impl

impl nmcp_router::AbacCheck for AbacStage {
    fn evaluate(
        &self,
        ctx: &CallContext,
        tool_name: &str,
        args: &serde_json::Value,
    ) -> nmcp_router::AbacDecision {
        // Read live rules from the policy arc -- this is what governance actually enforces.
        // A default (empty) policy never reaches this path.
        let rules = self.inner.policy.read().abac_rules.clone();
        match AbacStage::evaluate(self, ctx, tool_name, args, &rules) {
            AbacDecision::Allow => nmcp_router::AbacDecision::Allow,
            AbacDecision::Deny(r) => nmcp_router::AbacDecision::Deny(r),
            AbacDecision::RequireApproval(_) => nmcp_router::AbacDecision::RequireApproval,
        }
    }

    fn wait_for_approval<'a>(
        &'a self,
        ctx: &'a CallContext,
        tool_name: &'a str,
        args: &'a serde_json::Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        // Re-evaluate to recover the actual risk reasons for the approval view.
        let rules = self.inner.policy.read().abac_rules.clone();
        let risk_reasons = match AbacStage::evaluate(self, ctx, tool_name, args, &rules) {
            AbacDecision::RequireApproval(rc) => rc.risk_reasons,
            _ => vec!["escalated by ABAC rule".into()],
        };
        let risk = RiskContext {
            id: uuid::Uuid::new_v4(),
            tool: tool_name.to_string(),
            args_redacted: redact_args(args),
            args_for_approval: args.clone(),
            session_id: ctx.session_id.clone(),
            caller: ctx.agent_id.clone(),
            risk_reasons,
            created_at: chrono::Utc::now(),
            timeout_secs: self.inner.hitl_timeout_secs.load(Ordering::Relaxed),
        };
        Box::pin(async move {
            match self.register_hitl(risk, ctx).await {
                HitlOutcome::Approved => true,
                HitlOutcome::Denied(_) => false,
            }
        })
    }
}

/// Convenience: construct an `Arc<dyn AbacCheck>` from an `AbacStage`.
#[must_use]
pub fn into_abac_check(stage: AbacStage) -> std::sync::Arc<dyn nmcp_router::AbacCheck> {
    std::sync::Arc::new(stage)
}

// Tests

#[cfg(test)]
mod tests {
    #![allow(clippy::items_after_statements, clippy::unnecessary_literal_bound)]
    // Tests assert on shapes and outcomes, where unwrap/expect/indexing
    // ARE the assertion: a panic in a test is the failure signal, so the
    // production rationale for the workspace denies does not apply.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;
    use nmcp_policy::{AbacAction, AbacRule};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Declare the tools a test provider owns.
    ///
    /// NMCP-SPEC-003 section 4.3 makes `contracts` required, so the two providers in this
    /// module gain it. Nothing in this crate reads it: ABAC evaluates a tool name and the
    /// arguments, and the router still resolves through `tool_names`. Derived from
    /// `tool_names` on purpose, so the declaration cannot drift from the surface these tests
    /// were written against.
    fn declare(names: &[String]) -> Vec<nmcp_schema::ToolContract> {
        names
            .iter()
            .map(|name| nmcp_schema::ToolContract {
                name: name.clone(),
                description: name.clone(),
                input_schema: json!({"type": "object"}),
                authority: nmcp_schema::ToolAuthority {
                    permission: None,
                    path_args: Vec::new(),
                    grants: Vec::new(),
                    effect: nmcp_schema::ToolEffect::Observe,
                    reach: nmcp_schema::ToolReach::Local,
                },
            })
            .collect()
    }

    fn make_audit() -> AuditSink {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nmcp-abac-test-{stamp}"));
        std::fs::create_dir_all(&dir).unwrap();
        AuditSink::open(dir.join("audit.jsonl")).unwrap()
    }

    fn make_policy_arc() -> Arc<parking_lot::RwLock<nmcp_policy::PolicyConfig>> {
        Arc::new(parking_lot::RwLock::new(
            nmcp_policy::PolicyConfig::default(),
        ))
    }

    fn make_stage() -> AbacStage {
        AbacStage::new(make_audit(), make_policy_arc())
    }

    fn make_ctx() -> CallContext {
        CallContext::new(Some("test-session".into()))
    }

    #[test]
    fn deny_rule_short_circuits() {
        let stage = make_stage();
        let rules = vec![AbacRule::CallerIdentity {
            allowed_callers: vec!["trusted-agent".into()],
            tools: None,
            action: AbacAction::Deny,
        }];
        let mut ctx = make_ctx();
        ctx.agent_id = Some("untrusted".into());
        let decision = stage.evaluate(&ctx, "write_text_file", &json!({}), &rules);
        assert!(matches!(decision, AbacDecision::Deny(_)));
    }

    /// G3-12. The scenario is a third-party client such as `ChatGPT`: authenticating it
    /// establishes who is calling and nothing about what it may do, and what it may do by
    /// default is the entire 63-tool surface including execute as `LocalSystem`.
    fn third_party_allowlist() -> Vec<AbacRule> {
        vec![AbacRule::CallerToolAllowlist {
            caller: "chatgpt".into(),
            allowed_tools: vec![
                "list_roots".into(),
                "list_directory".into(),
                "read_file_window_report".into(),
                "search_repo".into(),
            ],
            action: AbacAction::Deny,
        }]
    }

    #[test]
    fn third_party_caller_is_denied_everything_outside_its_allowlist() {
        let stage = make_stage();
        let rules = third_party_allowlist();
        for tool in [
            "execute",
            "execute_start",
            "win_registry_write",
            "mem_write",
            "backup_file",
            "dev_git_publish",
            "write_text_file",
        ] {
            let mut ctx = make_ctx();
            ctx.agent_id = Some("chatgpt".into());
            let decision = stage.evaluate(&ctx, tool, &json!({}), &rules);
            assert!(
                matches!(decision, AbacDecision::Deny(_)),
                "{tool} must be denied to a restricted third-party caller"
            );
        }
    }

    #[test]
    fn third_party_caller_still_reaches_its_allowed_tools() {
        // A restriction that denies everything is not least privilege, it is a broken client.
        let stage = make_stage();
        let rules = third_party_allowlist();
        for tool in [
            "list_roots",
            "list_directory",
            "read_file_window_report",
            "search_repo",
        ] {
            let mut ctx = make_ctx();
            ctx.agent_id = Some("chatgpt".into());
            let decision = stage.evaluate(&ctx, tool, &json!({}), &rules);
            assert!(
                matches!(decision, AbacDecision::Allow),
                "{tool} is on the allowlist and must still be reachable"
            );
        }
    }

    #[test]
    fn the_allowlist_does_not_touch_any_other_caller() {
        // The rule names one identity. The operator's own client, and an unauthenticated
        // local caller with no agent_id at all, must be unaffected by it.
        let stage = make_stage();
        let rules = third_party_allowlist();

        let mut operator = make_ctx();
        operator.agent_id = Some("claude-connector".into());
        assert!(matches!(
            stage.evaluate(&operator, "execute", &json!({}), &rules),
            AbacDecision::Allow
        ));

        let anonymous = make_ctx();
        assert!(matches!(
            stage.evaluate(&anonymous, "execute", &json!({}), &rules),
            AbacDecision::Allow
        ));
    }

    #[test]
    fn a_tool_added_later_is_denied_to_the_restricted_caller_with_no_policy_edit() {
        // This is the whole reason for a new rule kind. CallerIdentity is a deny-list, so a
        // tool invented tomorrow would be unrestricted until somebody remembered it. Here the
        // default is denial, so forgetting is safe.
        let stage = make_stage();
        let rules = third_party_allowlist();
        let mut ctx = make_ctx();
        ctx.agent_id = Some("chatgpt".into());
        let decision = stage.evaluate(&ctx, "some_tool_invented_next_quarter", &json!({}), &rules);
        assert!(matches!(decision, AbacDecision::Deny(_)));
    }

    #[test]
    fn allow_rule_when_no_match() {
        let stage = make_stage();
        let rules: Vec<AbacRule> = vec![];
        let ctx = make_ctx();
        let decision = stage.evaluate(&ctx, "list_directory", &json!({}), &rules);
        assert!(matches!(decision, AbacDecision::Allow));
    }

    #[test]
    fn time_rule_denies_outside_window() {
        let stage = make_stage();
        let rules = vec![AbacRule::TimeOfDay {
            tools: None,
            allow_start_hour: 25,
            allow_end_hour: 26,
            action: AbacAction::Deny,
        }];
        let ctx = make_ctx();
        let decision = stage.evaluate(&ctx, "execute", &json!({}), &rules);
        assert!(matches!(decision, AbacDecision::Deny(_)));
    }

    #[test]
    fn time_rule_allows_inside_window() {
        let stage = make_stage();
        let rules = vec![AbacRule::TimeOfDay {
            tools: None,
            allow_start_hour: 0,
            allow_end_hour: 24,
            action: AbacAction::Deny,
        }];
        let ctx = make_ctx();
        let decision = stage.evaluate(&ctx, "execute", &json!({}), &rules);
        assert!(matches!(decision, AbacDecision::Allow));
    }

    #[test]
    fn command_content_escalates_on_rm_drop() {
        let stage = make_stage();
        let rules = vec![AbacRule::CommandContent {
            pattern: r"rm|drop|format".into(),
            tools: None,
            action: AbacAction::RequireApproval,
        }];
        let ctx = make_ctx();
        let args = json!({"command": "rm -rf /tmp/foo"});
        let decision = stage.evaluate(&ctx, "execute", &args, &rules);
        assert!(matches!(decision, AbacDecision::RequireApproval(_)));
    }

    #[test]
    fn command_content_allows_safe_args() {
        let stage = make_stage();
        let rules = vec![AbacRule::CommandContent {
            pattern: r"rm|drop|format".into(),
            tools: None,
            action: AbacAction::RequireApproval,
        }];
        let ctx = make_ctx();
        let args = json!({"command": "cargo build --release"});
        let decision = stage.evaluate(&ctx, "execute", &args, &rules);
        assert!(matches!(decision, AbacDecision::Allow));
    }

    #[test]
    fn command_content_invalid_regex_fails_closed() {
        let stage = make_stage();
        let rules = vec![AbacRule::CommandContent {
            pattern: "(".into(),
            tools: None,
            action: AbacAction::RequireApproval,
        }];
        let ctx = make_ctx();
        let decision = stage.evaluate(&ctx, "execute", &json!({"command": "safe"}), &rules);
        assert!(
            matches!(decision, AbacDecision::Deny(reason) if reason.contains("invalid ABAC command-content regex"))
        );
    }

    #[test]
    fn time_rule_supports_overnight_windows_and_rejects_invalid_hours() {
        assert_eq!(hour_in_window(23, 22, 6), Some(true));
        assert_eq!(hour_in_window(3, 22, 6), Some(true));
        assert_eq!(hour_in_window(12, 22, 6), Some(false));
        assert_eq!(hour_in_window(12, 25, 26), None);
        assert_eq!(hour_in_window(12, 6, 6), None);
    }

    #[tokio::test]
    async fn hitl_pending_exposes_operator_args_but_audit_summary_is_redacted() {
        let stage = make_stage().with_timeout(30);
        let risk = RiskContext {
            id: Uuid::new_v4(),
            tool: "execute".into(),
            args_redacted: json!({"command": "<redacted>"}),
            args_for_approval: json!({"command": "full command visible to operator"}),
            session_id: Some("sess".into()),
            caller: Some("agent-alpha".into()),
            risk_reasons: vec!["manual check".into()],
            created_at: Utc::now(),
            timeout_secs: 30,
        };
        let ctx = make_ctx();
        let pending_stage = stage.clone();
        let task = tokio::spawn(async move { pending_stage.register_hitl(risk, &ctx).await });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        let pending = stage.pending_hitl();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].args_for_approval["command"],
            "full command visible to operator"
        );
        assert_eq!(pending[0].args_redacted["command"], "<redacted>");
        assert!(stage.resolve_hitl(pending[0].id, false));
        let _ = task.await;
    }
    #[tokio::test]
    async fn hitl_timeout_fails_closed() {
        let stage = make_stage();
        let risk = RiskContext {
            id: Uuid::new_v4(),
            tool: "execute".into(),
            args_redacted: json!({"command": "<redacted>"}),
            args_for_approval: json!({"command": "dangerous long command"}),
            session_id: Some("sess".into()),
            caller: None,
            risk_reasons: vec!["rm detected".into()],
            created_at: Utc::now(),
            timeout_secs: 0,
        };
        let ctx = make_ctx();
        let outcome = stage.register_hitl(risk, &ctx).await;
        assert!(
            matches!(outcome, HitlOutcome::Denied(_)),
            "HITL must fail closed on timeout"
        );
    }

    #[test]
    fn redact_args_masks_long_strings() {
        let args = json!({"path": "/short", "content": "this is a very long string that should be redacted"});
        let redacted = redact_args(&args);
        assert_eq!(redacted["path"], "/short");
        assert_eq!(redacted["content"], "<redacted>");
    }

    #[tokio::test]
    async fn configured_deny_rule_denies_through_router_dispatch() {
        use async_trait::async_trait;
        use nmcp_router::{Router, ToolProvider};
        use nmcp_schema::{CallContext, ToolCallResult};

        let policy_arc = Arc::new(parking_lot::RwLock::new(nmcp_policy::PolicyConfig {
            abac_rules: vec![AbacRule::CallerIdentity {
                allowed_callers: vec!["trusted-only".into()],
                tools: None,
                action: AbacAction::Deny,
            }],
            ..nmcp_policy::PolicyConfig::default()
        }));

        let audit = make_audit();
        let abac = AbacStage::new(audit.clone(), policy_arc.clone());

        struct Echo;
        #[async_trait]
        impl ToolProvider for Echo {
            fn contract_version(&self) -> u32 {
                1
            }
            fn provider_id(&self) -> &str {
                ""
            }
            fn contracts(&self) -> Vec<nmcp_schema::ToolContract> {
                declare(&self.tool_names())
            }
            fn tool_names(&self) -> Vec<String> {
                vec!["echo".into()]
            }
            fn tool_list(&self) -> Vec<serde_json::Value> {
                vec![serde_json::json!({"name":"echo","description":"echo","inputSchema":{}})]
            }
            async fn call(
                &self,
                _: &str,
                args: serde_json::Value,
                _: &CallContext,
            ) -> ToolCallResult {
                ToolCallResult::ok(args)
            }
        }

        let mut router = Router::new(policy_arc, audit);
        router.set_abac(into_abac_check(abac));
        router.register(std::sync::Arc::new(Echo));

        let mut ctx = CallContext::new(Some("session-1".into()));
        ctx.agent_id = Some("untrusted-agent".into());
        let result = router
            .dispatch("echo", serde_json::json!({"msg": "hi"}), ctx)
            .await;
        assert!(
            result.is_error,
            "configured deny rule must deny through router.dispatch"
        );
        let msg = result.content[0]["text"].as_str().unwrap_or("");
        assert!(msg.contains("ABAC") || msg.contains("denied"), "got: {msg}");

        let mut ctx2 = CallContext::new(Some("session-2".into()));
        ctx2.agent_id = Some("trusted-only".into());
        let result2 = router
            .dispatch("echo", serde_json::json!({"msg": "hi"}), ctx2)
            .await;
        assert!(
            !result2.is_error,
            "trusted caller must pass through router.dispatch"
        );
    }

    #[tokio::test]
    async fn delete_guard_precedes_abac_through_router() {
        use nmcp_router::Router;
        use nmcp_schema::CallContext;

        let policy_arc = make_policy_arc();
        let audit = make_audit();
        let abac = AbacStage::new(audit.clone(), policy_arc.clone());
        let mut router = Router::new(policy_arc, audit);
        router.set_abac(into_abac_check(abac));

        let ctx = CallContext::new(None);
        let result = router
            .dispatch("delete_file", serde_json::json!({}), ctx)
            .await;
        assert!(
            result.is_error,
            "DeleteGuard must block delete tools before ABAC"
        );
        let msg = result.content[0]["text"].as_str().unwrap_or("");
        assert!(msg.contains("no-delete invariant"), "got: {msg}");
    }

    /// The shipped persona template has to restrict the client, not merely parse. This drives
    /// the template file itself through `router.dispatch`, which exercises the `AbacCheck` trait
    /// impl reading the live policy arc. Calling `AbacStage::evaluate` directly, as the unit
    /// tests above do, proves the rule logic but not that a real client is bound by it.
    ///
    /// `mem_write` is the sharp case on purpose. It has no `tool_policy_spec`, so the root ring
    /// never sees it, and it is not mutating by the ring's definition, so the auto-approve gate
    /// never sees it either. Per-client ABAC is the only thing between an authenticated
    /// third-party client and writing into the agent's persistent memory.
    #[tokio::test]
    async fn the_shipped_third_party_template_restricts_that_client_through_router_dispatch() {
        use async_trait::async_trait;
        use nmcp_router::{Router, ToolProvider};
        use nmcp_schema::{CallContext, ToolCallResult};

        let template: nmcp_policy::PolicyConfig = serde_json::from_str(include_str!(
            "../../../examples/policy.persona.third-party-client.example.json"
        ))
        .expect("the shipped third-party persona template must deserialize");
        assert!(
            template
                .abac_rules
                .iter()
                .any(|r| matches!(r, AbacRule::CallerToolAllowlist { .. })),
            "the template exists to carry a caller_tool_allowlist rule"
        );

        let policy_arc = Arc::new(parking_lot::RwLock::new(template));
        let audit = make_audit();
        let abac = AbacStage::new(audit.clone(), policy_arc.clone());

        struct Surface;
        #[async_trait]
        impl ToolProvider for Surface {
            fn contract_version(&self) -> u32 {
                1
            }
            fn provider_id(&self) -> &str {
                ""
            }
            fn contracts(&self) -> Vec<nmcp_schema::ToolContract> {
                declare(&self.tool_names())
            }
            fn tool_names(&self) -> Vec<String> {
                vec![
                    "mem_write".into(),
                    "win_registry_write".into(),
                    "list_roots".into(),
                ]
            }
            fn tool_list(&self) -> Vec<serde_json::Value> {
                self.tool_names()
                    .into_iter()
                    .map(|n| serde_json::json!({"name": n, "description": n, "inputSchema": {}}))
                    .collect()
            }
            async fn call(
                &self,
                _: &str,
                args: serde_json::Value,
                _: &CallContext,
            ) -> ToolCallResult {
                ToolCallResult::ok(args)
            }
        }

        let mut router = Router::new(policy_arc, audit);
        router.set_abac(into_abac_check(abac));
        router.register(std::sync::Arc::new(Surface));

        let third_party = || {
            let mut ctx = CallContext::new(Some("third-party-session".into()));
            ctx.agent_id = Some("third-party".into());
            ctx
        };

        // The case only ABAC can stop.
        let denied = router
            .dispatch("mem_write", serde_json::json!({}), third_party())
            .await;
        assert!(
            denied.is_error,
            "the third-party client must not reach agent memory"
        );
        let msg = denied.content[0]["text"].as_str().unwrap_or("");
        assert!(
            msg.contains("ABAC denied") && msg.contains("allowlist"),
            "the denial must come from the per-client allowlist, got: {msg}"
        );

        // Defense in depth: a capability-gated write surface is refused too. The root ring
        // answers first here, because the template grants no win.api capability, so the reason
        // is the ring's rather than the allowlist's.
        let capability_gated = router
            .dispatch("win_registry_write", serde_json::json!({}), third_party())
            .await;
        assert!(
            capability_gated.is_error,
            "the third-party client must not reach a capability-gated write surface"
        );

        // On the allowlist, so the client is restricted rather than broken.
        let allowed = router
            .dispatch("list_roots", serde_json::json!({}), third_party())
            .await;
        assert!(
            !allowed.is_error,
            "list_roots is on the template allowlist and must still dispatch"
        );

        // Same tool, two callers: only the one the rule names is bound by it.
        let mut operator = CallContext::new(Some("operator-session".into()));
        operator.agent_id = Some("operator".into());
        let operator_result = router
            .dispatch("mem_write", serde_json::json!({}), operator)
            .await;
        assert!(
            !operator_result.is_error,
            "the third-party allowlist must not restrict the operator client"
        );
    }
}
