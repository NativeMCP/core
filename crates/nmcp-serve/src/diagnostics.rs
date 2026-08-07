//! Diagnostics and observability endpoints (H9): health, readiness, metrics,
//! doctor, runtime snapshot, latency, log topology, and support bundle, plus the
//! builders and redaction helpers they use. Extracted from lib.rs.

// Every handler here is `async fn` with nothing to await, which is axum's contract rather
// than an oversight: its `Handler` trait is implemented for `async fn`, so the asynchrony
// belongs to the framework and not to the body. `allow` rather than `expect`, because a
// handler that never gains an await is the normal case and an expectation would fail the day
// one of them legitimately does.
#![allow(
    clippy::unused_async,
    reason = "axum implements Handler for async fn; the asynchrony is the framework's"
)]
// Nothing routes to this module yet. Its consumers are the route table, which is I-077's
// `admin_api`, `gateway_api` and `inspector_api`, and the composition root in I-078. Same shape
// as `peer` and `auth_attempts` at I-073 and the same reason for `allow` over `expect`: the
// module's own tests exercise what they cover, so the lint fires in the lib target and not in
// the lib-test target, and an unfulfilled expectation in either is an error.
//
// Crate-visible rather than public, which is what the base had. Making the builders public to
// silence this would invent an API surface: `value_ok`, `readiness_check` and `doctor_check` are
// internal to how a document is assembled and no caller outside the route table wants them.
#![allow(
    dead_code,
    reason = "the route table is I-077; the composition root is I-078"
)]

use crate::{AppState, resource_metadata_url};
use axum::Json;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use nmcp_authn::KeySetPosture;
use nmcp_policy::PolicyConfig;
use nmcp_router::SharedRouter;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::net::SocketAddr;

/// How long an inspector scan may run before the endpoint answers without it.
///
/// The scans walk configured roots, and a root on a slow or disconnected network share would
/// otherwise hold an admin request open indefinitely. Three seconds is long enough for a local
/// tree and short enough that an operator gets an answer rather than a hung page.
const INSPECTOR_FILE_SCAN_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(3);

/// The answer when a scan outran [`INSPECTOR_FILE_SCAN_TIMEOUT`].
fn inspector_timeout_response(endpoint: &str) -> axum::response::Response {
    (
        StatusCode::GATEWAY_TIMEOUT,
        Json(json!({"error":"inspector endpoint timed out", "endpoint": endpoint})),
    )
        .into_response()
}

/// The answer when the blocking task carrying a scan did not come back.
fn inspector_join_error_response(
    endpoint: &str,
    err: &tokio::task::JoinError,
) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": err.to_string(), "endpoint": endpoint})),
    )
        .into_response()
}

/// INSP-6's query string: how many latency samples to return.
#[derive(serde::Deserialize)]
pub(crate) struct LatencyQuery {
    #[serde(default = "default_latency_limit")]
    limit: usize,
}

fn default_latency_limit() -> usize {
    200
}
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) async fn health() -> Json<Value> {
    Json(build_health())
}
pub(crate) async fn healthz() -> Json<Value> {
    Json(build_health())
}
pub(crate) async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let report = build_readiness(&state);
    let status = if value_ok(&report) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(report))
}
/// `/readyz` on the MCP listener (G3-17).
///
/// Same verdicts as the admin listener's, none of the detail. See [`public_readiness`] for
/// why the projection is an allowlist rather than a redaction.
pub(crate) async fn readyz_public(State(state): State<AppState>) -> impl IntoResponse {
    let report = public_readiness(&build_readiness(&state));
    let status = if value_ok(&report) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(report))
}
pub(crate) async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        build_metrics(&state),
    )
}
pub(crate) async fn api_doctor(State(state): State<AppState>) -> Json<Value> {
    Json(build_doctor(&state))
}
pub(crate) async fn api_diagnostics_runtime(State(state): State<AppState>) -> Json<Value> {
    Json(build_diagnostics_runtime_snapshot(&state))
}
pub(crate) async fn api_diagnostics_log_topology(State(state): State<AppState>) -> Json<Value> {
    Json(build_log_topology(&state))
}
pub(crate) async fn api_diagnostics_latency_history(
    State(state): State<AppState>,
    Query(q): Query<LatencyQuery>,
) -> impl IntoResponse {
    let audit_path = state.policy().audit_path.clone();
    let limit = q.limit;
    let handle =
        tokio::task::spawn_blocking(move || build_latency_history_response(&audit_path, limit));
    match tokio::time::timeout(INSPECTOR_FILE_SCAN_TIMEOUT, handle).await {
        Err(_) => inspector_timeout_response("diagnostics/latency-history"),
        Ok(Err(err)) => inspector_join_error_response("diagnostics/latency-history", &err),
        Ok(Ok(value)) => Json(value).into_response(),
    }
}
pub(crate) async fn api_support_bundle(State(state): State<AppState>) -> Json<Value> {
    Json(build_support_bundle(&state))
}

#[derive(Deserialize)]
pub(crate) struct AuditRecentQuery {
    limit: Option<usize>,
}
pub(crate) async fn api_audit_recent(
    State(state): State<AppState>,
    Query(q): Query<AuditRecentQuery>,
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(200).min(1000);
    let audit_path = state.policy().audit_path.clone();
    match std::fs::read_to_string(&audit_path) {
        Ok(content) => {
            let events: Vec<Value> = content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect::<Vec<Value>>()
                .into_iter()
                .rev()
                .take(limit)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            Json(json!({"events": events, "total": events.len(), "path": audit_path.display().to_string()})).into_response()
        }
        Err(_) => Json(json!({"events": [], "total": 0, "path": audit_path.display().to_string()}))
            .into_response(),
    }
}

#[must_use]
pub(crate) fn build_health() -> Value {
    json!({"ok": true, "server": nmcp_identity::PRODUCT_NAME})
}

#[must_use]
pub(crate) fn build_readiness(state: &AppState) -> Value {
    let policy = state.policy();
    let mut checks = Map::new();
    let effective_exec_state_dir = policy.effective_exec_state_dir();

    readiness_check(&mut checks, "policy_loaded", true, None);
    readiness_check(
        &mut checks,
        "roots_canonicalized",
        !policy.roots.is_empty() && policy.roots.iter().all(|root| root.path.is_absolute()),
        None,
    );
    readiness_check(
        &mut checks,
        "audit_path",
        !policy.audit_path.as_os_str().is_empty(),
        Some(json!({"path": policy.audit_path.display().to_string()})),
    );
    readiness_check(
        &mut checks,
        "exec_state_dir",
        effective_exec_state_dir.is_absolute(),
        Some(json!({"path": effective_exec_state_dir.display().to_string()})),
    );
    readiness_check(
        &mut checks,
        "exec_state_dir_not_system32",
        !is_system32_path(&effective_exec_state_dir),
        None,
    );
    readiness_check(
        &mut checks,
        "admin_mcp_ports_distinct",
        admin_mcp_ports_distinct(&policy),
        None,
    );
    readiness_check(
        &mut checks,
        "mcp_tools_registered",
        !state.router.merged_tool_list().is_empty() && router_no_delete_check(&state.router),
        None,
    );
    // G4-25. "Ready" has to mean the process is running the configuration it was given. If
    // the file on disk will not parse, the prior policy stays live, which is fail-safe, but
    // the running config is no longer the config an operator is looking at. That is a state
    // worth failing readiness for, because the rejected edit is usually a tightening.
    match state.policy_load.rejection() {
        None => readiness_check(&mut checks, "policy_file_matches_live", true, None),
        Some(rejection) => readiness_check(
            &mut checks,
            "policy_file_matches_live",
            false,
            Some(json!({
                "error": rejection.error,
                "rejected_at_unix_ms": rejection.at_unix_ms,
                "detail": "the policy file was rejected at reload; the prior policy is still in force",
            })),
        ),
    }
    readiness_check(
        &mut checks,
        "transport_core_initialized",
        true,
        Some(json!({
            "active_sessions": state.transport.session_count(),
            "max_sessions": state.transport.capabilities().max_sessions,
        })),
    );

    let ok = checks.values().all(value_ok);
    json!({
        "ok": ok,
        "server": nmcp_identity::PRODUCT_NAME,
        "checks": checks
    })
}

/// The readiness document a tokenless caller on the MCP listener may see (G3-17).
///
/// A projection of [`build_readiness`] rather than a second builder, so the two cannot
/// drift: the checks and their verdicts are computed once, in one place, and the admin
/// listener keeps the full document an operator needs.
///
/// It is an ALLOWLIST, not a redaction. Each check contributes exactly one field, `ok`, and
/// nothing else is copied, so a check that grows a detail field tomorrow is private by
/// default. A denylist would have to be updated in step with every new field to keep
/// holding, and the failure mode of forgetting is silent disclosure.
///
/// What that keeps off the MCP listener today: the absolute audit log path and the absolute
/// exec state directory, which are exact write targets; the live and maximum session counts,
/// which are a gauge for session exhaustion; and the verbatim policy-reload rejection
/// string, which quotes the policy file back at the caller. On a loopback-only install none
/// of that is remarkable. Through a tunnel it is reconnaissance, and this listener is the
/// one that can be tunnelled.
#[must_use]
pub(crate) fn public_readiness(full: &Value) -> Value {
    let checks: Map<String, Value> = full
        .get("checks")
        .and_then(Value::as_object)
        .map(|checks| {
            checks
                .iter()
                .map(|(id, check)| (id.clone(), json!({"ok": value_ok(check)})))
                .collect()
        })
        .unwrap_or_default();
    json!({
        "ok": value_ok(full),
        "server": nmcp_identity::PRODUCT_NAME,
        "checks": checks,
    })
}

pub(crate) fn readiness_check(
    checks: &mut Map<String, Value>,
    id: &str,
    ok: bool,
    fields: Option<Value>,
) {
    let mut value = Map::new();
    value.insert("ok".into(), json!(ok));
    if let Some(Value::Object(extra)) = fields {
        value.extend(extra);
    }
    checks.insert(id.into(), Value::Object(value));
}

#[must_use]
pub(crate) fn build_metrics(state: &AppState) -> String {
    let policy = state.policy();
    let ready = u8::from(value_ok(&build_readiness(state)));
    let caps = state.transport.capabilities();
    [
        format!("nmcp_info{{server=\"{}\"}} 1", nmcp_identity::PRODUCT_NAME),
        format!("nmcp_roots_total {}", policy.roots.len()),
        format!(
            "nmcp_execution_profiles_total {}",
            policy.execution_profiles.len()
        ),
        format!("nmcp_tool_paths_total {}", policy.tool_paths.len()),
        "nmcp_exec_jobs_total 0".into(),
        format!("nmcp_ready {ready}"),
        // 1 means the file on disk is not the policy in force, because a reload was
        // rejected and the prior policy was kept (G4-25).
        format!(
            "nmcp_policy_file_rejected {}",
            u8::from(state.policy_load.rejection().is_some())
        ),
        // The two catalog metrics, `catalog_feed_rejected` and `catalog_servers_total`,
        // arrive with I-077, which introduces the `catalog` field they read. A metric
        // emitting a placeholder would be worse than a missing one: a series that always
        // reports zero is indistinguishable from a healthy one.
        // Streaming transport metrics (PR-09)
        format!(
            "nmcp_transport_sessions_active {}",
            state.transport.session_count()
        ),
        format!(
            "nmcp_transport_capacity_rejections_total {}",
            state.transport.capacity_rejections()
        ),
        format!(
            "nmcp_transport_journal_bytes {}",
            state.transport.total_journal_bytes()
        ),
        format!(
            "nmcp_transport_job_watchers_active {}",
            state.event_emitter.active_count()
        ),
        format!("nmcp_transport_max_sessions {}", caps.max_sessions),
        format!(
            "nmcp_transport_max_streams_per_session {}",
            caps.max_streams_per_session
        ),
        format!(
            "nmcp_transport_max_events_per_stream {}",
            caps.max_events_per_stream
        ),
    ]
    .join("\n")
        + "\n"
}

/// Whether the running policy still honors the machine's Group Policy settings (G4-29).
///
/// Three outcomes, each saying something different. No fleet policy is the unmanaged case and
/// reads as info. A fleet policy the running configuration satisfies is the managed steady
/// state, and the message names what is enforced so an operator sees it without a registry
/// editor. A fleet policy the running configuration does NOT satisfy means Group Policy
/// changed after this process loaded and the machine is looser than the fleet now requires,
/// which is an error rather than a warning.
/// The fleet-policy check, reading the source it was given rather than a hardcoded one.
///
/// The base called `MachinePolicy::from_registry()` here, which is a free function with nothing
/// to inject, so WD-8's criterion, a doctor check on a **managed** machine, could not be
/// written. In core that call is additionally a misnomer: `from_registry` reads no registry and
/// delegates to `NoFleetPolicy`. Taking the source as a parameter is what makes all three arms
/// reachable, and the daemon binds it once at construction (NMCP-SPEC-001 R-3).
fn machine_policy_check(
    policy: &nmcp_policy::PolicyConfig,
    source: &dyn nmcp_policy::machine::MachinePolicySource,
) -> Value {
    let (machine, unreadable) = source.read();

    if !unreadable.is_empty() {
        return doctor_check(
            "machine_policy",
            false,
            "warn",
            format!(
                "Group Policy set {} value(s) this build could not read: {}",
                unreadable.len(),
                unreadable.join(", ")
            ),
            Some(
                "Check the value types under HKLM\\SOFTWARE\\Policies\\nMCP against \
                 admx/nMCP.admx. A value written by hand with the wrong type is \
                 ignored rather than guessed at.",
            ),
        );
    }

    if machine.is_empty() {
        return doctor_check(
            "machine_policy",
            true,
            "info",
            "no Group Policy settings apply; the local policy file decides",
            None,
        );
    }

    let gaps = machine.unsatisfied(policy);
    if gaps.is_empty() {
        doctor_check(
            "machine_policy",
            true,
            "info",
            format!(
                "Group Policy is in force and honored: {}",
                machine_policy_summary(&machine)
            ),
            None,
        )
    } else {
        doctor_check(
            "machine_policy",
            false,
            "error",
            format!(
                "the running policy is looser than Group Policy requires: {}",
                gaps.join("; ")
            ),
            Some(
                "Group Policy changed after this process loaded its policy. Touch the policy \
                 file to trigger a hot reload, or restart winmcpd.",
            ),
        )
    }
}

/// The enforced settings, named, so the managed case is legible without a registry editor.
fn machine_policy_summary(machine: &nmcp_policy::machine::MachinePolicy) -> String {
    let mut parts = Vec::new();
    for (enforced, name) in [
        (machine.force_auto_approve_off, "ForceAutoApproveOff"),
        (machine.force_client_auth, "ForceClientAuth"),
        (machine.force_upstream_pinning, "ForceUpstreamPinning"),
        (machine.disable_ws_lane, "DisableWsLane"),
        (machine.disable_sse_lane, "DisableSseLane"),
        (machine.disable_all_upstreams, "DisableAllUpstreams"),
    ] {
        if enforced {
            parts.push(name.to_string());
        }
    }
    if let Some(allowed) = &machine.allowed_upstream_ids {
        parts.push(format!("{} approved upstream(s)", allowed.len()));
    }
    parts.join(", ")
}

#[must_use]
/// The doctor document: every check, plus the overall verdict.
///
/// Four groups, split exactly on the section comments the base already carried, so the
/// emitted order is unchanged and the diff moves lines rather than rewriting them.
pub(crate) fn build_doctor(state: &AppState) -> Value {
    let policy = state.policy();
    let mut checks = doctor_identity_and_path_checks(state, &policy);
    checks.extend(doctor_roots_and_profile_checks(state, &policy));
    checks.extend(doctor_oauth_checks(state, &policy));
    checks.extend(doctor_policy_posture_checks(&policy));
    checks.extend(doctor_transport_checks(state));
    let ok = checks.iter().all(|check| {
        check["ok"].as_bool().unwrap_or(false) || check["severity"].as_str() == Some("warning")
    });
    json!({
        "ok": ok,
        "server": nmcp_identity::PRODUCT_NAME,
        "summary": if ok {
            format!("{} is ready", nmcp_identity::PRODUCT_NAME)
        } else {
            format!("{} needs attention", nmcp_identity::PRODUCT_NAME)
        },
        "checks": checks
    })
}

/// Identity, paths, permissions and the delete-verb sweep.
/// Identity, the policy file, the two listeners and the configured paths.
///
/// Split from the roots and profile group below only for length: the base carried one
/// vector and the emitted order is unchanged.
fn doctor_identity_and_path_checks(state: &AppState, policy: &PolicyConfig) -> Vec<Value> {
    let effective_exec_state_dir = policy.effective_exec_state_dir();
    vec![
        doctor_check(
            "service_identity",
            true,
            "info",
            format!("server identity is {}", nmcp_identity::PRODUCT_NAME),
            None,
        ),
        doctor_check("policy_loaded", true, "info", "policy is loaded", None),
        machine_policy_check(policy, state.machine_policy.as_ref()),
        match state.policy_load.rejection() {
            None => doctor_check(
                "policy_file_matches_live",
                true,
                "info",
                "the policy in force is the policy on disk",
                None,
            ),
            Some(rejection) => doctor_check(
                "policy_file_matches_live",
                false,
                "error",
                format!(
                    "the policy file was rejected at reload and the prior policy is still in force: {}",
                    rejection.error
                ),
                Some(
                    "Fix the policy file and save it again; the watcher reapplies within two seconds. Until then the running policy is the one from before your edit.",
                ),
            ),
        },
        // G6-7's catalog check arrives with I-077, which introduces the `catalog` field.
        // Its shape is settled and recorded in NMCP-PLAN-002: a **warning** rather than an
        // error, and deliberately not a readiness check. A rejected policy fails readiness
        // because policy governs what runs; a catalog is a list of software an operator could
        // install, so a stale browse list is worth saying out loud and is not worth stopping a
        // deploy over. That asymmetry is the part a later reader is most likely to
        // "fix" by accident, which is why it is written down here as well as there.
        doctor_check(
            "policy_path",
            true,
            "info",
            state.policy_path.as_ref().map_or_else(
                || "policy path is explicitly absent".to_string(),
                |path| format!("policy path is {}", path.display()),
            ),
            None,
        ),
        doctor_check(
            "admin_bind_parses",
            policy.admin_bind.parse::<SocketAddr>().is_ok(),
            "error",
            format!("admin_bind is {}", policy.admin_bind),
            Some("Set admin_bind to a valid socket address."),
        ),
        doctor_check(
            "mcp_bind_parses",
            policy.mcp_bind.parse::<SocketAddr>().is_ok(),
            "error",
            format!("mcp_bind is {}", policy.mcp_bind),
            Some("Set mcp_bind to a valid socket address."),
        ),
        doctor_check(
            "admin_mcp_ports_distinct",
            admin_mcp_ports_distinct(policy),
            "error",
            "admin_bind and mcp_bind are distinct",
            Some("Use separate admin and MCP ports."),
        ),
        doctor_check(
            "audit_path_configured",
            !policy.audit_path.as_os_str().is_empty(),
            "error",
            format!("audit_path is {}", policy.audit_path.display()),
            Some("Configure audit_path."),
        ),
        doctor_check(
            "exec_state_dir_configured",
            effective_exec_state_dir.is_absolute(),
            "error",
            format!(
                "effective exec_state_dir is {}",
                effective_exec_state_dir.display()
            ),
            Some("Configure an absolute exec_state_dir."),
        ),
        doctor_check(
            "exec_state_dir_not_system32",
            !is_system32_path(&effective_exec_state_dir),
            "error",
            "exec_state_dir is outside C:\\WINDOWS\\system32",
            Some("Move exec_state_dir under the platform data directory's `work` folder."),
        ),
    ]
}

/// Roots, execution profiles, tool paths, and the delete-verb sweep over the merged catalogue.
fn doctor_roots_and_profile_checks(state: &AppState, policy: &PolicyConfig) -> Vec<Value> {
    let tools_without_delete_like = router_no_delete_check(&state.router);
    let mut checks = vec![
        doctor_check(
            "roots_present",
            !policy.roots.is_empty(),
            "error",
            format!("{} roots configured", policy.roots.len()),
            Some("Configure at least one allowed root."),
        ),
        doctor_check(
            "roots_have_ids",
            policy.roots.iter().all(|root| !root.id.trim().is_empty()),
            "error",
            "all roots have IDs",
            Some("Assign every root a stable id."),
        ),
        doctor_check(
            "roots_have_effective_paths",
            policy.roots.iter().all(|root| root.path.is_absolute()),
            "error",
            "all roots have effective absolute paths",
            Some("Use service-canonicalized absolute roots."),
        ),
        doctor_check(
            "default_execution_profile_exists",
            policy
                .default_execution_profile
                .as_deref()
                .is_none_or(|name| policy.execution_profiles.contains_key(name)),
            "error",
            policy.default_execution_profile.as_ref().map_or_else(
                || "default execution profile is not configured".to_string(),
                |name| format!("default execution profile is {name}"),
            ),
            Some("Configure default_execution_profile to an existing profile."),
        ),
        doctor_check(
            "profile_dev_exists_if_configured",
            true,
            "info",
            if policy.execution_profiles.contains_key("dev") {
                "profile=dev exists"
            } else {
                "profile=dev is not configured"
            },
            None,
        ),
        doctor_check(
            "tool_paths_count",
            true,
            "info",
            format!("{} tool aliases configured", policy.tool_paths.len()),
            None,
        ),
        doctor_check(
            "mcp_tool_contract_no_delete_like_tools",
            tools_without_delete_like,
            "error",
            "MCP tool contract contains no delete-like tools",
            Some("Remove delete-like tools from the MCP tool list."),
        ),
    ];

    for (id, path) in [
        (
            "programdata_root_exists",
            nmcp_identity::program_data_root(),
        ),
        ("programdata_bin_exists", nmcp_identity::bin_dir()),
        ("programdata_logs_exists", nmcp_identity::logs_dir()),
        ("programdata_work_exists", nmcp_identity::work_dir()),
        ("programdata_audit_exists", nmcp_identity::audit_dir()),
    ] {
        checks.push(doctor_check(
            id,
            path.exists(),
            "warning",
            format!("{} exists: {}", path.display(), path.exists()),
            Some(
                "Create the platform data directory via install or repair; it is named after \
                 nmcp_identity::DATA_DIR_NAME.",
            ),
        ));
    }
    checks
}

/// The resource-server posture an operator reads to tell a loopback install taking static
/// tokens from one accepting bearer tokens off the internet.
///
/// Reads `state.jwks`, which is why I-076 could not write the key-set arm and deleted it with
/// the owner named instead of stubbing it. The owner it named was I-074 and that was wrong; see
/// NMCP-SPEC-004 A-7. It returns here, with the field, by I-076's own rule that a check arrives
/// with the thing it checks.
fn doctor_oauth_checks(state: &AppState, policy: &PolicyConfig) -> Vec<Value> {
    let mut checks = Vec::new();
    // OAuth resource-server posture (G3-11, RS-14). An operator reading this should be able
    // to tell a loopback install taking static tokens from one accepting bearer tokens from
    // the internet, and to see which issuer and which resource identifier are in force.
    // Public values only: the metadata document already publishes both.
    match policy.oauth_resource.as_ref() {
        Some(oauth) => {
            checks.push(doctor_check(
                "oauth_resource_server",
                true,
                "info",
                format!(
                    "OAuth resource server enabled for resource {} trusting issuer(s) {}",
                    oauth.resource,
                    oauth.authorization_servers.join(", ")
                ),
                None,
            ));
            checks.push(doctor_check(
                "oauth_resource_metadata_url",
                true,
                "info",
                format!(
                    "protected resource metadata published at {}",
                    resource_metadata_url(&oauth.resource)
                ),
                None,
            ));
            // A key set this server can no longer trust refuses every caller, and the
            // caller is told only `invalid_token`, so this is the one place an operator can see
            // that the authorization server has been unreachable long enough to matter.
            //
            // The severities are not uniform and the difference is the point. `Stale` is a
            // warning because tokens are still being accepted: the refetch is failing and the
            // consequence has not arrived. `Expired` is an error because it already has.
            // Reporting both at one severity would either cry wolf during a brief outage or
            // stay quiet through a total one.
            for (issuer, posture) in state.jwks().posture(&oauth.authorization_servers) {
                let (ok, severity, detail) = match posture {
                    KeySetPosture::NeverFetched => (
                        true,
                        "info",
                        format!(
                            "no key set fetched yet for {issuer}; the first token to arrive \
                             fetches one"
                        ),
                    ),
                    KeySetPosture::Fresh { age_secs } => (
                        true,
                        "info",
                        format!("key set for {issuer} fetched {age_secs}s ago"),
                    ),
                    KeySetPosture::Stale { age_secs } => (
                        false,
                        "warning",
                        format!(
                            "key set for {issuer} is {age_secs}s old and refetching has not \
                             succeeded; tokens are still accepted for now"
                        ),
                    ),
                    KeySetPosture::Expired { age_secs } => (
                        false,
                        "error",
                        format!(
                            "key set for {issuer} is {age_secs}s old, past the trust ceiling, \
                             so every token from this issuer is being refused"
                        ),
                    ),
                };
                checks.push(doctor_check(
                    "oauth_key_set",
                    ok,
                    severity,
                    detail,
                    Some(
                        "Confirm this host can reach the authorization server's metadata and JWKS endpoints; the key set is refetched hourly and stops being trusted after 24 hours.",
                    ),
                ));
            }
            checks.push(doctor_check(
                "oauth_subject_bindings",
                !oauth.subjects.is_empty(),
                "warning",
                format!(
                    "{} token subject(s) mapped to an agent identity",
                    oauth.subjects.len()
                ),
                Some(
                    "Map each accepted token subject to an agent_id under oauth_resource.subjects; an unmapped subject is refused.",
                ),
            ));
        }
        None => checks.push(doctor_check(
            "oauth_resource_server",
            true,
            "info",
            "OAuth resource server not configured; MCP clients authenticate with a static token"
                .to_string(),
            None,
        )),
    }

    checks
}

/// Posture findings, at `warning` severity by construction.
///
/// [`build_doctor`] treats a failing warning as still ok overall, which is what lets a
/// finding be surfaced without turning an operator's deliberate configuration into a failed
/// health check.
fn doctor_policy_posture_checks(policy: &PolicyConfig) -> Vec<Value> {
    let mut checks = Vec::new();
    // Policy posture (G3-7). Severity is deliberately "warning": build_doctor treats a
    // failing warning as still ok overall, so surfacing a posture finding reports it
    // without turning an operator's deliberate configuration into a failed health check.
    let posture = policy.posture_findings();
    checks.push(doctor_check(
        "policy_posture",
        posture.is_empty(),
        "warning",
        if posture.is_empty() {
            "no compounding policy posture weaknesses detected".to_string()
        } else {
            format!(
                "{} posture finding(s): {}",
                posture.len(),
                posture
                    .iter()
                    .map(|finding| finding.id)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
        Some("Review the posture_* checks below and docs/SECURITY.md."),
    ));
    for finding in posture {
        checks.push(doctor_check(
            finding.id,
            false,
            "warning",
            finding.detail,
            Some(finding.remediation),
        ));
    }

    checks
}

/// Streaming transport capacity and liveness.
///
/// `event_emitter.active_count()` here can never be nonzero in a production build: the
/// emitter's only writers are `#[cfg(test)]`, which is finding F-2's corroborating half.
/// Ported in that shape on purpose, because inventing the wiring would hide the finding
/// rather than carry it. The writers belong with the lanes, at I-075.
fn doctor_transport_checks(state: &AppState) -> Vec<Value> {
    let mut checks = Vec::new();
    let capabilities = state.transport.capabilities();
    checks.push(doctor_check(
        "transport_core_available",
        capabilities.core_available,
        "error",
        format!(
            "streaming transport core: max_sessions={} max_streams_per_session={}",
            capabilities.max_sessions, capabilities.max_streams_per_session
        ),
        Some("Transport core init failed; restart the service."),
    ));
    checks.push(doctor_check(
        "transport_active_sessions",
        true,
        "info",
        format!(
            "{} active session(s), {} active job watcher(s)",
            state.transport.session_count(),
            state.event_emitter.active_count(),
        ),
        None,
    ));

    checks
}

pub(crate) fn doctor_check(
    id: &str,
    ok: bool,
    severity: &str,
    message: impl Into<String>,
    remediation: Option<&str>,
) -> Value {
    json!({
        "id": id,
        "ok": ok,
        "severity": if ok { "info" } else { severity },
        "message": message.into(),
        "remediation": if ok { Value::Null } else { remediation.map_or(Value::Null, Value::from) }
    })
}

#[must_use]
pub(crate) fn build_diagnostics_runtime_snapshot(state: &AppState) -> Value {
    let policy = state.policy();
    let capabilities = state.transport.capabilities();
    let ready = build_readiness(state);
    let doctor = build_doctor(state);
    let doctor_checks = doctor
        .get("checks")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let doctor_failures = doctor
        .get("checks")
        .and_then(Value::as_array)
        .map_or(0, |checks| {
            checks
                .iter()
                .filter(|check| !check.get("ok").and_then(Value::as_bool).unwrap_or(false))
                .count()
        });
    let latency = build_latency_summary(&policy.audit_path, 200);
    json!({
        "ok": ready.get("ok").and_then(Value::as_bool).unwrap_or(false)
            && doctor.get("ok").and_then(Value::as_bool).unwrap_or(false),
        "server": nmcp_identity::PRODUCT_NAME,
        "generated_at": unix_timestamp_string(),
        "transport": {
            "active_sessions": state.transport.session_count(),
            "active_job_watchers": state.event_emitter.active_count(),
            "max_sessions": capabilities.max_sessions,
            "max_streams_per_session": capabilities.max_streams_per_session,
            "max_events_per_stream": capabilities.max_events_per_stream,
            "core_available": capabilities.core_available,
        },
        "audit": {
            "subscriber_count": state.audit.subscriber_count(),
            "windows_event_log_mirror_enabled": state.audit.mirror_enabled(),
        },
        "execution": {
            "profiles": policy.execution_profiles.len(),
            "tool_paths": policy.tool_paths.len(),
            "exec_state_dir": policy.effective_exec_state_dir(),
        },
        "policy": {
            "roots": policy.roots.len(),
            "admin_bind": policy.admin_bind,
            "mcp_bind": policy.mcp_bind,
        },
        "doctor": {
            "ok": doctor.get("ok").and_then(Value::as_bool).unwrap_or(false),
            "checks": doctor_checks,
            "failures": doctor_failures,
            "summary": doctor.get("summary").cloned().unwrap_or(Value::Null),
        },
        "latency": latency,
        "log_topology": build_log_topology(state),
        "ready": ready,
    })
}

#[must_use]
pub(crate) fn build_latency_summary(audit_path: &Path, limit: usize) -> Value {
    match nmcp_inspector::latency_history(audit_path, limit) {
        Ok(history) => {
            let durations: Vec<u64> = history
                .entries
                .iter()
                .filter_map(|entry| entry.duration_ms)
                .collect();
            let latest = history.latest.as_ref();
            let latest_duration_ms = latest.and_then(|entry| entry.duration_ms);
            let max_duration_ms = durations.iter().copied().max();
            let average_duration_ms = if durations.is_empty() {
                None
            } else {
                Some(durations.iter().sum::<u64>() / durations.len() as u64)
            };
            json!({
                "ok": true,
                "sample_limit": limit,
                "sample_count": history.sample_count,
                "authorization_count": history.authorization_count,
                "effect_record_count": history.effect_record_count,
                "measured_count": history.measured_count,
                "unmeasured_count": history.unmeasured_count,
                "timeout_like_count": history.timeout_like_count,
                "history_count": history.entries.len(),
                "bucket_count": history.buckets.len(),
                "slowest_count": history.slowest.len(),
                "latest_action": latest.map(|entry| entry.action.clone()),
                "latest_decision": latest.map(|entry| entry.decision.clone()),
                "latest_duration_ms": latest_duration_ms,
                "latest_bucket": latest.and_then(|entry| entry.duration_bucket.clone()),
                "max_duration_ms": max_duration_ms,
                "average_duration_ms": average_duration_ms,
            })
        }
        Err(err) => json!({
            "ok": false,
            "sample_limit": limit,
            "sample_count": 0,
            "authorization_count": 0,
            "effect_record_count": 0,
            "measured_count": 0,
            "unmeasured_count": 0,
            "timeout_like_count": 0,
            "history_count": 0,
            "bucket_count": 0,
            "slowest_count": 0,
            "latest_action": Value::Null,
            "latest_decision": Value::Null,
            "latest_duration_ms": Value::Null,
            "latest_bucket": Value::Null,
            "max_duration_ms": Value::Null,
            "average_duration_ms": Value::Null,
            "error": err.to_string(),
        }),
    }
}

#[must_use]
pub(crate) fn build_latency_history_response(audit_path: &Path, limit: usize) -> Value {
    match nmcp_inspector::latency_history(audit_path, limit) {
        Ok(history) => {
            let mut value = serde_json::to_value(history).unwrap_or_else(|_| json!({}));
            if let Value::Object(ref mut obj) = value {
                obj.insert("ok".into(), Value::Bool(true));
            }
            value
        }
        Err(err) => json!({
            "ok": false,
            "sample_limit": limit,
            "sample_count": 0,
            "authorization_count": 0,
            "effect_record_count": 0,
            "measured_count": 0,
            "unmeasured_count": 0,
            "timeout_like_count": 0,
            "latest": Value::Null,
            "slowest": [],
            "buckets": [],
            "entries": [],
            "error": err.to_string(),
        }),
    }
}

#[must_use]
pub(crate) fn same_policy_path(left: &Path, right: &Path) -> bool {
    fn normalize(path: &Path) -> String {
        let mut chars: Vec<char> = path
            .to_string_lossy()
            .chars()
            .map(|ch| if ch == '/' { char::from(92) } else { ch })
            .collect();
        if chars.starts_with(&[char::from(92), char::from(92), '?', char::from(92)]) {
            chars.drain(0..4);
        } else if chars.starts_with(&[char::from(92), '?', char::from(92)]) {
            chars.drain(0..3);
        }
        while chars.last() == Some(&char::from(92)) {
            chars.pop();
        }
        chars.into_iter().collect::<String>().to_ascii_lowercase()
    }
    normalize(left) == normalize(right)
}

#[must_use]
pub(crate) fn build_log_topology(state: &AppState) -> Value {
    let policy = state.policy();
    let audit_path = policy.audit_path.clone();
    let effective_exec_state_dir = policy.effective_exec_state_dir();
    let canonical_logs_dir = nmcp_identity::logs_dir();
    let canonical_audit_dir = nmcp_identity::audit_dir();
    let canonical_work_dir = nmcp_identity::work_dir();
    let canonical_exec_jobs_dir = nmcp_identity::default_exec_state_dir();
    let global_policy_path = nmcp_identity::default_config_path();
    let active_policy_path = state
        .policy_path
        .clone()
        .unwrap_or_else(|| global_policy_path.clone());
    // The sink owns this name (`nmcp_audit::MirrorConfig::from_env` reads
    // `NMCP_AUDIT_MIRROR_SOURCE`), and it already applies the same product-name default. Reading
    // it through the sink rather than spelling the variable a second time is what stops one copy
    // being renamed while the other is not, which is precisely the drift DEC-001 exists to end.
    let event_log_source = state.audit().mirror_source();

    json!({
        "ok": true,
        "generated_at": unix_timestamp_string(),
        "canonical_root": nmcp_identity::program_data_root(),
        "config": {
            "global_policy_path": global_policy_path,
            "active_policy_path": active_policy_path,
            "uses_global_policy": same_policy_path(&active_policy_path, &nmcp_identity::default_config_path()),
            "root_count": policy.roots.len(),
        },
        "canonical": {
            "bin_dir": nmcp_identity::bin_dir(),
            "config_dir": nmcp_identity::config_dir(),
            "logs_dir": canonical_logs_dir,
            "audit_dir": canonical_audit_dir,
            "work_dir": canonical_work_dir,
            "default_audit_path": nmcp_identity::default_audit_path(),
            "default_exec_state_dir": canonical_exec_jobs_dir,
        },
        "active": {
            "policy_audit_path": audit_path,
            "effective_exec_state_dir": effective_exec_state_dir,
            "execution_job_logs_pattern": effective_exec_state_dir.join("<job_id>").join("stdout.log"),
            "execution_job_error_logs_pattern": effective_exec_state_dir.join("<job_id>").join("stderr.log"),
        },
        "process_logs": [
            {
                "id": "service-daemon",
                "component": "winmcpd service",
                "kind": "process-log",
                "directory": canonical_logs_dir,
                "expected_files": ["service.<YYYY-MM-DD>.log", "mcpd.log", "daemon.log"],
                "status": "conventional",
                "note": "Service wrappers and daemon hosts should write under the canonical ProgramData logs directory."
            },
            {
                "id": "tray",
                "component": "nmcp-tray",
                "kind": "process-log",
                "directory": canonical_logs_dir,
                "expected_files": ["tray.log"],
                "status": "conventional",
                "note": "Tray UI logs should resolve to the same canonical logs directory for support collection."
            }
        ],
        "audit_logs": [
            {
                "id": "audit-jsonl",
                "component": "governed audit JSONL",
                "kind": "append-only-jsonl",
                "path": audit_path,
                "canonical_default": nmcp_identity::default_audit_path(),
                "uses_canonical_default": policy.audit_path == nmcp_identity::default_audit_path(),
            },
            {
                "id": "windows-event-log",
                "component": "Windows Event Log mirror",
                "kind": "windows-event-log",
                "enabled": state.audit.mirror_enabled(),
                "source": event_log_source,
                "channel": "Application",
            }
        ],
        "execution_logs": {
            "id": "execution-job-logs",
            "component": "governed execution jobs",
            "kind": "per-job-stdout-stderr",
            "directory": effective_exec_state_dir,
            "canonical_default": nmcp_identity::default_exec_state_dir(),
            "uses_canonical_default": policy.effective_exec_state_dir() == nmcp_identity::default_exec_state_dir(),
            "files_per_job": ["job.json", "stdout.log", "stderr.log"],
        },
        "recommendation": "Use /api/diagnostics/log-topology as the operator-facing map before collecting tray, service, MCP daemon, audit, Event Log, or execution-job logs."
    })
}

#[must_use]
pub(crate) fn build_support_bundle(state: &AppState) -> Value {
    let policy = state.policy();
    let capabilities = state.transport.capabilities();
    json!({
        "server": nmcp_identity::PRODUCT_NAME,
        "generated_at": unix_timestamp_string(),
        "health": build_health(),
        "ready": build_readiness(state),
        "doctor": build_doctor(state),
        "policy_effective_redacted": redact_sensitive_value(json!(policy)),
        "metrics": build_metrics(state),
        "transport": {
            "capabilities": capabilities,
            "active_sessions": state.transport.session_count(),
            "active_job_watchers": state.event_emitter.active_count(),
        },
        "log_topology": build_log_topology(state),
        "notes": [
            "Sensitive env values are redacted.",
            "Raw file contents are not included.",
            "Transport section contains no raw stdout/stderr."
        ]
    })
}

#[must_use]
pub(crate) fn unix_timestamp_string() -> String {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or_else(
        |_| "0".to_string(),
        |duration| duration.as_secs().to_string(),
    )
}

#[must_use]
pub(crate) fn redact_sensitive_value(value: Value) -> Value {
    redact_value_with_key("", value)
}

#[must_use]
pub(crate) fn redact_value_with_key(key: &str, value: Value) -> Value {
    if is_sensitive_key(key) {
        return Value::String("[REDACTED]".into());
    }
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    let value = redact_value_with_key(&key, value);
                    (key, value)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| redact_value_with_key(key, value))
                .collect(),
        ),
        other => other,
    }
}

#[must_use]
pub(crate) fn is_sensitive_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    let normalized: String = upper
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect();
    let parts: Vec<&str> = normalized.split_whitespace().collect();
    let compact = parts.join("");

    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "CREDENTIAL",
        "AUTH",
        "COOKIE",
    ]
    .iter()
    .any(|needle| compact.contains(needle))
        || parts.iter().any(|part| *part == "KEY" || *part == "PAT")
        || compact.ends_with("KEY")
        || compact.ends_with("PAT")
}

/// Runs the no-delete banned-name scan over the router's merged (local + upstream) tool list.
/// This is the authoritative check for Epic GW-3: it covers both local and proxied tools.
#[must_use]
pub(crate) fn router_no_delete_check(router: &SharedRouter) -> bool {
    let banned = ["delete", "unlink", "remove", "rmdir", "trash", "recycle"];
    router.merged_tool_list().into_iter().all(|tool| {
        let name = tool.get("name").and_then(Value::as_str).unwrap_or("");
        !banned.iter().any(|b| name.contains(b))
    })
}

#[must_use]
pub(crate) fn admin_mcp_ports_distinct(policy: &PolicyConfig) -> bool {
    let Ok(admin_addr) = policy.admin_bind.parse::<SocketAddr>() else {
        return false;
    };
    let Ok(mcp_addr) = policy.mcp_bind.parse::<SocketAddr>() else {
        return false;
    };
    admin_addr.port() != mcp_addr.port()
}

#[must_use]
pub(crate) fn is_system32_path(path: &Path) -> bool {
    path.display()
        .to_string()
        .to_ascii_lowercase()
        .replace('/', "\\")
        .starts_with("c:\\windows\\system32")
}

#[must_use]
pub(crate) fn value_ok(value: &Value) -> bool {
    value.get("ok").and_then(Value::as_bool).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    // As the other test modules in this crate: a panic here is the assertion.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::{build_doctor, build_readiness, machine_policy_check, public_readiness};
    use crate::AppState;
    use nmcp_policy::PolicyConfig;
    use nmcp_policy::machine::{MachinePolicy, MachinePolicySource};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("nmcp-diagnostics-{label}-{stamp}"));
        std::fs::create_dir_all(&root).expect("mkdir");
        root
    }

    fn state_in(root: &std::path::Path) -> AppState {
        AppState::new(PolicyConfig {
            audit_path: root.join("audit.jsonl"),
            ..PolicyConfig::default()
        })
        .expect("state")
    }

    /// G3-17. The projection keeps every verdict and drops every detail, by construction rather
    /// than by keeping a denylist in step with the checks.
    ///
    /// Ported as-is, including the half that stops it passing vacuously. NMCP-PLAN-002 calls
    /// this out as the model for WD-14's "behavioural companion" language, and the reason is the
    /// four assertions on `full`: without them the test would keep passing the day a detail
    /// quietly stopped being **produced** rather than being **projected away**, which would make
    /// the projection look effective while proving nothing about it.
    #[test]
    fn the_public_readiness_document_is_verdicts_and_nothing_else() {
        let root = temp_root("readyz-public");
        let state = state_in(&root);
        let full = build_readiness(&state);
        let public = public_readiness(&full);

        assert!(full["checks"]["audit_path"]["path"].is_string());
        assert!(full["checks"]["exec_state_dir"]["path"].is_string());
        assert!(full["checks"]["transport_core_initialized"]["active_sessions"].is_number());
        assert!(full["checks"]["transport_core_initialized"]["max_sessions"].is_number());

        let mut top: Vec<&str> = public
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        top.sort_unstable();
        assert_eq!(
            top,
            ["checks", "ok", "server"],
            "the public readiness document grew a top-level field"
        );

        let full_checks = full["checks"].as_object().expect("checks");
        let public_checks = public["checks"].as_object().expect("checks");
        assert_eq!(public["ok"], full["ok"]);
        assert_eq!(
            public_checks.len(),
            full_checks.len(),
            "a tokenless caller must still learn which check failed"
        );
        for (id, check) in full_checks {
            assert_eq!(
                public_checks[id]["ok"], check["ok"],
                "the verdict for {id} changed under projection"
            );
            assert_eq!(
                public_checks[id]
                    .as_object()
                    .expect("check object")
                    .keys()
                    .collect::<Vec<_>>(),
                vec!["ok"],
                "check {id} carries a field other than ok into the public document"
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// A fleet that has an opinion, which is the state WD-8's criterion is about.
    ///
    /// `force_client_auth` is the narrowest setting that makes the fleet non-empty, so the
    /// check has a real opinion to compare a running policy against rather than an empty one.
    struct ManagedMachine(MachinePolicy);

    impl MachinePolicySource for ManagedMachine {
        fn read(&self) -> (MachinePolicy, Vec<String>) {
            (self.0.clone(), Vec::new())
        }
    }

    /// A fleet source that has values it could not read, which is the other arm of the check.
    struct UnreadableFleet;

    impl MachinePolicySource for UnreadableFleet {
        fn read(&self) -> (MachinePolicy, Vec<String>) {
            (
                MachinePolicy::default(),
                vec!["ForceClientAuth".to_string()],
            )
        }
    }

    /// WD-8's acceptance criterion, and the reason I-076 added a field to the frozen graph.
    ///
    /// The base could not write this. Its check called `MachinePolicy::from_registry()`, a free
    /// function with nothing to inject, so on a developer machine it answered "no fleet policy"
    /// and there was no way to make it answer anything else. In core that call additionally
    /// reads no registry at all: `from_registry` delegates to `NoFleetPolicy`.
    ///
    /// Driving the source is what makes the three arms reachable: no opinion, an opinion the
    /// running policy honours, and an opinion it does not.
    #[test]
    fn the_doctor_reports_a_managed_machine_through_the_injected_source() {
        let unmanaged = machine_policy_check(
            &PolicyConfig::default(),
            &nmcp_policy::machine::NoFleetPolicy,
        );
        assert!(
            unmanaged["ok"].as_bool().unwrap_or(false),
            "an unmanaged machine is the ordinary case and is not a finding: {unmanaged}"
        );

        // A fleet that requires a client credential, against a policy that does not.
        let managed = MachinePolicy {
            force_client_auth: true,
            ..MachinePolicy::default()
        };
        let unsatisfied =
            machine_policy_check(&PolicyConfig::default(), &ManagedMachine(managed.clone()));
        assert!(
            !unsatisfied["ok"].as_bool().unwrap_or(true),
            "a running policy looser than the fleet requires means Group Policy changed after \
             this process loaded, which is an error rather than a warning. Got: {unsatisfied}"
        );

        // The same fleet opinion, against a policy that honours it.
        let (tightened, _) = PolicyConfig::default().with_machine_policy(&managed);
        let honoured = machine_policy_check(&tightened, &ManagedMachine(managed));
        assert!(
            honoured["ok"].as_bool().unwrap_or(false),
            "a fleet opinion the running policy satisfies is not a finding: {honoured}"
        );

        let unreadable = machine_policy_check(&PolicyConfig::default(), &UnreadableFleet);
        assert!(
            !unreadable["ok"].as_bool().unwrap_or(true),
            "values the fleet set and this build could not read are a finding: {unreadable}"
        );
        assert_eq!(
            unreadable["severity"], "warn",
            "unreadable is a warning: the fleet has an opinion this build cannot act on, which \
             is different from an opinion it is failing to honour"
        );
    }

    /// The graph the doctor reads is the one it was given, not a global.
    #[test]
    fn the_state_carries_the_source_the_doctor_reads() {
        let root = temp_root("fleet-source");
        let state = state_in(&root);
        let (fleet, unreadable) = state.machine_policy.read();
        assert!(
            fleet.is_empty() && unreadable.is_empty(),
            "core binds NoFleetPolicy, which is the behaviour the base gave every non-Windows \
             build"
        );
        let doctor = build_doctor(&state);
        let checks = doctor["checks"].as_array().expect("checks");
        assert!(
            checks.iter().any(|check| check["id"] == "machine_policy"),
            "the doctor still reports the machine policy check on an unmanaged host"
        );
        let _ = std::fs::remove_dir_all(root);
    }
    /// The key-set posture reaches the doctor, once per configured issuer.
    ///
    /// The surfacing is what I-076 deleted and what this restores; the posture transitions
    /// themselves are `nmcp-authn`'s and are already pinned there against a driven clock. Two
    /// issuers rather than one on purpose: a loop replaced by a single summary check would pass
    /// a one-issuer test and lose exactly the information an operator needs, which is **which**
    /// authorization server has gone unreachable.
    #[test]
    fn the_doctor_reports_a_key_set_posture_for_every_configured_issuer() {
        let root = temp_root("key-set");
        let state = AppState::new(PolicyConfig {
            audit_path: root.join("audit.jsonl"),
            oauth_resource: Some(nmcp_policy::OAuthResourceConfig {
                resource: "https://mcp.example.com/mcp".into(),
                authorization_servers: vec![
                    "https://issuer-one.example".into(),
                    "https://issuer-two.example".into(),
                ],
                subjects: std::collections::BTreeMap::new(),
                algorithms: vec!["RS256".into()],
                clock_skew_secs: 60,
                scopes_supported: Vec::new(),
            }),
            ..PolicyConfig::default()
        })
        .expect("state");

        let doctor = build_doctor(&state);
        let checks = doctor["checks"].as_array().expect("checks");
        let key_sets: Vec<&serde_json::Value> = checks
            .iter()
            .filter(|check| check["id"] == "oauth_key_set")
            .collect();

        assert_eq!(
            key_sets.len(),
            2,
            "one key-set check per configured issuer; a summary check cannot say which \
             authorization server is unreachable"
        );
        for issuer in ["issuer-one", "issuer-two"] {
            assert!(
                key_sets.iter().any(|check| check["message"]
                    .as_str()
                    .is_some_and(|message| message.contains(issuer))),
                "no key-set check named {issuer}"
            );
        }
        // Nothing has been fetched, so both are `NeverFetched`: ordinary before the first token
        // arrives, and an `info` rather than a finding. A server that reported a problem here on
        // every cold start would train an operator to ignore the check that matters.
        for check in &key_sets {
            assert_eq!(check["severity"], "info");
            assert_eq!(check["ok"], true);
        }

        // An install with no `oauth_resource` publishes no key-set check at all, rather than one
        // reporting that nothing is wrong with a thing it does not have.
        let plain = build_doctor(&state_in(&root));
        assert!(
            !plain["checks"]
                .as_array()
                .expect("checks")
                .iter()
                .any(|check| check["id"] == "oauth_key_set")
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
