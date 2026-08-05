//! MCP Inspector: read-only protocol observer and debug surface.
//!
//! ## Features
//!
//! - **INSP-1** Live audit tap: subscribe to `AuditSink` broadcast and stream events.
//! - **INSP-2** Live JSON-RPC stream view: SSE endpoint streaming `AuditEvent` as JSON.
//! - **INSP-3** Session replay: re-stream a past session's audit events in order.
//! - **INSP-4** Tool-call simulator: dispatch through the full middleware ring.
//! - **INSP-5** Schema validator: check a tool descriptor against MCP contract rules.
//! - **INSP-6** Latency timeline: per-call durations from audit events.
//!
//! ## Governance guarantee
//!
//! INSP-4's simulator dispatches through `SharedRouter::dispatch()`, the same
//! policy ring and audit path as live calls. Simulated calls are governed and
//! audited identically to real ones. There is no side path.
//!
//! ## Read-only invariant
//!
//! The inspector never writes to policy, never mutates provider state, and
//! never calls tools with side-effects on its own initiative. The simulator
//! (INSP-4) *is* a tool call that may have side effects; that is intentional
//! and is what makes it useful for testing governance.

use nmcp_audit::AuditEvent;
use nmcp_router::SharedRouter;
use nmcp_schema::CallContext;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use uuid::Uuid;

// ── INSP-1: Live audit tap ────────────────────────────────────────────────────

/// A live subscriber to the audit broadcast channel.
pub use nmcp_audit::AuditReceiver;

// ── INSP-2: Admin SSE handler ─────────────────────────────────────────────────

/// Build an SSE stream of live audit events from the sink.
/// Each event is serialised as `data: <json>\n\n`.
pub fn live_events_stream(
    rx: nmcp_audit::AuditReceiver,
) -> impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>
{
    futures_util::stream::unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Ok(event) => {
                let data = serde_json::to_string(&event).unwrap_or_default();
                let sse = axum::response::sse::Event::default().data(data);
                Some((Ok(sse), rx))
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                let notice = serde_json::json!({"type":"lagged","skipped":n}).to_string();
                let sse = axum::response::sse::Event::default()
                    .event("lagged")
                    .data(notice);
                Some((Ok(sse), rx))
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => None,
        }
    })
}

// ── INSP-3: Session replay ────────────────────────────────────────────────────

/// Read the audit log and return all events for a given session, in order.
///
/// # Errors
///
/// Returns the error this operation can fail with.
pub fn replay_session(audit_path: &Path, session_id: &str) -> anyhow::Result<Vec<AuditEvent>> {
    let content = std::fs::read_to_string(audit_path)?;
    let events: Vec<AuditEvent> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<AuditEvent>(l).ok())
        .filter(|e| e.client == session_id)
        .collect();
    Ok(events)
}

// ── INSP-4: Tool-call simulator ───────────────────────────────────────────────

/// Request body for the tool-call simulator.
#[derive(Debug, Deserialize)]
pub struct SimulateRequest {
    /// Fully-qualified tool name (e.g. `list_directory` or `upstream::ping`).
    pub name: String,
    /// Tool arguments.
    #[serde(default)]
    pub args: Value,
    /// Optional session ID to associate with the simulated call in audit.
    pub session_id: Option<String>,
}

/// Result of a simulated tool call.
#[derive(Debug, Serialize)]
pub struct SimulateResult {
    /// The `tool` field.
    pub tool: String,
    /// The `is_error` field.
    pub is_error: bool,
    /// The `content` field.
    pub content: Vec<Value>,
    /// Always `true`: confirms this call went through the full ring.
    pub governed: bool,
}

/// Dispatch a simulated call through the full middleware ring.
///
/// The call is policy-checked, audited, and delete-guarded identically to
/// a live tool call arriving over MCP.
pub async fn simulate_call(router: &SharedRouter, req: SimulateRequest) -> SimulateResult {
    let session_label = req.session_id.as_deref().map_or_else(
        || "inspector:simulate".to_string(),
        |s| format!("inspector:simulate:{s}"),
    );
    let ctx = CallContext::new(Some(session_label));
    let result = router.dispatch(&req.name, req.args, ctx).await;
    SimulateResult {
        tool: req.name,
        is_error: result.is_error,
        content: result.content,
        governed: true,
    }
}

// ── INSP-5: Schema validator ──────────────────────────────────────────────────

const DELETE_BANNED: &[&str] = &[
    "delete",
    "remove",
    "uninstall",
    "drop",
    "destroy",
    "purge",
    "wipe",
    "truncate",
    "rm",
];

/// Validate a MCP tool descriptor against the platform's contract rules.
#[derive(Debug, Serialize)]
pub struct SchemaValidation {
    /// The `valid` field.
    pub valid: bool,
    /// The `errors` field.
    pub errors: Vec<String>,
    /// The `warnings` field.
    pub warnings: Vec<String>,
}

/// `validate_tool_schema`.
pub fn validate_tool_schema(descriptor: &Value) -> SchemaValidation {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let name = descriptor.get("name").and_then(Value::as_str).unwrap_or("");
    if name.is_empty() {
        errors.push("`name` field is missing or empty".into());
    } else {
        let lower = name.to_lowercase();
        for banned in DELETE_BANNED {
            if lower.contains(banned) {
                errors.push(format!(
                    "`name` contains banned term '{banned}': the no-delete invariant \
                     prohibits delete-like tool names"
                ));
            }
        }
        let clean = name.replace("::", "");
        if !clean
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            warnings.push(format!(
                "`name` '{name}' contains characters outside [a-zA-Z0-9_-::], \
                 may cause routing issues"
            ));
        }
    }

    if descriptor
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        errors.push("`description` field is missing or empty".into());
    }

    if descriptor.get("inputSchema").is_none() {
        errors.push("`inputSchema` field is missing".into());
    } else if let Some(schema) = descriptor.get("inputSchema")
        && schema.get("type").is_none()
        && schema.get("properties").is_none()
    {
        warnings.push(
            "`inputSchema` has no `type` or `properties`, consider \
                 `{\"type\":\"object\",\"properties\":{}}`"
                .into(),
        );
    }

    SchemaValidation {
        valid: errors.is_empty(),
        errors,
        warnings,
    }
}

// ── INSP-6: Latency timeline ──────────────────────────────────────────────────

/// A single entry in the latency timeline.
#[derive(Debug, Clone, Serialize)]
pub struct LatencyEntry {
    /// The `call_id` field.
    pub call_id: Option<Uuid>,
    /// The `action` field.
    pub action: String,
    /// The `client` field.
    pub client: String,
    /// The `decision` field.
    pub decision: String,
    /// The `timestamp` field.
    pub timestamp: String,
    /// Elapsed wall-clock time in milliseconds.
    pub duration_ms: Option<u64>,
    /// The `duration_bucket` field.
    pub duration_bucket: Option<String>,
    /// The `timeout_like` field.
    pub timeout_like: bool,
    /// One-line description.
    pub summary: String,
    /// The `upstream_id` field.
    pub upstream_id: Option<String>,
    /// The `agent_id` field.
    pub agent_id: Option<String>,
}

/// A latency distribution bucket for diagnostics history views.
#[derive(Debug, Clone, Serialize)]
pub struct LatencyBucket {
    /// The `label` field.
    pub label: String,
    /// The `min_ms` field.
    pub min_ms: u64,
    /// The `max_ms` field.
    pub max_ms: Option<u64>,
    /// The `count` field.
    pub count: usize,
}

/// Does this record carry an authorization decision, or is it a provider effect record?
///
/// Every governed call currently writes two audit records. The provider appends one
/// describing what it did, which keeps the `unspecified` default decision and carries no
/// duration. The `AuditRing` then appends one carrying the real decision and the measured
/// duration. Latency is a property of the ring record only.
///
/// Counting effect records as unmeasured made `unmeasured_count` read as a measurement
/// gap when it was a record-shape artifact, and made `latest_duration_ms` null whenever
/// the newest line happened to be an effect record. Collapsing the two records into one is
/// tracked as G4-21; this classification stops the metric lying in the meantime, and it
/// reads the distinction out of data the log already carries rather than requiring a
/// producer change to the chained record.
/// Bounded latency history derived from the audit timeline.
#[derive(Debug, Clone, Serialize)]
pub struct LatencyHistory {
    /// The `sample_limit` field.
    pub sample_limit: usize,
    /// The `sample_count` field.
    pub sample_count: usize,
    /// Records carrying a real authorization decision. Latency is measured over these.
    pub authorization_count: usize,
    /// Provider effect records, which never carry a duration by design.
    pub effect_record_count: usize,
    /// The `measured_count` field.
    pub measured_count: usize,
    /// The `unmeasured_count` field.
    pub unmeasured_count: usize,
    /// The `timeout_like_count` field.
    pub timeout_like_count: usize,
    /// The `latest` field.
    pub latest: Option<LatencyEntry>,
    /// The `slowest` field.
    pub slowest: Vec<LatencyEntry>,
    /// The `buckets` field.
    pub buckets: Vec<LatencyBucket>,
    /// The `entries` field.
    pub entries: Vec<LatencyEntry>,
}

/// Read the audit log and return a latency timeline, most recent first, capped at `limit`.
///
/// # Errors
///
/// Returns the error this operation can fail with.
pub fn latency_timeline(audit_path: &Path, limit: usize) -> anyhow::Result<Vec<LatencyEntry>> {
    let content = std::fs::read_to_string(audit_path)?;
    let mut entries: Vec<LatencyEntry> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<AuditEvent>(l).ok())
        .map(|e| {
            let duration_bucket = e.duration_ms.map(duration_bucket_label).map(String::from);
            let timeout_like = is_timeout_like(&e.action, &e.decision, &e.summary);
            LatencyEntry {
                call_id: e.call_id,
                action: e.action,
                client: e.client,
                decision: e.decision,
                timestamp: e.timestamp.to_rfc3339(),
                duration_ms: e.duration_ms,
                duration_bucket,
                timeout_like,
                summary: e.summary,
                upstream_id: e.upstream_id,
                agent_id: e.agent_id,
            }
        })
        .collect();
    entries.reverse();
    entries.truncate(limit);
    Ok(entries)
}

/// Return a richer bounded latency history with distribution buckets and slowest calls.
///
/// # Errors
///
/// Returns the error this operation can fail with.
pub fn latency_history(audit_path: &Path, limit: usize) -> anyhow::Result<LatencyHistory> {
    let entries = latency_timeline(audit_path, limit)?;
    let authorization_count = entries
        .iter()
        .filter(|entry| nmcp_audit::is_authorization_decision(&entry.decision))
        .count();
    let effect_record_count = entries.len().saturating_sub(authorization_count);
    let measured_count = entries
        .iter()
        .filter(|entry| entry.duration_ms.is_some())
        .count();
    // A genuine gap is a record that reached a decision and still has no duration. An
    // effect record has none because it was never meant to, which is a different thing and
    // was previously being reported as the same thing.
    let unmeasured_count = entries
        .iter()
        .filter(|entry| nmcp_audit::is_authorization_decision(&entry.decision))
        .filter(|entry| entry.duration_ms.is_none())
        .count();
    let timeout_like_count = entries.iter().filter(|entry| entry.timeout_like).count();
    let mut bucket_counts = [0usize; 5];
    for duration in entries.iter().filter_map(|entry| entry.duration_ms) {
        // get_mut rather than indexing: duration_bucket_index returns 0..=4 by
        // construction, and this keeps that provable if a bucket is ever added.
        if let Some(count) = bucket_counts.get_mut(duration_bucket_index(duration)) {
            *count += 1;
        }
    }
    let buckets = vec![
        LatencyBucket {
            label: "<100ms".into(),
            min_ms: 0,
            max_ms: Some(99),
            count: bucket_counts[0],
        },
        LatencyBucket {
            label: "100-499ms".into(),
            min_ms: 100,
            max_ms: Some(499),
            count: bucket_counts[1],
        },
        LatencyBucket {
            label: "500-999ms".into(),
            min_ms: 500,
            max_ms: Some(999),
            count: bucket_counts[2],
        },
        LatencyBucket {
            label: "1-4.9s".into(),
            min_ms: 1_000,
            max_ms: Some(4_999),
            count: bucket_counts[3],
        },
        LatencyBucket {
            label: ">=5s".into(),
            min_ms: 5_000,
            max_ms: None,
            count: bucket_counts[4],
        },
    ];
    let mut slowest: Vec<LatencyEntry> = entries
        .iter()
        .filter(|entry| entry.duration_ms.is_some())
        .cloned()
        .collect();
    slowest.sort_by_key(|entry| std::cmp::Reverse(entry.duration_ms.unwrap_or(0)));
    slowest.truncate(10);
    // The newest authorization record, not simply the newest line. Otherwise the "latest"
    // panel shows a null duration roughly half the time purely because a provider effect
    // record happened to be written last.
    let latest = entries
        .iter()
        .find(|entry| nmcp_audit::is_authorization_decision(&entry.decision))
        .or_else(|| entries.first())
        .cloned();
    Ok(LatencyHistory {
        sample_limit: limit,
        sample_count: entries.len(),
        authorization_count,
        effect_record_count,
        measured_count,
        unmeasured_count,
        timeout_like_count,
        latest,
        slowest,
        buckets,
        entries,
    })
}

fn duration_bucket_label(duration_ms: u64) -> &'static str {
    match duration_ms {
        0..=99 => "<100ms",
        100..=499 => "100-499ms",
        500..=999 => "500-999ms",
        1_000..=4_999 => "1-4.9s",
        _ => ">=5s",
    }
}

fn duration_bucket_index(duration_ms: u64) -> usize {
    match duration_ms {
        0..=99 => 0,
        100..=499 => 1,
        500..=999 => 2,
        1_000..=4_999 => 3,
        _ => 4,
    }
}

fn is_timeout_like(action: &str, decision: &str, summary: &str) -> bool {
    [action, decision, summary].iter().any(|value| {
        value.to_ascii_lowercase().contains("timeout")
            || value.to_ascii_lowercase().contains("timed_out")
    })
}

// ── MA-4: Cross-agent audit view ─────────────────────────────────────────────

/// Return audit events for the specified agent IDs, merged and sorted by timestamp (ascending).
///
/// Only events where `agent_id` is `Some(id)` and `id` is in `agent_ids` are returned.
/// Sorted oldest-first so interleaved A+B actions appear in wall-clock order.
///
/// # Errors
///
/// Returns the error this operation can fail with.
pub fn events_for_agents(
    audit_path: &Path,
    agent_ids: &[String],
    limit: usize,
) -> anyhow::Result<Vec<AuditEvent>> {
    let content = std::fs::read_to_string(audit_path)?;
    let mut events: Vec<AuditEvent> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<AuditEvent>(l).ok())
        .filter(|e| e.agent_id.as_ref().is_some_and(|id| agent_ids.contains(id)))
        .collect();
    events.sort_by_key(|e| e.timestamp);
    events.truncate(limit);
    Ok(events)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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
    use serde_json::json;

    // ── MA-4 ─────────────────────────────────────────────────────────────────

    #[test]
    fn events_for_agents_returns_interleaved_in_timestamp_order() {
        use nmcp_audit::AuditSink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nmcp-inspector-agents-{stamp}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("audit.jsonl");
        let sink = AuditSink::open(&path).expect("open");

        // Write events for agent_a and agent_b with interleaved timestamps.
        let mut e1 = nmcp_audit::AuditEvent::new("tool_a1", "a first action");
        e1.agent_id = Some("agent_a".into());
        sink.append(&e1).expect("append");

        let mut e2 = nmcp_audit::AuditEvent::new("tool_b1", "b first action");
        e2.agent_id = Some("agent_b".into());
        sink.append(&e2).expect("append");

        let mut e3 = nmcp_audit::AuditEvent::new("tool_a2", "a second action");
        e3.agent_id = Some("agent_a".into());
        sink.append(&e3).expect("append");

        // An unrelated agent's event, which must not appear in results.
        let mut e4 = nmcp_audit::AuditEvent::new("tool_c1", "c action");
        e4.agent_id = Some("agent_c".into());
        sink.append(&e4).expect("append");

        let ids = vec!["agent_a".to_string(), "agent_b".to_string()];
        let events = events_for_agents(&path, &ids, 100).expect("query");

        assert_eq!(events.len(), 3, "only agent_a and agent_b events returned");
        // All returned events belong to queried agents.
        for ev in &events {
            let id = ev.agent_id.as_deref().unwrap_or("");
            assert!(id == "agent_a" || id == "agent_b", "unexpected agent: {id}");
        }
        // Events are in timestamp order (non-decreasing).
        for w in events.windows(2) {
            assert!(w[0].timestamp <= w[1].timestamp, "events out of order");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    // ── INSP-5 ───────────────────────────────────────────────────────────────

    #[test]
    fn valid_descriptor_passes() {
        let d = json!({
            "name": "list_directory",
            "description": "List files in a directory",
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
        });
        let r = validate_tool_schema(&d);
        assert!(r.valid);
        assert!(r.errors.is_empty());
    }

    #[test]
    fn missing_name_fails() {
        let d = json!({"description": "something", "inputSchema": {}});
        let r = validate_tool_schema(&d);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.contains("`name`")));
    }

    #[test]
    fn delete_named_tool_fails() {
        let d = json!({"name": "delete_file", "description": "Delete a file", "inputSchema": {}});
        let r = validate_tool_schema(&d);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.contains("delete")));
    }

    #[test]
    fn missing_description_fails() {
        let d = json!({"name": "my_tool", "inputSchema": {}});
        let r = validate_tool_schema(&d);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.contains("`description`")));
    }

    #[test]
    fn missing_input_schema_fails() {
        let d = json!({"name": "my_tool", "description": "A tool"});
        let r = validate_tool_schema(&d);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.contains("`inputSchema`")));
    }

    #[test]
    fn namespaced_tool_name_passes() {
        let d = json!({
            "name": "upstream::ping",
            "description": "Ping upstream",
            "inputSchema": {"type": "object"}
        });
        let r = validate_tool_schema(&d);
        assert!(r.valid, "namespaced names must be valid: {r:?}");
    }

    // ── INSP-3 ───────────────────────────────────────────────────────────────

    #[test]
    fn replay_filters_by_session_id() {
        use nmcp_audit::AuditSink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nmcp-inspector-replay-{stamp}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("audit.jsonl");
        let sink = AuditSink::open(&path).expect("open");

        let mut e1 = nmcp_audit::AuditEvent::new("tool_a", "s1");
        e1.client = "session-AAA".into();
        let mut e2 = nmcp_audit::AuditEvent::new("tool_b", "s2");
        e2.client = "session-BBB".into();
        let mut e3 = nmcp_audit::AuditEvent::new("tool_c", "s1b");
        e3.client = "session-AAA".into();

        sink.append(&e1).expect("append");
        sink.append(&e2).expect("append");
        sink.append(&e3).expect("append");

        let replayed = replay_session(&path, "session-AAA").expect("replay");
        assert_eq!(replayed.len(), 2);
        assert!(replayed.iter().all(|e| e.client == "session-AAA"));
        let _ = std::fs::remove_dir_all(dir);
    }

    // ── INSP-6 ───────────────────────────────────────────────────────────────

    #[test]
    fn latency_timeline_respects_limit() {
        use nmcp_audit::AuditSink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nmcp-inspector-latency-{stamp}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("audit.jsonl");
        let sink = AuditSink::open(&path).expect("open");

        for i in 0..10u64 {
            let mut e = nmcp_audit::AuditEvent::new(format!("tool_{i}"), "ok");
            e.duration_ms = Some(i * 10);
            sink.append(&e).expect("append");
        }

        let timeline = latency_timeline(&path, 5).expect("timeline");
        assert_eq!(timeline.len(), 5);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn latency_timeline_includes_duration_when_present() {
        use nmcp_audit::AuditSink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nmcp-inspector-dur-{stamp}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("audit.jsonl");
        let sink = AuditSink::open(&path).expect("open");
        let mut e = nmcp_audit::AuditEvent::new("timed_tool", "ok");
        e.duration_ms = Some(42);
        sink.append(&e).expect("append");

        let timeline = latency_timeline(&path, 10).expect("timeline");
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].duration_ms, Some(42));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn latency_measurement_ignores_provider_effect_records() {
        // Every governed call writes two records today: a provider effect record with the
        // default `unspecified` decision and no duration, then the AuditRing record with
        // the real decision and the duration. Counting the effect record as unmeasured made
        // the panel report a measurement gap that did not exist, and made
        // latest_duration_ms null whenever an effect record happened to be written last.
        // Collapsing the two records is G4-21; this asserts the metric stops lying first.
        let dir = std::env::temp_dir().join(format!("nmcp-inspector-effect-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let sink = nmcp_audit::AuditSink::open(&path).unwrap();

        for _ in 0..3 {
            // Provider effect record: no decision, no duration, by design.
            let effect = nmcp_audit::AuditEvent::new("write_text_file", "wrote a file");
            sink.append(&effect).unwrap();

            // AuditRing record: the real decision and the measured duration.
            let mut ring = nmcp_audit::AuditEvent::new("write_text_file", "{}");
            ring.decision = "allowed".into();
            ring.duration_ms = Some(12);
            sink.append(&ring).unwrap();
        }

        let history = latency_history(&path, 100).expect("history");
        assert_eq!(
            history.sample_count, 6,
            "both record kinds are still sampled"
        );
        assert_eq!(history.authorization_count, 3);
        assert_eq!(history.effect_record_count, 3);
        assert_eq!(history.measured_count, 3);
        assert_eq!(
            history.unmeasured_count, 0,
            "an effect record without a duration is not a missed measurement"
        );

        // The newest line is an effect record; latest must still be the newest record that
        // actually carries a decision and a duration.
        let latest = history.latest.expect("latest");
        assert_eq!(latest.decision, "allowed");
        assert_eq!(latest.duration_ms, Some(12));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn latency_history_buckets_slowest_and_timeout_like() {
        use nmcp_audit::AuditSink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nmcp-inspector-latency-history-{stamp}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("audit.jsonl");
        let sink = AuditSink::open(&path).expect("open");

        let mut fast = nmcp_audit::AuditEvent::new("tool_fast", "ok");
        fast.duration_ms = Some(42);
        let mut medium = nmcp_audit::AuditEvent::new("tool_medium", "ok");
        medium.duration_ms = Some(750);
        let mut slow = nmcp_audit::AuditEvent::new("tool_slow", "timeout waiting for provider");
        slow.duration_ms = Some(6_000);
        slow.decision = "timed_out".into();

        sink.append(&fast).expect("append fast");
        sink.append(&medium).expect("append medium");
        sink.append(&slow).expect("append slow");

        let history = latency_history(&path, 10).expect("history");
        assert_eq!(history.sample_count, 3);
        assert_eq!(history.measured_count, 3);
        assert_eq!(history.timeout_like_count, 1);
        assert_eq!(history.buckets.len(), 5);
        assert_eq!(history.buckets[0].count, 1);
        assert_eq!(history.buckets[2].count, 1);
        assert_eq!(history.buckets[4].count, 1);
        assert_eq!(
            history.latest.as_ref().map(|entry| entry.action.as_str()),
            Some("tool_slow")
        );
        assert_eq!(history.slowest[0].duration_ms, Some(6_000));
        assert!(history.entries[0].timeout_like);
        assert_eq!(history.entries[0].duration_bucket.as_deref(), Some(">=5s"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
