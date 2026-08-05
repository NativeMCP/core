//! The `io.modelcontextprotocol/tasks` extension wire vocabulary (G5-6).
//!
//! This module is the shapes and nothing else. It holds no job state, reaches no registry, and
//! makes no policy decision about which calls become tasks. That separation is deliberate: the
//! extension's own trap is that a widely-circulated 2025-era description of "tasks" uses a
//! different vocabulary and an inverted control flow, so the wire surface is worth having in
//! one place that can be read against the schema without a runtime in the way.
//!
//! Two facts drive every shape below, both read off the published schemas rather than recalled:
//!
//! 1. `resultType` lives on the CORE `Result` in `2026-07-28` and is required of every result.
//!    `CreateTaskResult = Result & Task` therefore has no `resultType` member of its own; it
//!    inherits the required one. `ResultType` is an open union, `"complete" | "input_required"
//!    | string`, and `"task"` is this extension's contribution to it.
//! 2. `DetailedTask` is a discriminated union, `WorkingTask | InputRequiredTask | CompletedTask
//!    | FailedTask | CancelledTask`, with the status-specific member inlined. It is not one
//!    shape with optional fields, so [`TaskState`] is not either.
//!
//! Control flow, which is the inverse of the older vocabulary: the client declares in its
//! per-request `_meta` that it can survive a task, the server declares support in
//! `ServerCapabilities.extensions`, and the SERVER decides per call whether to answer with a
//! task instead of the ordinary result. A client never asks for one.

use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Map, Value, json};

use crate::RESULT_TYPE_COMPLETE;

/// Extension identifier, as it appears as a key in `ServerCapabilities.extensions` and in the
/// client's per-request `_meta` capabilities block.
pub const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";

/// The `resultType` a `CreateTaskResult` carries.
pub const RESULT_TYPE_TASK: &str = "task";

/// What a task is doing, carrying the payload each terminal state is required to carry.
///
/// A discriminated union because the schema's is: a completed task has a `result` and a failed
/// task has an `error`, and neither can be constructed here without one.
///
/// `input_required` is deliberately absent. That status means the server has asked the client
/// for sampling, roots or elicitation mid-task, and this server does none of those. A variant
/// that can never be constructed would be worse than no variant, because it would invite a
/// `tasks/update` handler for input the runtime has nowhere to route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskState {
    /// The task is still running.
    Working,
    /// The task finished; `result` is the whole result of the original request.
    Completed {
        /// The inlined result, shaped as the original request's result type.
        result: Value,
    },
    /// The task failed; `error` is a JSON-RPC error object.
    Failed {
        /// The JSON-RPC error object, from [`task_error`].
        error: Value,
    },
    /// The task was cancelled cooperatively.
    Cancelled,
}

impl TaskState {
    /// The `TaskStatus` string this state serializes as.
    #[must_use]
    pub fn status(&self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::Completed { .. } => "completed",
            Self::Failed { .. } => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether the task has stopped changing.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Working)
    }
}

/// A task as the wire sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskHandle {
    /// Server-assigned task identifier.
    pub task_id: String,
    /// Current state with its status-specific payload.
    pub state: TaskState,
    /// Optional human-readable progress note.
    pub status_message: Option<String>,
    /// When the task was created.
    pub created_at: DateTime<Utc>,
    /// When the task last changed.
    pub last_updated_at: DateTime<Utc>,
    /// Time to live from creation, in milliseconds. `None` serializes as the schema's `null`,
    /// which means unlimited rather than unknown.
    pub ttl_ms: Option<u64>,
    /// What the server suggests the client wait between polls. Clients SHOULD honour it.
    pub poll_interval_ms: Option<u64>,
}

impl TaskHandle {
    /// The `Task` members every shape in this extension carries.
    fn task_members(&self) -> Map<String, Value> {
        let mut members = Map::new();
        members.insert("taskId".into(), Value::from(self.task_id.clone()));
        members.insert("status".into(), Value::from(self.state.status()));
        if let Some(message) = &self.status_message {
            members.insert("statusMessage".into(), Value::from(message.clone()));
        }
        members.insert("createdAt".into(), Value::from(iso8601(self.created_at)));
        members.insert(
            "lastUpdatedAt".into(),
            Value::from(iso8601(self.last_updated_at)),
        );
        // Required and nullable rather than optional. `null` is the statement "no limit";
        // omitting the member would be a different statement, and not one the schema allows.
        members.insert("ttlMs".into(), self.ttl_ms.map_or(Value::Null, Value::from));
        if let Some(interval) = self.poll_interval_ms {
            members.insert("pollIntervalMs".into(), Value::from(interval));
        }
        members
    }
}

/// `CreateTaskResult`: what a server returns in lieu of the ordinary result when it elects to
/// process a request asynchronously.
#[must_use]
pub fn create_task_result(handle: &TaskHandle) -> Value {
    let mut members = handle.task_members();
    members.insert("resultType".into(), Value::from(RESULT_TYPE_TASK));
    Value::Object(members)
}

/// `GetTaskResult`: `Result & DetailedTask`, with the status-specific member inlined.
///
/// A completed task inlines the whole result of the original request here. It is not a status
/// with a pointer to fetch the output separately, which is the part of this extension most
/// easily got wrong: the schema says the structure matches the result type of the original
/// request, so a task created from `tools/call` inlines a whole `CallToolResult`.
#[must_use]
pub fn get_task_result(handle: &TaskHandle) -> Value {
    let mut members = handle.task_members();
    members.insert("resultType".into(), Value::from(RESULT_TYPE_COMPLETE));
    match &handle.state {
        TaskState::Completed { result } => {
            members.insert("result".into(), result.clone());
        }
        TaskState::Failed { error } => {
            members.insert("error".into(), error.clone());
        }
        TaskState::Working | TaskState::Cancelled => {}
    }
    Value::Object(members)
}

/// `CancelTaskResult`: an empty acknowledgement.
///
/// Deliberately not a status report, which is where this differs from `execute_cancel`. The
/// schema calls cancellation "cooperative and eventually consistent", so a status returned here
/// would be a snapshot the client has no right to rely on. The client polls `tasks/get` for the
/// outcome, which is what an `execute_cancel` caller does today by following with
/// `execute_status`.
#[must_use]
pub fn cancel_task_result() -> Value {
    json!({ "resultType": RESULT_TYPE_COMPLETE })
}

/// A JSON-RPC error object for a `FailedTask`.
///
/// `FailedTask.error` is typed as a JSON-RPC error rather than free text, so a job that never
/// started has to be shaped as one rather than reported as a completed task carrying a failure.
#[must_use]
pub fn task_error(code: i64, message: impl Into<String>) -> Value {
    json!({ "code": code, "message": message.into() })
}

/// ISO 8601, which is what the schema asks for on `createdAt` and `lastUpdatedAt`.
///
/// Millisecond precision with a `Z` suffix. `nmcp-audit` already writes this shape for every
/// audit record, so a reader correlating a task against the audit log is comparing like with
/// like rather than converting.
fn iso8601(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// The current instant, in the type [`TaskHandle`] holds.
///
/// Exposed so a caller can stamp a task created in the same breath as the response without
/// taking a date library of its own. The format requirement lives in this module, so the clock
/// does too.
#[must_use]
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// Convert the unix-millisecond timestamps the job registry persists.
///
/// Saturating rather than failing: a timestamp this server itself wrote cannot realistically be
/// out of range, and returning the epoch for an impossible value keeps a corrupt `job.json`
/// from taking down a poll that would otherwise report the job as failed.
#[must_use]
pub fn from_unix_ms(ms: u128) -> DateTime<Utc> {
    let clamped = i64::try_from(ms).unwrap_or(i64::MAX);
    Utc.timestamp_millis_opt(clamped)
        .single()
        .unwrap_or(DateTime::UNIX_EPOCH)
}

/// Whether a client declared it can survive a task, from its per-request capabilities block.
///
/// The control flow here is the inverse of the older vocabulary and it is worth restating at
/// the point of use: this is not a client asking for a task. It is a client saying it would
/// cope with one, which is a precondition on the server's freedom to answer with a task rather
/// than a request the server owes an answer to.
///
/// An absent or empty `extensions` object is a declaration that the client supports no optional
/// capabilities, not an omission to be guessed around.
#[must_use]
pub fn client_declared(client_capabilities: &Value) -> bool {
    client_capabilities
        .get("extensions")
        .and_then(|extensions| extensions.get(TASKS_EXTENSION))
        .is_some()
}

/// Add the tasks extension to a `capabilities` object.
///
/// Called only when the server can actually produce a task. A server whose policy names no task
/// tool will never answer with one, and advertising the capability anyway would invite a client
/// to wait for something that is never coming.
pub fn advertise_in(capabilities: &mut Value) {
    if let Some(object) = capabilities.as_object_mut() {
        object
            .entry("extensions")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .map(|extensions| extensions.insert(TASKS_EXTENSION.to_string(), json!({})));
    }
}

#[cfg(test)]
mod tests {
    // Tests assert on JSON shape, where indexing IS the assertion: a panic
    // in a test is the failure signal, so the production rationale for the
    // workspace denies does not apply. Scoped to the test module.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;

    fn handle(state: TaskState) -> TaskHandle {
        TaskHandle {
            task_id: "0f9d1c2e-0000-4000-8000-000000000001".into(),
            state,
            status_message: None,
            created_at: from_unix_ms(1_785_700_000_000),
            last_updated_at: from_unix_ms(1_785_700_005_000),
            ttl_ms: Some(30_000),
            poll_interval_ms: Some(1_000),
        }
    }

    #[test]
    fn a_created_task_names_itself_a_task_rather_than_a_complete_result() {
        // The whole point of the discriminator: this is the one result shape a client must not
        // parse as the answer to what it asked.
        let result = create_task_result(&handle(TaskState::Working));
        assert_eq!(result["resultType"], "task");
        assert_eq!(result["status"], "working");
        assert_eq!(result["taskId"], "0f9d1c2e-0000-4000-8000-000000000001");
        assert_eq!(result["ttlMs"], 30_000);
        assert_eq!(result["pollIntervalMs"], 1_000);
    }

    #[test]
    fn timestamps_are_iso_8601_and_not_unix_milliseconds() {
        let result = create_task_result(&handle(TaskState::Working));
        // 1_785_700_000_000 ms since the epoch, and five seconds later.
        assert_eq!(result["createdAt"], "2026-08-02T19:46:40.000Z");
        assert_eq!(result["lastUpdatedAt"], "2026-08-02T19:46:45.000Z");
    }

    #[test]
    fn an_unlimited_ttl_is_null_rather_than_absent() {
        // null means no limit. An absent member would be a different statement, and the schema
        // requires ttlMs, so absence is not one it permits.
        let mut task = handle(TaskState::Working);
        task.ttl_ms = None;
        let result = create_task_result(&task);
        assert!(result.get("ttlMs").is_some(), "{result}");
        assert!(result["ttlMs"].is_null(), "{result}");
    }

    #[test]
    fn a_completed_task_inlines_the_whole_result_of_the_original_request() {
        // Not a pointer to fetch the output separately. The schema says the structure matches
        // the result type of the original request, so a tools/call task inlines a whole
        // CallToolResult.
        let call_result = json!({
            "content": [{"type": "text", "text": "done"}],
            "isError": false,
        });
        let result = get_task_result(&handle(TaskState::Completed {
            result: call_result.clone(),
        }));
        assert_eq!(result["resultType"], "complete");
        assert_eq!(result["status"], "completed");
        assert_eq!(result["result"], call_result);
        assert!(result.get("error").is_none());
    }

    #[test]
    fn a_failed_task_carries_a_json_rpc_error_rather_than_a_message() {
        let result = get_task_result(&handle(TaskState::Failed {
            error: task_error(-32000, "program not found"),
        }));
        assert_eq!(result["status"], "failed");
        assert_eq!(result["error"]["code"], -32000);
        assert_eq!(result["error"]["message"], "program not found");
        assert!(result.get("result").is_none());
    }

    #[test]
    fn a_working_or_cancelled_task_inlines_nothing_extra() {
        for state in [TaskState::Working, TaskState::Cancelled] {
            let expected = state.status();
            let result = get_task_result(&handle(state));
            assert_eq!(result["status"], expected);
            assert!(result.get("result").is_none(), "{result}");
            assert!(result.get("error").is_none(), "{result}");
        }
    }

    #[test]
    fn cancelling_acknowledges_and_does_not_report_a_status() {
        // Cooperative and eventually consistent, so a status here would be a snapshot the
        // client has no right to rely on. It polls tasks/get for the outcome.
        let result = cancel_task_result();
        assert_eq!(result["resultType"], "complete");
        assert!(result.get("status").is_none(), "{result}");
        assert!(result.get("taskId").is_none(), "{result}");
    }

    #[test]
    fn a_client_that_says_nothing_has_not_declared_the_extension() {
        // An empty capabilities object is a declaration of no optional capabilities, so the
        // server must not read silence as consent to answer with a task.
        assert!(!client_declared(&json!({})));
        assert!(!client_declared(&json!({"extensions": {}})));
        assert!(!client_declared(
            &json!({"extensions": {"io.example/other": {}}})
        ));
    }

    #[test]
    fn an_empty_settings_object_is_a_declaration() {
        // The schema says an empty object means support with no settings, so it counts.
        assert!(client_declared(
            &json!({"extensions": {"io.modelcontextprotocol/tasks": {}}})
        ));
    }

    #[test]
    fn advertising_adds_the_extension_without_disturbing_what_is_there() {
        let mut capabilities = json!({"tools": {}});
        advertise_in(&mut capabilities);
        assert!(capabilities["tools"].is_object(), "{capabilities}");
        assert_eq!(
            capabilities["extensions"]["io.modelcontextprotocol/tasks"],
            json!({})
        );
    }

    #[test]
    fn only_working_is_non_terminal() {
        assert!(!TaskState::Working.is_terminal());
        for state in [
            TaskState::Completed { result: json!({}) },
            TaskState::Failed { error: json!({}) },
            TaskState::Cancelled,
        ] {
            assert!(state.is_terminal(), "{state:?}");
        }
    }

    #[test]
    fn a_status_message_is_carried_only_when_there_is_one() {
        let mut task = handle(TaskState::Working);
        assert!(create_task_result(&task).get("statusMessage").is_none());
        task.status_message = Some("waiting for a permit".into());
        assert_eq!(
            create_task_result(&task)["statusMessage"],
            "waiting for a permit"
        );
    }
}
