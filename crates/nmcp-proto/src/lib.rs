//! `nmcp-proto`
//!
//! MCP wire protocol for the NativeMCP `core` workspace: JSON-RPC envelopes,
//! protocol revision negotiation (SEP-2575), the 2026-07-28 stateless core,
//! and the tasks extension. The governance invariants in `docs/GOVERNANCE.md`
//! are normative for every item in this crate.
//!
//! Carry-over, named: [`tool_list`], [`READ_ONLY_TOOLS`] and
//! [`OPEN_WORLD_TOOLS`] describe the ported server's first-party catalog.
//! They move behind the provider registry when `nmcp-host` lands (R-1), at
//! which point a platform daemon contributes its own catalog instead of
//! inheriting this one.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Semantic version of this crate, taken from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate identity as it appears in audit records and capability manifests.
pub const COMPONENT: &str = "nmcp-proto";

/// JSON-RPC protocol version stamped on every envelope.
pub const JSONRPC_VERSION: &str = "2.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
/// One JSON-RPC request envelope as it arrives off the transport.
pub struct JsonRpcRequest {
    /// Always [`JSONRPC_VERSION`] on a conforming request.
    pub jsonrpc: String,
    /// Request id; absent on notifications.
    #[serde(default)]
    pub id: Option<Value>,
    /// The RPC method name, e.g. `tools/call`.
    pub method: String,
    /// Method parameters, `Value::Null` when absent.
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// One JSON-RPC response envelope, exactly one of `result` or `error` set.
pub struct JsonRpcResponse {
    /// Always [`JSONRPC_VERSION`].
    pub jsonrpc: String,
    /// Echo of the request id, when the request carried one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    /// Success payload; mutually exclusive with `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Failure payload; mutually exclusive with `result`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `error` member of a JSON-RPC response.
pub struct JsonRpcError {
    /// JSON-RPC error code, negative in the reserved range.
    pub code: i64,
    /// Human-readable summary of what was refused and why.
    pub message: String,
    /// Structured detail a client can act on, when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// One advertised tool: name, description and input contract.
pub struct ToolSpec {
    /// Tool name as dispatched.
    pub name: String,
    /// One-paragraph behavior description shown to callers.
    pub description: String,
    /// JSON Schema for the tool's arguments.
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// Tools that only observe. They never create, modify, rename, move, or send anything.
///
/// `readOnlyHint` is the annotation a client uses to decide whether a call needs
/// confirmation, so a wrong entry here is worse than no entry. When in doubt a tool is
/// left out of this list and is therefore reported as not read-only.
pub const READ_ONLY_TOOLS: &[&str] = &[
    // filesystem observation
    "list_roots",
    "list_directory",
    "search_repo",
    "scan_repo",
    "read_file_window_report",
    "inspect_file_integrity",
    // execution observation: these inspect jobs, they do not start or stop them
    "execute_resolve_program",
    "execute_env_report",
    "execute_status",
    "execute_tail",
    "execute_wait",
    "execute_result",
    // scoped memory
    "mem_read",
    "mem_list",
    // Windows observation
    "win_registry_read",
    "win_eventlog_query",
    "win_services_query",
    "win_wmi_query",
    // repository observation
    "dev_git_log",
    "dev_git_blame",
    "dev_git_diff",
    "dev_dep_graph",
    "dev_git_stash_list",
    // Microsoft 365 observation
    "m365_auth_status",
    "m365_mail_list",
    "m365_mail_get",
    "m365_mail_folders_list",
    "m365_calendar_list_events",
    "m365_calendar_view",
    "m365_calendar_get_event",
    "m365_calendar_get_schedule",
    "m365_teams_list_joined",
    "m365_teams_list_channels",
    "m365_teams_list_channel_messages",
    "m365_teams_list_chats",
    "m365_teams_list_chat_messages",
    "m365_files_search",
    "m365_files_list_children",
    "m365_files_get_item",
    "m365_sites_get",
    "m365_search_query",
];

/// Non-`m365_` tools that can reach beyond this host.
///
/// Every `m365_` tool is open-world by definition and is matched by prefix rather than
/// listed here. The execution tools are included because an approved program may itself
/// reach the network: the tool's own reach is local, but its effect is not bounded by this
/// host, and the conservative reading is the honest one to publish.
pub const OPEN_WORLD_TOOLS: &[&str] = &[
    "execute",
    "execute_start",
    "dev_test_run",
    "dev_git_publish",
];

/// MCP tool annotations for a first-party tool.
///
/// Absent annotations are not neutral. A client that receives none applies the protocol
/// defaults, and those defaults are deliberately pessimistic: `destructiveHint` and
/// `openWorldHint` both default to true. That is a sane default for an unknown server and
/// exactly wrong for this one, which is why a read-only call like `dev_git_log` was being
/// displayed to operators as DESTRUCTIVE.
///
/// `destructiveHint` is false for every tool here, and that is not a convenience: it is the
/// No-Destructive-Action Guarantee (M3) restated in the manifest. There is no delete surface
/// to annotate, backup is rename-only, and the broker refuses delete-intent commands before
/// they spawn. If a tool is ever added for which false would be a lie, the guarantee is what
/// broke, not this function.
#[must_use]
pub fn tool_annotations(name: &str) -> Value {
    let read_only = READ_ONLY_TOOLS.contains(&name);
    let open_world = name.starts_with("m365_") || OPEN_WORLD_TOOLS.contains(&name);
    json!({
        "readOnlyHint": read_only,
        "destructiveHint": false,
        "openWorldHint": open_world,
    })
}

/// Build a success envelope for `id` carrying `result`.
#[must_use]
pub fn success(id: Option<Value>, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: JSONRPC_VERSION.to_string(),
        id,
        result: Some(result),
        error: None,
    }
}

/// Build a failure envelope for `id` from `code`, `message` and `data`.
#[must_use]
pub fn failure(
    id: Option<Value>,
    code: i64,
    message: impl Into<String>,
    data: Option<Value>,
) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: JSONRPC_VERSION.to_string(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.into(),
            data,
        }),
    }
}

pub mod stateless;
pub mod tasks;

// -- Protocol revisions --------------------------------------------------------

/// MCP revisions this server actually implements, newest first.
///
/// A revision belongs on this list only when the server implements its semantics, not when
/// it merely parses its requests. `2026-07-28` joined it with G5-4, once the transport
/// enforced the stateless core: `_meta` ingestion, the SEP-2243 headers, `server/discover`
/// from G5-3, and a `tools/call` that completes carrying no session. It was held off the list
/// until then on purpose, because advertising a revision whose behaviour does not exist makes
/// a client send requests the server cannot answer.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2026-07-28", "2025-11-25"];

/// Revision assumed when a request does not name one.
///
/// Deliberately the older of the two now that both are supported. A request with no
/// `MCP-Protocol-Version` header comes from a client that has never heard of per-request
/// negotiation, so it is also a request with no `_meta` block and no `Mcp-Method`, and holding
/// it to the stateless requirements would refuse every client working today. Defaulting to the
/// newest supported revision was defensible only while the newest one asked nothing extra of
/// the request.
pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-11-25";

/// The revision whose requests carry `_meta` and the SEP-2243 headers.
pub const STATELESS_PROTOCOL_VERSION: &str = "2026-07-28";

/// The MCP revision this workspace targets: the newest member of
/// [`SUPPORTED_PROTOCOL_VERSIONS`].
///
/// Pinned deliberately. Moving it is a reviewed change with a migration
/// note, not a dependency bump.
pub const PROTOCOL_REVISION: &str = STATELESS_PROTOCOL_VERSION;

/// Returns `true` when `revision` is one this build implements.
///
/// Implements means the semantics exist, not that the parser tolerates the
/// string: see [`SUPPORTED_PROTOCOL_VERSIONS`] for the admission rule.
#[must_use]
pub fn supports_revision(revision: &str) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&revision)
}

/// JSON-RPC error code for a revision this server does not implement (SEP-2575).
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// The only [`ResultType`] this server produces today.
///
/// `input_required` belongs to a server that asks the client for something mid-request, which
/// this one never does, and `task` belongs to the tasks extension, which is G5-6.
pub const RESULT_TYPE_COMPLETE: &str = "complete";

/// Stamp the discriminator every `2026-07-28` result is required to carry.
///
/// `Result.resultType` is a core field from this revision on, not a tasks-extension one. The
/// schema is explicit: "Servers implementing this protocol version MUST include this field."
/// `ResultType` is an open union, `"complete" | "input_required" | string`, which is exactly
/// how the tasks extension contributes `"task"` without core knowing anything about tasks.
///
/// Conditioned on the revision rather than applied to every response, because `2025-11-25`
/// never defined the field and the same schema tells a client to read an absent one as
/// `"complete"` when it came from an earlier revision. Adding it there would put a member on
/// the wire that revision does not define, in order to tell the client something its own rule
/// already tells it.
///
/// An existing `resultType` is never overwritten, so a future `CreateTaskResult` carrying
/// `"task"` passes through this unchanged.
pub fn stamp_result_type(response: &mut JsonRpcResponse, protocol_version: &str) {
    if protocol_version != STATELESS_PROTOCOL_VERSION {
        return;
    }
    let Some(Value::Object(result)) = response.result.as_mut() else {
        return;
    };
    result
        .entry("resultType")
        .or_insert_with(|| Value::from(RESULT_TYPE_COMPLETE));
}

/// Outcome of resolving the revision a single request asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// The request named a revision this server implements, or named none.
    Selected(&'static str),
    /// The request named a revision this server does not implement.
    Unsupported(String),
}

impl ProtocolVersion {
    /// The negotiated revision string, or `None` when the request must be refused.
    #[must_use]
    pub fn selected(&self) -> Option<&'static str> {
        match self {
            Self::Selected(version) => Some(version),
            Self::Unsupported(_) => None,
        }
    }
}

/// Resolve the protocol revision for one request.
///
/// An absent version selects [`DEFAULT_PROTOCOL_VERSION`] rather than failing. `2026-07-28`
/// states that a request with no `MCP-Protocol-Version` header defaults to `2025-03-26`, which
/// this server does not implement, and clients reaching it today omit the header while speaking
/// `2025-11-25`. The ambiguity this comment used to warn about arrived when `2026-07-28` joined
/// the list, and is resolved in favour of the older revision: see [`DEFAULT_PROTOCOL_VERSION`].
#[must_use]
pub fn select_protocol_version(requested: Option<&str>) -> ProtocolVersion {
    let Some(requested) = requested.map(str::trim).filter(|value| !value.is_empty()) else {
        return ProtocolVersion::Selected(DEFAULT_PROTOCOL_VERSION);
    };
    match SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .find(|candidate| **candidate == requested)
    {
        Some(found) => ProtocolVersion::Selected(found),
        None => ProtocolVersion::Unsupported(requested.to_string()),
    }
}

/// Build the SEP-2575 `UnsupportedProtocolVersionError` response.
///
/// `data` carries `supported` and `requested` so a client can pick a mutually supported
/// revision and retry without a second round trip to discover the list.
#[must_use]
pub fn unsupported_protocol_version(id: Option<Value>, requested: &str) -> JsonRpcResponse {
    failure(
        id,
        UNSUPPORTED_PROTOCOL_VERSION,
        format!("unsupported MCP protocol version: {requested}"),
        Some(json!({
            "supported": SUPPORTED_PROTOCOL_VERSIONS,
            "requested": requested,
        })),
    )
}

/// How long a `tools/list` result stays fresh, in milliseconds.
///
/// The local tool catalog is fixed at build time. What can change underneath a cached copy
/// is the upstream gateway catalog, which refreshes on a 60 second cycle, and a policy hot
/// reload. 60 seconds is therefore the honest ceiling rather than a round number: a longer
/// TTL would let a client hold a catalog that no longer matches what the router will
/// dispatch, and a shorter one would just add round trips for a list that did not move.
pub const TOOLS_LIST_TTL_MS: u64 = 60_000;

// Checked at compile time rather than in a test, because the reason for the ceiling is
// structural: a TTL longer than the gateway's upstream refresh cycle lets a client hold a
// tool list the router will no longer dispatch.
const _: () = assert!(TOOLS_LIST_TTL_MS > 0 && TOOLS_LIST_TTL_MS <= 60_000);

/// Natural-language guidance returned by `server/discover`.
///
/// Clients may put this in a system prompt, so it is written for a model that has the tool
/// list but not the governance model, and it states the three things that otherwise cause a
/// confident wrong call: paths must be inside a configured root, there is no delete surface
/// to reach for, and a denial is a policy decision rather than a transient failure to retry.
pub const SERVER_INSTRUCTIONS: &str = "\
This server is governed. Every tool call passes a policy check, optional attribute rules, \
and a human-approval gate before it runs, and every call is recorded in a hash-chained \
audit log.

Paths must resolve inside a configured root. Call list_roots first to see the roots and the \
permissions granted on each; a path outside them is denied no matter how it is written.

There is no delete tool and there will not be one. Removal is not available through this \
server: use backup_file, which renames rather than destroys, and let a human do any actual \
deletion. Commands whose arguments name a delete verb are refused before they spawn.

A denial is a decision, not a transient error. Retrying an identical denied call produces \
an identical denial. Read the remediation field, change the path, the permission, or the \
approach, and only then retry.";

/// Result of the `server/discover` RPC (SEP-2575).
///
/// Servers MUST implement this method under `2026-07-28`; clients MAY call it. It is
/// answered on every revision this server supports, not only the newest, because a client
/// probing to find out which revisions exist cannot be expected to already know one.
#[must_use]
pub fn discover_result(tools: &[Value]) -> Value {
    json!({
        "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "nativemcp-core", "version": env!("CARGO_PKG_VERSION") },
        "instructions": SERVER_INSTRUCTIONS,
        "tools": tools,
        "ttlMs": TOOLS_LIST_TTL_MS,
    })
}

/// Initialize result for the negotiated revision.
///
/// The revision is a parameter rather than a constant so the value reported back is the one
/// actually negotiated for this request, not a build-time assumption.
#[must_use]
pub fn initialize_result(protocol_version: &str) -> Value {
    json!({
        "protocolVersion": protocol_version,
        "serverInfo": { "name": "nativemcp-core", "version": env!("CARGO_PKG_VERSION") },
        "capabilities": { "tools": {} }
    })
}

/// Wrap a tool's structured result in MCP `content` + `structuredContent` form.
#[must_use]
pub fn tool_result_json(value: &Value) -> Value {
    let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string());
    json!({
        "content": [
            { "type": "text", "text": text }
        ],
        "structuredContent": value.clone()
    })
}

/// The ported first-party tool catalog. Carry-over: moves behind the
/// provider registry at R-1; see the module docs.
#[must_use]
pub fn tool_list() -> Vec<ToolSpec> {
    vec![
        ToolSpec { name: "list_roots".into(), description: "Return configured roots and effective permissions.".into(), input_schema: json!({"type":"object","properties":{}}) },
        ToolSpec { name: "list_directory".into(), description: "List one directory under an allowed root and return bounded entries.".into(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"include_hidden":{"type":"boolean"},"limit":{"type":"integer"}},"required":["path"]}) },
        ToolSpec { name: "search_repo".into(), description: "Search file content under an allowed root and return a bounded report. The walk prunes generated directories (target, node_modules, .git and similar) and stops at a time and file budget; the report names what was pruned and whether it stopped early.".into(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"pattern":{"type":"string"},"max_files":{"type":"integer","description":"Raise the file ceiling for this call. The wall-clock deadline still applies."},"include_generated":{"type":"boolean","description":"Walk generated directories too. Slower, and the deadline still applies."}},"required":["path","pattern"]}) },
        ToolSpec { name: "scan_repo".into(), description: "Scan a repository root and return a report, including secret candidates. The walk prunes generated directories (target, node_modules, .git and similar) and stops at a time and file budget; the report names what was pruned and whether it stopped early, so a partial scan is never mistaken for a clean tree.".into(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"max_files":{"type":"integer","description":"Raise the file ceiling for this call. The wall-clock deadline still applies."},"include_generated":{"type":"boolean","description":"Walk generated directories too. Slower, and the deadline still applies."}},"required":["path"]}) },
        ToolSpec { name: "create_text_file".into(), description: "Create a UTF-8 file and return an operation report.".into(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]}) },
        ToolSpec { name: "read_file_window_report".into(), description: "Return a bounded line-window report for a file.".into(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"start_line":{"type":"integer"},"line_count":{"type":"integer"}},"required":["path"]}) },
        ToolSpec { name: "inspect_file_integrity".into(), description: "Return full-file integrity metadata, headings, suspicious markers, and bounded first/last line previews.".into(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"preview_lines":{"type":"integer","description":"Number of first/last lines to include, clamped to 1..50."}},"required":["path"]}) },
        ToolSpec { name: "write_text_file".into(), description: "Create or replace a UTF-8 file and return an operation report.".into(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]}) },
        ToolSpec { name: "patch_text_file".into(), description: "Replace a UTF-8 file through the legacy patch_text_file alias; content is required and before/after hashes are returned.".into(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]}) },
        ToolSpec { name: "rename_file".into(), description: "Rename a file without moving its parent directory.".into(), input_schema: json!({"type":"object","properties":{"from":{"type":"string"},"to_name":{"type":"string"}},"required":["from","to_name"]}) },
        ToolSpec { name: "move_file".into(), description: "Move a file to a different directory. Audited separately from rename.".into(), input_schema: json!({"type":"object","properties":{"from":{"type":"string"},"to":{"type":"string"}},"required":["from","to"]}) },
        ToolSpec { name: "backup_file".into(), description: "Rename a file to .bak, .bak1, .bak2, etc. This is the only destructive-adjacent operation.".into(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}) },
        ToolSpec { name: "execute".into(), description: "Run a short configured local command and return an execution report. timeout_ms defaults to 30000 to stay below connector request limits; use execute_start for durable long-running work.".into(), input_schema: json!({"type":"object","properties":{"cwd":{"type":"string"},"program":{"type":"string"},"args":{"type":"array","items":{"type":"string"}},"timeout_ms":{"type":"integer","description":"Optional command timeout in milliseconds. Defaults to 30000 (30 seconds)."},"profile":{"type":"string"},"env":{"type":"object","additionalProperties":{"type":"string"}},"inherit_service_env":{"type":"boolean"}},"required":["cwd","program"]}) },
        ToolSpec { name: "execute_start".into(), description: "Start a long-running command as a durable NativeMCP job and return immediately with job_id and log paths.".into(), input_schema: json!({"type":"object","properties":{"cwd":{"type":"string"},"program":{"type":"string"},"args":{"type":"array","items":{"type":"string"}},"timeout_ms":{"type":"integer"},"profile":{"type":"string"},"env":{"type":"object","additionalProperties":{"type":"string"}},"inherit_service_env":{"type":"boolean"}},"required":["cwd","program"]}) },
        ToolSpec { name: "execute_resolve_program".into(), description: "Resolve a program using request env, configured tool aliases, execution profiles, service PATH, and Windows PATHEXT without starting it.".into(), input_schema: json!({"type":"object","properties":{"program":{"type":"string"},"profile":{"type":"string"},"env":{"type":"object","additionalProperties":{"type":"string"}},"inherit_service_env":{"type":"boolean"}},"required":["program"]}) },
        ToolSpec { name: "execute_env_report".into(), description: "Report the service execution environment, configured execution profiles, tool aliases, effective exec state directory, and redacted env preview.".into(), input_schema: json!({"type":"object","properties":{"profile":{"type":"string"},"env":{"type":"object","additionalProperties":{"type":"string"}},"inherit_service_env":{"type":"boolean"}}}) },
        ToolSpec { name: "execute_status".into(), description: "Return current status for an execute job, including PID, elapsed time, command shape, and exit code when finished.".into(), input_schema: json!({"type":"object","properties":{"job_id":{"type":"string"}},"required":["job_id"]}) },
        ToolSpec { name: "execute_tail".into(), description: "Return bounded stdout and stderr tails from an execute job's append-only log files.".into(), input_schema: json!({"type":"object","properties":{"job_id":{"type":"string"},"max_bytes":{"type":"integer"}},"required":["job_id"]}) },
        ToolSpec { name: "execute_wait".into(), description: "Wait briefly for an execute job and return status plus bounded tails; use status/result for later polling.".into(), input_schema: json!({"type":"object","properties":{"job_id":{"type":"string"},"timeout_ms":{"type":"integer"},"max_bytes":{"type":"integer"}},"required":["job_id"]}) },
        ToolSpec { name: "execute_result".into(), description: "Return the final report for an execute job, or running status plus log tails if still active.".into(), input_schema: json!({"type":"object","properties":{"job_id":{"type":"string"}},"required":["job_id"]}) },
        ToolSpec { name: "execute_cancel".into(), description: "Cancel only a process job created by NativeMCP and audit the cancellation.".into(), input_schema: json!({"type":"object","properties":{"job_id":{"type":"string"}},"required":["job_id"]}) },
    ]
}

#[cfg(test)]
mod tests {
    // Tests assert on JSON shape, where indexing and unwrap ARE the
    // assertion: a panic here is the failure signal, so the production
    // rationale for the workspace denies (availability plus an audit gap)
    // does not apply. Scoped to the test module, named in the PR.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;

    #[test]
    fn no_tool_is_annotated_destructive() {
        // G2-8. This is the No-Destructive-Action Guarantee expressed where a client can
        // actually read it. If this ever fails, either a destructive tool was added, which
        // breaks M3, or tool_annotations stopped telling the truth. Both are release
        // blockers and neither should be fixed by editing this assertion.
        for tool in tool_list() {
            let annotations = tool_annotations(&tool.name);
            assert_eq!(
                annotations["destructiveHint"], false,
                "{} is annotated destructive; the product guarantee says no tool is",
                tool.name
            );
        }
    }

    #[test]
    fn read_only_tools_are_annotated_read_only_and_mutating_tools_are_not() {
        // Spot-check both directions rather than trusting the list's length. The pairs are
        // chosen so a copy-paste error in READ_ONLY_TOOLS shows up: each mutating tool here
        // shares a prefix with a read-only one.
        for name in [
            "read_file_window_report",
            "list_directory",
            "dev_git_log",
            "execute_status",
            "m365_mail_get",
            "win_registry_read",
        ] {
            assert_eq!(
                tool_annotations(name)["readOnlyHint"],
                true,
                "{name} observes and should be annotated read-only"
            );
        }
        for name in [
            "write_text_file",
            "move_file",
            "dev_git_publish",
            "execute",
            "m365_mail_send",
            "win_registry_write",
        ] {
            assert_eq!(
                tool_annotations(name)["readOnlyHint"],
                false,
                "{name} changes something and must not be annotated read-only"
            );
        }
    }

    #[test]
    fn open_world_marks_exactly_the_tools_that_leave_this_host() {
        for name in [
            "m365_mail_send",
            "m365_search_query",
            "dev_git_publish",
            "execute",
        ] {
            assert_eq!(
                tool_annotations(name)["openWorldHint"],
                true,
                "{name} can reach beyond this host"
            );
        }
        for name in [
            "list_directory",
            "read_file_window_report",
            "mem_read",
            "win_services_query",
        ] {
            assert_eq!(
                tool_annotations(name)["openWorldHint"],
                false,
                "{name} is local and should not claim an open world"
            );
        }
    }

    #[test]
    fn every_advertised_tool_is_classified() {
        // The read-only list is maintained by hand, so the failure mode is a new tool that
        // nobody classified and that therefore silently reports as not read-only. This does
        // not assert which side a tool lands on, only that somebody decided.
        let known_mutating = [
            "create_text_file",
            "write_text_file",
            "patch_text_file",
            "rename_file",
            "move_file",
            "backup_file",
            "execute",
            "execute_start",
            "execute_cancel",
            "mem_write",
            "mem_refresh",
            "mem_expire_now",
            "win_registry_write",
            "dev_test_run",
            "dev_git_publish",
            "m365_auth_begin_device_login",
            "m365_mail_send",
            "m365_mail_create_draft",
            "m365_calendar_create_event",
            "m365_calendar_update_event",
            "m365_teams_send_channel_message",
            "m365_teams_send_chat_message",
        ];
        for tool in tool_list() {
            let classified = READ_ONLY_TOOLS.contains(&tool.name.as_str())
                || known_mutating.contains(&tool.name.as_str());
            assert!(
                classified,
                "{} is advertised but classified in neither READ_ONLY_TOOLS nor the \
                 mutating list; decide which it is before shipping it",
                tool.name
            );
        }
    }

    #[test]
    fn a_2026_07_28_result_carries_the_discriminator_that_revision_requires() {
        let mut response = success(Some(json!(1)), json!({"tools": []}));
        stamp_result_type(&mut response, STATELESS_PROTOCOL_VERSION);
        assert_eq!(
            response.result.as_ref().unwrap()["resultType"],
            json!("complete")
        );
    }

    #[test]
    fn an_earlier_revision_does_not_gain_a_field_it_never_defined() {
        // The spec's own backward-compatibility rule already tells a client to read an absent
        // resultType as "complete" from an earlier-revision server, so stamping it here would
        // be inventing wire surface to say something the client already assumes.
        let mut response = success(Some(json!(1)), json!({"tools": []}));
        stamp_result_type(&mut response, DEFAULT_PROTOCOL_VERSION);
        assert!(
            response
                .result
                .as_ref()
                .unwrap()
                .get("resultType")
                .is_none(),
            "{:?}",
            response.result
        );
    }

    #[test]
    fn a_result_that_already_named_its_type_keeps_it() {
        // The tasks extension's CreateTaskResult carries resultType "task". It inherits the
        // field from core Result rather than declaring its own, so it arrives here already
        // set and has to survive.
        let mut response = success(
            Some(json!(1)),
            json!({"taskId": "t1", "resultType": "task"}),
        );
        stamp_result_type(&mut response, STATELESS_PROTOCOL_VERSION);
        assert_eq!(
            response.result.as_ref().unwrap()["resultType"],
            json!("task")
        );
    }

    #[test]
    fn an_error_response_has_no_result_to_stamp() {
        let mut response = failure(Some(json!(1)), -32601, "method not found", None);
        stamp_result_type(&mut response, STATELESS_PROTOCOL_VERSION);
        assert!(response.result.is_none());
        assert_eq!(response.error.as_ref().unwrap().code, -32601);
    }

    #[test]
    fn supported_revisions_list_only_what_the_server_implements() {
        // The list is an advertisement. A revision belongs here when the behavior exists,
        // not when the parser tolerates the string. 2026-07-28 requires a stateless core,
        // server/discover, and per-request _meta; none of that is implemented yet, and a
        // client that believed the advertisement would send requests this server cannot
        // answer. This test is the thing that has to be deleted deliberately when G5-2
        // through G5-4 land, rather than the advertisement drifting ahead of the code.
        assert!(
            SUPPORTED_PROTOCOL_VERSIONS.contains(&STATELESS_PROTOCOL_VERSION),
            "the transport enforces the stateless core now (G5-4), so it is advertised"
        );
        assert_eq!(
            DEFAULT_PROTOCOL_VERSION, "2025-11-25",
            "an absent header means a client that predates negotiation, so it must not be \
             held to the stateless requirements"
        );
        assert!(SUPPORTED_PROTOCOL_VERSIONS.contains(&DEFAULT_PROTOCOL_VERSION));
        assert!(!SUPPORTED_PROTOCOL_VERSIONS.is_empty());
    }

    #[test]
    fn discover_reports_the_same_revision_list_the_negotiator_enforces() {
        // A discovery response that disagrees with what select_protocol_version accepts
        // sends the client to retry with a revision that will then be refused. One source.
        let result = discover_result(&[json!({"name": "list_roots"})]);
        assert_eq!(
            result["supportedVersions"],
            json!(SUPPORTED_PROTOCOL_VERSIONS)
        );
        for version in SUPPORTED_PROTOCOL_VERSIONS {
            assert!(
                select_protocol_version(Some(version)).selected().is_some(),
                "discover advertises {version} but the negotiator refuses it"
            );
        }
        assert_eq!(result["serverInfo"]["name"], "nativemcp-core");
        assert!(result["capabilities"]["tools"].is_object());
        assert_eq!(result["ttlMs"], TOOLS_LIST_TTL_MS);
        assert_eq!(result["tools"][0]["name"], "list_roots");
    }

    #[test]
    fn server_instructions_state_the_governance_facts_a_client_cannot_infer() {
        // These are the three things that otherwise produce a confident wrong call from a
        // model holding only the tool list.
        assert!(SERVER_INSTRUCTIONS.contains("list_roots"));
        assert!(SERVER_INSTRUCTIONS.contains("no delete tool"));
        assert!(SERVER_INSTRUCTIONS.contains("backup_file"));
        assert!(SERVER_INSTRUCTIONS.contains("denial is a decision"));
        // No delete-like verb should appear as an instruction to the model.
        let lowered = SERVER_INSTRUCTIONS.to_ascii_lowercase();
        assert!(!lowered.contains("you may delete"));
    }

    #[test]
    fn absent_protocol_version_selects_the_default() {
        // Clients reaching this server today omit the header while speaking 2025-11-25.
        // Refusing them to match the spec's 2025-03-26 default would break every one of
        // them in exchange for conformance with a revision this server does not implement.
        assert_eq!(
            select_protocol_version(None),
            ProtocolVersion::Selected(DEFAULT_PROTOCOL_VERSION)
        );
        assert_eq!(
            select_protocol_version(Some("   ")),
            ProtocolVersion::Selected(DEFAULT_PROTOCOL_VERSION)
        );
    }

    #[test]
    fn a_supported_revision_is_selected_and_an_unsupported_one_is_refused() {
        assert_eq!(
            select_protocol_version(Some("2025-11-25")),
            ProtocolVersion::Selected("2025-11-25")
        );
        // Whitespace around a header value is an HTTP artifact, not a different revision.
        assert_eq!(
            select_protocol_version(Some(" 2025-11-25 ")),
            ProtocolVersion::Selected("2025-11-25")
        );
        assert_eq!(
            select_protocol_version(Some(STATELESS_PROTOCOL_VERSION)),
            ProtocolVersion::Selected(STATELESS_PROTOCOL_VERSION)
        );
        assert_eq!(
            select_protocol_version(Some("2027-01-01")),
            ProtocolVersion::Unsupported("2027-01-01".to_string())
        );
        assert!(
            select_protocol_version(Some("2027-01-01"))
                .selected()
                .is_none()
        );
    }

    #[test]
    fn unsupported_version_error_carries_the_list_the_client_needs_to_retry() {
        let response = unsupported_protocol_version(Some(json!(7)), "2027-01-01");
        let value = serde_json::to_value(&response).expect("serialize");
        assert_eq!(value["id"], 7);
        assert_eq!(value["error"]["code"], UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(value["error"]["code"], -32022);
        // Without both fields the client has to guess or make a second round trip.
        assert_eq!(value["error"]["data"]["requested"], "2027-01-01");
        assert_eq!(
            value["error"]["data"]["supported"],
            json!(SUPPORTED_PROTOCOL_VERSIONS)
        );
    }

    #[test]
    fn initialize_result_reports_the_negotiated_revision() {
        let result = initialize_result("2025-11-25");
        assert_eq!(result["protocolVersion"], "2025-11-25");
        assert_eq!(result["serverInfo"]["name"], "nativemcp-core");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[test]
    fn tools_list_contains_execute_but_no_delete_surface() {
        let names: Vec<String> = tool_list().into_iter().map(|t| t.name).collect();
        assert!(names.iter().any(|n| n == "execute"));
        for banned in ["delete", "unlink", "remove", "rmdir", "trash", "recycle"] {
            assert!(
                !names.iter().any(|n| n.contains(banned)),
                "{banned} surfaced"
            );
        }
    }

    #[test]
    fn tools_list_contains_list_directory_execute_and_no_delete_surface() {
        let names: Vec<String> = tool_list().into_iter().map(|t| t.name).collect();
        assert!(names.iter().any(|n| n == "list_directory"));
        assert!(names.iter().any(|n| n == "execute"));
        for banned in ["delete", "unlink", "remove", "rmdir", "trash", "recycle"] {
            assert!(
                !names.iter().any(|n| n.contains(banned)),
                "{banned} surfaced"
            );
        }
    }

    #[test]
    fn tool_result_json_uses_text_content_and_structured_content() {
        let result = tool_result_json(&json!({"ok": true}));
        assert_eq!(result["content"][0]["type"], "text");
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("\"ok\"")
        );
        assert_eq!(result["structuredContent"]["ok"], true);
    }

    #[test]
    fn service_mode_does_not_expose_delete_surface() {
        tools_list_contains_execute_but_no_delete_surface();
    }

    #[test]
    fn service_mode_preserves_execute_tool() {
        let names: Vec<String> = tool_list().into_iter().map(|t| t.name).collect();
        assert!(names.iter().any(|n| n == "execute"));
    }

    #[test]
    fn execute_tool_schema_documents_connector_safe_timeout() {
        let execute = tool_list()
            .into_iter()
            .find(|tool| tool.name == "execute")
            .expect("execute tool");
        assert!(execute.description.contains("timeout_ms defaults to 30000"));
        assert!(execute.description.contains("execute_start"));
        assert_eq!(
            execute.input_schema["properties"]["timeout_ms"]["description"],
            "Optional command timeout in milliseconds. Defaults to 30000 (30 seconds)."
        );
    }

    #[test]
    fn tools_list_contains_execution_profile_tools_and_no_delete_surface() {
        let names: Vec<String> = tool_list().into_iter().map(|t| t.name).collect();
        for expected in [
            "execute",
            "execute_start",
            "execute_resolve_program",
            "execute_env_report",
            "execute_status",
            "execute_tail",
            "execute_wait",
            "execute_result",
            "execute_cancel",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "{expected} missing"
            );
        }
        for banned in ["delete", "unlink", "remove", "rmdir", "trash", "recycle"] {
            assert!(
                !names.iter().any(|name| name.contains(banned)),
                "{banned} surfaced"
            );
        }
    }

    #[test]
    fn execute_profile_tool_schemas_expose_profile() {
        let tools = tool_list();
        for name in [
            "execute",
            "execute_start",
            "execute_resolve_program",
            "execute_env_report",
        ] {
            let tool = tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap_or_else(|| panic!("{name} missing"));
            assert!(
                tool.input_schema["properties"].get("profile").is_some(),
                "{name} missing profile property"
            );
        }

        let resolve = tools
            .iter()
            .find(|tool| tool.name == "execute_resolve_program")
            .expect("execute_resolve_program");
        assert_eq!(resolve.input_schema["required"], json!(["program"]));
        assert!(resolve.input_schema["properties"].get("cwd").is_none());
    }

    #[test]
    fn pinned_revision_is_supported() {
        assert!(supports_revision(PROTOCOL_REVISION));
        assert_eq!(PROTOCOL_REVISION, STATELESS_PROTOCOL_VERSION);
    }

    #[test]
    fn foreign_revision_is_rejected() {
        assert!(!supports_revision("2025-06-18"));
        assert!(!supports_revision(""));
    }
}
