//! Model Context Platform - tool router and middleware ring.
//!
//! ## Architecture
//!
//! ```text
//! MCP client request
//!   - Router::dispatch()
//!       - PolicyRing::check()      (deny before provider is called)
//!       - provider.call()
//!       - AuditRing::record()      (record result + is_error)
//!       - DeleteGuard::assert()    (unconditional, never bypassed)
//!   - ToolCallResult - JSON-RPC response
//! ```
//!
//! Providers implement [`ToolProvider`] and register with [`Router`].
//! The ring applies identically to local and proxied (gateway) calls.

use async_trait::async_trait;
use nmcp_audit::{AuditEvent, AuditSink};
use nmcp_memory::MemoryScope;
use nmcp_policy::{Permission, PolicyConfig, RootRule};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;

// - CallContext -

/// Immutable context threaded through every tool call in the ring.
/// Constructed by the router before entering the middleware ring.
/// Providers receive it read-only - they must not modify it.
#[derive(Debug, Clone)]
pub struct CallContext {
    /// Unique ID for this tool invocation. Written to every audit event.
    pub call_id: Uuid,
    /// MCP session this call arrived on. `None` for calls from tests/CLI.
    pub session_id: Option<String>,
    /// Agent-supplied identity, if the transport provided one.
    pub agent_id: Option<String>,
    /// Policy root matched to the primary path argument of this call.
    /// `None` for tools that don't operate on a filesystem path.
    pub matched_root: Option<RootRule>,
    /// For proxied (gateway) calls: the upstream ID this will be forwarded to.
    /// `None` for local providers.
    pub upstream_id: Option<String>,
    /// Memory scope for this call - defaults to matched root ID, falls back to session.
    pub memory_scope: MemoryScope,
    /// Gateway profile this session is scoped to, if any (G6-8).
    ///
    /// `None` means the session is not scoped and reaches whatever the machine-wide profile
    /// leaves running, which is what every call did before sessions had profiles.
    pub profile: Option<String>,
    /// Where the call arrived from, ALREADY REDACTED (G3-15, AF-5).
    ///
    /// A `String` rather than a richer type because mcp-router must not depend on mcp-server,
    /// and because a field that can only hold the redacted form is the point: the truncation
    /// happens at the transport boundary, so a full address cannot reach this struct rather
    /// than being trusted not to. `loopback` for a loopback caller.
    ///
    /// `None` for every caller with no transport, which is the CLI and every test path.
    pub peer: Option<String>,
    /// Which credential path authenticated this caller (G3-15, AF-7).
    ///
    /// `static` or `oauth`. A `&'static str` from a closed set, so it cannot carry
    /// caller-supplied bytes. Without it an OAuth subject mapped to `agent_id: chatgpt` and a
    /// static credential using the same `agent_id` produce byte-identical audit records, and
    /// an operator asking whether a destructive call came from the console or from the
    /// internet cannot answer it from the chain.
    pub credential_path: Option<&'static str>,
    /// What the client said it was, when the revision carries it (G5-9).
    ///
    /// Recorded, never read. Nothing in the ring branches on this, because it is
    /// transport-supplied text and SEP-2243 forbids treating that as trusted input for a
    /// security-sensitive decision. `agent_id` remains the only identity ABAC authorizes on.
    pub client_info: Option<String>,
}

impl CallContext {
    #[must_use]
    /// `new`.
    pub fn new(session_id: Option<String>) -> Self {
        Self::with_agent(session_id, None)
    }

    /// `with_agent`.
    pub fn with_agent(session_id: Option<String>, agent_id: Option<String>) -> Self {
        let scope = session_id
            .as_deref()
            .map_or_else(|| MemoryScope::named("default"), MemoryScope::session);
        Self {
            call_id: Uuid::new_v4(),
            session_id,
            agent_id,
            matched_root: None,
            upstream_id: None,
            memory_scope: scope,
            profile: None,
            client_info: None,
            peer: None,
            credential_path: None,
        }
    }

    /// Scope this call to a gateway profile.
    #[must_use]
    pub fn with_profile(mut self, profile: Option<String>) -> Self {
        self.profile = profile;
        self
    }

    /// Attach what the client said it was, for the audit record.
    #[must_use]
    pub fn with_client_info(mut self, client_info: Option<String>) -> Self {
        self.client_info = client_info;
        self
    }

    /// Attach where the call arrived from and which credential admitted it (G3-15, AF-7).
    ///
    /// `peer` must already be redacted. See the field doc.
    #[must_use]
    pub fn with_provenance(
        mut self,
        peer: Option<String>,
        credential_path: Option<&'static str>,
    ) -> Self {
        self.peer = peer;
        self.credential_path = credential_path;
        self
    }

    /// Resolve the memory scope from the matched root, falling back to session.
    #[must_use]
    pub fn with_root(mut self, root: Option<RootRule>) -> Self {
        if let Some(ref r) = root {
            self.memory_scope = MemoryScope::root(&r.id);
        }
        self.matched_root = root;
        self
    }
}

// - ToolCallResult -

/// The result of a single tool call, as returned by a [`ToolProvider`].
/// The ring uses `audit_payload` to build the `AuditEvent`; providers fill it
/// with tool-specific detail (path, command, upstream, etc.).
#[derive(Debug, Clone)]
pub struct ToolCallResult {
    /// MCP content array to return to the caller.
    pub content: Vec<Value>,
    /// True if this result represents an error condition.
    pub is_error: bool,
    /// Structured audit payload. Provider fills this; ring records it.
    /// If `None`, the ring records the tool name and `call_id` only.
    pub audit_payload: Option<Value>,
    /// Preserved `structuredContent` from `tool_result_json`, if the provider
    /// produced one. Threaded through so the MCP response retains the field.
    pub structured_content: Option<Value>,
}

impl ToolCallResult {
    #[must_use]
    /// `ok`.
    // The constructors take owned values: a caller builds a result and hands
    // it over, matching the JSON it becomes on the wire.
    #[allow(clippy::needless_pass_by_value)]
    pub fn ok(content: Value) -> Self {
        Self {
            content: vec![json!({"type": "text", "text": content.to_string()})],
            is_error: false,
            audit_payload: None,
            structured_content: None,
        }
    }

    /// Construct from a pre-built `tool_result_json` value, preserving
    /// `content` and `structuredContent` fields as-is.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_tool_result_json(v: Value, audit: Value) -> Self {
        let content = v.get("content").cloned().unwrap_or(json!([]));
        let structured = v.get("structuredContent").cloned();
        let content_arr = if let Value::Array(arr) = content {
            arr
        } else {
            vec![]
        };
        Self {
            content: content_arr,
            is_error: false,
            audit_payload: Some(audit),
            structured_content: structured,
        }
    }

    /// `err`.
    pub fn err(message: impl Into<String>) -> Self {
        Self::err_with_metadata(message, "runtime_error", None)
    }

    /// `err_with_metadata`.
    pub fn err_with_metadata(
        message: impl Into<String>,
        error_kind: impl Into<String>,
        remediation: Option<&str>,
    ) -> Self {
        let msg = message.into();
        let kind = error_kind.into();
        let structured = json!({
            "ok": false,
            "error_kind": kind,
            "message": msg,
            "remediation": remediation,
        });
        Self {
            content: vec![json!({"type": "text", "text": msg.clone()})],
            is_error: true,
            audit_payload: Some(structured.clone()),
            structured_content: Some(structured),
        }
    }

    /// Convert to the JSON-RPC response value expected by `dispatch_tool`.
    #[must_use]
    pub fn into_dispatch_json(self) -> Value {
        let mut v = json!({
            "content": self.content,
            "isError": self.is_error
        });
        if let Some(sc) = self.structured_content
            && let Some(object) = v.as_object_mut()
        {
            // Insert rather than index: serde_json's IndexMut panics on a
            // non-object, and the workspace denies indexing. `v` is the object
            // literal above, so this branch always takes; writing it this way
            // makes that provable instead of assumed.
            object.insert("structuredContent".into(), sc);
        }
        v
    }
}

/// The public tool name derivation and its validator, re-exported from `nmcp-schema`.
///
/// Both moved there under NMCP-SPEC-003 RC-D6, because the registry that owns the
/// local-to-public mapping lives in the contract crate and a name derived in two places is
/// the defect that spec's section 1 measures. Behaviour is unchanged, which is what
/// `public_tool_names_are_claude_safe` below asserts on the same table it always did.
pub use nmcp_schema::{is_valid_public_tool_name, public_tool_name};

// - ToolProvider -

/// The single interface every tool provider implements.
///
/// Providers **must not** perform policy checks or audit writes - those happen
/// in the middleware ring before and after `call()`. Providers also must not
/// call other tools directly; cross-tool composition belongs at the router level.
#[async_trait]
pub trait ToolProvider: Send + Sync {
    /// Stable, unique prefix for this provider's tools.
    /// Local providers use `""` (no prefix). Upstream providers use their ID
    /// so tool names become `upstream_id::tool_name`.
    fn provider_id(&self) -> &str;

    /// Tool names owned by this provider (without prefix).
    fn tool_names(&self) -> Vec<String>;

    /// MCP-formatted tool list entries (the `tools` array element schema).
    fn tool_list(&self) -> Vec<Value>;

    /// Execute a single tool call. The provider receives args and context only.
    /// Policy and audit are already handled by the ring.
    async fn call(&self, name: &str, args: Value, ctx: &CallContext) -> ToolCallResult;
}

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

/// Synchronous pre-call check. Implement in `mcp-abac`; inject via `Router::set_abac`.
///
/// `evaluate` is sync so it does not introduce async complexity at the ring boundary.
/// The HITL async wait happens in `mcp-abac::AbacStage::register_hitl`, called by the
/// router after this method returns `RequireApproval`.
pub trait AbacCheck: Send + Sync {
    /// Evaluate ABAC rules for a pending call.
    /// Called after base policy check, before provider call.
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

const DELETE_DENIED_NAMES: &[&str] = &[
    "delete",
    "delete_file",
    "remove",
    "remove_root",
    "uninstall",
    "drop",
    "drop_table",
    "destroy",
    "purge",
    "wipe",
    "truncate",
    "rm",
];
fn contains_delete_intent(tool_name: &str) -> bool {
    let lower = tool_name.to_ascii_lowercase();
    DELETE_DENIED_NAMES.iter().any(|d| lower == *d)
}

/// Unconditional last stage of the ring. Panics in debug builds; returns a
/// governed error in release. Applied to every call - local, proxied, OS, memory.
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

// - PolicyRing -

#[derive(Debug, Clone, Copy)]
struct ToolPolicySpec {
    permission: Permission,
    path_args: &'static [&'static str],
    require_windows_api: bool,
}

const PATH_ARG_PATH: &[&str] = &["path"];
const PATH_ARG_FROM: &[&str] = &["from"];
const PATH_ARG_CWD: &[&str] = &["cwd"];
const PATH_ARG_REPO: &[&str] = &["repo", "repo_path", "repository", "repository_path", "path"];
const PATH_ARG_PROGRAM: &[&str] = &["program"];
const PATH_ARG_DEV: &[&str] = &["path", "repo", "repo_path", "cwd"];

fn tool_policy_spec(tool_name: &str) -> Option<ToolPolicySpec> {
    let n = tool_name.replace('.', "_");
    let spec = match n.as_str() {
        "execute" | "execute_start" => ToolPolicySpec {
            permission: Permission::Execute,
            path_args: PATH_ARG_CWD,
            require_windows_api: false,
        },
        "execute_resolve_program" => ToolPolicySpec {
            permission: Permission::Execute,
            path_args: PATH_ARG_PROGRAM,
            require_windows_api: false,
        },
        "read_text_file"
        | "fs_read_text_file"
        | "read_file_window_report"
        | "inspect_file_integrity" => ToolPolicySpec {
            permission: Permission::Read,
            path_args: PATH_ARG_PATH,
            require_windows_api: false,
        },
        "create_text_file" => ToolPolicySpec {
            permission: Permission::Create,
            path_args: PATH_ARG_PATH,
            require_windows_api: false,
        },
        "write_text_file" | "patch_text_file" | "fs_write_text_file" | "fs_patch_text_file" => {
            ToolPolicySpec {
                permission: Permission::Write,
                path_args: PATH_ARG_PATH,
                require_windows_api: false,
            }
        }
        "list_directory" | "fs_list_directory" => ToolPolicySpec {
            permission: Permission::List,
            path_args: PATH_ARG_PATH,
            require_windows_api: false,
        },
        "rename" | "fs_rename" | "rename_file" => ToolPolicySpec {
            permission: Permission::Rename,
            path_args: PATH_ARG_FROM,
            require_windows_api: false,
        },
        "move" | "fs_move" | "move_file" => ToolPolicySpec {
            permission: Permission::Move,
            path_args: PATH_ARG_FROM,
            require_windows_api: false,
        },
        "backup" | "fs_backup" | "backup_file" => ToolPolicySpec {
            permission: Permission::Backup,
            path_args: PATH_ARG_PATH,
            require_windows_api: false,
        },
        "search_repo" | "scan_repo" | "dev_search_repo" | "dev_scan_repo" => ToolPolicySpec {
            permission: Permission::Search,
            path_args: PATH_ARG_DEV,
            require_windows_api: false,
        },
        "git_status" | "git_diff" | "git_log" | "dev_git_status" | "dev_git_diff"
        | "dev_git_log" | "git_blame" | "dev_git_blame" | "git_stash_list"
        | "dev_git_stash_list" => ToolPolicySpec {
            permission: Permission::Read,
            path_args: PATH_ARG_REPO,
            require_windows_api: false,
        },
        "git_publish" | "dev_git_publish" => ToolPolicySpec {
            permission: Permission::GitPublish,
            path_args: PATH_ARG_REPO,
            require_windows_api: false,
        },
        "test_run" | "dev_test_run" | "dep_graph" | "dev_dep_graph" => ToolPolicySpec {
            permission: Permission::Execute,
            path_args: PATH_ARG_DEV,
            require_windows_api: false,
        },
        "win_registry_read" | "win_registry_write" | "win_eventlog_query"
        | "win_services_query" | "win_wmi_query" => ToolPolicySpec {
            permission: Permission::Read,
            path_args: &[],
            require_windows_api: true,
        },
        _ => return None,
    };
    Some(spec)
}

fn path_arg<'a>(args: &'a Value, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| args.get(*name).and_then(Value::as_str))
}

fn has_windows_api_grant(policy: &PolicyConfig) -> bool {
    policy
        .roots
        .iter()
        .any(|root| root.permissions.contains(&Permission::WindowsApi))
}

fn has_windows_api_write_grant(policy: &PolicyConfig) -> bool {
    policy
        .roots
        .iter()
        .any(|root| root.permissions.contains(&Permission::WindowsApiWrite))
}

/// Whether a tool mutates state (used by the `auto_approve` global gate).
fn tool_is_mutating(tool_name: &str) -> bool {
    let n = tool_name.replace('.', "_");
    if n == "win_registry_write" {
        return true;
    }
    match tool_policy_spec(tool_name) {
        Some(spec) => matches!(
            spec.permission,
            Permission::Write
                | Permission::Create
                | Permission::Modify
                | Permission::Move
                | Permission::Rename
                | Permission::Backup
                | Permission::Execute
                | Permission::GitPublish
        ),
        // A first-party tool with no spec, such as list_roots or scan_repo, reads or reports
        // and does not mutate. A tool from an admitted upstream also has no spec and is a
        // different question entirely, but this function only sees a name. The third-party
        // rule lives in `dispatch`, which has resolved the provider and can tell them apart
        // (M6).
        None => false,
    }
}

fn policy_check(policy: &PolicyConfig, tool_name: &str, args: &Value) -> Option<ToolCallResult> {
    // Registry writes require a dedicated capability beyond win.api, so a
    // read + win.api grant cannot escalate to arbitrary HKLM writes.
    if tool_name.replace('.', "_") == "win_registry_write" {
        if !has_windows_api_grant(policy) {
            warn!(tool = tool_name, "PolicyRing: denied missing win.api grant");
            return Some(ToolCallResult::err_with_metadata(
                "Policy denied: win.api permission is required for Windows API tools".to_string(),
                "policy_denied",
                Some("Grant win.api only on a policy root approved for Windows API operations."),
            ));
        }
        if !has_windows_api_write_grant(policy) {
            warn!(
                tool = tool_name,
                "PolicyRing: denied missing win.api.write grant"
            );
            return Some(ToolCallResult::err_with_metadata(
                "Policy denied: win.api.write permission is required to modify the Windows registry".to_string(),
                "policy_denied",
                Some("Grant win.api.write only on a policy root approved for registry writes."),
            ));
        }
        return None;
    }
    let spec = tool_policy_spec(tool_name)?;
    if spec.require_windows_api && !has_windows_api_grant(policy) {
        warn!(tool = tool_name, "PolicyRing: denied missing win.api grant");
        return Some(ToolCallResult::err_with_metadata(
            "Policy denied: win.api permission is required for Windows API tools".to_string(),
            "policy_denied",
            Some("Grant win.api only on a policy root approved for Windows API operations."),
        ));
    }
    if spec.path_args.is_empty() {
        return None;
    }
    let Some(path) = path_arg(args, spec.path_args) else {
        return Some(ToolCallResult::err_with_metadata(
            format!("Policy denied: missing required path argument for {tool_name}"),
            "policy_denied",
            Some("Provide the required governed path argument for this tool."),
        ));
    };
    if let Err(e) = policy.require(spec.permission, path) {
        warn!(tool = tool_name, path, "PolicyRing: denied - {e}");
        let remediation = match spec.permission {
            Permission::GitPublish => {
                "Grant the explicit git.publish permission on the repository root only after outbound git publishing is approved."
            }
            _ => {
                "Adjust the NativeMCP policy root permissions or use a path inside an approved root."
            }
        };
        return Some(ToolCallResult::err_with_metadata(
            format!("Policy denied: {e}"),
            "policy_denied",
            Some(remediation),
        ));
    }
    None
}

fn matched_root_for_call(policy: &PolicyConfig, tool_name: &str, args: &Value) -> Option<RootRule> {
    let spec = tool_policy_spec(tool_name)?;
    let path = path_arg(args, spec.path_args)?;
    let decision = policy.require(spec.permission, path).ok()?;
    let root_id = decision.root_id?;
    policy.roots.iter().find(|r| r.id == root_id).cloned()
}
/// Write the authorization record for a completed or denied call.
///
/// One of the two records a governed call produces (ADR-0005). This is the one carrying the
/// verdict, the duration and the caller. It does not carry the content hashes, because the ring
/// never sees the bytes; the effect record written where the effect happened does.
///
/// `started` is the top of `dispatch`, not the provider call, so the recorded duration is
/// what the client actually waited: delete guard, policy ring, ABAC, any human approval
/// wait, and the provider. A policy denial that took three seconds is then as visible as a
/// slow provider, and an operator sitting on approvals shows up in the latency history
/// rather than hiding behind a fast provider.
fn audit_record(
    sink: &AuditSink,
    tool_name: &str,
    ctx: &CallContext,
    result: &ToolCallResult,
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
    // M4-1. The capability the ring required, taken from the tool's policy spec rather than
    // from anything the caller sent, so the Event Log mirror can give a read and an execution
    // different Event IDs and a SIEM rule can tell them apart without parsing a body. Absent
    // for a tool with no spec, which is every upstream tool, because the permission an
    // upstream call requires is declared on the upstream and not per tool.
    event.permission = tool_policy_spec(tool_name).map(|spec| spec.permission.as_str().to_string());

    if let Some(ref root) = ctx.matched_root {
        event.normalized_path = Some(root.path.display().to_string());
    }
    event.agent_id.clone_from(&ctx.agent_id);
    event.client_info.clone_from(&ctx.client_info);
    // The half of G4-26 nobody had noticed was missing. `AuditEvent::call_id` and
    // `CallContext::call_id` have both existed for a long time and were never connected, so
    // every authorization record ever written carries none. Without this the effect side has
    // nothing to join to.
    event.call_id = Some(ctx.call_id);
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
/// Register providers with [`Router::register`]. The router merges their tool
/// catalogs, resolves tool names (with upstream namespacing), and dispatches
/// calls through the middleware ring.
pub struct Router {
    providers: Arc<parking_lot::RwLock<Vec<Arc<dyn ToolProvider>>>>,
    policy: Arc<parking_lot::RwLock<PolicyConfig>>,
    audit: AuditSink,
    abac: Option<Arc<dyn AbacCheck>>,
}

impl Router {
    /// `new`.
    pub fn new(policy: Arc<parking_lot::RwLock<PolicyConfig>>, audit: AuditSink) -> Self {
        Self {
            providers: Arc::new(parking_lot::RwLock::new(Vec::new())),
            policy,
            audit,
            abac: None,
        }
    }

    /// Register a tool provider. Tool names must be unique across all providers
    /// (upstream providers are namespaced automatically via `provider_id`).
    /// Safe to call on a `SharedRouter` at runtime - takes a write lock.
    #[must_use]
    pub fn unregister_provider(&self, provider_id: &str) -> bool {
        let mut providers = self.providers.write();
        let before = providers.len();
        providers.retain(|provider| provider.provider_id() != provider_id);
        providers.len() != before
    }
    /// `register`.
    pub fn register(&self, provider: Arc<dyn ToolProvider>) {
        info!(
            provider = provider.provider_id(),
            "Router: registered provider"
        );
        self.providers.write().push(provider);
    }

    /// Inject an ABAC stage into the router. Must be called before the Arc is shared.
    /// The stage runs after base policy check, before provider call - on the single dispatch path.
    pub fn set_abac(&mut self, stage: Arc<dyn AbacCheck>) {
        self.abac = Some(stage);
    }

    /// Merged, Claude-safe tool list for `tools/list` responses.
    /// NOT FOR A REQUEST PATH (G6-11).
    ///
    /// This is every tool of every registered provider, ignoring gateway profiles, and it
    /// exists for the callers that legitimately have no session to scope to: readiness,
    /// doctor, and the no-delete sweep, which are asking about this process rather than about
    /// a caller. Answering a request with it hands a scoped session the full upstream and
    /// tool inventory the profile exists to hide.
    ///
    /// Every method that answers a caller must call [`Router::merged_tool_list_for`] with that
    /// session's profile. `every_request_lane_scopes_its_tool_list_to_the_session_profile` in
    /// `mcp-server` reads the request lanes out of the source and fails on any call to this
    /// one, because the defect it was written for was a single method out of four.
    #[must_use]
    pub fn merged_tool_list(&self) -> Vec<Value> {
        self.merged_tool_list_for(None)
    }

    /// The same list, scoped to one session's gateway profile (G6-8).
    ///
    /// The filter here and the check in `dispatch` both go through
    /// `PolicyConfig::provider_visible_to_session`, which is the point: a session that can
    /// see a tool it cannot call, or call one it cannot see, is worse than either restriction
    /// on its own, and two copies of the rule is how that happens.
    #[must_use]
    pub fn merged_tool_list_for(&self, profile: Option<&str>) -> Vec<Value> {
        let policy = self.policy.read();
        self.providers
            .read()
            .iter()
            .filter(|p| policy.provider_visible_to_session(profile, p.provider_id()))
            .flat_map(|p| {
                let provider_id = p.provider_id().to_string();
                p.tool_list().into_iter().map(move |mut tool| {
                    if let Some(name) = tool.get("name").and_then(Value::as_str) {
                        let safe_name = public_tool_name(&provider_id, name);
                        debug_assert!(is_valid_public_tool_name(&safe_name));
                        // Insert rather than index, for the reason in
                        // `into_dispatch_json`: a provider could hand back a
                        // non-object and indexing would panic in the dispatch
                        // path. A non-object simply carries no rewrite.
                        if let Some(object) = tool.as_object_mut() {
                            object.insert("name".into(), json!(safe_name));
                        }
                        // Annotate first-party tools only. A proxied upstream is somebody
                        // else's software: this server can vouch for what its own tools do
                        // and cannot vouch for theirs, so an upstream keeps whatever
                        // annotations it published and gets none invented for it.
                        if provider_id.is_empty() && tool.get("annotations").is_none() {
                            // Classify on the PUBLIC name, not the provider's internal one.
                            // public_tool_name sanitizes separators, so a provider tool such
                            // as dev.git_log is advertised as dev_git_log. Keying on the
                            // internal name silently missed every prefixed tool and let it
                            // fall through to not-read-only and not-open-world.
                            if let Some(object) = tool.as_object_mut() {
                                object.insert(
                                    "annotations".into(),
                                    nmcp_proto::tool_annotations(&safe_name),
                                );
                            }
                        }
                    }
                    tool
                })
            })
            .collect()
    }

    /// Dispatch a tool call through the full middleware ring.
    // The governed call pipeline: resolve, policy, profile scope, ABAC,
    // approval, provider, audit. Every stage is ordered with respect to the
    // others and the ordering IS the governance; splitting it into helpers
    // would scatter one decision procedure and invite a stage being skipped.
    #[allow(clippy::too_many_lines)]
    pub async fn dispatch(&self, tool_name: &str, args: Value, ctx: CallContext) -> ToolCallResult {
        // Every exit from this function audits, and every audit records how long the client
        // waited to reach it.
        let started = Instant::now();

        // - Stage 0: DeleteGuard (pre-call, before provider is even found) -
        if let Some(denied) = delete_guard_check(tool_name) {
            audit_record(&self.audit, tool_name, &ctx, &denied, started);
            return denied;
        }

        // - Resolve provider and local name -
        let Some((provider, local_name)) = self.resolve(tool_name) else {
            let result = ToolCallResult::err_with_metadata(
                format!("Unknown tool: {tool_name}"),
                "command_not_found",
                Some("Call tools/list and retry with a registered tool name."),
            );
            audit_record(&self.audit, tool_name, &ctx, &result, started);
            return result;
        };

        let policy = self.policy.read().clone();

        // - Stage 0.5: session profile scope (G6-8) -
        //
        // Before PolicyRing because it is a visibility question rather than a permission one:
        // if this session cannot reach the server at all, nothing about the tool's own policy
        // matters. Here rather than at the transport edge because the public tool name is
        // lossy and not invertible, so the only reliable way to know which upstream a call
        // lands on is to have resolved the provider, which has just happened above.
        if !policy.provider_visible_to_session(ctx.profile.as_deref(), provider.provider_id()) {
            let denied = ToolCallResult::err_with_metadata(
                format!("Tool '{tool_name}' is not in this session's gateway profile"),
                "policy_denied",
                Some(
                    "Call tools/list to see what this session can reach, or connect with a client bound to a profile that includes this server.",
                ),
            );
            audit_record(&self.audit, tool_name, &ctx, &denied, started);
            return denied;
        }

        // - Stage 0.7: upstream admission (G4-28) -
        //
        // The ring cannot govern what an admitted upstream does. A stdio or container upstream
        // is a child process of the daemon, an HTTP one is somebody else's server, and neither
        // goes through mcp-fs, so no root permission constrains it. What the ring can govern is
        // whether its tools are reachable, and that is what this asks.
        //
        // Here rather than in PolicyRing because PolicyRing answers a path question from a
        // compiled-in table of first-party tool names, which an upstream's tools are not in and
        // cannot be: this server has never seen the name and does not know whether it takes a
        // path. Before PolicyRing for the same reason the profile check is: if the caller may
        // not reach this upstream at all, nothing about an individual tool matters.
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
                audit_record(&self.audit, tool_name, &ctx, &denied, started);
                return denied;
            }
        }

        // - Stage 1: PolicyRing -
        if let Some(denied) = policy_check(&policy, &local_name, &args) {
            audit_record(&self.audit, tool_name, &ctx, &denied, started);
            return denied;
        }

        // Enrich context with the same canonical policy decision used for authorization.
        let ctx = ctx.with_root(matched_root_for_call(&policy, &local_name, &args));

        // - Stage 1.5: ABAC -
        // Runs after base policy, before provider. Cannot be bypassed.
        // Global auto-approve gate: when auto_approve is disabled, mutating tools
        // require HITL approval even without a matching ABAC rule. Default
        // auto_approve=true leaves this inert (no behavior change).
        // A tool from an admitted upstream has no compiled-in policy spec and cannot have
        // one, so `tool_is_mutating` reads it as harmless for want of anything to consult.
        // That put the tool this server knows least about on the trusting side of the gate.
        // An operator who turned auto_approve off asked for mutating calls to be approved;
        // for a third-party tool the honest answer to "does this mutate" is that nobody here
        // knows, and unknown belongs on the gated side (M6).
        //
        // Keyed off the resolved provider rather than the tool name, because the name is the
        // thing that carries no information here. Inert while auto_approve is true, which is
        // the default and what the live policy runs.
        let third_party = !provider.provider_id().is_empty();
        let mut require_approval =
            !policy.auto_approve && (tool_is_mutating(&local_name) || third_party);
        if let Some(ref abac) = self.abac {
            match abac.evaluate(&ctx, tool_name, &args) {
                AbacDecision::Deny(reason) => {
                    let denied = ToolCallResult::err_with_metadata(
                        format!("ABAC denied: {reason}"),
                        "policy_denied",
                        Some(
                            "Review ABAC policy constraints or request approval through the configured workflow.",
                        ),
                    );
                    audit_record(&self.audit, tool_name, &ctx, &denied, started);
                    return denied;
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
            let Some(abac) = self.abac.as_ref() else {
                let denied = ToolCallResult::err_with_metadata(
                    "Approval required (auto_approve is disabled) but no approval workflow is configured".to_string(),
                    "policy_denied",
                    Some("Enable auto_approve or configure an ABAC approval workflow before invoking mutating tools."),
                );
                audit_record(&self.audit, tool_name, &ctx, &denied, started);
                return denied;
            };
            // Block until human approves or timeout fires (fail closed).
            let approved = abac.wait_for_approval(&ctx, tool_name, &args).await;
            if !approved {
                let denied = ToolCallResult::err_with_metadata(
                    "Approval denied: call rejected by operator or timed out".to_string(),
                    "approval_denied",
                    Some("Retry only after operator approval or adjust the HITL policy."),
                );
                audit_record(&self.audit, tool_name, &ctx, &denied, started);
                return denied;
            }
        }

        // - Stage 2: Provider call -
        let result = provider.call(&local_name, args, &ctx).await;

        // - Stage 3: AuditRing -
        audit_record(&self.audit, tool_name, &ctx, &result, started);

        result
    }

    fn resolve(&self, tool_name: &str) -> Option<(Arc<dyn ToolProvider>, String)> {
        let providers = self.providers.read();
        for provider in providers.iter() {
            let provider_id = provider.provider_id();
            for local in provider.tool_names() {
                if provider_id.is_empty() && local == tool_name {
                    return Some((provider.clone(), local));
                }
                if public_tool_name(provider_id, &local) == tool_name {
                    return Some((provider.clone(), local));
                }
                if !provider_id.is_empty() {
                    let legacy = format!("{provider_id}::{local}");
                    if legacy == tool_name {
                        return Some((provider.clone(), local));
                    }
                }
            }
        }
        None
    }
}

// - Shared handle -

/// Clone-cheap handle to the router.
/// `register()` uses an internal `RwLock` so providers can be added at runtime
/// without restarting the daemon.
pub type SharedRouter = Arc<Router>;

/// `make_router`.
pub fn make_router(
    policy: Arc<parking_lot::RwLock<PolicyConfig>>,
    audit: AuditSink,
) -> SharedRouter {
    Arc::new(Router::new(policy, audit))
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
    use super::*;
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

    /// M4-1. The permission on the record is the one the policy spec declares for the tool,
    /// taken from the spec rather than from anything the caller sent.
    #[test]
    fn the_authorization_record_names_the_capability_the_ring_required() {
        let spec = tool_policy_spec("write_text_file").expect("write_text_file has a spec");
        assert_eq!(spec.permission.as_str(), "write");
        assert_eq!(
            nmcp_policy::Permission::Execute.as_str(),
            "execute",
            "the name on the record is the name policy serializes, or a policy file and an \
             audit record disagree about the same capability"
        );
        assert!(
            tool_policy_spec("an_upstream_tool_nobody_declared").is_none(),
            "a tool with no spec carries no permission rather than a guessed one"
        );
    }

    fn make_test_router() -> Router {
        let policy = Arc::new(parking_lot::RwLock::new(PolicyConfig::default()));
        let audit = AuditSink::open(
            std::env::temp_dir().join(format!("nmcp-router-test-{}.jsonl", uuid::Uuid::new_v4())),
        )
        .unwrap();
        Router::new(policy, audit)
    }

    struct EchoProvider;

    #[async_trait]
    impl ToolProvider for EchoProvider {
        fn provider_id(&self) -> &str {
            ""
        }
        fn tool_names(&self) -> Vec<String> {
            vec!["echo".into()]
        }
        fn tool_list(&self) -> Vec<Value> {
            vec![json!({"name": "echo", "description": "Echo args back", "inputSchema": {}})]
        }
        async fn call(&self, _name: &str, args: Value, _ctx: &CallContext) -> ToolCallResult {
            ToolCallResult::ok(args)
        }
    }

    // Provider whose tool maps to a mutating permission (Write) in tool_policy_spec,
    // used to exercise the auto_approve gate.
    struct WriteProvider;

    #[async_trait]
    impl ToolProvider for WriteProvider {
        fn provider_id(&self) -> &str {
            ""
        }
        fn tool_names(&self) -> Vec<String> {
            vec!["write_text_file".into()]
        }
        fn tool_list(&self) -> Vec<Value> {
            vec![json!({"name": "write_text_file", "description": "write", "inputSchema": {}})]
        }
        async fn call(&self, _name: &str, args: Value, _ctx: &CallContext) -> ToolCallResult {
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
        let audit = AuditSink::open(
            std::env::temp_dir().join(format!("nmcp-router-abac-{}.jsonl", uuid::Uuid::new_v4())),
        )
        .unwrap();
        let mut router = Router::new(Arc::new(parking_lot::RwLock::new(policy)), audit);
        if let Some(stage) = abac {
            router.set_abac(stage);
        }
        router
    }

    #[test]
    fn tool_is_mutating_classifies_correctly() {
        // The dotted spellings are here on purpose: the classifier folds `.` to `_` before it
        // consults the spec table, so a caller using either form gets the same verdict.
        for name in [
            "write_text_file",
            "backup",
            "execute",
            "win_registry_write",
            "fs.write_text_file",
            "dev.git_publish",
        ] {
            assert!(tool_is_mutating(name), "{name} should be mutating");
        }
        for name in [
            "list_directory",
            "read_file_window_report",
            "fs.list_directory",
        ] {
            assert!(!tool_is_mutating(name), "{name} should not be mutating");
        }
        // A specless name stays not-mutating here. That is right for the first-party tools
        // that legitimately have no spec, and the third-party question is not answerable from
        // a name at all, so `dispatch` answers it from the resolved provider instead (M6).
        for name in ["echo", "vendor_do_something"] {
            assert!(
                !tool_is_mutating(name),
                "{name} carries no information about mutation in its name alone"
            );
        }
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
        router.register(Arc::new(EchoProvider));
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
        router.register(Arc::new(EchoProvider));
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
        router.register(Arc::new(EchoProvider));
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
        fn provider_id(&self) -> &str {
            "vendor"
        }
        fn tool_names(&self) -> Vec<String> {
            vec!["do_something".into()]
        }
        fn tool_list(&self) -> Vec<Value> {
            vec![json!({"name": "do_something", "description": "unknown", "inputSchema": {}})]
        }
        async fn call(&self, _name: &str, args: Value, _ctx: &CallContext) -> ToolCallResult {
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

    /// G3-11 RS-11. A caller's token must never reach an upstream, and here it cannot,
    /// because there is no field for one to travel in. `CallContext` is everything a
    /// provider is given besides the tool arguments, and `authenticate_mcp_client` turns a
    /// credential into an `agent_id` and a profile before this type is ever built.
    ///
    /// Destructured rather than field-accessed on purpose: adding a field to `CallContext`
    /// breaks this compile, which puts the confused-deputy question in front of whoever adds
    /// it instead of letting a header ride along unnoticed.
    #[test]
    fn a_call_context_has_no_field_a_caller_credential_could_travel_in() {
        let CallContext {
            call_id: _,
            session_id: _,
            agent_id: _,
            matched_root: _,
            upstream_id: _,
            memory_scope: _,
            profile: _,
            client_info: _,
            // G3-15 added these two, and both are incapable of holding a credential BY TYPE
            // rather than by convention: `peer` is redacted at the transport boundary before
            // it can reach here, and `credential_path` is a compile-time constant from a
            // closed set. That is the bar a new field has to clear to be added here.
            peer: _,
            credential_path: _,
        } = CallContext::new(Some("session-1".to_string()));
    }

    #[tokio::test]
    async fn an_unspecced_third_party_tool_is_treated_as_mutating_rather_than_trusted() {
        // M6, first leg. tool_policy_spec is a compiled-in table of first-party tool names,
        // so every tool from an admitted upstream falls through it. It used to fall through
        // to "not mutating", which meant an operator who disabled auto_approve gated their
        // own write_text_file and waved through a third party's do_something. The gate now
        // reads the resolved provider, so unknown provenance means unknown effect.
        let policy = PolicyConfig {
            auto_approve: false,
            ..PolicyConfig::default()
        };
        let router = router_with(policy, None);
        router.register(Arc::new(ThirdPartyProvider));
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
        router.register(Arc::new(EchoProvider));
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
        router.register(Arc::new(ThirdPartyProvider));
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
        router.register(Arc::new(ThirdPartyProvider));
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
        router.register(Arc::new(ThirdPartyProvider));
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
        router.register(Arc::new(ThirdPartyProvider));
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
        router.register(Arc::new(ThirdPartyProvider));
        let undeclared = router
            .dispatch("vendor_do_something", json!({}), CallContext::new(None))
            .await;
        assert!(
            undeclared.is_error,
            "undeclared must refuse: {undeclared:?}"
        );

        // And a provider whose id policy has never heard of is not a provider policy admitted.
        let router = router_with(PolicyConfig::default(), None);
        router.register(Arc::new(ThirdPartyProvider));
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
        router.register(Arc::new(EchoProvider));
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
        router.register(Arc::new(WriteProvider));
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
        router.register(Arc::new(WriteProvider));
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
        router.register(Arc::new(WriteProvider));
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
        fn provider_id(&self) -> &str {
            ""
        }
        fn tool_names(&self) -> Vec<String> {
            vec!["dev.git_publish".into()]
        }
        fn tool_list(&self) -> Vec<Value> {
            vec![json!({"name": "dev.git_publish", "description": "Publish", "inputSchema": {}})]
        }
        async fn call(&self, _name: &str, args: Value, _ctx: &CallContext) -> ToolCallResult {
            ToolCallResult::ok(args)
        }
    }

    struct NamespacedProvider;

    #[async_trait]
    impl ToolProvider for NamespacedProvider {
        fn provider_id(&self) -> &str {
            "upstream"
        }
        fn tool_names(&self) -> Vec<String> {
            vec!["ping".into()]
        }
        fn tool_list(&self) -> Vec<Value> {
            vec![json!({"name": "ping", "description": "Ping", "inputSchema": {}})]
        }
        async fn call(&self, _name: &str, _args: Value, _ctx: &CallContext) -> ToolCallResult {
            ToolCallResult::ok(json!("pong"))
        }
    }

    /// A second namespaced provider, so a profile has something to include and something to
    /// leave out.
    struct OtherUpstreamProvider;

    #[async_trait]
    impl ToolProvider for OtherUpstreamProvider {
        fn provider_id(&self) -> &str {
            "partner"
        }
        fn tool_names(&self) -> Vec<String> {
            vec!["fetch".into()]
        }
        fn tool_list(&self) -> Vec<Value> {
            vec![json!({"name": "fetch", "description": "Fetch", "inputSchema": {}})]
        }
        async fn call(&self, _name: &str, _args: Value, _ctx: &CallContext) -> ToolCallResult {
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
        router.register(Arc::new(NamespacedProvider));
        router.register(Arc::new(OtherUpstreamProvider));
        router.register(Arc::new(EchoProvider));

        let names = |profile: Option<&str>| -> Vec<String> {
            let mut names: Vec<String> = router
                .merged_tool_list_for(profile)
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
        router.register(Arc::new(EchoProvider));
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
        router.register(Arc::new(NamespacedProvider));
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
        let path = std::env::temp_dir().join(format!(
            "nmcp-router-duration-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let audit = AuditSink::open(&path).unwrap();
        let policy = Arc::new(parking_lot::RwLock::new(PolicyConfig::default()));
        let router = Router::new(policy, audit);
        router.register(Arc::new(EchoProvider));

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
        assert_eq!(events.len(), 2, "both calls must be audited");
        for event in &events {
            assert!(
                event.get("duration_ms").is_some(),
                "audit record is missing duration_ms: {event}"
            );
            assert!(
                event["duration_ms"].is_u64(),
                "duration_ms must be a number: {event}"
            );
        }
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

    #[test]
    fn devtools_policy_specs_cover_provider_tools() {
        let blame = tool_policy_spec("dev_git_blame").expect("blame spec");
        assert_eq!(blame.permission, Permission::Read);
        let stash = tool_policy_spec("dev_git_stash_list").expect("stash spec");
        assert_eq!(stash.permission, Permission::Read);
        let dep = tool_policy_spec("dev_dep_graph").expect("dep graph spec");
        assert_eq!(dep.permission, Permission::Execute);
    }

    #[tokio::test]
    async fn git_publish_denial_has_specific_remediation() {
        let router = make_test_router();
        router.register(Arc::new(PublishProvider));
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
        router.register(Arc::new(EchoProvider));
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
        router.register(Arc::new(EchoProvider));
        router.register(Arc::new(NamespacedProvider));
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
        router.register(Arc::new(EchoProvider));
        router.register(Arc::new(NamespacedProvider));
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
}
