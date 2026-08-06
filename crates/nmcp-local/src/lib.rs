//! The first-party local tools: filesystem, execution, and bounded reporting.
//!
//! Twenty-one tools over `nmcp-fs`, `nmcp-exec` and `nmcp-reports`, declared one at a time.
//!
//! Part of the NativeMCP `core` workspace. The governance invariants in
//! `docs/GOVERNANCE.md` apply.
//!
//! # This port is not a copy, and NMCP-PLAN-002 section 4a says why
//!
//! The base derived every schema from a shared static table in `mcp-protocol` and let a
//! second static table in `mcp-router` say which permission and which path argument governed
//! each tool. RC-D3 forbids the first and I-047d deleted the second. What replaced them is a
//! `ToolContract` per tool, owned here.
//!
//! Three of the base's declarations disagreed with what the handler actually enforces, and
//! **RC-20's fix catches none of them.** RC-20 filters declared path arguments down to the
//! tool's own schema properties, which only finds a wrong argument the schema never defined.
//! Each of these three is a different shape:
//!
//! - `execute_resolve_program` declared `path_args: ["program"]` while `CommandBroker`
//!   authorizes against `cwd`. `program` is a legitimate schema property, so the filter keeps
//!   it, and a bare command name like `git` canonicalizes outside every configured root. A
//!   faithful copy would have **denied nearly every call** while the internal check would
//!   have allowed it. It declares `cwd` here, and `cwd` was added to its schema, because
//!   RC-D5 refuses a declared path argument the schema cannot receive.
//! - `scan_repo` was declared `Search` and enforces `Scan`. An operator granting `Scan` for a
//!   tool named `scan_repo` was refused at the ring by a table that disagreed with the code.
//! - `write_text_file` and `patch_text_file` were declared `Write`, a permission `nmcp-fs`
//!   references nowhere. A root needed `Write` to pass the ring and `Modify` to pass the
//!   handler, so the grant an operator was told to give did nothing on its own.
//!
//! # Why `create_text_file` refuses an existing file
//!
//! It dispatched to the same function as `write_text_file` and silently overwrote, despite
//! its name and its own description saying "Create". That is a defect on its own, and it was
//! also why its authority could not be written down: it needed `Create` when the target was
//! absent and `Modify` when it was present, and `ToolAuthority::permission` is one
//! `Option<Permission>`. Making the name true makes `Create` exactly right, so one change
//! closes both. `write_text_file` is the replace path and always was.
//!
//! # What this crate does not do
//!
//! No policy check. The base ran `policy.require` inside `call` for two of its twenty-one
//! arms, which the `ToolProvider` contract forbids; both are gone. `FileSystemService` and
//! `CommandBroker` keep their own internal checks, and that is deliberate rather than
//! redundant: `nmcpctl` drives them directly, with no ring above, so a service that trusted
//! its caller would be ungoverned there.

use std::sync::Arc;

use async_trait::async_trait;
use nmcp_audit::AuditSink;
use nmcp_exec::{
    CommandBroker, ExecuteCancelRequest, ExecuteEnvReportRequest, ExecuteJobIdRequest,
    ExecuteJobRegistry, ExecuteRequest, ExecuteResolveProgramRequest, ExecuteStartRequest,
    ExecuteTailRequest, ExecuteWaitRequest,
};
use nmcp_fs::FileSystemService;
use nmcp_policy::{Permission, PolicyConfig};
use nmcp_schema::{
    CallContext, CapabilityGrant, GrantedAuthority, ToolAuthority, ToolCallResult, ToolContract,
    ToolEffect, ToolProvider, ToolReach,
};
use serde_json::{Value, json};

/// Ceiling on the per-call `max_files` override.
///
/// A caller can raise the file bound, but not to a value that turns the walk back into an
/// unbounded one by another name.
const MAX_WALK_FILES_CEILING: u64 = 1_000_000;

/// One tool's advertised identity, owned by this crate.
///
/// The base read these from `mcp_protocol::tool_list()`, a table shared across providers,
/// which RC-D3 forbids: a provider must declare what it serves. The table is private here and
/// `contracts` is the only reader, so the declaration and the advertised entry are one source
/// rather than two that have to agree.
struct ToolDescriptor {
    name: &'static str,
    description: &'static str,
    schema: Value,
}

/// The twenty-one tools this provider owns.
/// The twenty-one tools this provider owns.
///
/// Declared in two groups because they are two groups: twelve over `nmcp-fs` and
/// `nmcp-reports`, nine over `nmcp-exec`. The order is the advertised order and it does not
/// change here.
fn local_tool_descriptors() -> Vec<ToolDescriptor> {
    let mut all = filesystem_tool_descriptors();
    all.extend(execution_tool_descriptors());
    all
}

/// The twelve tools over `nmcp-fs` and `nmcp-reports`.
fn filesystem_tool_descriptors() -> Vec<ToolDescriptor> {
    vec![
        ToolDescriptor {
            name: "list_roots",
            description: "Return configured roots and effective permissions.",
            schema: json!({"type":"object","properties":{}}),
        },
        ToolDescriptor {
            name: "list_directory",
            description: "List one directory under an allowed root and return bounded entries.",
            schema: json!({"type":"object","properties":{"path":{"type":"string"},"include_hidden":{"type":"boolean"},"limit":{"type":"integer"}},"required":["path"]}),
        },
        ToolDescriptor {
            name: "search_repo",
            description: "Search file content under an allowed root and return a bounded report. The walk prunes generated directories (target, node_modules, .git and similar) and stops at a time and file budget; the report names what was pruned and whether it stopped early.",
            schema: json!({"type":"object","properties":{"path":{"type":"string"},"pattern":{"type":"string"},"max_files":{"type":"integer","description":"Raise the file ceiling for this call. The wall-clock deadline still applies."},"include_generated":{"type":"boolean","description":"Walk generated directories too. Slower, and the deadline still applies."}},"required":["path","pattern"]}),
        },
        ToolDescriptor {
            name: "scan_repo",
            description: "Scan a repository root and return a report, including secret candidates. The walk prunes generated directories (target, node_modules, .git and similar) and stops at a time and file budget; the report names what was pruned and whether it stopped early, so a partial scan is never mistaken for a clean tree.",
            schema: json!({"type":"object","properties":{"path":{"type":"string"},"max_files":{"type":"integer","description":"Raise the file ceiling for this call. The wall-clock deadline still applies."},"include_generated":{"type":"boolean","description":"Walk generated directories too. Slower, and the deadline still applies."}},"required":["path"]}),
        },
        ToolDescriptor {
            name: "create_text_file",
            description: "Create a UTF-8 text file under an allowed root. Refuses when the target already exists; use write_text_file to replace one.",
            schema: json!({"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]}),
        },
        ToolDescriptor {
            name: "read_file_window_report",
            description: "Return a bounded line-window report for a file.",
            schema: json!({"type":"object","properties":{"path":{"type":"string"},"start_line":{"type":"integer"},"line_count":{"type":"integer"}},"required":["path"]}),
        },
        ToolDescriptor {
            name: "inspect_file_integrity",
            description: "Return full-file integrity metadata, headings, suspicious markers, and bounded first/last line previews.",
            schema: json!({"type":"object","properties":{"path":{"type":"string"},"preview_lines":{"type":"integer","description":"Number of first/last lines to include, clamped to 1..50."}},"required":["path"]}),
        },
        ToolDescriptor {
            name: "write_text_file",
            description: "Create or replace a UTF-8 file and return an operation report.",
            schema: json!({"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]}),
        },
        ToolDescriptor {
            name: "patch_text_file",
            description: "Replace a UTF-8 file through the legacy patch_text_file alias; content is required and before/after hashes are returned.",
            schema: json!({"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]}),
        },
        ToolDescriptor {
            name: "rename_file",
            description: "Rename a file without moving its parent directory.",
            schema: json!({"type":"object","properties":{"from":{"type":"string"},"to_name":{"type":"string"}},"required":["from","to_name"]}),
        },
        ToolDescriptor {
            name: "move_file",
            description: "Move a file to a different directory. Audited separately from rename.",
            schema: json!({"type":"object","properties":{"from":{"type":"string"},"to":{"type":"string"}},"required":["from","to"]}),
        },
        ToolDescriptor {
            name: "backup_file",
            description: "Rename a file to .bak, .bak1, .bak2, etc. This is the only destructive-adjacent operation.",
            schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
        },
    ]
}

/// The nine tools over `nmcp-exec`.
fn execution_tool_descriptors() -> Vec<ToolDescriptor> {
    vec![
        ToolDescriptor {
            name: "execute",
            description: "Run a short configured local command and return an execution report. timeout_ms defaults to 30000 to stay below connector request limits; use execute_start for durable long-running work.",
            schema: json!({"type":"object","properties":{"cwd":{"type":"string"},"program":{"type":"string"},"args":{"type":"array","items":{"type":"string"}},"timeout_ms":{"type":"integer","description":"Optional command timeout in milliseconds. Defaults to 30000 (30 seconds)."},"profile":{"type":"string"},"env":{"type":"object","additionalProperties":{"type":"string"}},"inherit_service_env":{"type":"boolean"}},"required":["cwd","program"]}),
        },
        ToolDescriptor {
            name: "execute_start",
            description: "Start a long-running command as a durable nMCP job and return immediately with job_id and log paths.",
            schema: json!({"type":"object","properties":{"cwd":{"type":"string"},"program":{"type":"string"},"args":{"type":"array","items":{"type":"string"}},"timeout_ms":{"type":"integer"},"profile":{"type":"string"},"env":{"type":"object","additionalProperties":{"type":"string"}},"inherit_service_env":{"type":"boolean"}},"required":["cwd","program"]}),
        },
        ToolDescriptor {
            name: "execute_resolve_program",
            description: "Resolve a program using request env, configured tool aliases, execution profiles, service PATH, and Windows PATHEXT without starting it.",
            schema: json!({"type":"object","properties":{"program":{"type":"string"},"cwd":{"type":"string","description":"Directory the resolution is authorized against. Defaults to the first configured root when omitted."},"profile":{"type":"string"},"env":{"type":"object","additionalProperties":{"type":"string"}},"inherit_service_env":{"type":"boolean"}},"required":["program"]}),
        },
        ToolDescriptor {
            name: "execute_env_report",
            description: "Report the service execution environment, configured execution profiles, tool aliases, effective exec state directory, and redacted env preview.",
            schema: json!({"type":"object","properties":{"profile":{"type":"string"},"env":{"type":"object","additionalProperties":{"type":"string"}},"inherit_service_env":{"type":"boolean"}}}),
        },
        ToolDescriptor {
            name: "execute_status",
            description: "Return current status for an execute job, including PID, elapsed time, command shape, and exit code when finished.",
            schema: json!({"type":"object","properties":{"job_id":{"type":"string"}},"required":["job_id"]}),
        },
        ToolDescriptor {
            name: "execute_tail",
            description: "Return bounded stdout and stderr tails from an execute job's append-only log files.",
            schema: json!({"type":"object","properties":{"job_id":{"type":"string"},"max_bytes":{"type":"integer"}},"required":["job_id"]}),
        },
        ToolDescriptor {
            name: "execute_wait",
            description: "Wait briefly for an execute job and return status plus bounded tails; use status/result for later polling.",
            schema: json!({"type":"object","properties":{"job_id":{"type":"string"},"timeout_ms":{"type":"integer"},"max_bytes":{"type":"integer"}},"required":["job_id"]}),
        },
        ToolDescriptor {
            name: "execute_result",
            description: "Return the final report for an execute job, or running status plus log tails if still active.",
            schema: json!({"type":"object","properties":{"job_id":{"type":"string"}},"required":["job_id"]}),
        },
        ToolDescriptor {
            name: "execute_cancel",
            description: "Cancel only a process job created by nMCP and audit the cancellation.",
            schema: json!({"type":"object","properties":{"job_id":{"type":"string"}},"required":["job_id"]}),
        },
    ]
}

/// What a local tool needs in order to run.
///
/// Exhaustive over the twenty-one names `local_tool_descriptors` declares, with no wildcard
/// arm, so a tool added there without a line here does not compile. Every deviation from the
/// base's two tables is deliberate and is argued in the module doc.
// Several tools share a body because they share a decision, and the arms stay separate
// because they do not share a reason: `list_roots` returns the caller's own policy, the
// execute reporting tools take an opaque `job_id` the registry scopes, and
// `execute_env_report` describes this server's resolution environment. Collapsing them into
// one arm would satisfy the lint by deleting the argument each one carries, and that
// argument is what makes this a declaration rather than a table.
#[expect(
    clippy::match_same_arms,
    reason = "per-tool declarations, argued individually"
)]
fn local_tool_authority(name: &str) -> ToolAuthority {
    // (permission, path_args, effect, reach)
    let (permission, path_args, effect, reach): (Option<Permission>, &[&str], _, _) = match name {
        // Metadata about the caller's own policy. No path, no permission, and that is a
        // decision now rather than the absence of a table entry it used to be.
        "list_roots" => (None, &[], ToolEffect::Observe, ToolReach::Local),

        "list_directory" => (
            Some(Permission::List),
            &["path"],
            ToolEffect::Observe,
            ToolReach::Local,
        ),
        "read_file_window_report" | "inspect_file_integrity" => (
            Some(Permission::Read),
            &["path"],
            ToolEffect::Observe,
            ToolReach::Local,
        ),
        // Was declared Search against a handler that requires Scan.
        "scan_repo" => (
            Some(Permission::Scan),
            &["path"],
            ToolEffect::Observe,
            ToolReach::Local,
        ),
        "search_repo" => (
            Some(Permission::Search),
            &["path"],
            ToolEffect::Observe,
            ToolReach::Local,
        ),
        // Create-only now, which is what makes a single permission expressible.
        "create_text_file" => (
            Some(Permission::Create),
            &["path"],
            ToolEffect::Mutate,
            ToolReach::Local,
        ),
        // Was declared Write, which nmcp-fs references nowhere.
        "write_text_file" | "patch_text_file" => (
            Some(Permission::Modify),
            &["path"],
            ToolEffect::Mutate,
            ToolReach::Local,
        ),
        "rename_file" => (
            Some(Permission::Rename),
            &["from"],
            ToolEffect::Mutate,
            ToolReach::Local,
        ),
        // `to` is enforced inside nmcp-fs, which checks both ends. The kernel resolves one
        // root from the first present path argument, so declaring `to` as well would not
        // check it. The consequence, written down rather than discovered from an audit
        // record: for a cross-root move the audit-visible matched root names the source and
        // never the destination.
        "move_file" => (
            Some(Permission::Move),
            &["from"],
            ToolEffect::Mutate,
            ToolReach::Local,
        ),
        "backup_file" => (
            Some(Permission::Backup),
            &["path"],
            ToolEffect::Mutate,
            ToolReach::Local,
        ),
        // Reach is Remote because a command this server did not write can do anything the
        // caller's account can, including reaching the network. The ring uses it for
        // openWorldHint, and understating it would advertise a shell as sandboxed.
        "execute" | "execute_start" => (
            Some(Permission::Execute),
            &["cwd"],
            ToolEffect::Mutate,
            ToolReach::Remote,
        ),
        // Declared `program` and enforced on `cwd`. See the module doc: this is the one a
        // faithful copy would have broken outright rather than merely mislabelled.
        "execute_resolve_program" => (
            Some(Permission::Execute),
            &["cwd"],
            ToolEffect::Observe,
            ToolReach::Local,
        ),
        // A `job_id` is an opaque identifier the job registry scopes, not a governed path,
        // and `execute_env_report` describes the server's own resolution environment. None of
        // the six had a table entry or an internal check in either tree. Declaring the
        // absence turns an accident into a decision.
        "execute_env_report" | "execute_status" | "execute_tail" | "execute_result" => {
            (None, &[], ToolEffect::Observe, ToolReach::Local)
        }
        "execute_wait" => (None, &[], ToolEffect::Observe, ToolReach::Local),
        "execute_cancel" => (None, &[], ToolEffect::Mutate, ToolReach::Local),

        other => return unknown_tool_authority(other),
    };
    ToolAuthority {
        permission,
        path_args: path_args.iter().map(|a| (*a).to_string()).collect(),
        grants: Vec::new(),
        effect,
        reach,
    }
}

/// The authority of a tool this crate declares and has no line for.
///
/// Unreachable through [`LocalProvider::contracts`], and written anyway because the
/// alternative to a fail-closed arm is a fallback that grants something. This one requires a
/// capability grant no `Permission` defines, which `authorize` refuses by name on every call,
/// so a tool that reached here would be visible and uncallable rather than callable and
/// ungoverned.
fn unknown_tool_authority(name: &str) -> ToolAuthority {
    ToolAuthority {
        permission: Some(Permission::Read),
        path_args: vec!["path".to_string()],
        grants: vec![CapabilityGrant::new(format!("nmcp.undeclared.{name}"))],
        effect: ToolEffect::Mutate,
        reach: ToolReach::Remote,
    }
}

/// Build a walk budget for `scan_repo` and `search_repo` from optional tool arguments.
///
/// The defaults keep a repo-scale walk inside the connector request window. A caller can
/// raise the file ceiling and can opt into walking generated directories, but the wall-clock
/// deadline is deliberately not exposed: a connector must never be able to remove its own
/// timeout and wedge the session behind one call.
fn walk_budget_from_args(args: &Value) -> nmcp_reports::ScanBudget {
    let mut budget = nmcp_reports::ScanBudget::default();
    if args
        .get("include_generated")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        budget.skip_dirs.clear();
    }
    if let Some(max_files) = args.get("max_files").and_then(Value::as_u64) {
        budget.max_files =
            usize::try_from(max_files.min(MAX_WALK_FILES_CEILING)).unwrap_or(usize::MAX);
    }
    budget
}

/// Read an optional `usize` argument with a default, saturating rather than casting.
fn usize_arg(args: &Value, key: &str, default: usize) -> usize {
    args.get(key)
        .and_then(Value::as_u64)
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(default)
}

/// The local filesystem, execution and reporting tools as one provider.
pub struct LocalProvider {
    policy: Arc<parking_lot::RwLock<PolicyConfig>>,
    audit: AuditSink,
    exec_jobs: ExecuteJobRegistry,
}

impl LocalProvider {
    /// Build the provider over a shared policy handle, an audit sink and the job registry.
    #[must_use]
    pub fn new(
        policy: Arc<parking_lot::RwLock<PolicyConfig>>,
        audit: AuditSink,
        exec_jobs: ExecuteJobRegistry,
    ) -> Self {
        Self {
            policy,
            audit,
            exec_jobs,
        }
    }
}

#[async_trait]
impl ToolProvider for LocalProvider {
    fn contract_version(&self) -> u32 {
        1
    }

    // The trait declares `-> &str`; an impl cannot narrow it to a static lifetime on its own.
    #[allow(clippy::unnecessary_literal_bound)]
    fn provider_id(&self) -> &str {
        ""
    }

    fn contracts(&self) -> Vec<ToolContract> {
        local_tool_descriptors()
            .into_iter()
            .map(|entry| ToolContract {
                authority: local_tool_authority(entry.name),
                // RC-21: `None`, and it has to be. This provider is first party, so its
                // annotations are derived from the authority above, and a second source that
                // could disagree with the first is the defect RC-A4 makes unrepresentable.
                published_annotations: None,
                description: entry.description.to_string(),
                input_schema: entry.schema,
                name: entry.name.to_string(),
            })
            .collect()
    }

    async fn call(
        &self,
        name: &str,
        args: Value,
        ctx: &CallContext,
        _granted: &GrantedAuthority,
    ) -> ToolCallResult {
        let policy = self.policy.read().clone();
        // Both handles are bound to this call, so every effect record they write names the
        // decision that permitted it (G4-26).
        let fs = FileSystemService::new(policy.clone(), self.audit.clone())
            .with_call_id(Some(ctx.call_id));
        let broker = CommandBroker::with_job_registry(
            policy.clone(),
            self.audit.clone(),
            self.exec_jobs.clone(),
        )
        .with_call_id(Some(ctx.call_id));

        let result: anyhow::Result<Value> = async {
            if let Some(value) = call_filesystem(name, &args, &fs, &policy)? {
                return Ok(value);
            }
            if let Some(value) = call_execution(name, args, &broker).await? {
                return Ok(value);
            }
            anyhow::bail!("unknown tool: {name}")
        }
        .await;

        match result {
            Ok(v) => ToolCallResult::from_tool_result_json(v, json!({"tool": name})),
            Err(e) => ToolCallResult::err(e.to_string()),
        }
    }
}

/// Dispatch the twelve tools over `nmcp-fs` and `nmcp-reports`.
///
/// `None` means the name is not one of these rather than that the call failed, so the
/// caller can try the next group. A name belonging to no group is the unknown-tool error,
/// raised once at the end rather than by each group in turn.
///
/// No policy check here, and none in the execution half either. `FileSystemService` and
/// `CommandBroker` keep their own, which is what governs `nmcpctl` where there is no ring.
///
/// # Errors
///
/// Returns whatever the underlying service returned.
fn call_filesystem(
    name: &str,
    args: &Value,
    fs: &FileSystemService,
    policy: &PolicyConfig,
) -> anyhow::Result<Option<Value>> {
    let value: anyhow::Result<Value> = match name {
        "list_roots" => Ok(nmcp_proto::tool_result_json(&json!({
            "roots": policy.roots,
            "root_count": policy.roots.len()
        }))),
        "list_directory" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or_default();
            let include_hidden = args
                .get("include_hidden")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let limit = usize_arg(args, "limit", 500);
            Ok(nmcp_proto::tool_result_json(&json!(
                fs.list_directory_report(path, include_hidden, limit)?
            )))
        }
        "scan_repo" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let budget = walk_budget_from_args(args);
            let report = nmcp_reports::scan_repo_with(path, &budget)?;
            Ok(nmcp_proto::tool_result_json(&json!(report)))
        }
        "search_repo" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let pattern = args
                .get("pattern")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let budget = walk_budget_from_args(args);
            let report =
                nmcp_reports::search_repo_with(std::path::Path::new(path), pattern, &budget)?;
            Ok(nmcp_proto::tool_result_json(&json!(report)))
        }
        "create_text_file" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or_default();
            let Some(content) = args.get("content").and_then(Value::as_str) else {
                anyhow::bail!("content is required for create_text_file");
            };
            // Create-only. The existence check is here rather than in nmcp-fs because
            // write_text_file is the shared primitive and must keep replacing; this
            // is the one caller that must not. A racing creator between this check
            // and the write is possible and is the same window every create-if-absent
            // has without an O_EXCL primitive; what it cannot do is turn this into a
            // silent overwrite of a file that was already there when the call began,
            // which is the behaviour being removed.
            if std::path::Path::new(path).exists() {
                anyhow::bail!(
                    "create_text_file: {path} already exists; use write_text_file to replace it"
                );
            }
            Ok(nmcp_proto::tool_result_json(&json!(
                fs.write_text_file(path, content)?
            )))
        }
        "read_file_window_report" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or_default();
            let start = usize_arg(args, "start_line", 1);
            let count = usize_arg(args, "line_count", 120);
            Ok(nmcp_proto::tool_result_json(&json!(
                fs.read_file_window_report(path, start, count)?
            )))
        }
        "inspect_file_integrity" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or_default();
            let preview_lines = usize_arg(args, "preview_lines", 12);
            Ok(nmcp_proto::tool_result_json(&json!(
                fs.inspect_file_integrity(path, preview_lines)?
            )))
        }
        "write_text_file" | "patch_text_file" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or_default();
            let Some(content) = args.get("content").and_then(Value::as_str) else {
                anyhow::bail!("content is required for write_text_file and patch_text_file");
            };
            Ok(nmcp_proto::tool_result_json(&json!(
                fs.write_text_file(path, content)?
            )))
        }
        "rename_file" => {
            let from = args.get("from").and_then(Value::as_str).unwrap_or_default();
            let to_name = args
                .get("to_name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            Ok(nmcp_proto::tool_result_json(&json!(
                fs.rename_file(from, to_name)?
            )))
        }
        "move_file" => {
            let from = args.get("from").and_then(Value::as_str).unwrap_or_default();
            let to = args.get("to").and_then(Value::as_str).unwrap_or_default();
            Ok(nmcp_proto::tool_result_json(&json!(
                fs.move_file(from, to)?
            )))
        }
        "backup_file" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or_default();
            Ok(nmcp_proto::tool_result_json(&json!(fs.backup_file(path)?)))
        }
        _ => return Ok(None),
    };
    Ok(Some(value?))
}

/// Dispatch the nine tools over `nmcp-exec`.
///
/// Takes `args` by value because every arm here deserializes the whole object into a
/// request type, and only one arm runs.
///
/// # Errors
///
/// Returns whatever the broker returned.
async fn call_execution(
    name: &str,
    args: Value,
    broker: &CommandBroker,
) -> anyhow::Result<Option<Value>> {
    let value: anyhow::Result<Value> = match name {
        "execute" => {
            let req: ExecuteRequest = serde_json::from_value(args)?;
            Ok(nmcp_proto::tool_result_json(&json!(
                broker.execute(req).await?
            )))
        }
        "execute_start" => {
            let req: ExecuteStartRequest = serde_json::from_value(args)?;
            let report = broker.execute_start(req).await?;
            Ok(nmcp_proto::tool_result_json(&json!(report)))
        }
        "execute_resolve_program" => {
            let req: ExecuteResolveProgramRequest = serde_json::from_value(args)?;
            Ok(nmcp_proto::tool_result_json(&json!(
                broker.execute_resolve_program(req)?
            )))
        }
        "execute_env_report" => {
            let req: ExecuteEnvReportRequest = serde_json::from_value(args)?;
            Ok(nmcp_proto::tool_result_json(&json!(
                broker.execute_env_report(req)
            )))
        }
        "execute_status" => {
            let req: ExecuteJobIdRequest = serde_json::from_value(args)?;
            Ok(nmcp_proto::tool_result_json(&json!(
                broker.execute_status(req)?
            )))
        }
        "execute_tail" => {
            let req: ExecuteTailRequest = serde_json::from_value(args)?;
            Ok(nmcp_proto::tool_result_json(&json!(
                broker.execute_tail(req)?
            )))
        }
        "execute_wait" => {
            let req: ExecuteWaitRequest = serde_json::from_value(args)?;
            Ok(nmcp_proto::tool_result_json(&json!(
                broker.execute_wait(req).await?
            )))
        }
        "execute_result" => {
            let req: ExecuteJobIdRequest = serde_json::from_value(args)?;
            Ok(nmcp_proto::tool_result_json(&json!(
                broker.execute_result(req)?
            )))
        }
        "execute_cancel" => {
            let req: ExecuteCancelRequest = serde_json::from_value(args)?;
            Ok(nmcp_proto::tool_result_json(&json!(
                broker.execute_cancel(req).await?
            )))
        }
        _ => return Ok(None),
    };
    Ok(Some(value?))
}

#[cfg(test)]
mod tests {
    // Tests assert on shapes, verdicts and JSON, where expect/indexing ARE the assertion: a
    // panic in a test is the failure signal, so the production rationale for the workspace
    // denies (availability plus an audit gap) does not apply. Scoped to the test module,
    // named in the PR.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::{LocalProvider, local_tool_authority, local_tool_descriptors};
    use nmcp_audit::AuditSink;
    use nmcp_exec::ExecuteJobRegistry;
    use nmcp_policy::{Permission, PolicyConfig, RootRule};
    use nmcp_schema::{
        CallContext, GrantedAuthority, HeldAuthority, ToolEffect, ToolProvider, authorize,
    };
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn temp_root(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("{label}-{stamp}"));
        std::fs::create_dir_all(&root).expect("mkdir");
        root
    }

    fn policy_for(root: &Path, permissions: &[Permission]) -> PolicyConfig {
        PolicyConfig {
            roots: vec![RootRule {
                id: "root".into(),
                path: root.to_path_buf(),
                permissions: permissions.iter().copied().collect::<BTreeSet<_>>(),
            }],
            ..PolicyConfig::default()
        }
    }

    fn provider_for(policy: PolicyConfig) -> LocalProvider {
        LocalProvider::new(
            Arc::new(parking_lot::RwLock::new(policy)),
            AuditSink::open(temp_root("nmcp-local-audit").join("audit.jsonl")).expect("audit"),
            ExecuteJobRegistry::default(),
        )
    }

    /// What the ring would hand the provider. Minted through `authorize` rather than
    /// constructed, because there is no other constructor: these tests drive the real
    /// authorization path rather than a stand-in for it.
    fn granted(
        tool: &str,
        policy: &PolicyConfig,
        args: &Value,
    ) -> Result<GrantedAuthority, String> {
        let held = HeldAuthority {
            roots: policy.roots.clone(),
            grants: BTreeSet::new(),
            agent_id: None,
        };
        authorize(&local_tool_authority(tool), &held, args).map_err(|d| d.to_string())
    }

    #[test]
    fn every_declared_path_argument_is_a_property_of_its_own_schema() {
        // RC-D5. The base's tables named `repo`, `repo_path`, `cwd` and others across tool
        // families that did not accept them, which is what RC-20 was about. This is the
        // property that makes the set the kernel authorizes on and the set the tool reads the
        // same set.
        for d in local_tool_descriptors() {
            let authority = local_tool_authority(d.name);
            for arg in &authority.path_args {
                assert!(
                    d.schema
                        .get("properties")
                        .and_then(|p| p.get(arg))
                        .is_some(),
                    "{}: declares path arg {arg} its own schema cannot receive",
                    d.name
                );
            }
        }
    }

    #[test]
    fn every_declared_tool_has_an_authority_line() {
        let descriptors = local_tool_descriptors();
        assert_eq!(descriptors.len(), 21, "the tool set is twenty-one");
        for d in &descriptors {
            let a = local_tool_authority(d.name);
            assert!(
                a.grants.is_empty(),
                "{}: no local tool requires a capability grant beyond its permission",
                d.name
            );
        }
    }

    #[test]
    fn execute_resolve_program_authorizes_the_argument_the_broker_reads() {
        // The finding this port exists to fix. The base declared `program` and the broker
        // checks `cwd`. Declaring `program` would resolve a root from a bare command name,
        // which lands outside every root, so the tool would have been denied on almost every
        // call while the internal check would have allowed it.
        let authority = local_tool_authority("execute_resolve_program");
        assert_eq!(
            authority.path_args,
            vec!["cwd".to_string()],
            "the declared path argument must be the one CommandBroker authorizes against"
        );
        let root = temp_root("nmcp-local-erp");
        let policy = policy_for(&root, &[Permission::Execute]);

        // A bare program name with a governed cwd is authorized.
        let ok = granted(
            "execute_resolve_program",
            &policy,
            &json!({"program": "git", "cwd": root.to_string_lossy()}),
        );
        assert!(ok.is_ok(), "a governed cwd must authorize: {ok:?}");

        // The same call declared the old way would have resolved the root from `git`.
        assert!(
            granted(
                "execute_resolve_program",
                &policy,
                &json!({"program": "git", "cwd": "/definitely/not/a/root"})
            )
            .is_err(),
            "an ungoverned cwd must still refuse"
        );
    }

    #[test]
    fn scan_repo_declares_the_permission_its_handler_requires() {
        assert_eq!(
            local_tool_authority("scan_repo").permission,
            Some(Permission::Scan),
            "the base declared Search while nmcp-reports' caller requires Scan"
        );
        let root = temp_root("nmcp-local-scan");
        let policy = policy_for(&root, &[Permission::Scan]);
        assert!(
            granted(
                "scan_repo",
                &policy,
                &json!({"path": root.to_string_lossy()})
            )
            .is_ok(),
            "granting Scan must authorize scan_repo"
        );
    }

    #[test]
    fn the_write_tools_declare_a_permission_the_filesystem_actually_checks() {
        for tool in ["write_text_file", "patch_text_file"] {
            assert_eq!(
                local_tool_authority(tool).permission,
                Some(Permission::Modify),
                "{tool}: Permission::Write is referenced nowhere in nmcp-fs"
            );
        }
    }

    #[test]
    fn the_seven_ungoverned_tools_say_so_explicitly() {
        for tool in [
            "list_roots",
            "execute_env_report",
            "execute_status",
            "execute_tail",
            "execute_wait",
            "execute_result",
            "execute_cancel",
        ] {
            let a = local_tool_authority(tool);
            assert!(
                a.permission.is_none() && a.path_args.is_empty(),
                "{tool}: the absence of governance is a decision, and it is written here"
            );
        }
    }

    #[test]
    fn a_tool_with_no_authority_line_is_visible_and_uncallable() {
        let root = temp_root("nmcp-local-unknown");
        let policy = policy_for(&root, &Permission::ALL);
        assert!(
            granted(
                "invented_tool",
                &policy,
                &json!({"path": root.to_string_lossy()})
            )
            .is_err(),
            "the fallback arm must refuse even a caller holding every permission"
        );
    }

    #[tokio::test]
    async fn create_text_file_refuses_an_existing_target_and_write_replaces_it() {
        let root = temp_root("nmcp-local-create");
        let policy = policy_for(
            &root,
            &[Permission::Create, Permission::Modify, Permission::Read],
        );
        let p = provider_for(policy.clone());
        let ctx = CallContext::new(Some("sess".into()));
        let target = root.join("note.txt");
        let path = target.to_string_lossy().to_string();

        let args = json!({"path": path, "content": "first"});
        let g = granted("create_text_file", &policy, &args).expect("authorized");
        let first = p.call("create_text_file", args.clone(), &ctx, &g).await;
        assert!(!first.is_error, "the first create must succeed: {first:?}");

        let args2 = json!({"path": path, "content": "second"});
        let g2 = granted("create_text_file", &policy, &args2).expect("authorized");
        let second = p.call("create_text_file", args2, &ctx, &g2).await;
        assert!(
            second.is_error,
            "create_text_file must refuse an existing target rather than overwrite it"
        );
        assert_eq!(
            std::fs::read_to_string(&target).expect("read"),
            "first",
            "the refused call must not have written"
        );

        // write_text_file is the replace path and still replaces.
        let args3 = json!({"path": path, "content": "third"});
        let g3 = granted("write_text_file", &policy, &args3).expect("authorized");
        let third = p.call("write_text_file", args3, &ctx, &g3).await;
        assert!(!third.is_error, "write_text_file must replace: {third:?}");
        assert_eq!(std::fs::read_to_string(&target).expect("read"), "third");
    }

    #[tokio::test]
    async fn the_ring_refuses_before_the_provider_runs() {
        // The two policy.require calls the base ran inside `call` are gone. This is what
        // replaced them: a caller holding Read alone cannot reach a create.
        let root = temp_root("nmcp-local-refuse");
        let policy = policy_for(&root, &[Permission::Read]);
        let args = json!({"path": root.join("x.txt").to_string_lossy(), "content": "x"});
        assert!(
            granted("create_text_file", &policy, &args).is_err(),
            "Read alone must not authorize a create"
        );
        assert!(
            !root.join("x.txt").exists(),
            "nothing may have been written by a refused call"
        );
    }

    #[test]
    fn only_the_mutating_tools_declare_mutate() {
        let mutating: Vec<&str> = local_tool_descriptors()
            .iter()
            .filter(|d| local_tool_authority(d.name).effect == ToolEffect::Mutate)
            .map(|d| d.name)
            .collect();
        assert_eq!(
            mutating,
            vec![
                "create_text_file",
                "write_text_file",
                "patch_text_file",
                "rename_file",
                "move_file",
                "backup_file",
                "execute",
                "execute_start",
                "execute_cancel",
            ],
            "the mutating set drives the approval gate; a change here is a change to what a \
             human is asked to approve"
        );
    }
}
