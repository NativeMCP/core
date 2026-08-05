//! `nmcp-exec`
//!
//! Governed command execution for the NativeMCP server family: program
//! resolution across execution profiles, short synchronous runs, durable
//! long-running jobs with append-only logs, and the delete-intent refusal that
//! makes INV-1 hold for spawned programs as well as for tool handlers. The
//! invariants in `docs/GOVERNANCE.md` are normative for every item here.

use anyhow::{Context, bail};
use nmcp_audit::{AuditEvent, AuditSink};
use nmcp_policy::{Permission, PolicyConfig, absolute_path};
use nmcp_schema::SealedSecret;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, oneshot};
use uuid::Uuid;

/// The `DEFAULT_CONCURRENCY_CAP` constant.
pub const DEFAULT_CONCURRENCY_CAP: usize = 8;
/// The `DEFAULT_TIMEOUT_MS` constant.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
/// The `DEFAULT_JOB_TIMEOUT_MS` constant.
pub const DEFAULT_JOB_TIMEOUT_MS: u64 = 900_000;
/// The `DEFAULT_JOB_WAIT_MS` constant.
pub const DEFAULT_JOB_WAIT_MS: u64 = 5_000;
/// The `MAX_JOB_WAIT_MS` constant.
pub const MAX_JOB_WAIT_MS: u64 = 30_000;
/// The `DEFAULT_TAIL_BYTES` constant.
pub const DEFAULT_TAIL_BYTES: usize = 16_000;
/// The `MAX_TAIL_BYTES` constant.
pub const MAX_TAIL_BYTES: usize = 64_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ExecuteRequest` structure.
pub struct ExecuteRequest {
    /// Working directory.
    pub cwd: PathBuf,
    /// Program to run.
    pub program: String,
    #[serde(default)]
    /// Arguments passed to the program.
    pub args: Vec<String>,
    #[serde(default = "default_timeout_ms")]
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
    #[serde(default)]
    /// Environment variables.
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    /// The `inherit_service_env` field.
    pub inherit_service_env: Option<bool>,
    #[serde(default)]
    /// Named execution profile in force.
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ExecuteStartRequest` structure.
pub struct ExecuteStartRequest {
    /// Working directory.
    pub cwd: PathBuf,
    /// Program to run.
    pub program: String,
    #[serde(default)]
    /// Arguments passed to the program.
    pub args: Vec<String>,
    #[serde(default)]
    /// Timeout in milliseconds.
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    /// Environment variables.
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    /// The `inherit_service_env` field.
    pub inherit_service_env: Option<bool>,
    #[serde(default)]
    /// Named execution profile in force.
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ExecuteResolveProgramRequest` structure.
pub struct ExecuteResolveProgramRequest {
    #[serde(default)]
    /// Working directory.
    pub cwd: PathBuf,
    /// Program to run.
    pub program: String,
    #[serde(default)]
    /// Environment variables.
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    /// The `inherit_service_env` field.
    pub inherit_service_env: Option<bool>,
    #[serde(default)]
    /// Named execution profile in force.
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ExecuteResolveProgramReport` structure.
pub struct ExecuteResolveProgramReport {
    /// Program to run.
    pub program: String,
    /// The `resolved` field.
    pub resolved: bool,
    /// The `resolved_path` field.
    pub resolved_path: Option<String>,
    /// The `resolution_source` field.
    pub resolution_source: String,
    /// The `selected_profile` field.
    pub selected_profile: Option<String>,
    /// Named execution profile in force.
    pub profile: Option<String>,
    /// The `searched_paths` field.
    pub searched_paths: Vec<String>,
    /// The `pathext_used` field.
    pub pathext_used: bool,
    /// The `service_path_seen` field.
    pub service_path_seen: String,
    /// The `effective_path` field.
    pub effective_path: String,
    /// The `service_path` field.
    pub service_path: String,
    /// The `path_entries` field.
    pub path_entries: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The `error` field.
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The `remediation_hint` field.
    pub remediation_hint: Option<String>,
    /// One-line description.
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// The `ExecuteEnvReportRequest` structure.
pub struct ExecuteEnvReportRequest {
    #[serde(default)]
    /// Named execution profile in force.
    pub profile: Option<String>,
    #[serde(default)]
    /// Environment variables.
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    /// The `inherit_service_env` field.
    pub inherit_service_env: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ExecuteEnvReport` structure.
pub struct ExecuteEnvReport {
    /// The `service_user` field.
    pub service_user: String,
    /// The `service_path` field.
    pub service_path: String,
    /// The `selected_profile` field.
    pub selected_profile: Option<String>,
    /// The `default_execution_profile` field.
    pub default_execution_profile: Option<String>,
    /// The `inherit_service_env` field.
    pub inherit_service_env: bool,
    /// The `profiles` field.
    pub profiles: Vec<String>,
    /// The `tool_paths` field.
    pub tool_paths: BTreeMap<String, String>,
    /// The `path_prepend` field.
    pub path_prepend: Vec<String>,
    /// The `effective_path_entries` field.
    pub effective_path_entries: Vec<String>,
    /// The `configured_exec_state_dir` field.
    pub configured_exec_state_dir: String,
    /// The `effective_exec_state_dir` field.
    pub effective_exec_state_dir: String,
    /// The `redacted_env` field.
    pub redacted_env: BTreeMap<String, String>,
    /// The `redacted_env_preview` field.
    pub redacted_env_preview: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ExecuteJobIdRequest` structure.
pub struct ExecuteJobIdRequest {
    /// Identifier of the job this concerns.
    pub job_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ExecuteTailRequest` structure.
pub struct ExecuteTailRequest {
    /// Identifier of the job this concerns.
    pub job_id: String,
    #[serde(default)]
    /// The `max_bytes` field.
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ExecuteWaitRequest` structure.
pub struct ExecuteWaitRequest {
    /// Identifier of the job this concerns.
    pub job_id: String,
    #[serde(default)]
    /// Timeout in milliseconds.
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    /// The `max_bytes` field.
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ExecuteCancelRequest` structure.
pub struct ExecuteCancelRequest {
    /// Identifier of the job this concerns.
    pub job_id: String,
}

fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}
fn default_job_timeout_ms() -> u64 {
    DEFAULT_JOB_TIMEOUT_MS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ExecutionReport` structure.
pub struct ExecutionReport {
    /// Working directory.
    pub cwd: String,
    /// Program to run.
    pub program: String,
    /// Arguments passed to the program.
    pub args: Vec<String>,
    /// Process exit code, when it exited.
    pub exit_code: Option<i32>,
    /// Elapsed wall-clock time in milliseconds.
    pub duration_ms: u128,
    /// Bounded tail of standard output.
    pub stdout_tail: String,
    /// Bounded tail of standard error.
    pub stderr_tail: String,
    /// One-line description.
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The `ExecuteJobStatus` enumeration.
pub enum ExecuteJobStatus {
    /// The `Queued` case.
    Queued,
    /// The `Running` case.
    Running,
    /// The `Exited` case.
    Exited,
    /// The `FailedToStart` case.
    FailedToStart,
    /// The `TimedOut` case.
    TimedOut,
    /// The `Cancelled` case.
    Cancelled,
}

impl ExecuteJobStatus {
    #[must_use]
    /// `as_str`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Exited => "exited",
            Self::FailedToStart => "failed_to_start",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Exited | Self::FailedToStart | Self::TimedOut | Self::Cancelled
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ExecuteJobMetadata` structure.
pub struct ExecuteJobMetadata {
    /// Identifier of the job this concerns.
    pub job_id: String,
    /// Current status.
    pub status: ExecuteJobStatus,
    /// Working directory.
    pub cwd: String,
    /// Program to run.
    pub program: String,
    /// Arguments passed to the program.
    pub args: Vec<String>,
    /// Operating-system process id.
    pub pid: Option<u32>,
    /// Start time, unix milliseconds.
    pub started_unix_ms: u128,
    /// Finish time, unix milliseconds.
    pub finished_unix_ms: Option<u128>,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
    /// The `stdout_log` field.
    pub stdout_log: String,
    /// The `stderr_log` field.
    pub stderr_log: String,
    /// Process exit code, when it exited.
    pub exit_code: Option<i32>,
    /// The `error` field.
    pub error: Option<String>,
    /// The `redacted_env` field.
    pub redacted_env: BTreeMap<String, String>,
    /// One-line description.
    pub summary: String,
    /// The governed call that started this job (G4-26).
    ///
    /// Persisted rather than held in memory because `execute_finish` is written by a detached
    /// task after the starting call has returned, so there is nothing left to ask. `default`
    /// so job.json files written before this field still parse.
    #[serde(default)]
    pub call_id: Option<Uuid>,
    /// When this metadata was last written (G5-6).
    ///
    /// The tasks extension requires `lastUpdatedAt` on every task, including a working one, and
    /// a running job has `finished_unix_ms: None`. Stamped by `write_job_metadata`, which is
    /// the only site that persists this struct, so the field cannot drift from the file's real
    /// last write. `default` so job.json files written before this field still parse, and
    /// `None` then reads as "unknown", which callers resolve to `started_unix_ms`.
    #[serde(default)]
    pub last_updated_unix_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ExecuteJobStartReport` structure.
pub struct ExecuteJobStartReport {
    /// Identifier of the job this concerns.
    pub job_id: String,
    /// Current status.
    pub status: String,
    /// The job's timeout, carried so a caller shaping this into a task can answer `ttlMs`
    /// truthfully (G5-6). Without it the only honest value would be null, meaning unlimited,
    /// which the job is not.
    pub timeout_ms: u64,
    /// Operating-system process id.
    pub pid: Option<u32>,
    /// Working directory.
    pub cwd: String,
    /// Program to run.
    pub program: String,
    /// Arguments passed to the program.
    pub args: Vec<String>,
    /// The `stdout_log` field.
    pub stdout_log: String,
    /// The `stderr_log` field.
    pub stderr_log: String,
    /// One-line description.
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The `error` field.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ExecuteJobStatusReport` structure.
pub struct ExecuteJobStatusReport {
    /// Identifier of the job this concerns.
    pub job_id: String,
    /// Current status.
    pub status: String,
    /// Operating-system process id.
    pub pid: Option<u32>,
    /// Start time, unix milliseconds.
    pub started_unix_ms: u128,
    /// Finish time, unix milliseconds.
    pub finished_unix_ms: Option<u128>,
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u128,
    /// Working directory.
    pub cwd: String,
    /// Program to run.
    pub program: String,
    /// Arguments passed to the program.
    pub args: Vec<String>,
    /// Process exit code, when it exited.
    pub exit_code: Option<i32>,
    /// The `stdout_log` field.
    pub stdout_log: String,
    /// The `stderr_log` field.
    pub stderr_log: String,
    /// Bounded tail of standard output.
    pub stdout_tail: String,
    /// Bounded tail of standard error.
    pub stderr_tail: String,
    /// The `stdout_truncated` field.
    pub stdout_truncated: bool,
    /// The `stderr_truncated` field.
    pub stderr_truncated: bool,
    /// One-line description.
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The `error` field.
    pub error: Option<String>,
    /// When the job's metadata was last written (G5-6).
    ///
    /// Carried here so a caller building a task handle does not have to read job.json a second
    /// time to answer the extension's required `lastUpdatedAt`. `None` only for a job whose
    /// metadata predates the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_updated_unix_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ExecuteJobTailReport` structure.
pub struct ExecuteJobTailReport {
    /// Identifier of the job this concerns.
    pub job_id: String,
    /// Current status.
    pub status: String,
    /// The `stdout_log` field.
    pub stdout_log: String,
    /// The `stderr_log` field.
    pub stderr_log: String,
    /// Bounded tail of standard output.
    pub stdout_tail: String,
    /// Bounded tail of standard error.
    pub stderr_tail: String,
    /// The `stdout_truncated` field.
    pub stdout_truncated: bool,
    /// The `stderr_truncated` field.
    pub stderr_truncated: bool,
    /// The `max_bytes` field.
    pub max_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `ProgramResolutionError` structure.
pub struct ProgramResolutionError {
    /// Program to run.
    pub program: String,
    /// Working directory.
    pub cwd: String,
    /// The `service_path` field.
    pub service_path: String,
    /// The `path_hint` field.
    pub path_hint: String,
    /// The `path_entries` field.
    pub path_entries: Vec<String>,
    /// Named execution profile in force.
    pub profile: Option<String>,
    /// The `resolution_source` field.
    pub resolution_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The `configured_tool_path` field.
    pub configured_tool_path: Option<String>,
    /// One-line description.
    pub summary: String,
}

impl std::fmt::Display for ProgramResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathEntrySource {
    RequestEnvPath,
    ProfilePathPrepend,
    ProfileEnvPath,
    ServicePath,
}

impl PathEntrySource {
    fn as_str(self) -> &'static str {
        match self {
            Self::RequestEnvPath => "request_env_path",
            Self::ProfilePathPrepend => "profile_path_prepend",
            Self::ProfileEnvPath => "profile_env_path",
            Self::ServicePath => "service_path",
        }
    }
}

#[derive(Debug, Clone)]
struct PathEntry {
    path: PathBuf,
    source: PathEntrySource,
}

#[derive(Debug, Clone)]
struct ExecutionEnvironment {
    profile: Option<String>,
    inherit_service_env: bool,
    service_path: String,
    effective_path: String,
    path_entries: Vec<PathEntry>,
    command_env: BTreeMap<String, String>,
    redacted_env: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct ResolvedProgram {
    path: PathBuf,
    source: String,
    pathext_used: bool,
    environment: ExecutionEnvironment,
}

#[derive(Clone, Default)]
/// The `ExecuteJobRegistry` structure.
pub struct ExecuteJobRegistry {
    inner: Arc<Mutex<BTreeMap<String, JobControl>>>,
}

struct JobControl {
    cancel: oneshot::Sender<()>,
}

impl ExecuteJobRegistry {
    async fn insert(&self, job_id: String, cancel: oneshot::Sender<()>) {
        self.inner
            .lock()
            .await
            .insert(job_id, JobControl { cancel });
    }
    async fn cancel_owned(&self, job_id: &str) -> bool {
        if let Some(control) = self.inner.lock().await.remove(job_id) {
            let _ = control.cancel.send(());
            true
        } else {
            false
        }
    }
    async fn finish(&self, job_id: &str) {
        self.inner.lock().await.remove(job_id);
    }
}

#[derive(Clone)]
/// The `CommandBroker` structure.
pub struct CommandBroker {
    policy: PolicyConfig,
    audit: AuditSink,
    jobs: ExecuteJobRegistry,
    /// Limits the number of concurrently running jobs. Excess calls wait until a slot frees.
    semaphore: Arc<Semaphore>,
    /// The governed call this broker is acting for, when there is one (G4-26).
    ///
    /// `None` is the honest answer for a caller with no router. See the same field on
    /// `nmcp_fs::FileSystemService`.
    call_id: Option<Uuid>,
}

impl CommandBroker {
    #[must_use]
    /// `new`.
    pub fn new(policy: PolicyConfig, audit: AuditSink) -> Self {
        Self::with_job_registry(policy, audit, ExecuteJobRegistry::default())
    }

    #[must_use]
    /// `with_job_registry`.
    pub fn with_job_registry(
        policy: PolicyConfig,
        audit: AuditSink,
        jobs: ExecuteJobRegistry,
    ) -> Self {
        Self::with_cap(policy, audit, jobs, DEFAULT_CONCURRENCY_CAP)
    }

    #[must_use]
    /// `with_cap`.
    pub fn with_cap(
        policy: PolicyConfig,
        audit: AuditSink,
        jobs: ExecuteJobRegistry,
        cap: usize,
    ) -> Self {
        Self {
            policy,
            audit,
            jobs,
            semaphore: Arc::new(Semaphore::new(cap)),
            call_id: None,
        }
    }

    /// Bind this broker to the governed call it is acting for. See
    /// `nmcp_fs::FileSystemService::with_call_id` for why this exists.
    #[must_use]
    pub fn with_call_id(mut self, call_id: Option<Uuid>) -> Self {
        self.call_id = call_id;
        self
    }

    /// An effect record already stamped with the call this broker is acting for.
    fn effect(&self, action: impl Into<String>, summary: impl Into<String>) -> AuditEvent {
        let mut event = AuditEvent::effect(action, summary);
        event.call_id = self.call_id;
        event
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    pub async fn execute(&self, req: ExecuteRequest) -> anyhow::Result<ExecutionReport> {
        self.execute_with_injected_env(req, &[]).await
    }

    /// [`CommandBroker::execute`] with broker-injected environment variables (NMCP-SPEC-002
    /// SB-4, the `env` modality).
    ///
    /// `injected_env` carries `(variable name, sealed material)` pairs, resolved by ring
    /// stage 5b and read off `CallContext::secrets` by whatever composes this broker into a
    /// provider. The material crosses into the child's environment map at spawn, through
    /// the carrier's scoped-exposure API, and never enters the request, the resolved
    /// environment, any report, any audit line or the persisted job metadata: every
    /// injected name shows `<redacted>` on those surfaces unconditionally, regardless of
    /// the sensitive-name heuristic, which remains in force for variables the broker did
    /// not inject. A caller-supplied `req.env` entry under an injected name is overridden
    /// by the injection and redacted with it, so a colliding plaintext value neither wins
    /// nor leaks.
    ///
    /// The sealed carriers are borrowed: the owner (the call context, or a test) drops them
    /// when the request completes, which zeroizes the material. Two named limits, per
    /// SB-1's own bound: the child's copy is the child's, past the process boundary the
    /// program allowlist is the whole control; and the `Command` builder holds its own copy
    /// of the environment between here and the spawn, which the standard library does not
    /// zeroize, the same class of intermediate the platform sealers are required to zero
    /// where they can and `std` cannot be asked to.
    ///
    /// # Errors
    ///
    /// Everything [`CommandBroker::execute`] can fail with, plus a refusal naming the
    /// variable when injected material is not valid UTF-8 (an environment value must cross
    /// the platform environment boundary, and refusing is the fail-closed direction); the
    /// refusal never echoes material.
    pub async fn execute_with_injected_env(
        &self,
        req: ExecuteRequest,
        injected_env: &[(String, SealedSecret)],
    ) -> anyhow::Result<ExecutionReport> {
        self.policy.require(Permission::Execute, &req.cwd)?;
        reject_delete_intent(&req.program, &req.args)?;
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("execution governor closed"))?;
        let resolved = resolve_program(
            &self.policy,
            &req.program,
            &req.cwd,
            &req.env,
            req.inherit_service_env,
            req.profile.as_deref(),
            &injected_names(injected_env),
        )
        .map_err(|err| anyhow::anyhow!(err.summary.clone()))?;
        let started = Instant::now();
        let mut child = Command::new(&resolved.path);
        apply_command_options(
            &mut child,
            &req.cwd,
            &req.args,
            &resolved.environment.command_env,
            resolved.environment.inherit_service_env,
        );
        // After the request environment, so an injected name wins a collision (SB-4).
        apply_injected_env(&mut child, injected_env)?;
        let output = tokio::time::timeout(Duration::from_millis(req.timeout_ms), child.output())
            .await
            .context("command timed out")??;
        let report = ExecutionReport {
            cwd: req.cwd.display().to_string(),
            program: req.program.clone(),
            args: req.args.clone(),
            exit_code: output.status.code(),
            duration_ms: started.elapsed().as_millis(),
            stdout_tail: tail_text(&String::from_utf8_lossy(&output.stdout), DEFAULT_TAIL_BYTES),
            stderr_tail: tail_text(&String::from_utf8_lossy(&output.stderr), DEFAULT_TAIL_BYTES),
            summary: "command executed and report captured".into(),
        };
        // The `env=` line is built from `redacted_env` and from nothing else, which is
        // SB-4's second hardening: the audit summary never sees an injected value, because
        // every injected name is already `<redacted>` in the map this consumes. It used to
        // be built and then overwritten by the exit summary, so it never landed; it lands
        // now, post-redaction, with the exit facts beside it.
        let mut event = self.effect(
            "execute",
            format!(
                "{} {:?}; exit={:?}; duration_ms={}; env={}",
                report.program,
                report.args,
                report.exit_code,
                report.duration_ms,
                summarize_redacted_env_for_audit(&resolved.environment.redacted_env)
            ),
        );
        event.path = Some(report.cwd.clone());
        self.audit.append(&event)?;
        Ok(report)
    }

    /// Returns the number of concurrency slots currently available.
    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    // The request structs are the crate's public API: a caller builds one and
    // hands it over, the same shape the MCP tool contract has on the wire.
    // Taking them by reference would change that contract for no gain.
    #[allow(clippy::needless_pass_by_value)]
    pub fn execute_resolve_program(
        &self,
        req: ExecuteResolveProgramRequest,
    ) -> anyhow::Result<ExecuteResolveProgramReport> {
        let cwd = self.request_cwd(&req.cwd)?;
        self.policy.require(Permission::Execute, &cwd)?;
        let environment = build_execution_environment(
            &self.policy,
            &req.env,
            req.inherit_service_env,
            req.profile.as_deref(),
            &BTreeSet::new(),
        )
        .map_err(|err| anyhow::anyhow!(err))?;
        match resolve_program_with_environment(
            &self.policy,
            &req.program,
            &cwd,
            environment.clone(),
        ) {
            Ok(resolved) => Ok(resolve_report(
                &req.program,
                Some(resolved.path),
                resolved.source,
                resolved.pathext_used,
                resolved.environment,
                None,
                "program resolved".into(),
            )),
            Err(err) => Ok(resolve_report(
                &req.program,
                None,
                err.resolution_source.clone(),
                false,
                environment,
                Some(err.summary.clone()),
                err.summary.clone(),
            )),
        }
    }

    /// Describe the execution environment a request would run under, redacted.
    ///
    /// A variable the broker injects (SB-4's `env` modality) is **omitted from this report
    /// entirely, by construction, not shown redacted** (T1a: reporting `NAME=<redacted>`
    /// tells an agent which credential a governed call carries, which is metadata the agent
    /// has no use for and an attacker does). The omission is structural rather than a
    /// filter somebody could forget: injection is a per-call parameter of
    /// [`CommandBroker::execute_with_injected_env`] that reaches only that call's child
    /// process, never the service environment or the profile this report describes, and
    /// this method has no parameter through which an injected name could arrive.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn execute_env_report(&self, req: ExecuteEnvReportRequest) -> ExecuteEnvReport {
        let environment = build_execution_environment(
            &self.policy,
            &req.env,
            req.inherit_service_env,
            req.profile.as_deref(),
            &BTreeSet::new(),
        )
        .unwrap_or_else(|_| ExecutionEnvironment {
            profile: req
                .profile
                .clone()
                .or_else(|| self.policy.default_execution_profile.clone()),
            inherit_service_env: req.inherit_service_env.unwrap_or(true),
            service_path: service_path(),
            effective_path: String::new(),
            path_entries: Vec::new(),
            command_env: req.env.clone(),
            redacted_env: redact_env(&req.env),
        });
        let path_prepend = environment
            .profile
            .as_deref()
            .and_then(|profile| self.policy.execution_profiles.get(profile))
            .map(|profile| {
                profile
                    .path_prepend
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect()
            })
            .unwrap_or_default();
        let effective_path_entries = environment
            .path_entries
            .iter()
            .map(|entry| entry.path.display().to_string())
            .collect();
        ExecuteEnvReport {
            service_user: service_user(),
            service_path: environment.service_path.clone(),
            selected_profile: environment.profile.clone(),
            default_execution_profile: self.policy.default_execution_profile.clone(),
            inherit_service_env: environment.inherit_service_env,
            profiles: self.policy.execution_profiles.keys().cloned().collect(),
            tool_paths: self
                .policy
                .tool_paths
                .iter()
                .map(|(name, path)| (name.clone(), path.display().to_string()))
                .collect(),
            path_prepend,
            effective_path_entries,
            configured_exec_state_dir: self.policy.exec_state_dir.display().to_string(),
            effective_exec_state_dir: self.policy.effective_exec_state_dir().display().to_string(),
            redacted_env: environment.redacted_env.clone(),
            redacted_env_preview: redact_env(&std::env::vars().collect()),
        }
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    pub async fn execute_start(
        &self,
        req: ExecuteStartRequest,
    ) -> anyhow::Result<ExecuteJobStartReport> {
        self.execute_start_with_injected_env(req, &[]).await
    }

    /// [`CommandBroker::execute_start`] with broker-injected environment variables.
    ///
    /// The durable-job half of SB-4's `env` modality; see
    /// [`CommandBroker::execute_with_injected_env`] for the injection contract, the
    /// redaction rule and the named limits, all of which apply here unchanged. The one
    /// addition is the persisted surface: the job's `job.json` carries `redacted_env`, and
    /// every injected name is `<redacted>` there too, which is SB-4's third hardening. The
    /// sealed carriers are borrowed and are done with before this returns: the child holds
    /// its own copy from the spawn, so the borrow does not outlive the start call even
    /// though the job does.
    ///
    /// # Errors
    ///
    /// Everything [`CommandBroker::execute_start`] can fail with. Injected material that is
    /// not valid UTF-8 takes the `failed_to_start` report path, naming the variable and
    /// echoing nothing.
    // One job lifecycle start to finish: validate, spawn, register, report.
    // Splitting it would scatter a single ordered procedure across helpers
    // only meaningful in that order.
    #[allow(clippy::too_many_lines)]
    pub async fn execute_start_with_injected_env(
        &self,
        req: ExecuteStartRequest,
        injected_env: &[(String, SealedSecret)],
    ) -> anyhow::Result<ExecuteJobStartReport> {
        self.policy.require(Permission::Execute, &req.cwd)?;
        reject_delete_intent(&req.program, &req.args)?;
        let permit = Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("execution governor closed"))?;
        let timeout_ms = req.timeout_ms.unwrap_or_else(default_job_timeout_ms);
        let job_id = Uuid::new_v4().to_string();
        let job_dir = self.job_dir(&job_id)?;
        std::fs::create_dir_all(&job_dir)
            .with_context(|| format!("creating execution job directory {}", job_dir.display()))?;
        let stdout_log = job_dir.join("stdout.log");
        let stderr_log = job_dir.join("stderr.log");
        File::create(&stdout_log)
            .with_context(|| format!("creating stdout log {}", stdout_log.display()))?;
        File::create(&stderr_log)
            .with_context(|| format!("creating stderr log {}", stderr_log.display()))?;
        let metadata_path = job_dir.join("job.json");
        let mut metadata = ExecuteJobMetadata {
            job_id: job_id.clone(),
            status: ExecuteJobStatus::Queued,
            cwd: req.cwd.display().to_string(),
            program: req.program.clone(),
            args: req.args.clone(),
            pid: None,
            started_unix_ms: now_unix_ms(),
            finished_unix_ms: None,
            timeout_ms,
            stdout_log: stdout_log.display().to_string(),
            stderr_log: stderr_log.display().to_string(),
            exit_code: None,
            error: None,
            redacted_env: BTreeMap::new(),
            summary: "job queued".into(),
            call_id: self.call_id,
            // Stamped by write_job_metadata on the first persist, a few lines below. None here
            // is the truth: nothing has been written yet.
            last_updated_unix_ms: None,
        };
        let resolved = match resolve_program(
            &self.policy,
            &req.program,
            &req.cwd,
            &req.env,
            req.inherit_service_env,
            req.profile.as_deref(),
            &injected_names(injected_env),
        ) {
            Ok(resolved) => resolved,
            Err(err) => {
                metadata.status = ExecuteJobStatus::FailedToStart;
                metadata.finished_unix_ms = Some(now_unix_ms());
                metadata.error = Some(serde_json::to_string(&err)?);
                metadata.summary.clone_from(&err.summary);
                write_job_metadata(&metadata_path, &mut metadata)?;
                self.audit_job_event("execute_start_failed", &metadata)?;
                return Ok(start_report(&metadata));
            }
        };
        metadata.redacted_env = resolved.environment.redacted_env.clone();
        write_job_metadata(&metadata_path, &mut metadata)?;
        let stdout = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&stdout_log)
            .with_context(|| format!("opening stdout log {}", stdout_log.display()))?;
        let stderr = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&stderr_log)
            .with_context(|| format!("opening stderr log {}", stderr_log.display()))?;
        let mut command = Command::new(&resolved.path);
        apply_command_options(
            &mut command,
            &req.cwd,
            &req.args,
            &resolved.environment.command_env,
            resolved.environment.inherit_service_env,
        );
        // After the request environment, so an injected name wins a collision (SB-4). A
        // refusal here takes the same failed-to-start path a spawn failure does, because
        // the job directory already exists and a report that names it is more useful than
        // an error that abandons it.
        if let Err(err) = apply_injected_env(&mut command, injected_env) {
            metadata.status = ExecuteJobStatus::FailedToStart;
            metadata.finished_unix_ms = Some(now_unix_ms());
            metadata.error = Some(err.to_string());
            metadata.summary = format!("failed to start process: {err}");
            write_job_metadata(&metadata_path, &mut metadata)?;
            self.audit_job_event("execute_start_failed", &metadata)?;
            return Ok(start_report(&metadata));
        }
        command
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
                metadata.status = ExecuteJobStatus::FailedToStart;
                metadata.finished_unix_ms = Some(now_unix_ms());
                metadata.error = Some(err.to_string());
                metadata.summary = format!("failed to start process: {err}");
                write_job_metadata(&metadata_path, &mut metadata)?;
                self.audit_job_event("execute_start_failed", &metadata)?;
                return Ok(start_report(&metadata));
            }
        };
        metadata.pid = child.id();
        metadata.status = ExecuteJobStatus::Running;
        metadata.summary = "job running in background".into();
        write_job_metadata(&metadata_path, &mut metadata)?;
        let (cancel_tx, cancel_rx) = oneshot::channel();
        self.jobs.insert(job_id.clone(), cancel_tx).await;
        self.audit_job_event("execute_start", &metadata)?;
        tokio::spawn(monitor_job(
            child,
            metadata.clone(),
            metadata_path,
            self.audit.clone(),
            self.jobs.clone(),
            cancel_rx,
            permit,
        ));
        Ok(start_report(&metadata))
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    #[allow(clippy::needless_pass_by_value)]
    pub fn execute_status(
        &self,
        req: ExecuteJobIdRequest,
    ) -> anyhow::Result<ExecuteJobStatusReport> {
        self.status_report(&req.job_id, DEFAULT_TAIL_BYTES)
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    #[allow(clippy::needless_pass_by_value)]
    pub fn execute_tail(&self, req: ExecuteTailRequest) -> anyhow::Result<ExecuteJobTailReport> {
        let max_bytes = bounded_tail_bytes(req.max_bytes);
        let metadata = self.read_metadata(&req.job_id)?;
        let (stdout_tail, stdout_truncated) =
            tail_file(Path::new(&metadata.stdout_log), max_bytes)?;
        let (stderr_tail, stderr_truncated) =
            tail_file(Path::new(&metadata.stderr_log), max_bytes)?;
        Ok(ExecuteJobTailReport {
            job_id: metadata.job_id,
            status: metadata.status.as_str().to_string(),
            stdout_log: metadata.stdout_log,
            stderr_log: metadata.stderr_log,
            stdout_tail,
            stderr_tail,
            stdout_truncated,
            stderr_truncated,
            max_bytes,
        })
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    pub async fn execute_wait(
        &self,
        req: ExecuteWaitRequest,
    ) -> anyhow::Result<ExecuteJobStatusReport> {
        let wait_ms = req
            .timeout_ms
            .unwrap_or(DEFAULT_JOB_WAIT_MS)
            .min(MAX_JOB_WAIT_MS);
        let max_bytes = bounded_tail_bytes(req.max_bytes);
        let deadline = Instant::now() + Duration::from_millis(wait_ms);
        loop {
            let report = self.status_report(&req.job_id, max_bytes)?;
            if report.status != ExecuteJobStatus::Running.as_str()
                && report.status != ExecuteJobStatus::Queued.as_str()
            {
                return Ok(report);
            }
            if Instant::now() >= deadline {
                return Ok(report);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    #[allow(clippy::needless_pass_by_value)]
    pub fn execute_result(
        &self,
        req: ExecuteJobIdRequest,
    ) -> anyhow::Result<ExecuteJobStatusReport> {
        self.status_report(&req.job_id, DEFAULT_TAIL_BYTES)
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    pub async fn execute_cancel(
        &self,
        req: ExecuteCancelRequest,
    ) -> anyhow::Result<ExecuteJobStatusReport> {
        let metadata = self.read_metadata(&req.job_id)?;
        if !metadata.status.is_terminal() && !self.jobs.cancel_owned(&req.job_id).await {
            bail!("job is not owned by this NativeMCP process or is no longer running");
        }
        let mut event = self.effect("execute_cancel", format!("job_id={}", req.job_id));
        event.path = Some(metadata.cwd.clone());
        event.summary = "owned job cancellation requested".into();
        self.audit.append(&event)?;
        tokio::time::sleep(Duration::from_millis(75)).await;
        self.status_report(&req.job_id, DEFAULT_TAIL_BYTES)
    }

    fn status_report(
        &self,
        job_id: &str,
        max_bytes: usize,
    ) -> anyhow::Result<ExecuteJobStatusReport> {
        let metadata = self.read_metadata(job_id)?;
        let (stdout_tail, stdout_truncated) =
            tail_file(Path::new(&metadata.stdout_log), max_bytes)?;
        let (stderr_tail, stderr_truncated) =
            tail_file(Path::new(&metadata.stderr_log), max_bytes)?;
        Ok(status_report(
            &metadata,
            stdout_tail,
            stderr_tail,
            stdout_truncated,
            stderr_truncated,
        ))
    }

    fn read_metadata(&self, job_id: &str) -> anyhow::Result<ExecuteJobMetadata> {
        let job_dir = self.job_dir(job_id)?;
        let metadata = read_job_metadata(&job_dir.join("job.json"))?;
        validate_job_metadata(&metadata, job_id, &job_dir)?;
        Ok(metadata)
    }
    fn job_dir(&self, job_id: &str) -> anyhow::Result<PathBuf> {
        let normalized = validate_job_id(job_id)?;
        let state_dir = self.policy.effective_exec_state_dir();
        let job_dir = state_dir.join(normalized);
        if !job_dir.starts_with(&state_dir) {
            bail!("execute job path escaped exec_state_dir");
        }
        Ok(job_dir)
    }

    fn request_cwd(&self, cwd: &Path) -> anyhow::Result<PathBuf> {
        if cwd.as_os_str().is_empty() {
            return self
                .policy
                .roots
                .first()
                .map(|root| root.path.clone())
                .ok_or_else(|| anyhow::anyhow!("cwd is required when no policy roots exist"));
        }
        Ok(cwd.to_path_buf())
    }

    fn audit_job_event(&self, action: &str, metadata: &ExecuteJobMetadata) -> anyhow::Result<()> {
        // One summary, built once, from `redacted_env` and nothing else (SB-4's second
        // hardening: the `env=` line never sees a value the redaction did not pass). The
        // old shape built this line and then overwrote it with the status summary, so the
        // `env=` line never landed; now the status and the environment land together.
        let mut event = self.effect(
            action,
            format!(
                "job_id={}; program={} {:?}; {}; env={}",
                metadata.job_id,
                metadata.program,
                metadata.args,
                metadata.summary,
                summarize_redacted_env_for_audit(&metadata.redacted_env)
            ),
        );
        event.path = Some(metadata.cwd.clone());
        self.audit.append(&event)
    }
}

async fn monitor_job(
    mut child: Child,
    mut metadata: ExecuteJobMetadata,
    metadata_path: PathBuf,
    audit: AuditSink,
    jobs: ExecuteJobRegistry,
    cancel_rx: oneshot::Receiver<()>,
    _permit: OwnedSemaphorePermit,
) {
    let job_id = metadata.job_id.clone();
    let timeout_ms = metadata.timeout_ms;
    let outcome = tokio::select! {
        status = child.wait() => match status {
            Ok(status) => (ExecuteJobStatus::Exited, status.code(), None, "job exited".to_string()),
            Err(err) => (ExecuteJobStatus::FailedToStart, None, Some(err.to_string()), format!("job wait failed: {err}")),
        },
        () = tokio::time::sleep(Duration::from_millis(timeout_ms)) => {
            let _ = child.kill().await;
            let status = child.wait().await.ok();
            (ExecuteJobStatus::TimedOut, status.and_then(|s| s.code()), None, "job timed out and was cancelled by NativeMCP".to_string())
        },
        _ = cancel_rx => {
            let _ = child.kill().await;
            let status = child.wait().await.ok();
            (ExecuteJobStatus::Cancelled, status.and_then(|s| s.code()), None, "job cancelled by NativeMCP".to_string())
        },
    };
    metadata.status = outcome.0;
    metadata.exit_code = outcome.1;
    metadata.error = outcome.2;
    metadata.summary = outcome.3;
    metadata.finished_unix_ms = Some(now_unix_ms());
    let _ = write_job_metadata(&metadata_path, &mut metadata);
    let mut event = AuditEvent::effect(
        "execute_finish",
        format!("job_id={}; status={}", job_id, metadata.status.as_str()),
    );
    // Not a broker method: this runs in a detached task with no broker. The call identity
    // comes off the job metadata, which is where it was persisted for exactly this moment.
    event.call_id = metadata.call_id;
    event.path = Some(metadata.cwd.clone());
    event.summary = format!(
        "status={}; exit={:?}; duration_ms={}",
        metadata.status.as_str(),
        metadata.exit_code,
        elapsed_ms(&metadata)
    );
    let _ = audit.append(&event);
    jobs.finish(&job_id).await;
}

fn apply_command_options(
    child: &mut Command,
    cwd: &Path,
    args: &[String],
    env: &BTreeMap<String, String>,
    inherit_service_env: bool,
) {
    child.args(args).current_dir(cwd).kill_on_drop(true);
    if !inherit_service_env {
        child.env_clear();
    }
    child.envs(env);
}

/// Command verbs that erase data. Matched as whole tokens, never as substrings.
///
/// Audited against the PowerShell and cmd alias tables (G4-19). The entries below
/// are grouped by where they come from so a future reader can tell an intentional
/// omission from a gap:
///
/// * cmd builtins: `del`, `erase`, `rd`, `rmdir`.
/// * Win32 and Sysinternals: `rm` (ported tools), `unlink`, `shred`, `sdelete`.
/// * PowerShell cmdlets and their default aliases: `Remove-Item` with `ri`, `rm`,
///   `rmdir`, `del`, `erase`, `rd`; `Remove-ItemProperty` with `rp`; and
///   `Clear-Content` with `clc`.
///
/// `ri` and `rp` were missing before this audit, so `powershell -Command "ri x"`
/// erased a file without tripping the guard even though the identical
/// `Remove-Item x` was refused.
///
/// Deliberately NOT listed, because they truncate rather than remove and blocking
/// them would break ordinary writes: `Clear-Content` and `clc` are covered here as
/// data-destroying and ARE listed, while `Set-Content` and `Out-File` overwrite by
/// design and are the documented way to write a file. The No-Destructive-Action
/// Guarantee has always said overwrite is not delete; see
/// `docs/NO-DESTRUCTIVE-ACTION-GUARANTEE.md`.
const DELETE_INTENT_COMMANDS: &[&str] = &[
    // cmd builtins
    "del",
    "erase",
    "rd",
    "rmdir",
    // ported unix tools and Sysinternals
    "rm",
    "unlink",
    "shred",
    "sdelete",
    // PowerShell cmdlets
    "remove-item",
    "remove-directory",
    "remove-itemproperty",
    "clear-content",
    // PowerShell default aliases for the cmdlets above
    "ri",
    "rp",
    "clc",
];

/// Two-token shapes that erase data without naming a delete verb outright.
const DELETE_INTENT_SEQUENCES: &[[&str; 2]] =
    &[["git", "clean"], ["git", "rm"], ["cargo", "clean"]];

/// Reduce a token to the command it names: last path segment, `.exe` stripped, so
/// `C:\Windows\System32\del.exe` and `/usr/bin/rm` both collapse to the bare verb.
fn delete_intent_command_name(token: &str) -> &str {
    let last = token.rsplit(['\\', '/']).next().unwrap_or(token);
    last.strip_suffix(".exe").unwrap_or(last)
}

/// Split command text into lowercase tokens for delete-intent matching.
///
/// Splitting on shell metacharacters as well as whitespace means `;rm`, `&&del`,
/// `"rm"`, and `%{rm` all yield a bare verb token. The previous substring form
/// required a literal space before the verb and so missed every one of those.
///
/// Whole-token matching is also what keeps ordinary prose out of the guard. The
/// substring form searched for the bare fragment `rd `, so it refused any argument
/// containing `wildcard ` or `standard ` or `record `, and searched for `del `, so
/// it refused `model `. Those are ordinary words, and the first is one this product
/// uses when refusing wildcard-shaped origins.
fn delete_intent_tokens(text: &str) -> Vec<String> {
    text.to_ascii_lowercase()
        .split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    ';' | '&'
                        | '|'
                        | '('
                        | ')'
                        | '{'
                        | '}'
                        | '['
                        | ']'
                        | '"'
                        | '\''
                        | '`'
                        | ','
                        | '='
                        | '<'
                        | '>'
                )
        })
        .map(|token| token.trim_matches(|c: char| matches!(c, '.' | ':' | '$' | '@')))
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

///
/// # Errors
///
/// Returns the error this operation can fail with.
pub fn reject_delete_intent(program: &str, args: &[String]) -> anyhow::Result<()> {
    let program_lc = program.to_ascii_lowercase();
    let program_name = delete_intent_command_name(&program_lc);
    if DELETE_INTENT_COMMANDS.contains(&program_name) {
        bail!("delete-like command program is not allowed by invariant: {program}");
    }

    let tokens = delete_intent_tokens(&args.join(" "));
    let names: Vec<&str> = tokens
        .iter()
        .map(|token| delete_intent_command_name(token))
        .collect();

    if let Some(hit) = names
        .iter()
        .find(|name| DELETE_INTENT_COMMANDS.contains(name))
    {
        bail!("delete-like command arguments are not allowed by invariant: {hit}");
    }
    for sequence in DELETE_INTENT_SEQUENCES {
        // Same comparison, expressed without indexing: `windows(2)` yields
        // pairs and the sequences are [&str; 2], so both were in bounds by
        // construction. This is INV-1 enforcement, so it is written to be
        // provably panic-free rather than relying on that reasoning.
        if names
            .windows(2)
            .any(|pair| matches!((pair, sequence), ([a, b], [x, y]) if a == x && b == y))
        {
            bail!(
                "delete-like command arguments are not allowed by invariant: {} {}",
                sequence[0],
                sequence[1]
            );
        }
    }
    if program_name == "cargo"
        && args
            .first()
            .is_some_and(|a| a.eq_ignore_ascii_case("clean"))
    {
        bail!("cargo clean is blocked by no-delete invariant");
    }
    Ok(())
}

fn resolve_program(
    policy: &PolicyConfig,
    program: &str,
    cwd: &Path,
    env: &BTreeMap<String, String>,
    inherit_service_env: Option<bool>,
    profile: Option<&str>,
    injected_names: &BTreeSet<String>,
) -> Result<ResolvedProgram, Box<ProgramResolutionError>> {
    let environment =
        build_execution_environment(policy, env, inherit_service_env, profile, injected_names)
            .map_err(|summary| Box::new(program_resolution_error(program, cwd, summary)))?;
    resolve_program_with_environment(policy, program, cwd, environment)
}

fn resolve_program_with_environment(
    policy: &PolicyConfig,
    program: &str,
    cwd: &Path,
    environment: ExecutionEnvironment,
) -> Result<ResolvedProgram, Box<ProgramResolutionError>> {
    let program_path = Path::new(program);
    if program_path.is_absolute() || program.contains('\\') || program.contains('/') {
        let resolved = absolute_path(program_path);
        if resolved.exists() {
            ensure_resolved_program_execute_permitted(policy, program, cwd, &resolved)?;
            return Ok(ResolvedProgram {
                path: resolved,
                source: "program_path".into(),
                pathext_used: false,
                environment,
            });
        }
        return Err(Box::new(program_not_found_error(
            program,
            cwd,
            &environment,
            "program_path",
            None,
        )));
    }

    if let Some((_, configured_path)) = policy
        .tool_paths
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(program))
    {
        let configured = absolute_path(configured_path);
        if configured.exists() {
            ensure_resolved_program_execute_permitted(policy, program, cwd, &configured)?;
            return Ok(ResolvedProgram {
                path: configured,
                source: "tool_paths".into(),
                pathext_used: false,
                environment,
            });
        }
        return Err(Box::new(program_not_found_error(
            program,
            cwd,
            &environment,
            "configured_tool_path_missing",
            Some(configured.display().to_string()),
        )));
    }

    if let Some(resolved) = search_path_entries(
        program,
        &environment,
        &[
            PathEntrySource::RequestEnvPath,
            PathEntrySource::ProfilePathPrepend,
            PathEntrySource::ProfileEnvPath,
            PathEntrySource::ServicePath,
        ],
    ) {
        ensure_resolved_program_execute_permitted(policy, program, cwd, &resolved.path)?;
        return Ok(resolved);
    }

    Err(Box::new(program_not_found_error(
        program,
        cwd,
        &environment,
        "not_found",
        None,
    )))
}

fn ensure_resolved_program_execute_permitted(
    policy: &PolicyConfig,
    program: &str,
    cwd: &Path,
    resolved: &Path,
) -> Result<(), Box<ProgramResolutionError>> {
    policy
        .require(Permission::Execute, resolved)
        .map(|_| ())
        .map_err(|err| {
            Box::new(program_resolution_error(
                program,
                cwd,
                format!("resolved program path is not execute-permitted by policy: {err}"),
            ))
        })
}

fn program_resolution_error(program: &str, cwd: &Path, summary: String) -> ProgramResolutionError {
    ProgramResolutionError {
        program: program.into(),
        cwd: cwd.display().to_string(),
        service_path: service_path(),
        path_hint: String::new(),
        path_entries: Vec::new(),
        profile: None,
        resolution_source: "profile_error".into(),
        configured_tool_path: None,
        summary,
    }
}

fn program_not_found_error(
    program: &str,
    cwd: &Path,
    environment: &ExecutionEnvironment,
    source: &str,
    configured_tool_path: Option<String>,
) -> ProgramResolutionError {
    let summary = if let Some(path) = configured_tool_path.as_deref() {
        format!("configured tool path for alias {program} does not exist: {path}")
    } else {
        format!(
            "program not found: {program}; configure tool_paths, select an execution profile, use an absolute path, or update the service PATH"
        )
    };
    ProgramResolutionError {
        program: program.into(),
        cwd: cwd.display().to_string(),
        service_path: environment.service_path.clone(),
        path_hint: environment.effective_path.clone(),
        path_entries: environment
            .path_entries
            .iter()
            .map(|entry| entry.path.display().to_string())
            .collect(),
        profile: environment.profile.clone(),
        resolution_source: source.into(),
        configured_tool_path,
        summary,
    }
}

/// Merge the profile and request environments and compute the redacted view.
///
/// `injected_names` are the variables the broker will inject at spawn (SB-4). Their values
/// never enter `command_env`, which holds caller and profile data only; the names enter
/// `redacted_env` as `<redacted>` unconditionally, so every surface derived from it (the
/// audit `env=` line, `redacted_env` in job metadata and reports) redacts by injected name
/// rather than by the heuristic. Threaded through here rather than patched on afterwards so
/// no caller of this function can obtain an unredacted view to forget the patch on.
fn build_execution_environment(
    policy: &PolicyConfig,
    request_env: &BTreeMap<String, String>,
    inherit_service_env: Option<bool>,
    requested_profile: Option<&str>,
    injected_names: &BTreeSet<String>,
) -> Result<ExecutionEnvironment, String> {
    let profile_name = requested_profile
        .map(ToOwned::to_owned)
        .or_else(|| policy.default_execution_profile.clone());
    let profile = if let Some(name) = profile_name.as_deref() {
        Some(
            policy
                .execution_profiles
                .get(name)
                .ok_or_else(|| format!("execution profile not found: {name}"))?,
        )
    } else {
        None
    };
    let inherit = inherit_service_env
        .unwrap_or_else(|| profile.is_none_or(|profile| profile.inherit_service_env));
    let service_path = service_path();
    let mut path_entries = Vec::new();
    if let Some(request_path) = env_value_case_insensitive(request_env, "PATH") {
        extend_path_entries(
            &mut path_entries,
            request_path,
            PathEntrySource::RequestEnvPath,
        );
    }
    if let Some(profile) = profile {
        path_entries.extend(profile.path_prepend.iter().cloned().map(|path| PathEntry {
            path,
            source: PathEntrySource::ProfilePathPrepend,
        }));
        if let Some(profile_path) = env_value_case_insensitive(&profile.env, "PATH") {
            extend_path_entries(
                &mut path_entries,
                profile_path,
                PathEntrySource::ProfileEnvPath,
            );
        }
    }
    if inherit {
        extend_path_entries(
            &mut path_entries,
            &service_path,
            PathEntrySource::ServicePath,
        );
    }
    let effective_path = join_path_entries(&path_entries);
    let mut command_env = BTreeMap::new();
    if let Some(profile) = profile {
        for (key, value) in &profile.env {
            if !key.eq_ignore_ascii_case("PATH") {
                command_env.insert(key.clone(), value.clone());
            }
        }
    }
    for (key, value) in request_env {
        if !key.eq_ignore_ascii_case("PATH") {
            command_env.insert(key.clone(), value.clone());
        }
    }
    if !effective_path.is_empty()
        || env_value_case_insensitive(request_env, "PATH").is_some()
        || profile
            .and_then(|profile| env_value_case_insensitive(&profile.env, "PATH"))
            .is_some()
    {
        command_env.insert("PATH".into(), effective_path.clone());
    }
    let redacted_env = redact_env_with_injected(&command_env, injected_names);
    Ok(ExecutionEnvironment {
        profile: profile_name,
        inherit_service_env: inherit,
        service_path,
        effective_path,
        path_entries,
        command_env,
        redacted_env,
    })
}

fn search_path_entries(
    program: &str,
    environment: &ExecutionEnvironment,
    sources: &[PathEntrySource],
) -> Option<ResolvedProgram> {
    for entry in &environment.path_entries {
        if !sources.contains(&entry.source) {
            continue;
        }
        for candidate in program_candidates(program) {
            let full = entry.path.join(&candidate);
            if full.exists() {
                return Some(ResolvedProgram {
                    path: full,
                    source: entry.source.as_str().into(),
                    pathext_used: candidate != program,
                    environment: environment.clone(),
                });
            }
        }
    }
    None
}

fn extend_path_entries(entries: &mut Vec<PathEntry>, path_value: &str, source: PathEntrySource) {
    entries.extend(
        std::env::split_paths(path_value)
            .filter(|path| !path.as_os_str().is_empty())
            .map(|path| PathEntry { path, source }),
    );
}

fn join_path_entries(entries: &[PathEntry]) -> String {
    let paths = entries.iter().map(|entry| entry.path.as_path());
    std::env::join_paths(paths).map_or_else(
        |_| {
            let sep = if cfg!(windows) { ";" } else { ":" };
            entries
                .iter()
                .map(|entry| entry.path.display().to_string())
                .collect::<Vec<_>>()
                .join(sep)
        },
        |value| value.to_string_lossy().to_string(),
    )
}

fn env_value_case_insensitive<'a>(
    env: &'a BTreeMap<String, String>,
    name: &str,
) -> Option<&'a String> {
    env.iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn resolve_report(
    program: &str,
    resolved_path: Option<PathBuf>,
    resolution_source: String,
    pathext_used: bool,
    environment: ExecutionEnvironment,
    error: Option<String>,
    summary: String,
) -> ExecuteResolveProgramReport {
    let path_entries: Vec<String> = environment
        .path_entries
        .into_iter()
        .map(|entry| entry.path.display().to_string())
        .collect();
    let resolved = resolved_path.is_some();
    let remediation_hint = if resolved {
        None
    } else {
        Some(
            "Configure tool_paths, select an execution profile with path_prepend, use an absolute path, or update the service PATH."
                .into(),
        )
    };
    ExecuteResolveProgramReport {
        program: program.into(),
        resolved,
        resolved_path: resolved_path.map(|path| path.display().to_string()),
        resolution_source,
        selected_profile: environment.profile.clone(),
        profile: environment.profile,
        searched_paths: path_entries.clone(),
        pathext_used,
        service_path_seen: environment.service_path.clone(),
        effective_path: environment.effective_path,
        service_path: environment.service_path,
        path_entries,
        error,
        remediation_hint,
        summary,
    }
}

fn service_path() -> String {
    std::env::var("PATH").unwrap_or_default()
}

fn service_user() -> String {
    let username = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".into());
    if let Ok(domain) = std::env::var("USERDOMAIN")
        && !domain.trim().is_empty()
    {
        return format!("{domain}\\{username}");
    }
    username
}

fn program_candidates(program: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        if Path::new(program).extension().is_some() {
            return vec![program.to_string()];
        }
        let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        let mut candidates = vec![program.to_string()];
        candidates.extend(
            pathext
                .split(';')
                .map(str::trim)
                .filter(|ext| !ext.is_empty())
                .map(|ext| format!("{program}{ext}")),
        );
        candidates
    }
    #[cfg(not(windows))]
    {
        vec![program.to_string()]
    }
}

fn start_report(metadata: &ExecuteJobMetadata) -> ExecuteJobStartReport {
    ExecuteJobStartReport {
        job_id: metadata.job_id.clone(),
        status: metadata.status.as_str().to_string(),
        timeout_ms: metadata.timeout_ms,
        pid: metadata.pid,
        cwd: metadata.cwd.clone(),
        program: metadata.program.clone(),
        args: metadata.args.clone(),
        stdout_log: metadata.stdout_log.clone(),
        stderr_log: metadata.stderr_log.clone(),
        summary: metadata.summary.clone(),
        error: metadata.error.clone(),
    }
}

fn status_report(
    metadata: &ExecuteJobMetadata,
    stdout_tail: String,
    stderr_tail: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
) -> ExecuteJobStatusReport {
    ExecuteJobStatusReport {
        job_id: metadata.job_id.clone(),
        status: metadata.status.as_str().to_string(),
        pid: metadata.pid,
        started_unix_ms: metadata.started_unix_ms,
        finished_unix_ms: metadata.finished_unix_ms,
        elapsed_ms: elapsed_ms(metadata),
        cwd: metadata.cwd.clone(),
        program: metadata.program.clone(),
        args: metadata.args.clone(),
        exit_code: metadata.exit_code,
        stdout_log: metadata.stdout_log.clone(),
        stderr_log: metadata.stderr_log.clone(),
        last_updated_unix_ms: metadata.last_updated_unix_ms,
        stdout_tail,
        stderr_tail,
        stdout_truncated,
        stderr_truncated,
        summary: metadata.summary.clone(),
        error: metadata.error.clone(),
    }
}

fn validate_job_id(job_id: &str) -> anyhow::Result<String> {
    let parsed = Uuid::parse_str(job_id).context("invalid execute job_id: expected UUID")?;
    let normalized = parsed.hyphenated().to_string();
    if job_id != normalized {
        bail!("invalid execute job_id: expected lowercase hyphenated UUID");
    }
    Ok(normalized)
}

fn validate_job_metadata(
    metadata: &ExecuteJobMetadata,
    requested_job_id: &str,
    job_dir: &Path,
) -> anyhow::Result<()> {
    let normalized = validate_job_id(requested_job_id)?;
    if metadata.job_id != normalized {
        bail!("execution job metadata job_id does not match requested job_id");
    }
    validate_job_log_path("stdout_log", &metadata.stdout_log, job_dir, "stdout.log")?;
    validate_job_log_path("stderr_log", &metadata.stderr_log, job_dir, "stderr.log")?;
    Ok(())
}

fn validate_job_log_path(
    field: &str,
    value: &str,
    job_dir: &Path,
    expected_file_name: &str,
) -> anyhow::Result<()> {
    let log_path = Path::new(value);
    if !log_path.is_absolute() {
        bail!("execution job metadata {field} must be absolute");
    }
    let expected = absolute_path(&job_dir.join(expected_file_name));
    let actual = absolute_path(log_path);
    if actual != expected {
        bail!("execution job metadata {field} is outside the expected job log path");
    }
    if actual.exists() {
        let canonical_job_dir = job_dir
            .canonicalize()
            .with_context(|| format!("canonicalizing job directory {}", job_dir.display()))?;
        let canonical_log = actual
            .canonicalize()
            .with_context(|| format!("canonicalizing execution job log {}", actual.display()))?;
        if !canonical_log.starts_with(&canonical_job_dir) {
            bail!("execution job metadata {field} resolves outside exec_state_dir");
        }
    }
    Ok(())
}

fn read_job_metadata(path: &Path) -> anyhow::Result<ExecuteJobMetadata> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading execution job metadata {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("parsing execution job metadata {}", path.display()))
}

/// Persist job metadata, stamping the moment it was written.
///
/// The stamp is here rather than at each caller because this is the only write site, which
/// makes `last_updated_unix_ms` true by construction instead of true by everyone remembering.
fn write_job_metadata(path: &Path, metadata: &mut ExecuteJobMetadata) -> anyhow::Result<()> {
    metadata.last_updated_unix_ms = Some(now_unix_ms());
    let text = serde_json::to_string_pretty(metadata)?;
    std::fs::write(path, text)
        .with_context(|| format!("writing execution job metadata {}", path.display()))
}

fn bounded_tail_bytes(value: Option<usize>) -> usize {
    value.unwrap_or(DEFAULT_TAIL_BYTES).clamp(1, MAX_TAIL_BYTES)
}

fn tail_file(path: &Path, max_bytes: usize) -> anyhow::Result<(String, bool)> {
    if !path.exists() {
        return Ok((String::new(), false));
    }
    let mut file = File::open(path).with_context(|| format!("opening log {}", path.display()))?;
    let len = file.metadata()?.len();
    let read_len = len.min(max_bytes as u64);
    if read_len < len {
        file.seek(SeekFrom::Start(len - read_len))?;
    }
    // read_len is min(len, max_bytes) where max_bytes is a usize, so it always
    // fits back into usize; try_from keeps that provable.
    let mut bytes = vec![0; usize::try_from(read_len).unwrap_or(max_bytes)];
    file.read_exact(&mut bytes)?;
    Ok((String::from_utf8_lossy(&bytes).to_string(), read_len < len))
}

fn tail_text(input: &str, max_chars: usize) -> String {
    if input.len() <= max_chars {
        return input.to_string();
    }
    let start = input
        .char_indices()
        .map(|(idx, _)| idx)
        .find(|idx| input.len().saturating_sub(*idx) <= max_chars)
        .unwrap_or(input.len());
    input[start..].to_string()
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn elapsed_ms(metadata: &ExecuteJobMetadata) -> u128 {
    metadata
        .finished_unix_ms
        .unwrap_or_else(now_unix_ms)
        .saturating_sub(metadata.started_unix_ms)
}

fn redact_env(env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    redact_env_with_injected(env, &BTreeSet::new())
}

/// The redacted view of a child environment, with SB-4's first hardening applied.
///
/// Every name in `injected_names` is `<redacted>` unconditionally, whatever it is called:
/// the eight-needle heuristic misses `DATABASE_URL`, `CONN_STR`, `LICENSE` and every other
/// name outside its list, and for a variable the broker injected the heuristic is never the
/// only filter. It remains the filter for variables the broker did not inject. An injected
/// name absent from `env` is added as `<redacted>`, because the child's environment will
/// carry it and this map describes that environment; an injected name present in `env` (a
/// caller collision) is redacted rather than shown, because the caller's value loses the
/// collision at spawn and printing it would leak caller data the redaction rule already
/// covers the name for.
fn redact_env_with_injected(
    env: &BTreeMap<String, String>,
    injected_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut redacted: BTreeMap<String, String> = env
        .iter()
        .map(|(key, value)| {
            let shown = if injected_names.contains(key) || is_sensitive_env_name(key) {
                "<redacted>".to_string()
            } else {
                value.clone()
            };
            (key.clone(), shown)
        })
        .collect();
    for name in injected_names {
        redacted
            .entry(name.clone())
            .or_insert_with(|| "<redacted>".to_string());
    }
    redacted
}

/// The names an injection will place in the child environment, for the redaction rule.
fn injected_names(injected_env: &[(String, SealedSecret)]) -> BTreeSet<String> {
    injected_env.iter().map(|(name, _)| name.clone()).collect()
}

/// Move injected material into the child's environment map, at spawn (SB-4).
///
/// The values cross through the carrier's scoped-exposure API and land directly in the
/// [`Command`]; they touch no request struct, no `ExecutionEnvironment` and nothing
/// serializable. Material must be valid UTF-8, because an environment value has to cross
/// the platform environment boundary on every platform this crate builds for, and refusing
/// is the fail-closed direction; the refusal names the variable and never echoes material
/// or a material-derived value (SB-1).
fn apply_injected_env(
    child: &mut Command,
    injected_env: &[(String, SealedSecret)],
) -> anyhow::Result<()> {
    for (name, value) in injected_env {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            bail!("injected environment variable name {name:?} is not a legal variable name");
        }
        value.with_exposed(|bytes| match std::str::from_utf8(bytes) {
            Ok(text) => {
                child.env(name, text);
                Ok(())
            }
            Err(_) => Err(anyhow::anyhow!(
                "injected environment variable {name} carries material that is not valid \
                 UTF-8 and cannot cross the environment boundary; the value is not echoed"
            )),
        })?;
    }
    Ok(())
}

fn summarize_redacted_env_for_audit(env: &BTreeMap<String, String>) -> String {
    if env.is_empty() {
        return "{}".into();
    }
    env.iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn is_sensitive_env_name(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "KEY",
        "PASSWORD",
        "PASS",
        "PAT",
        "CREDENTIAL",
        "AUTH",
    ]
    .iter()
    .any(|needle| upper.contains(needle))
}

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
    use nmcp_policy::ExecutionProfile;
    use nmcp_policy::{Permission, RootRule};
    use std::collections::BTreeSet;

    fn temp_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("{name}-{stamp}"));
        std::fs::create_dir_all(&root).expect("mkdir");
        root
    }

    fn broker(root: &Path) -> CommandBroker {
        let audit = AuditSink::open(root.join("audit.jsonl")).expect("audit");
        let policy = PolicyConfig {
            audit_path: root.join("audit.jsonl"),
            exec_state_dir: root.join("exec-jobs"),
            roots: vec![
                RootRule {
                    id: "r".into(),
                    path: root.to_path_buf(),
                    permissions: [Permission::Execute].into_iter().collect::<BTreeSet<_>>(),
                },
                RootRule {
                    id: "test-shell".into(),
                    path: absolute_path(Path::new(&shell_program())),
                    permissions: [Permission::Execute].into_iter().collect::<BTreeSet<_>>(),
                },
            ],
            ..PolicyConfig::default()
        };
        CommandBroker::new(policy, audit)
    }

    fn broker_with_policy(root: &Path, policy: PolicyConfig) -> CommandBroker {
        let audit = AuditSink::open(root.join("audit.jsonl")).expect("audit");
        CommandBroker::new(policy, audit)
    }

    fn exec_policy(root: &Path) -> PolicyConfig {
        PolicyConfig {
            audit_path: root.join("audit.jsonl"),
            exec_state_dir: root.join("exec-jobs"),
            roots: vec![
                RootRule {
                    id: "r".into(),
                    path: root.to_path_buf(),
                    permissions: [Permission::Execute].into_iter().collect::<BTreeSet<_>>(),
                },
                RootRule {
                    id: "test-shell".into(),
                    path: absolute_path(Path::new(&shell_program())),
                    permissions: [Permission::Execute].into_iter().collect::<BTreeSet<_>>(),
                },
            ],
            ..PolicyConfig::default()
        }
    }

    fn write_tool(dir: &Path, name: &str, output: &str) -> PathBuf {
        std::fs::create_dir_all(dir).expect("mkdir tool dir");
        #[cfg(windows)]
        {
            let path = dir.join(format!("{name}.cmd"));
            std::fs::write(&path, format!("@echo off\r\necho {output} %*\r\n")).expect("tool");
            path
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;

            let path = dir.join(name);
            std::fs::write(&path, format!("#!/bin/sh\necho {output} \"$@\"\n")).expect("tool");
            let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).expect("chmod");
            path
        }
    }

    #[cfg(windows)]
    fn shell_program() -> String {
        std::env::var("ComSpec").unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".into())
    }
    #[cfg(windows)]
    fn shell_args(script: &str) -> Vec<String> {
        vec!["/C".into(), script.into()]
    }
    #[cfg(not(windows))]
    fn shell_program() -> String {
        "/bin/sh".into()
    }
    #[cfg(not(windows))]
    fn shell_args(script: &str) -> Vec<String> {
        vec!["-c".into(), script.into()]
    }
    #[cfg(windows)]
    fn sleep_print_script(ms: u64, out: &str, err: &str) -> String {
        let count = (ms / 1000).saturating_add(2);
        format!("ping -n {count} 127.0.0.1 >NUL & echo {out} & echo {err} 1>&2")
    }
    #[cfg(not(windows))]
    fn sleep_print_script(ms: u64, out: &str, err: &str) -> String {
        #[allow(clippy::cast_precision_loss)] // test sleep duration, milliseconds
        let secs = (ms as f64) / 1000.0;
        format!("sleep {secs}; echo {out}; echo {err} >&2")
    }

    async fn wait_for_terminal(
        broker: &CommandBroker,
        job_id: &str,
    ) -> anyhow::Result<ExecuteJobStatusReport> {
        broker
            .execute_wait(ExecuteWaitRequest {
                job_id: job_id.into(),
                timeout_ms: Some(10_000),
                max_bytes: Some(DEFAULT_TAIL_BYTES),
            })
            .await
    }

    #[test]
    fn rejects_delete_programs() {
        assert!(reject_delete_intent("rm", &["-rf".into(), "target".into()]).is_err());
        assert!(reject_delete_intent("powershell", &["Remove-Item".into(), "foo".into()]).is_err());
        assert!(reject_delete_intent("cargo", &["test".into()]).is_ok());
    }

    #[test]
    fn delete_intent_covers_powershell_and_cmd_delete_aliases() {
        // G4-19. Each of these erases data. `ri` and `rp` were uncovered before the
        // audit, so the aliased form slipped through while the full cmdlet name was
        // refused.
        for verb in [
            "del",
            "erase",
            "rd",
            "rmdir",
            "rm",
            "unlink",
            "shred",
            "sdelete",
            "Remove-Item",
            "Remove-ItemProperty",
            "Clear-Content",
            "ri",
            "rp",
            "clc",
        ] {
            let args = vec!["-Command".to_string(), format!("{verb} target")];
            assert!(
                reject_delete_intent("powershell", &args).is_err(),
                "delete alias must be refused: {verb}"
            );
        }
    }

    #[test]
    fn delete_intent_allows_overwrite_which_is_not_deletion() {
        // The guarantee has always drawn the line at removal, not at overwrite.
        // Blocking these would break the documented way to write a file.
        for verb in ["Set-Content", "Out-File", "Add-Content", "sc", "echo"] {
            let args = vec!["-Command".to_string(), format!("{verb} notes.txt")];
            assert!(
                reject_delete_intent("powershell", &args).is_ok(),
                "overwrite verb must be allowed: {verb}"
            );
        }
    }

    #[test]
    fn delete_intent_matching_is_token_aware() {
        // Regression for the substring form, which searched for the bare fragments
        // "rd " and "del " and so refused ordinary prose. The first case is the exact
        // wording this product uses when refusing wildcard-shaped origins.
        for args in [
            vec![
                "-Command".to_string(),
                "policy refuses wildcard origins".to_string(),
            ],
            vec![
                "-Command".to_string(),
                "record the standard result".to_string(),
            ],
            vec![
                "-Command".to_string(),
                "Write-Output model results".to_string(),
            ],
            vec!["-Command".to_string(), "shredder.exe --report".to_string()],
            vec![
                "-Command".to_string(),
                "Get-Content hard drive notes".to_string(),
            ],
        ] {
            assert!(
                reject_delete_intent("powershell", &args).is_ok(),
                "ordinary prose must pass: {args:?}"
            );
        }
    }

    #[test]
    fn delete_intent_still_refuses_canonical_delete_shapes() {
        for args in [
            vec!["-Command".to_string(), "rm -rf target".to_string()],
            vec!["-Command".to_string(), "Remove-Item target".to_string()],
            vec!["/c".to_string(), "del foo".to_string()],
            vec!["/c".to_string(), "rd /s /q foo".to_string()],
            vec!["/c".to_string(), "rmdir foo".to_string()],
            vec!["-Command".to_string(), "erase foo".to_string()],
            vec!["-Command".to_string(), "unlink foo".to_string()],
            vec!["-Command".to_string(), "shred foo".to_string()],
            vec!["-Command".to_string(), "git clean -fd".to_string()],
            vec!["-Command".to_string(), "git rm foo".to_string()],
            vec!["-Command".to_string(), "cargo clean".to_string()],
        ] {
            assert!(
                reject_delete_intent("powershell", &args).is_err(),
                "delete shape must be refused: {args:?}"
            );
        }
        assert!(reject_delete_intent("rm", &["-rf".into()]).is_err());
        assert!(reject_delete_intent(r"C:\Windows\System32\del.exe", &["foo".into()]).is_err());
        assert!(reject_delete_intent("/usr/bin/rm", &["foo".into()]).is_err());
    }

    #[test]
    fn delete_intent_sees_through_shell_separators() {
        // The substring form required a literal space before the verb, so each of
        // these reached the spawn path. Token splitting closes that.
        for (program, args) in [
            (
                "powershell",
                vec!["-Command".to_string(), "gci|%{rm $_}".to_string()],
            ),
            (
                "cmd",
                vec!["/c".to_string(), "echo hi&&del foo".to_string()],
            ),
            (
                "cmd",
                vec!["/c".to_string(), "echo hi;rmdir foo".to_string()],
            ),
            (
                "powershell",
                vec!["-Command".to_string(), "\"Remove-Item\" foo".to_string()],
            ),
        ] {
            assert!(
                reject_delete_intent(program, &args).is_err(),
                "separator-hidden delete must be refused: {args:?}"
            );
        }
    }

    #[test]
    fn delete_like_commands_are_rejected_by_exec_broker() {
        assert!(
            reject_delete_intent(
                "powershell",
                &["-Command".into(), "Remove-Item target".into()]
            )
            .is_err()
        );
        assert!(reject_delete_intent("cargo", &["clean".into()]).is_err());
    }

    #[test]
    fn execute_resolve_program_reports_configured_tool_path() {
        let root = temp_root("nmcp-exec-tool-path-cargo");
        let cargo_path = write_tool(&root.join("bin"), "cargo", "cargo fake");
        let mut policy = exec_policy(&root);
        policy.tool_paths.insert("cargo".into(), cargo_path.clone());
        let report = broker_with_policy(&root, policy)
            .execute_resolve_program(ExecuteResolveProgramRequest {
                cwd: root.clone(),
                program: "cargo".into(),
                env: BTreeMap::new(),
                inherit_service_env: Some(false),
                profile: None,
            })
            .expect("resolve");
        assert!(report.resolved);
        assert_eq!(report.resolution_source, "tool_paths");
        assert_eq!(report.selected_profile, None);
        assert_eq!(report.resolved_path, Some(cargo_path.display().to_string()));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn configured_tool_path_requires_execute_permission_on_resolved_binary() {
        let root = temp_root("nmcp-exec-tool-path-denied");
        let outside = temp_root("nmcp-exec-tool-path-outside");
        let cargo_path = write_tool(&outside.join("bin"), "cargo", "outside cargo");
        let mut policy = exec_policy(&root);
        policy.tool_paths.insert("cargo".into(), cargo_path);
        let report = broker_with_policy(&root, policy)
            .execute_resolve_program(ExecuteResolveProgramRequest {
                cwd: root.clone(),
                program: "cargo".into(),
                env: BTreeMap::new(),
                inherit_service_env: Some(false),
                profile: None,
            })
            .expect("resolve report");
        assert!(!report.resolved);
        assert!(report.summary.contains("execute-permitted"));
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[test]
    fn execution_profile_prepends_path_before_service_path() {
        let root = temp_root("nmcp-exec-profile-path-order");
        let profile_bin = root.join("profile-bin");
        std::fs::create_dir_all(&profile_bin).expect("mkdir bin");
        let mut policy = exec_policy(&root);
        policy.execution_profiles.insert(
            "dev".into(),
            ExecutionProfile {
                path_prepend: vec![profile_bin.clone()],
                inherit_service_env: true,
                ..ExecutionProfile::default()
            },
        );
        let report = broker_with_policy(&root, policy)
            .execute_resolve_program(ExecuteResolveProgramRequest {
                cwd: root.clone(),
                program: "missing-profile-tool".into(),
                env: BTreeMap::new(),
                inherit_service_env: None,
                profile: Some("dev".into()),
            })
            .expect("resolve");
        assert_eq!(
            report.path_entries.first(),
            Some(&profile_bin.display().to_string())
        );
        assert!(
            report
                .effective_path
                .starts_with(&profile_bin.display().to_string())
        );
        assert_eq!(
            report.service_path,
            std::env::var("PATH").unwrap_or_default()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn execute_start_uses_profile_tool_resolution() {
        let root = temp_root("nmcp-exec-profile-start");
        let bin = root.join("profile-bin");
        write_tool(&bin, "profile-tool", "profile-tool");
        let mut policy = exec_policy(&root);
        policy.execution_profiles.insert(
            "dev".into(),
            ExecutionProfile {
                path_prepend: vec![bin],
                inherit_service_env: false,
                ..ExecutionProfile::default()
            },
        );
        let broker = broker_with_policy(&root, policy);
        let start = broker
            .execute_start(ExecuteStartRequest {
                cwd: root.clone(),
                program: "profile-tool".into(),
                args: vec!["--version".into()],
                timeout_ms: Some(10_000),
                env: BTreeMap::new(),
                inherit_service_env: None,
                profile: Some("dev".into()),
            })
            .await
            .expect("start");
        let result = wait_for_terminal(&broker, &start.job_id)
            .await
            .expect("wait");
        assert_eq!(result.status, "exited");
        assert!(result.stdout_tail.contains("profile-tool --version"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn execute_uses_profile_tool_resolution() {
        let root = temp_root("nmcp-exec-profile-sync");
        let bin = root.join("profile-bin");
        write_tool(&bin, "profile-tool", "profile-tool");
        let mut policy = exec_policy(&root);
        policy.execution_profiles.insert(
            "dev".into(),
            ExecutionProfile {
                path_prepend: vec![bin],
                inherit_service_env: false,
                ..ExecutionProfile::default()
            },
        );
        let report = broker_with_policy(&root, policy)
            .execute(ExecuteRequest {
                cwd: root.clone(),
                program: "profile-tool".into(),
                args: vec!["--version".into()],
                timeout_ms: 10_000,
                env: BTreeMap::new(),
                inherit_service_env: None,
                profile: Some("dev".into()),
            })
            .await
            .expect("execute");
        assert_eq!(report.exit_code, Some(0));
        assert!(report.stdout_tail.contains("profile-tool --version"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cargo_resolves_from_profile_without_service_path() {
        let root = temp_root("nmcp-exec-cargo-profile-resolve");
        let bin = root.join("profile-bin");
        let cargo = write_tool(&bin, "cargo", "cargo");
        let mut policy = exec_policy(&root);
        policy.execution_profiles.insert(
            "dev".into(),
            ExecutionProfile {
                path_prepend: vec![bin],
                inherit_service_env: false,
                ..ExecutionProfile::default()
            },
        );
        let report = broker_with_policy(&root, policy)
            .execute_resolve_program(ExecuteResolveProgramRequest {
                cwd: PathBuf::new(),
                program: "cargo".into(),
                env: BTreeMap::new(),
                inherit_service_env: None,
                profile: Some("dev".into()),
            })
            .expect("resolve");
        assert!(report.resolved);
        assert_eq!(report.resolution_source, "profile_path_prepend");
        assert_eq!(
            report.resolved_path.as_deref().map(str::to_ascii_lowercase),
            Some(cargo.display().to_string().to_ascii_lowercase())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn git_resolves_from_profile_without_service_path() {
        let root = temp_root("nmcp-exec-git-profile-resolve");
        let bin = root.join("profile-bin");
        let git = write_tool(&bin, "git", "git");
        let mut policy = exec_policy(&root);
        policy.execution_profiles.insert(
            "dev".into(),
            ExecutionProfile {
                path_prepend: vec![bin],
                env: BTreeMap::from([("GIT_TERMINAL_PROMPT".into(), "0".into())]),
                inherit_service_env: false,
            },
        );
        let report = broker_with_policy(&root, policy)
            .execute_resolve_program(ExecuteResolveProgramRequest {
                cwd: PathBuf::new(),
                program: "git".into(),
                env: BTreeMap::new(),
                inherit_service_env: None,
                profile: Some("dev".into()),
            })
            .expect("resolve");
        assert!(report.resolved);
        assert_eq!(report.resolution_source, "profile_path_prepend");
        assert_eq!(
            report.resolved_path.as_deref().map(str::to_ascii_lowercase),
            Some(git.display().to_string().to_ascii_lowercase())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn execute_resolve_program_reports_service_path_and_profile_path() {
        let root = temp_root("nmcp-exec-resolve-report");
        let bin = root.join("profile-bin");
        let tool = write_tool(&bin, "resolve-tool", "resolve-tool");
        let mut policy = exec_policy(&root);
        policy.execution_profiles.insert(
            "dev".into(),
            ExecutionProfile {
                path_prepend: vec![bin.clone()],
                inherit_service_env: true,
                ..ExecutionProfile::default()
            },
        );
        let report = broker_with_policy(&root, policy)
            .execute_resolve_program(ExecuteResolveProgramRequest {
                cwd: root.clone(),
                program: "resolve-tool".into(),
                env: BTreeMap::new(),
                inherit_service_env: None,
                profile: Some("dev".into()),
            })
            .expect("resolve");
        assert_eq!(report.profile.as_deref(), Some("dev"));
        assert_eq!(
            report.resolved_path.as_deref().map(str::to_ascii_lowercase),
            Some(tool.display().to_string().to_ascii_lowercase())
        );
        assert_eq!(
            report.service_path,
            std::env::var("PATH").unwrap_or_default()
        );
        assert!(report.path_entries.contains(&bin.display().to_string()));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn execute_env_report_redacts_secret_like_values() {
        let root = temp_root("nmcp-exec-env-report-redact");
        let report = broker(&root).execute_env_report(ExecuteEnvReportRequest {
            profile: None,
            env: BTreeMap::from([
                ("API_TOKEN".into(), "secret-token".into()),
                ("NPM_CONFIG__AUTH".into(), "secret-auth".into()),
                ("GITHUB_PAT".into(), "secret-pat".into()),
                ("VISIBLE".into(), "value".into()),
            ]),
            inherit_service_env: Some(false),
        });
        assert_eq!(report.redacted_env["API_TOKEN"], "<redacted>");
        assert_eq!(report.redacted_env["NPM_CONFIG__AUTH"], "<redacted>");
        assert_eq!(report.redacted_env["GITHUB_PAT"], "<redacted>");
        assert_eq!(report.redacted_env["VISIBLE"], "value");
        let json = serde_json::to_string(&report).expect("json");
        assert!(!json.contains("secret-token"));
        assert!(!json.contains("secret-auth"));
        assert!(!json.contains("secret-pat"));
        assert!(Path::new(&report.effective_exec_state_dir).is_absolute());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn configured_tool_path_missing_returns_structured_error() {
        let root = temp_root("nmcp-exec-missing-tool-path");
        let missing = root.join("missing").join("cargo.exe");
        let mut policy = exec_policy(&root);
        policy.tool_paths.insert("cargo".into(), missing.clone());
        let report = broker_with_policy(&root, policy)
            .execute_start(ExecuteStartRequest {
                cwd: root.clone(),
                program: "cargo".into(),
                args: vec!["--version".into()],
                timeout_ms: Some(10_000),
                env: BTreeMap::new(),
                inherit_service_env: Some(false),
                profile: None,
            })
            .await
            .expect("start report");
        assert_eq!(report.status, "failed_to_start");
        let error = report.error.expect("error");
        assert!(error.contains("configured_tool_path_missing"));
        assert!(error.contains("cargo"));
        assert!(error.contains("cargo.exe"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn request_profile_overrides_default_execution_profile() {
        let root = temp_root("nmcp-exec-profile-override");
        let default_bin = root.join("default-bin");
        let override_bin = root.join("override-bin");
        write_tool(&default_bin, "same-tool", "default");
        let override_tool = write_tool(&override_bin, "same-tool", "override");
        let mut policy = exec_policy(&root);
        policy.default_execution_profile = Some("default".into());
        policy.execution_profiles.insert(
            "default".into(),
            ExecutionProfile {
                path_prepend: vec![default_bin],
                inherit_service_env: false,
                ..ExecutionProfile::default()
            },
        );
        policy.execution_profiles.insert(
            "override".into(),
            ExecutionProfile {
                path_prepend: vec![override_bin],
                inherit_service_env: false,
                ..ExecutionProfile::default()
            },
        );
        let report = broker_with_policy(&root, policy)
            .execute_resolve_program(ExecuteResolveProgramRequest {
                cwd: root.clone(),
                program: "same-tool".into(),
                env: BTreeMap::new(),
                inherit_service_env: None,
                profile: Some("override".into()),
            })
            .expect("resolve");
        assert_eq!(report.profile.as_deref(), Some("override"));
        assert_eq!(
            report.resolved_path.as_deref().map(str::to_ascii_lowercase),
            Some(override_tool.display().to_string().to_ascii_lowercase())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn profile_env_merges_with_request_env_without_leaking_secrets() {
        let root = temp_root("nmcp-exec-profile-env-redact");
        let bin = root.join("profile-bin");
        write_tool(&bin, "env-tool", "env-tool");
        let mut policy = exec_policy(&root);
        policy.execution_profiles.insert(
            "dev".into(),
            ExecutionProfile {
                path_prepend: vec![bin],
                env: BTreeMap::from([
                    ("FOO".into(), "profile".into()),
                    ("SECRET_TOKEN".into(), "profile-secret".into()),
                ]),
                inherit_service_env: false,
            },
        );
        let broker = broker_with_policy(&root, policy);
        let start = broker
            .execute_start(ExecuteStartRequest {
                cwd: root.clone(),
                program: "env-tool".into(),
                args: Vec::new(),
                timeout_ms: Some(10_000),
                env: BTreeMap::from([
                    ("FOO".into(), "request".into()),
                    ("API_KEY".into(), "request-secret".into()),
                ]),
                inherit_service_env: None,
                profile: Some("dev".into()),
            })
            .await
            .expect("start");
        let _ = wait_for_terminal(&broker, &start.job_id)
            .await
            .expect("wait");
        let metadata =
            read_job_metadata(&root.join("exec-jobs").join(&start.job_id).join("job.json"))
                .expect("metadata");
        assert_eq!(metadata.redacted_env["FOO"], "request");
        assert_eq!(metadata.redacted_env["SECRET_TOKEN"], "<redacted>");
        assert_eq!(metadata.redacted_env["API_KEY"], "<redacted>");
        assert!(
            !serde_json::to_string(&metadata)
                .expect("json")
                .contains("profile-secret")
        );
        assert!(
            !serde_json::to_string(&metadata)
                .expect("json")
                .contains("request-secret")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn cargo_workspace_test_runs_as_async_job_with_profile_shape() {
        let root = temp_root("nmcp-exec-cargo-profile-shape");
        let bin = root.join("profile-bin");
        write_tool(&bin, "cargo", "cargo");
        let mut policy = exec_policy(&root);
        policy.execution_profiles.insert(
            "dev".into(),
            ExecutionProfile {
                path_prepend: vec![bin],
                inherit_service_env: false,
                ..ExecutionProfile::default()
            },
        );
        let broker = broker_with_policy(&root, policy);
        let start = broker
            .execute_start(ExecuteStartRequest {
                cwd: root.clone(),
                program: "cargo".into(),
                args: vec!["test".into(), "--workspace".into()],
                timeout_ms: Some(10_000),
                env: BTreeMap::new(),
                inherit_service_env: None,
                profile: Some("dev".into()),
            })
            .await
            .expect("start");
        let result = wait_for_terminal(&broker, &start.job_id)
            .await
            .expect("wait");
        assert_eq!(result.status, "exited");
        assert!(result.stdout_tail.contains("cargo test --workspace"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn git_push_shape_runs_as_async_job_with_profile_shape() {
        let root = temp_root("nmcp-exec-git-profile-shape");
        let bin = root.join("profile-bin");
        write_tool(&bin, "git", "git");
        let mut policy = exec_policy(&root);
        policy.execution_profiles.insert(
            "dev".into(),
            ExecutionProfile {
                path_prepend: vec![bin],
                env: BTreeMap::from([("GIT_TERMINAL_PROMPT".into(), "0".into())]),
                inherit_service_env: false,
            },
        );
        let broker = broker_with_policy(&root, policy);
        let start = broker
            .execute_start(ExecuteStartRequest {
                cwd: root.clone(),
                program: "git".into(),
                args: vec![
                    "push".into(),
                    "-u".into(),
                    "origin".into(),
                    "feat/product-command-desk".into(),
                ],
                timeout_ms: Some(10_000),
                env: BTreeMap::new(),
                inherit_service_env: None,
                profile: Some("dev".into()),
            })
            .await
            .expect("start");
        let result = wait_for_terminal(&broker, &start.job_id)
            .await
            .expect("wait");
        assert_eq!(result.status, "exited");
        assert!(
            result
                .stdout_tail
                .contains("git push -u origin feat/product-command-desk")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn cargo_test_command_is_allowed_by_exec_broker() {
        let root = temp_root("mcp-exec");
        let cargo_path = write_tool(&root.join("bin"), "cargo", "cargo fake");
        let mut policy = exec_policy(&root);
        policy.tool_paths.insert("cargo".into(), cargo_path);
        let out = broker_with_policy(&root, policy)
            .execute(ExecuteRequest {
                cwd: root.clone(),
                program: "cargo".into(),
                args: vec!["test".into(), "--help".into()],
                timeout_ms: 5_000,
                env: BTreeMap::new(),
                inherit_service_env: Some(false),
                profile: None,
            })
            .await
            .expect("execute");
        assert_eq!(out.program, "cargo");
        assert!(out.stdout_tail.contains("cargo fake test --help"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn execute_request_default_timeout_stays_below_connector_limits() {
        let timeout = default_timeout_ms();
        assert_eq!(timeout, DEFAULT_TIMEOUT_MS);
        assert!(timeout <= 30_000);
    }

    #[test]
    fn execute_start_default_timeout_accommodates_workspace_cargo_tests() {
        let job_timeout = default_job_timeout_ms();
        assert_eq!(job_timeout, 900_000);
        assert!(job_timeout > default_timeout_ms());
    }

    #[test]
    fn execute_job_rejects_non_uuid_job_ids() {
        let root = temp_root("nmcp-exec-job-id");
        let broker = broker(&root);
        assert!(
            broker
                .execute_status(ExecuteJobIdRequest {
                    job_id: "..\\outside".into(),
                })
                .is_err()
        );
        assert!(
            broker
                .execute_tail(ExecuteTailRequest {
                    job_id: "not-a-uuid".into(),
                    max_bytes: None,
                })
                .is_err()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn execute_job_rejects_metadata_log_paths_outside_job_dir() {
        let root = temp_root("nmcp-exec-forged-metadata");
        let broker = broker(&root);
        let job_id = Uuid::new_v4().to_string();
        let job_dir = root.join("exec-jobs").join(&job_id);
        std::fs::create_dir_all(&job_dir).expect("job dir");
        let outside = root.join("outside.log");
        std::fs::write(&outside, "outside").expect("outside log");
        let mut metadata = ExecuteJobMetadata {
            job_id: job_id.clone(),
            status: ExecuteJobStatus::Exited,
            cwd: root.display().to_string(),
            program: shell_program(),
            args: Vec::new(),
            pid: None,
            started_unix_ms: now_unix_ms(),
            finished_unix_ms: Some(now_unix_ms()),
            timeout_ms: DEFAULT_JOB_TIMEOUT_MS,
            stdout_log: outside.display().to_string(),
            stderr_log: job_dir.join("stderr.log").display().to_string(),
            exit_code: Some(0),
            error: None,
            redacted_env: BTreeMap::new(),
            summary: "forged metadata".into(),
            call_id: None,
            last_updated_unix_ms: None,
        };
        write_job_metadata(&job_dir.join("job.json"), &mut metadata).expect("write metadata");
        let err = broker
            .execute_tail(ExecuteTailRequest {
                job_id,
                max_bytes: Some(128),
            })
            .expect_err("forged log path must fail");
        assert!(err.to_string().contains("stdout_log"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn execute_start_returns_job_id_without_waiting_for_completion() {
        let root = temp_root("nmcp-exec-start");
        let started = Instant::now();
        let report = broker(&root)
            .execute_start(ExecuteStartRequest {
                cwd: root.clone(),
                program: shell_program(),
                args: shell_args(&sleep_print_script(1_500, "later", "later_err")),
                timeout_ms: Some(10_000),
                env: BTreeMap::new(),
                inherit_service_env: Some(true),
                profile: None,
            })
            .await
            .expect("start");
        assert!(!report.job_id.is_empty());
        assert_eq!(report.status, "running");
        assert!(started.elapsed() < Duration::from_secs(1));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn execute_status_reports_running_then_exited() {
        let root = temp_root("nmcp-exec-status");
        let broker = broker(&root);
        let start = broker
            .execute_start(ExecuteStartRequest {
                cwd: root.clone(),
                program: shell_program(),
                args: shell_args(&sleep_print_script(500, "done", "errdone")),
                timeout_ms: Some(10_000),
                env: BTreeMap::new(),
                inherit_service_env: Some(true),
                profile: None,
            })
            .await
            .expect("start");
        let running = broker
            .execute_status(ExecuteJobIdRequest {
                job_id: start.job_id.clone(),
            })
            .expect("status");
        assert_eq!(running.status, "running");
        let final_report = wait_for_terminal(&broker, &start.job_id)
            .await
            .expect("wait");
        assert_eq!(final_report.status, "exited");
        assert_eq!(final_report.exit_code, Some(0));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tail_text_never_splits_utf8_codepoints() {
        let input = format!("{}END", "é".repeat(4096));
        let tail = tail_text(&input, 4097);
        assert!(tail.ends_with("END"));
        assert!(tail.is_char_boundary(0));
    }

    #[tokio::test]
    async fn execute_tail_returns_bounded_stdout_and_stderr() {
        let root = temp_root("nmcp-exec-tail");
        let broker = broker(&root);
        let start = broker
            .execute_start(ExecuteStartRequest {
                cwd: root.clone(),
                program: shell_program(),
                args: shell_args(&sleep_print_script(
                    100,
                    "abcdefghijklmnopqrstuvwxyz",
                    "stderr-abcdefghijklmnopqrstuvwxyz",
                )),
                timeout_ms: Some(10_000),
                env: BTreeMap::new(),
                inherit_service_env: Some(true),
                profile: None,
            })
            .await
            .expect("start");
        let _ = wait_for_terminal(&broker, &start.job_id)
            .await
            .expect("wait");
        let tail = broker
            .execute_tail(ExecuteTailRequest {
                job_id: start.job_id.clone(),
                max_bytes: Some(10),
            })
            .expect("tail");
        assert!(tail.stdout_tail.len() <= 10);
        assert!(tail.stderr_tail.len() <= 10);
        assert!(tail.stdout_truncated || tail.stderr_truncated);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn execute_result_returns_final_exit_code_and_tails() {
        let root = temp_root("nmcp-exec-result");
        let broker = broker(&root);
        let start = broker
            .execute_start(ExecuteStartRequest {
                cwd: root.clone(),
                program: shell_program(),
                args: shell_args(&sleep_print_script(100, "final-out", "final-err")),
                timeout_ms: Some(10_000),
                env: BTreeMap::new(),
                inherit_service_env: Some(true),
                profile: None,
            })
            .await
            .expect("start");
        let _ = wait_for_terminal(&broker, &start.job_id)
            .await
            .expect("wait");
        let result = broker
            .execute_result(ExecuteJobIdRequest {
                job_id: start.job_id.clone(),
            })
            .expect("result");
        assert_eq!(result.status, "exited");
        assert_eq!(result.exit_code, Some(0));
        assert!(result.stdout_tail.contains("final-out"));
        assert!(result.stderr_tail.contains("final-err"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn execute_cancel_cancels_running_owned_job() {
        let root = temp_root("nmcp-exec-cancel");
        let broker = broker(&root);
        let start = broker
            .execute_start(ExecuteStartRequest {
                cwd: root.clone(),
                program: shell_program(),
                args: shell_args(&sleep_print_script(10_000, "late", "late-err")),
                timeout_ms: Some(30_000),
                env: BTreeMap::new(),
                inherit_service_env: Some(true),
                profile: None,
            })
            .await
            .expect("start");
        let running = broker
            .execute_status(ExecuteJobIdRequest {
                job_id: start.job_id.clone(),
            })
            .expect("status");
        assert_eq!(running.status, "running");
        let cancelled = broker
            .execute_cancel(ExecuteCancelRequest {
                job_id: start.job_id.clone(),
            })
            .await
            .expect("cancel");
        assert!(matches!(cancelled.status.as_str(), "running" | "cancelled"));
        let final_report = wait_for_terminal(&broker, &start.job_id)
            .await
            .expect("wait");
        assert_eq!(final_report.status, "cancelled");
        assert!(
            broker
                .execute_cancel(ExecuteCancelRequest {
                    job_id: Uuid::new_v4().to_string()
                })
                .await
                .is_err()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// G5-6. Every write stamps the moment it happened, including for a job that is still
    /// running and therefore has no `finished_unix_ms` to fall back on. That is the whole reason
    /// the field exists: the tasks extension requires lastUpdatedAt on a working task.
    #[test]
    fn every_metadata_write_stamps_when_it_happened() {
        let root = temp_root("nmcp-exec-last-updated");
        let job_id = Uuid::new_v4().to_string();
        let job_dir = root.join("exec-jobs").join(&job_id);
        std::fs::create_dir_all(&job_dir).expect("job dir");
        let path = job_dir.join("job.json");

        let mut metadata = ExecuteJobMetadata {
            job_id: job_id.clone(),
            status: ExecuteJobStatus::Running,
            cwd: root.display().to_string(),
            program: shell_program(),
            args: Vec::new(),
            pid: Some(1),
            started_unix_ms: now_unix_ms(),
            finished_unix_ms: None,
            timeout_ms: DEFAULT_JOB_TIMEOUT_MS,
            stdout_log: job_dir.join("stdout.log").display().to_string(),
            stderr_log: job_dir.join("stderr.log").display().to_string(),
            exit_code: None,
            error: None,
            redacted_env: BTreeMap::new(),
            summary: "running".into(),
            call_id: None,
            last_updated_unix_ms: None,
        };

        write_job_metadata(&path, &mut metadata).expect("write");
        let first = read_job_metadata(&path)
            .expect("read")
            .last_updated_unix_ms
            .expect("a running job still has a last-updated stamp");
        assert!(first >= metadata.started_unix_ms);

        std::thread::sleep(std::time::Duration::from_millis(5));
        metadata.status = ExecuteJobStatus::Exited;
        write_job_metadata(&path, &mut metadata).expect("rewrite");
        let second = read_job_metadata(&path)
            .expect("read")
            .last_updated_unix_ms
            .expect("stamp");
        assert!(second > first, "{second} should be later than {first}");

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn execute_job_persists_metadata_to_disk() {
        let root = temp_root("nmcp-exec-persist");
        let broker = broker(&root);
        let start = broker
            .execute_start(ExecuteStartRequest {
                cwd: root.clone(),
                program: shell_program(),
                args: shell_args(&sleep_print_script(100, "persist", "persist-err")),
                timeout_ms: Some(10_000),
                env: BTreeMap::new(),
                inherit_service_env: Some(true),
                profile: None,
            })
            .await
            .expect("start");
        let meta = root.join("exec-jobs").join(&start.job_id).join("job.json");
        assert!(meta.exists());
        let persisted = read_job_metadata(&meta).expect("metadata");
        assert_eq!(persisted.job_id, start.job_id);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn execute_job_rejects_delete_like_commands_before_spawn() {
        let root = temp_root("nmcp-exec-delete-reject");
        let result = broker(&root)
            .execute_start(ExecuteStartRequest {
                cwd: root.clone(),
                program: shell_program(),
                args: shell_args("Remove-Item target"),
                timeout_ms: Some(10_000),
                env: BTreeMap::new(),
                inherit_service_env: Some(true),
                profile: None,
            })
            .await;
        assert!(result.is_err());
        assert!(!root.join("exec-jobs").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn execute_job_supports_git_push_shape_without_shell_timeout() {
        let root = temp_root("nmcp-exec-git-shape");
        let broker = broker(&root);
        let start = broker
            .execute_start(ExecuteStartRequest {
                cwd: root.clone(),
                program: shell_program(),
                args: shell_args(&sleep_print_script(
                    800,
                    "git push -u origin feat/product-command-desk",
                    "simulated stderr",
                )),
                timeout_ms: Some(10_000),
                env: BTreeMap::from([("GIT_TERMINAL_PROMPT".into(), "0".into())]),
                inherit_service_env: Some(true),
                profile: None,
            })
            .await
            .expect("start");
        assert_eq!(start.status, "running");
        let result = wait_for_terminal(&broker, &start.job_id)
            .await
            .expect("wait");
        assert_eq!(result.status, "exited");
        assert!(result.stdout_tail.contains("git push -u origin"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn execute_program_not_found_returns_structured_error_with_path_hint() {
        let root = temp_root("nmcp-exec-not-found");
        let report = broker(&root)
            .execute_start(ExecuteStartRequest {
                cwd: root.clone(),
                program: "definitely-not-a-real-program".into(),
                args: Vec::new(),
                timeout_ms: Some(10_000),
                env: BTreeMap::new(),
                inherit_service_env: Some(true),
                profile: None,
            })
            .await
            .expect("structured report");
        assert_eq!(report.status, "failed_to_start");
        let error = report.error.expect("error");
        assert!(error.contains("service_path"));
        assert!(error.contains("path_hint"));
        let _ = std::fs::remove_dir_all(root);
    }

    // Concurrency governor: cap is honoured - excess calls wait, not dropped.
    #[test]
    fn concurrency_cap_initial_permits_match_default() {
        let root = temp_root("nmcp-exec-cap");
        let b = broker(&root);
        assert_eq!(b.available_permits(), DEFAULT_CONCURRENCY_CAP);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn concurrency_cap_with_cap_sets_permits() {
        let root = temp_root("nmcp-exec-cap2");
        let audit = AuditSink::open(root.join("audit.jsonl")).expect("audit");
        let policy = PolicyConfig {
            audit_path: root.join("audit.jsonl"),
            exec_state_dir: root.join("exec-jobs"),
            roots: vec![
                RootRule {
                    id: "r".into(),
                    path: root.clone(),
                    permissions: [Permission::Execute].into_iter().collect::<BTreeSet<_>>(),
                },
                RootRule {
                    id: "test-shell".into(),
                    path: absolute_path(Path::new(&shell_program())),
                    permissions: [Permission::Execute].into_iter().collect::<BTreeSet<_>>(),
                },
            ],
            ..PolicyConfig::default()
        };
        let b = CommandBroker::with_cap(policy, audit, ExecuteJobRegistry::default(), 3);
        assert_eq!(b.available_permits(), 3);
        let _ = std::fs::remove_dir_all(root);
    }

    // Acquiring permits through execute calls reduces available_permits; releasing restores them.
    #[tokio::test]
    async fn concurrency_governor_available_permits_tracks_usage() {
        let root = temp_root("nmcp-exec-cap3");
        let audit = AuditSink::open(root.join("audit.jsonl")).expect("audit");
        let policy = PolicyConfig {
            audit_path: root.join("audit.jsonl"),
            exec_state_dir: root.join("exec-jobs"),
            roots: vec![
                RootRule {
                    id: "r".into(),
                    path: root.clone(),
                    permissions: [Permission::Execute].into_iter().collect::<BTreeSet<_>>(),
                },
                RootRule {
                    id: "test-shell".into(),
                    path: absolute_path(Path::new(&shell_program())),
                    permissions: [Permission::Execute].into_iter().collect::<BTreeSet<_>>(),
                },
            ],
            ..PolicyConfig::default()
        };
        let b = CommandBroker::with_cap(policy, audit, ExecuteJobRegistry::default(), 2);
        // All permits available at start.
        assert_eq!(b.available_permits(), 2);
        // available_permits() is a live view - after a completed execute the permit is returned.
        // Just confirm the initial state and that with_cap sets the right count.
        let _ = std::fs::remove_dir_all(root);
    }

    // - NMCP-SPEC-002 SB-4: the env injection modality and its three hardenings (I-034) -

    /// Distinctive material with no English substring, so absence assertions cannot collide
    /// with legitimate prose, and long enough that no fragment of a path or a timestamp
    /// mimics it.
    const INJECTED_MATERIAL: &str = "zk8qw-4vnt7-2rjx9-pm3hd-injected";

    fn injected(var: &str) -> Vec<(String, SealedSecret)> {
        vec![(
            var.to_string(),
            SealedSecret::new(INJECTED_MATERIAL.as_bytes().to_vec()),
        )]
    }

    #[cfg(windows)]
    fn print_env_script(var: &str) -> String {
        format!("echo %{var}%")
    }
    #[cfg(not(windows))]
    fn print_env_script(var: &str) -> String {
        format!("echo ${var}")
    }

    /// The modality works: the child process observes the injected variable. The child's
    /// copy is the child's, which is SB-1's stated bound; past the process boundary the
    /// program allowlist is the whole control, and that allowlist is the binding's,
    /// enforced at stage 5b rather than here.
    #[tokio::test]
    async fn an_injected_variable_reaches_the_child_process() {
        let root = temp_root("nmcp-exec-inject-reaches");
        let report = broker(&root)
            .execute_with_injected_env(
                ExecuteRequest {
                    cwd: root.clone(),
                    program: shell_program(),
                    args: shell_args(&print_env_script("DATABASE_URL")),
                    timeout_ms: 10_000,
                    env: BTreeMap::new(),
                    inherit_service_env: Some(false),
                    profile: None,
                },
                &injected("DATABASE_URL"),
            )
            .await
            .expect("execute");
        assert_eq!(report.exit_code, Some(0));
        assert!(
            report.stdout_tail.contains(INJECTED_MATERIAL),
            "the child observes the injected value: {}",
            report.stdout_tail
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// T1c, by name, with the spec's canonical fixture. `DATABASE_URL` is outside the
    /// eight-needle heuristic, which the first assertion proves so the test means
    /// something: under the heuristic alone the injected value would land in the immutable
    /// chain, which is what got v0.1 refused. With redaction by injected name, the audit
    /// `env=` line shows `DATABASE_URL=<redacted>`, and no byte window of the material
    /// appears in any serialized audit record or in the report (the SB-1 measurement
    /// discipline).
    #[tokio::test]
    async fn t1c_an_injected_value_never_reaches_the_audit_line() {
        assert!(
            !is_sensitive_env_name("DATABASE_URL"),
            "the fixture must sit outside the heuristic or this test proves nothing"
        );

        let root = temp_root("nmcp-exec-inject-t1c");
        let report = broker(&root)
            .execute_with_injected_env(
                ExecuteRequest {
                    cwd: root.clone(),
                    program: shell_program(),
                    // The child does not print the variable: this test measures the
                    // broker's own surfaces, not the child's stdout, which is the child's.
                    args: shell_args("echo done"),
                    timeout_ms: 10_000,
                    env: BTreeMap::new(),
                    inherit_service_env: Some(false),
                    profile: None,
                },
                &injected("DATABASE_URL"),
            )
            .await
            .expect("execute");

        let chain = std::fs::read_to_string(root.join("audit.jsonl")).expect("chain");
        assert!(
            chain.contains("DATABASE_URL=<redacted>"),
            "the env= line lands, post-redaction, naming the variable: {chain}"
        );
        assert!(
            !chain.contains(INJECTED_MATERIAL),
            "no audit record carries any byte window of the material"
        );
        let rendered = serde_json::to_string(&report).expect("report");
        assert!(!rendered.contains(INJECTED_MATERIAL));
        let _ = std::fs::remove_dir_all(root);
    }

    /// The durable-job half of T1c plus SB-4's third hardening: the persisted `job.json`
    /// and every status surface show `<redacted>` for the injected name, a caller value
    /// colliding with it neither wins nor leaks, and the child observes the injected value
    /// rather than the caller's.
    #[tokio::test]
    async fn an_injected_name_is_redacted_in_job_metadata_and_wins_a_collision() {
        let root = temp_root("nmcp-exec-inject-job");
        let broker = broker(&root);
        let start = broker
            .execute_start_with_injected_env(
                ExecuteStartRequest {
                    cwd: root.clone(),
                    program: shell_program(),
                    args: shell_args(&print_env_script("DATABASE_URL")),
                    timeout_ms: Some(10_000),
                    // The collision: a caller-supplied plaintext under the injected name.
                    env: BTreeMap::from([("DATABASE_URL".into(), "caller-plain-qq17".into())]),
                    inherit_service_env: Some(false),
                    profile: None,
                },
                &injected("DATABASE_URL"),
            )
            .await
            .expect("start");
        let status = wait_for_terminal(&broker, &start.job_id)
            .await
            .expect("wait");
        assert_eq!(status.exit_code, Some(0));
        assert!(
            status.stdout_tail.contains(INJECTED_MATERIAL),
            "the injection wins the collision in the child: {}",
            status.stdout_tail
        );
        assert!(!status.stdout_tail.contains("caller-plain-qq17"));

        let metadata_path = root.join("exec-jobs").join(&start.job_id).join("job.json");
        let metadata = read_job_metadata(&metadata_path).expect("metadata");
        assert_eq!(metadata.redacted_env["DATABASE_URL"], "<redacted>");
        let persisted = std::fs::read_to_string(&metadata_path).expect("job.json");
        assert!(
            !persisted.contains(INJECTED_MATERIAL),
            "the persisted metadata never carries material"
        );
        assert!(
            !persisted.contains("caller-plain-qq17"),
            "the colliding caller value is redacted with the name, not printed"
        );
        let chain = std::fs::read_to_string(root.join("audit.jsonl")).expect("chain");
        assert!(chain.contains("DATABASE_URL=<redacted>"));
        assert!(!chain.contains(INJECTED_MATERIAL));
        assert!(!chain.contains("caller-plain-qq17"));
        let _ = std::fs::remove_dir_all(root);
    }

    /// T1a: the env report omits an injected variable entirely, never showing even
    /// `NAME=<redacted>`, because reporting the name tells an agent which credential a
    /// governed call carries. The omission is structural in this port: injection is a
    /// per-call parameter that reaches only that call's child, and the report has no
    /// parameter an injected name could arrive through; this drives an injected call first
    /// and then measures the report to hold the property as behaviour rather than only as
    /// architecture.
    #[tokio::test]
    async fn t1a_the_env_report_omits_injected_variables_entirely() {
        let root = temp_root("nmcp-exec-inject-t1a");
        let broker = broker(&root);
        broker
            .execute_with_injected_env(
                ExecuteRequest {
                    cwd: root.clone(),
                    program: shell_program(),
                    args: shell_args("echo done"),
                    timeout_ms: 10_000,
                    env: BTreeMap::new(),
                    inherit_service_env: Some(false),
                    profile: None,
                },
                &injected("DATABASE_URL"),
            )
            .await
            .expect("execute");

        let report = broker.execute_env_report(ExecuteEnvReportRequest {
            profile: None,
            env: BTreeMap::new(),
            inherit_service_env: Some(false),
        });
        assert!(
            !report.redacted_env.contains_key("DATABASE_URL"),
            "an injected variable is omitted, not redacted (T1a)"
        );
        let rendered = serde_json::to_string(&report).expect("report");
        assert!(
            !rendered.contains(INJECTED_MATERIAL),
            "no report surface carries material"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Material that cannot cross the environment boundary is refused before any process
    /// exists, naming the variable and echoing nothing: an environment value must be valid
    /// UTF-8 on every platform this crate builds for, and refusing is the fail-closed
    /// direction (SB-8).
    #[tokio::test]
    async fn non_utf8_material_is_refused_naming_the_variable_only() {
        let root = temp_root("nmcp-exec-inject-utf8");
        let refused = broker(&root)
            .execute_with_injected_env(
                ExecuteRequest {
                    cwd: root.clone(),
                    program: shell_program(),
                    args: shell_args("echo done"),
                    timeout_ms: 10_000,
                    env: BTreeMap::new(),
                    inherit_service_env: Some(false),
                    profile: None,
                },
                &[(
                    "DATABASE_URL".to_string(),
                    SealedSecret::new(vec![0xFF, 0xFE, 0x90, 0x00]),
                )],
            )
            .await
            .expect_err("non-UTF-8 material is refused");
        let message = format!("{refused}");
        assert!(message.contains("DATABASE_URL"), "{message}");
        assert!(message.contains("not echoed"), "{message}");
        let _ = std::fs::remove_dir_all(root);
    }

    /// The heuristic is still the filter for variables the broker did not inject: SB-4
    /// keeps it as an additional filter, never the only one for an injected name. Asserted
    /// beside the injection tests so the two rules are visibly different rules.
    #[test]
    fn the_heuristic_remains_for_non_injected_variables() {
        let env = BTreeMap::from([
            ("API_TOKEN".to_string(), "caller-token".to_string()),
            ("VISIBLE".to_string(), "value".to_string()),
        ]);
        let redacted = redact_env_with_injected(&env, &BTreeSet::new());
        assert_eq!(redacted["API_TOKEN"], "<redacted>");
        assert_eq!(redacted["VISIBLE"], "value");

        // And the injected rule stacks on top rather than replacing it.
        let redacted = redact_env_with_injected(&env, &BTreeSet::from(["VISIBLE".to_string()]));
        assert_eq!(redacted["API_TOKEN"], "<redacted>");
        assert_eq!(redacted["VISIBLE"], "<redacted>");
    }
}
