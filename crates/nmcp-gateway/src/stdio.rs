//! Stdio transport: the gateway starts an MCP server as a child process and speaks
//! JSON-RPC over its standard input and output.
//!
//! This is the half of the gateway that did not exist before DEC-007. Until it landed, an
//! upstream was a URL, which quietly meant the gateway could only reach a server somebody
//! else had already started, while the catalog model describes servers distributed as
//! stdio processes. The crate documentation carries the DEC-007 posture in full.
//!
//! ## Two properties worth stating before the code
//!
//! **The child does not inherit this process's environment.** The service environment holds
//! upstream credentials (`auth_header_env` names variables that live there), so inheriting
//! it would hand every credential to every third-party MCP server the operator ever admits.
//! The child gets exactly what its transport config names, plus the minimum the platform
//! needs to start a process at all. That is a deliberate difference from how most MCP
//! launchers behave.
//!
//! **The spawn is audited.** Starting a long-lived process as the service account is an
//! execution event, not a configuration detail, so it goes in the hash-chained log with its
//! command line, and so does its exit.

use nmcp_audit::{AuditEvent, AuditSink};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tracing::{info, warn};

/// How long to wait for one JSON-RPC response before treating the child as wedged.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for the initialize handshake specifically. Longer, because a server
/// distributed through a package runner may be fetching itself on first run.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_mins(2);

/// The protocol revision the gateway speaks to a downstream stdio server.
///
/// Deliberately a revision this server family implements rather than the newest published
/// one: the gateway is a client here, and claiming a revision it cannot hold up its end of
/// would be the same dishonesty the proto crate's supported-versions set exists to avoid.
/// `the_client_protocol_revision_is_one_this_family_supports` drift-locks it against that
/// set.
pub(crate) const CLIENT_PROTOCOL_VERSION: &str = "2025-11-25";

/// A running child and the pipes to it.
struct Running {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

/// A link to an MCP server this gateway starts and owns.
pub struct StdioLink {
    upstream_id: String,
    command: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    cwd: Option<PathBuf>,
    audit: AuditSink,
    /// One request at a time. MCP stdio servers are commonly single-threaded and a shared
    /// pipe has no framing that would let responses be told apart out of order, so the
    /// alternative to this mutex is a correlation layer that buys concurrency the operator
    /// did not ask for. Serialising is the honest default.
    running: Mutex<Option<Running>>,
}

impl StdioLink {
    /// Build a link. The child spawns on first use, not here.
    pub fn new(
        upstream_id: impl Into<String>,
        command: impl Into<String>,
        args: Vec<String>,
        env: BTreeMap<String, String>,
        cwd: Option<PathBuf>,
        audit: AuditSink,
    ) -> Self {
        Self {
            upstream_id: upstream_id.into(),
            command: command.into(),
            args,
            env,
            cwd,
            audit,
            running: Mutex::new(None),
        }
    }

    /// The command line, for logs and audit records. Never includes environment values.
    fn command_line(&self) -> String {
        if self.args.is_empty() {
            self.command.clone()
        } else {
            format!("{} {}", self.command, self.args.join(" "))
        }
    }

    fn audit_spawn(&self, decision: &str, summary: String) {
        let mut event = AuditEvent::new("gateway.stdio.spawn", summary);
        event.decision = decision.to_string();
        event.upstream_id = Some(self.upstream_id.clone());
        if let Err(e) = self.audit.append(&event) {
            warn!(upstream = %self.upstream_id, "gateway: failed to audit stdio spawn: {e}");
        }
    }

    /// Ask the child for its tool list, starting it first if it is not running.
    ///
    /// # Errors
    ///
    /// A message naming what failed: the spawn, the pipe, or the child's own error.
    pub async fn list_tools(&self) -> Result<Vec<Value>, String> {
        let response = self
            .request("tools/list", json!({}), REQUEST_TIMEOUT)
            .await?;
        let tools = response
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(tools)
    }

    /// Proxy one tool call to the child.
    ///
    /// # Errors
    ///
    /// A message naming what failed: the spawn, the pipe, or the child's own error.
    pub async fn call_tool(&self, name: &str, args: Value) -> Result<Value, String> {
        self.request(
            "tools/call",
            json!({ "name": name, "arguments": args }),
            REQUEST_TIMEOUT,
        )
        .await
    }

    /// Stop the child, if one is running. Idempotent.
    pub async fn shutdown(&self) {
        let mut guard = self.running.lock().await;
        if let Some(mut running) = guard.take() {
            let _ = running.child.start_kill();
            let _ = running.child.wait().await;
            info!(upstream = %self.upstream_id, "gateway: stdio child stopped");
            self.audit_spawn(
                "stopped",
                json!({"upstream": self.upstream_id, "command": self.command_line()}).to_string(),
            );
        }
    }

    /// Send one request, restarting the child once if the pipe has died under us.
    ///
    /// A single retry rather than a loop: a server that dies on every request is broken, and
    /// retrying forever would turn that into an invisible restart storm rather than a
    /// reported failure.
    async fn request(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        match self.request_once(method, params.clone(), timeout).await {
            Ok(value) => Ok(value),
            Err(first) => {
                warn!(
                    upstream = %self.upstream_id,
                    method,
                    "gateway: stdio request failed, restarting the child once: {first}"
                );
                self.shutdown().await;
                self.request_once(method, params, timeout)
                    .await
                    .map_err(|second| format!("{second} (after a restart; first failure: {first})"))
            }
        }
    }

    async fn request_once(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        let mut guard = self.running.lock().await;
        if guard.is_none() {
            let started = self.spawn().await?;
            *guard = Some(started);
        }
        // Written as a refusal rather than an `expect`: the branch above just filled the
        // slot, so this cannot fire, and writing it this way keeps the transport provably
        // panic-free instead of relying on that reasoning.
        let Some(running) = guard.as_mut() else {
            return Err("stdio link state is inconsistent: no child after a spawn".to_string());
        };
        let id = running.next_id;
        running.next_id += 1;
        send_request(running, id, method, params, timeout).await
    }

    /// Start the child process.
    async fn spawn(&self) -> Result<Running, String> {
        let mut command = Command::new(&self.command);
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // The child's stderr is its own business and reading it would need another
            // pump; inheriting it would interleave into the service log without attribution.
            .stderr(Stdio::null())
            .kill_on_drop(true);

        // Credential isolation. See the module header: the service environment holds
        // upstream tokens, and a third-party MCP server has no business seeing them.
        apply_isolated_env(&mut command);
        for (key, value) in &self.env {
            command.env(key, value);
        }
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        let mut child = command.spawn().map_err(|e| {
            let reason = format!("could not start '{}': {e}", self.command_line());
            self.audit_spawn(
                "denied",
                json!({"upstream": self.upstream_id, "command": self.command_line(), "error": e.to_string()})
                    .to_string(),
            );
            reason
        })?;

        let stdin = child.stdin.take().ok_or("child stdin was not piped")?;
        let stdout = child.stdout.take().ok_or("child stdout was not piped")?;
        let pid = child.id();
        let mut running = Running {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
        };

        info!(
            upstream = %self.upstream_id,
            pid = pid.unwrap_or_default(),
            "gateway: started stdio child {}",
            self.command_line()
        );
        self.audit_spawn(
            "allowed",
            json!({
                "upstream": self.upstream_id,
                "command": self.command_line(),
                "pid": pid,
                "env_inherited": false,
            })
            .to_string(),
        );

        // Handshake before anything else, so a server that will not negotiate is reported as
        // a failed start rather than as a tool list that is mysteriously empty.
        let id = running.next_id;
        running.next_id += 1;
        send_request(
            &mut running,
            id,
            "initialize",
            json!({
                "protocolVersion": CLIENT_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "nMCP", "version": env!("CARGO_PKG_VERSION") },
            }),
            HANDSHAKE_TIMEOUT,
        )
        .await?;
        send_notification(&mut running, "notifications/initialized").await?;

        Ok(running)
    }
}

/// Variables a child needs before it can start at all. Everything else is withheld.
#[cfg(windows)]
const MINIMUM_ENV: &[&str] = &[
    "SystemRoot",
    "windir",
    "PATH",
    "PATHEXT",
    "COMSPEC",
    "TEMP",
    "TMP",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
];

#[cfg(not(windows))]
const MINIMUM_ENV: &[&str] = &["PATH", "HOME", "TMPDIR", "LANG"];

/// No console window for a background child of a service.
#[cfg(windows)]
pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Build a child environment from nothing, plus the minimum a process needs to start.
///
/// Shared with [`crate::container`] so the container runtime CLI is held to exactly the same
/// isolation as a server this gateway starts directly. A runtime CLI that inherited the
/// service environment would hand it on to every container it starts, which is the same leak
/// this module exists to prevent wearing a different hat.
pub(crate) fn apply_isolated_env(command: &mut Command) {
    command.env_clear();
    for passthrough in MINIMUM_ENV {
        if let Ok(value) = std::env::var(passthrough) {
            command.env(passthrough, value);
        }
    }
}

/// Write one JSON-RPC request and read until its response arrives.
async fn send_request(
    running: &mut Running,
    id: u64,
    method: &str,
    params: Value,
    timeout: Duration,
) -> Result<Value, String> {
    let request = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let mut line = serde_json::to_string(&request).map_err(|e| e.to_string())?;
    line.push('\n');
    running
        .stdin
        .write_all(line.as_bytes())
        .await
        .map_err(|e| format!("writing to child stdin: {e}"))?;
    running
        .stdin
        .flush()
        .await
        .map_err(|e| format!("flushing child stdin: {e}"))?;

    tokio::time::timeout(timeout, read_response(running, id))
        .await
        .map_err(|_| {
            format!(
                "child did not answer '{method}' within {}s",
                timeout.as_secs()
            )
        })?
}

async fn send_notification(running: &mut Running, method: &str) -> Result<(), String> {
    let notification = json!({"jsonrpc": "2.0", "method": method, "params": {}});
    let mut line = serde_json::to_string(&notification).map_err(|e| e.to_string())?;
    line.push('\n');
    running
        .stdin
        .write_all(line.as_bytes())
        .await
        .map_err(|e| format!("writing to child stdin: {e}"))?;
    running
        .stdin
        .flush()
        .await
        .map_err(|e| format!("flushing child stdin: {e}"))
}

/// Read lines until one is a JSON-RPC message carrying our id.
///
/// Anything else on the pipe (notifications, log lines a server writes to stdout despite the
/// spec, blank lines) is skipped rather than treated as an answer. A server that pollutes
/// stdout is common enough that failing on the first unparseable line would make this
/// transport useless in practice.
async fn read_response(running: &mut Running, id: u64) -> Result<Value, String> {
    loop {
        let mut line = String::new();
        let read = running
            .stdout
            .read_line(&mut line)
            .await
            .map_err(|e| format!("reading child stdout: {e}"))?;
        if read == 0 {
            return Err("child closed its stdout".to_string());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if message.get("id").and_then(Value::as_u64) != Some(id) {
            continue;
        }
        if let Some(error) = message.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("upstream error");
            return Err(message.to_string());
        }
        return Ok(message.get("result").cloned().unwrap_or(Value::Null));
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
    use super::*;

    fn test_audit() -> AuditSink {
        AuditSink::open(
            std::env::temp_dir().join(format!("nmcp-gateway-stdio-{}.jsonl", uuid::Uuid::new_v4())),
        )
        .expect("audit sink")
    }

    fn link(command: &str, args: &[&str]) -> StdioLink {
        StdioLink::new(
            "test",
            command,
            args.iter().map(|a| (*a).to_string()).collect(),
            BTreeMap::new(),
            None,
            test_audit(),
        )
    }

    /// The revision this transport claims as a client is one this server family actually
    /// supports, read from the proto crate rather than restated, so the two cannot drift.
    #[test]
    fn the_client_protocol_revision_is_one_this_family_supports() {
        assert!(
            nmcp_proto::SUPPORTED_PROTOCOL_VERSIONS.contains(&CLIENT_PROTOCOL_VERSION),
            "the stdio client claims {CLIENT_PROTOCOL_VERSION}, which this family does not implement"
        );
    }

    /// G4-30. The credential-isolation property, driven through the function that implements
    /// it rather than asserted about the allowlist beside it.
    ///
    /// The previous version of this test iterated `MINIMUM_ENV` and substring-matched each
    /// NAME. It never called [`apply_isolated_env`] and never asserted `env_clear()` runs,
    /// which is the line that actually implements isolation: delete that line and every
    /// third-party child inherits the service environment, where `auth_header_env` upstream
    /// tokens live, with the suite still green.
    ///
    /// So this starts a real child and reads the environment it actually got. `USERPROFILE`
    /// is the probe because it always exists on Windows, is not in `MINIMUM_ENV`, and is the
    /// kind of thing that should never cross this boundary: it names the account the service
    /// runs as. The parent is asserted to have it first, so the test cannot pass by the
    /// probe simply not existing.
    #[cfg(windows)]
    #[tokio::test]
    async fn an_isolated_child_starts_from_a_cleared_environment() {
        let system_root = std::env::var("SystemRoot").expect("SystemRoot on Windows");
        assert!(
            std::env::var("USERPROFILE").is_ok(),
            "the parent must carry the probe variable, or this test proves nothing"
        );

        let mut command = Command::new(format!("{system_root}\\System32\\cmd.exe"));
        command.args(["/c", "set"]);
        apply_isolated_env(&mut command);
        let output = command.output().await.expect("child ran");
        let seen = String::from_utf8_lossy(&output.stdout).to_ascii_uppercase();

        assert!(
            seen.contains("SYSTEMROOT="),
            "the child must get the minimum it needs to start: {seen}"
        );
        assert!(
            !seen.contains("USERPROFILE="),
            "the child inherited the parent environment, so env_clear() is not doing its job"
        );
    }

    /// The allowlist itself, which is the other half: `apply_isolated_env` clears everything
    /// and then hands back exactly these, so a credential-shaped name added here would be
    /// isolation-proof and still leak.
    #[test]
    fn the_minimum_environment_carries_nothing_that_looks_like_a_credential() {
        for name in MINIMUM_ENV {
            let lower = name.to_ascii_lowercase();
            assert!(
                !lower.contains("token")
                    && !lower.contains("secret")
                    && !lower.contains("key")
                    && !lower.contains("password")
                    && !lower.starts_with("nmcp"),
                "{name} must not be passed through to a third-party server"
            );
        }
    }

    #[tokio::test]
    async fn a_command_that_does_not_exist_fails_with_the_command_line_named() {
        let link = link("nmcp-this-program-does-not-exist", &[]);
        let err = link
            .list_tools()
            .await
            .expect_err("a missing program must not look like an empty tool list");
        assert!(
            err.contains("nmcp-this-program-does-not-exist"),
            "the failure must name what it tried to start: {err}"
        );
    }

    /// Drives a real child process end to end. The child is a PowerShell loop speaking just
    /// enough MCP to answer initialize and tools/list, so the test proves the pipe, the
    /// framing, the handshake and the id correlation without depending on a third-party
    /// server being installed.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_real_child_process_completes_the_handshake_and_answers_tools_list() {
        let script = std::env::temp_dir().join(format!("nmcp-stdio-{}.ps1", uuid::Uuid::new_v4()));
        std::fs::write(
            &script,
            r"
$ErrorActionPreference = 'Stop'
while ($true) {
  $line = [Console]::In.ReadLine()
  if ($null -eq $line) { break }
  if ($line.Trim() -eq '') { continue }
  $msg = $line | ConvertFrom-Json
  if (-not $msg.id) { continue }
  # A stray line on stdout, which real servers do emit and this transport must skip.
  [Console]::Out.WriteLine('not json at all')
  if ($msg.method -eq 'initialize') {
    [Console]::Out.WriteLine((@{jsonrpc='2.0';id=$msg.id;result=@{protocolVersion='2025-11-25';serverInfo=@{name='fake';version='0'}}} | ConvertTo-Json -Compress -Depth 6))
  } elseif ($msg.method -eq 'tools/list') {
    [Console]::Out.WriteLine((@{jsonrpc='2.0';id=$msg.id;result=@{tools=@(@{name='echo';description='echo';inputSchema=@{}})}} | ConvertTo-Json -Compress -Depth 8))
  } elseif ($msg.method -eq 'tools/call') {
    [Console]::Out.WriteLine((@{jsonrpc='2.0';id=$msg.id;result=@{content=@(@{type='text';text='pong'})}} | ConvertTo-Json -Compress -Depth 8))
  } else {
    [Console]::Out.WriteLine((@{jsonrpc='2.0';id=$msg.id;error=@{code=-32601;message='method not found'}} | ConvertTo-Json -Compress -Depth 6))
  }
}
",
        )
        .expect("write fake server");

        let link = link(
            "powershell",
            &[
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script.to_str().expect("script path"),
            ],
        );

        let tools = link.list_tools().await.expect("tools/list must succeed");
        assert_eq!(tools.len(), 1, "got {tools:?}");
        assert_eq!(tools[0]["name"], "echo");

        let result = link
            .call_tool("echo", json!({"msg": "ping"}))
            .await
            .expect("tools/call must succeed");
        assert_eq!(result["content"][0]["text"], "pong");

        link.shutdown().await;
        let _ = std::fs::remove_file(&script);
    }
}
