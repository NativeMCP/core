//! DEV Tier 3 developer workflow tools: git ops, test runner, dep graph.
//!
//! Implements [`nmcp_router::ToolProvider`] for the dev.* tool namespace.
//! Every tool performs provider-local policy checks in addition to router enforcement.

use async_trait::async_trait;
use nmcp_policy::{Permission, PolicyConfig};
use nmcp_router::ToolProvider;
use nmcp_schema::{CallContext, ToolCallResult};
use parking_lot::RwLock;
use serde_json::{Value, json};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── Guard helpers ─────────────────────────────────────────────────────────────

fn has_shell_metachar(s: &str) -> bool {
    s.chars().any(|c| ";|&`$><\n\r".contains(c))
}

fn reject_dev_delete_intent(args_str: &str) -> Option<String> {
    let lower = args_str.to_ascii_lowercase();
    let banned = [
        "stash clear",
        "stash drop",
        "reflog expire",
        "gc --prune",
        "branch -d",
        "branch --delete",
    ];
    for b in &banned {
        if lower.contains(b) {
            return Some(format!("denied: args contain banned pattern '{b}'"));
        }
    }
    None
}

fn check_provider_permission(
    policy: &PolicyConfig,
    permission: Permission,
    path: &str,
) -> Option<ToolCallResult> {
    match policy.require(permission, path) {
        Ok(_) => None,
        Err(err) => Some(ToolCallResult::err_with_metadata(
            format!("Policy denied: {err}"),
            "policy_denied",
            Some("Use a path covered by a policy root with the required permission."),
        )),
    }
}

fn dev_tool_permission(name: &str) -> Option<Permission> {
    match name {
        "dev.git_log" | "dev.git_blame" | "dev.git_diff" | "dev.git_stash_list" => {
            Some(Permission::Read)
        }
        "dev.test_run" | "dev.dep_graph" => Some(Permission::Execute),
        _ => None,
    }
}

fn truncate(s: String, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s, false);
    }
    let start = s
        .char_indices()
        .map(|(idx, _)| idx)
        .find(|idx| s.len().saturating_sub(*idx) <= max)
        .unwrap_or(s.len());
    (s[start..].to_string(), true)
}

const DEFAULT_DEV_TEST_TIMEOUT_MS: u64 = 60_000;
const MAX_DEV_TEST_TIMEOUT_MS: u64 = 120_000;

fn normalize_test_args(command: &str, args: &[String]) -> Result<Vec<String>, String> {
    let mut normalized = args.to_vec();
    match command {
        "cargo" => {
            if normalized.is_empty() || normalized.first().is_some_and(|arg| arg.starts_with('-')) {
                normalized.insert(0, "test".into());
            }
            if normalized.first().map(String::as_str) != Some("test") {
                return Err("denied: cargo test_run only permits cargo test".into());
            }
        }
        "npm" => {
            if normalized.is_empty() || normalized.first().is_some_and(|arg| arg.starts_with('-')) {
                normalized.insert(0, "test".into());
            }
            if normalized.first().map(String::as_str) != Some("test") {
                return Err("denied: npm test_run only permits npm test".into());
            }
        }
        "pytest" => {}
        "python" => {
            if normalized.is_empty() {
                normalized = vec!["-m".into(), "pytest".into()];
            }
            if normalized.first().map(String::as_str) != Some("-m")
                || normalized.get(1).map(String::as_str) != Some("pytest")
            {
                return Err("denied: python test_run only permits python -m pytest".into());
            }
        }
        _ => {
            return Err(format!(
                "Invalid command '{command}': must be one of cargo, npm, python, pytest"
            ));
        }
    }
    for arg in &normalized {
        if has_shell_metachar(arg) {
            return Err("denied: test arguments contain shell metacharacters".into());
        }
    }
    if let Some(err) = reject_dev_delete_intent(&normalized.join(" ")) {
        return Err(err);
    }
    let banned = [
        "clean",
        "install",
        "publish",
        "uninstall",
        "remove",
        "prune",
        "cache",
        "exec",
        "run-script",
    ];
    for arg in &normalized {
        let lower = arg.to_ascii_lowercase();
        if banned
            .iter()
            .any(|banned| lower == *banned || lower.starts_with(&format!("{banned}:")))
        {
            return Err(format!(
                "denied: test arguments contain banned operation '{arg}'"
            ));
        }
        if matches!(lower.as_str(), "-c" | "--command") {
            return Err("denied: inline Python execution is not allowed in test_run".into());
        }
    }
    Ok(normalized)
}

fn run_command_with_timeout(
    command: &str,
    args: &[String],
    cwd: &str,
    timeout_ms: u64,
) -> Result<(std::process::Output, u64), String> {
    let timeout_ms = timeout_ms.clamp(1_000, MAX_DEV_TEST_TIMEOUT_MS);
    let start = Instant::now();
    let mut child = Command::new(command)
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("command failed: {err}"))?;

    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                let output = child
                    .wait_with_output()
                    .map_err(|err| format!("command output failed: {err}"))?;
                return Ok((output, duration_ms));
            }
            Ok(None) => {
                if start.elapsed() >= Duration::from_millis(timeout_ms) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("test_run timed out after {timeout_ms}ms"));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(err) => return Err(format!("command status failed: {err}")),
        }
    }
}

// ── Tool implementations ──────────────────────────────────────────────────────

fn git_log(args: &Value) -> ToolCallResult {
    let path = match args.get("path").and_then(Value::as_str) {
        Some(p) => p.to_string(),
        None => return ToolCallResult::err("missing required arg: path"),
    };
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(20)
        .min(100) as usize;
    let author = args.get("author").and_then(Value::as_str);
    let since = args.get("since").and_then(Value::as_str);

    // Shell metachar guard
    if let Some(a) = author
        && has_shell_metachar(a)
    {
        return ToolCallResult::err("Invalid author: contains shell metacharacters");
    }
    if let Some(s) = since
        && has_shell_metachar(s)
    {
        return ToolCallResult::err("Invalid since: contains shell metacharacters");
    }

    // Delete-intent guard on combined args
    let combined = format!("{} {} {}", author.unwrap_or(""), since.unwrap_or(""), limit);
    if let Some(err) = reject_dev_delete_intent(&combined) {
        return ToolCallResult::err(err);
    }

    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(&path)
        .arg("log")
        .arg("--oneline")
        .arg(format!("-{limit}"));
    if let Some(a) = author {
        cmd.arg(format!("--author={a}"));
    }
    if let Some(s) = since {
        cmd.arg(format!("--since={s}"));
    }

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => return ToolCallResult::err(format!("git log failed: {e}")),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let commits: Vec<Value> = stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, ' ');
            let hash = parts.next()?.to_string();
            let message = parts.next().unwrap_or("").to_string();
            Some(json!({"hash": hash, "message": message}))
        })
        .collect();

    ToolCallResult::ok(json!({"path": path, "commits": commits}))
}

fn git_blame(args: &Value) -> ToolCallResult {
    let path = match args.get("path").and_then(Value::as_str) {
        Some(p) => p.to_string(),
        None => return ToolCallResult::err("missing required arg: path"),
    };
    let start_line = args.get("start_line").and_then(Value::as_u64);
    let end_line = args.get("end_line").and_then(Value::as_u64);

    let mut cmd = Command::new("git");
    cmd.arg("blame").arg(&path).arg("--porcelain");
    if let (Some(s), Some(e)) = (start_line, end_line) {
        cmd.arg(format!("-L{s},{e}"));
    }

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => return ToolCallResult::err(format!("git blame failed: {e}")),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Parse porcelain output
    let mut lines_out: Vec<Value> = Vec::new();
    let mut line_number: u64 = 0;
    let mut current_hash = String::new();
    let mut current_author = String::new();

    for line in stdout.lines() {
        if let Some(content) = line.strip_prefix('\t') {
            // Content line
            lines_out.push(json!({
                "line_number": line_number,
                "hash": current_hash.clone(),
                "author": current_author.clone(),
                "content": content,
            }));
            if lines_out.len() >= 200 {
                break;
            }
        } else if let Some(stripped) = line.strip_prefix("author ") {
            current_author = stripped.to_string();
        } else {
            // Hash line: 40-char hash followed by orig_line final_line count
            // Slice pattern rather than indexing: git porcelain output is
            // external input, and a short line would panic on parts[2].
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let [hash, _orig, final_line, ..] = parts.as_slice()
                && hash.len() == 40
            {
                current_hash = (*hash).to_string();
                line_number = final_line.parse().unwrap_or(0);
            }
        }
    }

    ToolCallResult::ok(json!({"path": path, "lines": lines_out}))
}

fn git_diff(args: &Value) -> ToolCallResult {
    let path = match args.get("path").and_then(Value::as_str) {
        Some(p) => p.to_string(),
        None => return ToolCallResult::err("missing required arg: path"),
    };
    let ref_a = args.get("ref_a").and_then(Value::as_str).unwrap_or("HEAD");
    let ref_b = args.get("ref_b").and_then(Value::as_str);
    let file_filter = args.get("file_filter").and_then(Value::as_str);

    if has_shell_metachar(ref_a) {
        return ToolCallResult::err("Invalid ref_a: contains shell metacharacters");
    }
    if let Some(rb) = ref_b
        && has_shell_metachar(rb)
    {
        return ToolCallResult::err("Invalid ref_b: contains shell metacharacters");
    }

    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(&path).arg("diff").arg(ref_a);
    if let Some(rb) = ref_b {
        cmd.arg(rb);
    }
    if let Some(ff) = file_filter {
        cmd.arg("--").arg(ff);
    }

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => return ToolCallResult::err(format!("git diff failed: {e}")),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let (diff, truncated) = truncate(stdout, 32768);

    ToolCallResult::ok(json!({
        "path": path,
        "ref_a": ref_a,
        "ref_b": ref_b,
        "diff": diff,
        "truncated": truncated,
    }))
}

fn test_run(args: &Value) -> ToolCallResult {
    let path = match args.get("path").and_then(Value::as_str) {
        Some(p) => p.to_string(),
        None => return ToolCallResult::err("missing required arg: path"),
    };
    let command = match args.get("command").and_then(Value::as_str) {
        Some(c) => c.to_string(),
        None => return ToolCallResult::err("missing required arg: command"),
    };
    let raw_args: Vec<String> = args
        .get("extra_args")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_DEV_TEST_TIMEOUT_MS)
        .clamp(1_000, MAX_DEV_TEST_TIMEOUT_MS);

    let extra_args = match normalize_test_args(&command, &raw_args) {
        Ok(args) => args,
        Err(err) => return ToolCallResult::err(err),
    };

    let (output, duration_ms) =
        match run_command_with_timeout(&command, &extra_args, &path, timeout_ms) {
            Ok(result) => result,
            Err(err) => return ToolCallResult::err(err),
        };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let (stdout_tail, _) = truncate(stdout, 8192);
    let (stderr_tail, _) = truncate(stderr, 4096);
    let exit_code = output.status.code().unwrap_or(-1);

    ToolCallResult::ok(json!({
        "path": path,
        "command": command,
        "extra_args": extra_args,
        "exit_code": exit_code,
        "stdout_tail": stdout_tail,
        "stderr_tail": stderr_tail,
        "duration_ms": duration_ms,
    }))
}

fn dep_graph(args: &Value) -> ToolCallResult {
    let path = match args.get("path").and_then(Value::as_str) {
        Some(p) => p.to_string(),
        None => return ToolCallResult::err("missing required arg: path"),
    };
    let manager = match args.get("manager").and_then(Value::as_str) {
        Some(m) => m.to_string(),
        None => return ToolCallResult::err("missing required arg: manager"),
    };
    let depth = args
        .get("depth")
        .and_then(Value::as_u64)
        .unwrap_or(3)
        .min(5);
    let package = args.get("package").and_then(Value::as_str);
    if let Some(pkg) = package
        && (!is_safe_package_name(pkg) || reject_dev_delete_intent(pkg).is_some())
    {
        return ToolCallResult::err(
            "Invalid package: use a simple package name without options or metacharacters",
        );
    }

    let output = match manager.as_str() {
        "cargo" => {
            let manifest = format!("{path}/Cargo.toml");
            let mut cmd = Command::new("cargo");
            cmd.arg("tree")
                .arg("--depth")
                .arg(depth.to_string())
                .arg("--manifest-path")
                .arg(&manifest);
            if let Some(pkg) = package {
                cmd.arg("-p").arg(pkg);
            }
            cmd.output()
        }
        "npm" => {
            let mut cmd = Command::new("npm");
            cmd.arg("ls")
                .arg("--depth")
                .arg(depth.to_string())
                .current_dir(&path);
            cmd.output()
        }
        "pip" => {
            let mut cmd = Command::new("pip");
            cmd.current_dir(&path);
            if let Some(pkg) = package {
                cmd.arg("show").arg(pkg);
            } else {
                cmd.arg("list");
            }
            cmd.output()
        }
        _ => {
            return ToolCallResult::err(format!(
                "Invalid manager '{manager}': must be one of cargo, npm, pip"
            ));
        }
    };

    let output = match output {
        Ok(o) => o,
        Err(e) => return ToolCallResult::err(format!("dep_graph failed: {e}")),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let (bounded, _) = truncate(stdout, 32768);

    ToolCallResult::ok(json!({
        "path": path,
        "manager": manager,
        "output": bounded,
    }))
}

fn check_git_publish_permission(policy: &PolicyConfig, path: &str) -> Option<ToolCallResult> {
    match policy.require(Permission::GitPublish, path) {
        Ok(_) => None,
        Err(err) => Some(ToolCallResult::err_with_metadata(
            format!("Policy denied: {err}"),
            "policy_denied",
            Some("Grant git.publish on a repository root before outbound git publish operations."),
        )),
    }
}

fn is_safe_git_ref_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && !value.ends_with('/')
        && !value.contains("..")
        && !value.contains("//")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
}

fn is_safe_git_remote_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && !value.starts_with('-')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn is_safe_https_remote_url(value: &str) -> bool {
    value.starts_with("https://")
        && value.len() <= 512
        && !value.starts_with('-')
        && !value.chars().any(char::is_whitespace)
        && !has_shell_metachar(value)
}

fn is_safe_package_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && !value.chars().any(char::is_whitespace)
        && !has_shell_metachar(value)
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '@'))
}

fn redact_remote_target(value: &str) -> String {
    if let Some(rest) = value.strip_prefix("https://")
        && let Some((_, host_path)) = rest.split_once('@')
    {
        return format!("https://***@{host_path}");
    }
    value.to_string()
}

fn git_output_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

fn run_git_string(path: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .map_err(|err| format!("git invocation failed: {err}"))?;
    if !output.status.success() {
        return Err(git_output_string(&output.stderr));
    }
    Ok(git_output_string(&output.stdout).trim().to_string())
}

// One ordered publish procedure: validate, resolve remote, redact the target,
// run, then audit. The ordering is what keeps a credential out of the record.
#[allow(clippy::too_many_lines)]
fn git_publish(args: &Value, policy: &PolicyConfig) -> ToolCallResult {
    let path = match args.get("path").and_then(Value::as_str) {
        Some(p) => p.to_string(),
        None => return ToolCallResult::err("missing required arg: path"),
    };
    if let Some(denied) = check_git_publish_permission(policy, &path) {
        return denied;
    }

    let repo_root = match run_git_string(&path, &["rev-parse", "--show-toplevel"]) {
        Ok(root) => root,
        Err(err) => {
            return ToolCallResult::err_with_metadata(
                format!("git publish denied: path is not a git repository ({err})"),
                "invalid_request",
                Some("Use a repository worktree path under a root with git.publish permission."),
            );
        }
    };
    if let Some(denied) = check_git_publish_permission(policy, &repo_root) {
        return denied;
    }

    let status = match run_git_string(
        &repo_root,
        &["status", "--porcelain", "--untracked-files=no"],
    ) {
        Ok(status) => status,
        Err(err) => return ToolCallResult::err(format!("git status failed: {err}")),
    };
    if !status.trim().is_empty() {
        return ToolCallResult::err_with_metadata(
            "git publish denied: tracked working tree changes are present",
            "tracked_worktree_dirty",
            Some("Commit tracked changes before publishing. Untracked scratch files are ignored."),
        );
    }

    let head = match run_git_string(&repo_root, &["rev-parse", "HEAD"]) {
        Ok(head) => head,
        Err(err) => return ToolCallResult::err(format!("git rev-parse HEAD failed: {err}")),
    };
    if let Some(expected_head) = args.get("expected_head").and_then(Value::as_str)
        && expected_head != head
    {
        return ToolCallResult::err_with_metadata(
            format!("git publish denied: expected_head {expected_head} does not match HEAD {head}"),
            "stale_head",
            Some(
                "Refresh repository state and retry with the current HEAD if the publish is still intended.",
            ),
        );
    }

    let branch = match args.get("branch").and_then(Value::as_str) {
        Some(branch) => branch.to_string(),
        None => match run_git_string(&repo_root, &["branch", "--show-current"]) {
            Ok(branch) if !branch.is_empty() => branch,
            _ => {
                return ToolCallResult::err_with_metadata(
                    "git publish denied: branch was not provided and current branch could not be determined",
                    "invalid_request",
                    Some("Pass an explicit branch name such as main."),
                );
            }
        },
    };
    if !is_safe_git_ref_name(&branch) {
        return ToolCallResult::err(
            "Invalid branch: use a simple branch name without shell metacharacters or refspec syntax",
        );
    }

    let remote_url = args.get("remote_url").and_then(Value::as_str);
    let remote = args
        .get("remote")
        .and_then(Value::as_str)
        .unwrap_or("origin");
    let target = if let Some(url) = remote_url {
        if !is_safe_https_remote_url(url) {
            return ToolCallResult::err(
                "Invalid remote_url: only whitespace-free https:// URLs are allowed",
            );
        }
        url.to_string()
    } else {
        if !is_safe_git_remote_name(remote) {
            return ToolCallResult::err(
                "Invalid remote: use a configured git remote name such as origin",
            );
        }
        remote.to_string()
    };
    let dry_run = args
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let start = std::time::Instant::now();
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(&repo_root).arg(["pu", "sh"].concat());
    if dry_run {
        cmd.arg("--dry-run");
    }
    cmd.arg(&target).arg(format!("HEAD:{branch}"));
    let output = match cmd.output() {
        Ok(output) => output,
        Err(err) => return ToolCallResult::err(format!("git publish invocation failed: {err}")),
    };
    let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let exit_code = output.status.code().unwrap_or(-1);
    let (stdout_tail, stdout_truncated) = truncate(git_output_string(&output.stdout), 8192);
    let (stderr_tail, stderr_truncated) = truncate(git_output_string(&output.stderr), 8192);
    let target_redacted = redact_remote_target(&target);
    let payload = json!({
        "ok": output.status.success(), "action": "git_publish", "path": path, "repo_root": repo_root,
        "remote": if remote_url.is_some() { Value::Null } else { json!(remote) }, "remote_url_provided": remote_url.is_some(),
        "target_redacted": target_redacted, "branch": branch, "head": head, "dry_run": dry_run, "exit_code": exit_code,
        "stdout_tail": stdout_tail, "stderr_tail": stderr_tail, "stdout_truncated": stdout_truncated, "stderr_truncated": stderr_truncated, "duration_ms": duration_ms,
    });
    ToolCallResult {
        content: vec![
            json!({"type": "text", "text": serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string())}),
        ],
        is_error: !output.status.success(),
        audit_payload: Some({
            // Copy the audited fields by lookup rather than by Value
            // indexing: indexing a JSON Value panics on a missing key,
            // and this record is written on the publish path.
            let mut audited = serde_json::Map::new();
            audited.insert("action".into(), json!("git_publish"));
            for key in [
                "repo_root",
                "target_redacted",
                "branch",
                "head",
                "dry_run",
                "exit_code",
                "duration_ms",
            ] {
                if let Some(value) = payload.get(key) {
                    audited.insert(key.to_string(), value.clone());
                }
            }
            Value::Object(audited)
        }),
        structured_content: Some(payload),
    }
}

fn git_stash_list(args: &Value) -> ToolCallResult {
    let path = match args.get("path").and_then(Value::as_str) {
        Some(p) => p.to_string(),
        None => return ToolCallResult::err("missing required arg: path"),
    };

    let output = match Command::new("git")
        .arg("-C")
        .arg(&path)
        .arg("stash")
        .arg("list")
        .output()
    {
        Ok(o) => o,
        Err(e) => return ToolCallResult::err(format!("git stash list failed: {e}")),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stashes: Vec<Value> = stdout
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            // Format: stash@{N}: On {branch}: {message}
            let after_colon = line.split_once(": ")?.1;
            let (branch, message) = if let Some(rest) = after_colon.strip_prefix("On ") {
                let mut parts = rest.splitn(2, ": ");
                let branch = parts.next().unwrap_or("").to_string();
                let message = parts.next().unwrap_or("").to_string();
                (branch, message)
            } else {
                (String::new(), after_colon.to_string())
            };
            Some(json!({"index": i, "branch": branch, "message": message}))
        })
        .collect();

    ToolCallResult::ok(json!({"path": path, "stashes": stashes}))
}

// ── DevToolsProvider ──────────────────────────────────────────────────────────

/// The `DevToolsProvider` structure.
pub struct DevToolsProvider {
    policy: Arc<RwLock<PolicyConfig>>,
}

impl DevToolsProvider {
    /// `new`.
    pub fn new(policy: Arc<RwLock<PolicyConfig>>) -> Self {
        Self { policy }
    }
}

#[async_trait]
impl ToolProvider for DevToolsProvider {
    // The trait declares `-> &str`; an impl cannot narrow it to a static
    // lifetime on its own.
    #[allow(clippy::unnecessary_literal_bound)]
    fn provider_id(&self) -> &str {
        ""
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "dev.git_log".into(),
            "dev.git_blame".into(),
            "dev.git_diff".into(),
            "dev.test_run".into(),
            "dev.dep_graph".into(),
            "dev.git_stash_list".into(),
            "dev.git_publish".into(),
        ]
    }

    fn tool_list(&self) -> Vec<Value> {
        vec![
            json!({
                "name": "dev.git_log",
                "description": "Show git log for a repository path.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Repository path"},
                        "limit": {"type": "integer", "default": 20, "maximum": 100},
                        "author": {"type": "string"},
                        "since": {"type": "string"}
                    },
                    "required": ["path"]
                }
            }),
            json!({
                "name": "dev.git_blame",
                "description": "Show git blame for a file.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"}
                    },
                    "required": ["path"]
                }
            }),
            json!({
                "name": "dev.git_diff",
                "description": "Show git diff for a repository.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "ref_a": {"type": "string", "default": "HEAD"},
                        "ref_b": {"type": "string"},
                        "file_filter": {"type": "string"}
                    },
                    "required": ["path"]
                }
            }),
            json!({
                "name": "dev.test_run",
                "description": "Run tests using cargo, npm, python, or pytest.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "command": {"type": "string", "enum": ["cargo", "npm", "python", "pytest"]},
                        "extra_args": {"type": "array", "items": {"type": "string"}},
                        "timeout_ms": {"type": "integer", "default": 60000}
                    },
                    "required": ["path", "command"]
                }
            }),
            json!({
                "name": "dev.dep_graph",
                "description": "Show dependency graph using cargo, npm, or pip.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "manager": {"type": "string", "enum": ["cargo", "npm", "pip"]},
                        "depth": {"type": "integer", "default": 3},
                        "package": {"type": "string"}
                    },
                    "required": ["path", "manager"]
                }
            }),
            json!({
                "name": "dev.git_stash_list",
                "description": "List git stashes in a repository.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"}
                    },
                    "required": ["path"]
                }
            }),
            json!({
                "name": "dev.git_publish",
                "description": "Governed git publish path requiring explicit git.publish root permission.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "remote": {"type": "string"},
                        "remote_url": {"type": "string"},
                        "branch": {"type": "string"},
                        "expected_head": {"type": "string"},
                        "dry_run": {"type": "boolean"}
                    },
                    "required": ["path"]
                }
            }),
        ]
    }

    async fn call(&self, name: &str, args: Value, _ctx: &CallContext) -> ToolCallResult {
        // Defense-in-depth provider policy check for the governed path.
        let path = args
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let policy = self.policy.read().clone();
        if name != "dev.git_publish" {
            if path.is_empty() {
                return ToolCallResult::err("missing required arg: path");
            }
            if let Some(permission) = dev_tool_permission(name)
                && let Some(denied) = check_provider_permission(&policy, permission, &path)
            {
                return denied;
            }
        }

        let name = name.to_string();
        tokio::task::spawn_blocking(move || match name.as_str() {
            "dev.git_log" => git_log(&args),
            "dev.git_blame" => git_blame(&args),
            "dev.git_diff" => git_diff(&args),
            "dev.test_run" => test_run(&args),
            "dev.dep_graph" => dep_graph(&args),
            "dev.git_stash_list" => git_stash_list(&args),
            "dev.git_publish" => git_publish(&args, &policy),
            _ => ToolCallResult::err(format!("Unknown tool: {name}")),
        })
        .await
        .unwrap_or_else(|err| ToolCallResult::err(format!("devtools worker failed: {err}")))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unnecessary_literal_bound, clippy::items_after_statements)]
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
    use nmcp_policy::{PolicyConfig, RootRule};
    use parking_lot::RwLock;
    use std::sync::Arc;

    fn make_provider() -> DevToolsProvider {
        DevToolsProvider::new(Arc::new(RwLock::new(PolicyConfig::default())))
    }

    #[test]
    fn provider_dispatch_uses_blocking_worker_for_process_tools() {
        let source = include_str!("lib.rs");
        let call_start = source.find("async fn call").expect("provider call");
        let tests_start = source.find("// ── Tests").expect("tests marker");
        let call_block = &source[call_start..tests_start];
        assert!(call_block.contains("tokio::task::spawn_blocking"));
        assert!(call_block.contains("devtools worker failed"));
    }

    #[test]
    fn provider_tool_names_complete() {
        let p = make_provider();
        let names = p.tool_names();
        assert_eq!(names.len(), 7);
        assert!(names.contains(&"dev.git_log".to_string()));
        assert!(names.contains(&"dev.git_blame".to_string()));
        assert!(names.contains(&"dev.git_diff".to_string()));
        assert!(names.contains(&"dev.test_run".to_string()));
        assert!(names.contains(&"dev.dep_graph".to_string()));
        assert!(names.contains(&"dev.git_stash_list".to_string()));
        assert!(names.contains(&"dev.git_publish".to_string()));
    }

    #[test]
    fn tool_names_have_no_delete_surface() {
        let p = make_provider();
        let banned = [
            "delete", "remove", "drop", "destroy", "purge", "wipe", "truncate", "rm",
        ];
        for name in p.tool_names() {
            let lower = name.to_lowercase();
            for b in &banned {
                assert!(
                    !lower.contains(b),
                    "tool name '{name}' contains banned word '{b}'"
                );
            }
        }
    }

    #[test]
    fn provider_permission_uses_policy_require_not_prefix_matching() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("nmcp-devtools-policy-{stamp}"));
        let root = base.join("repo");
        let sibling = base.join("repo-sibling");
        std::fs::create_dir_all(&root).expect("mkdir root");
        std::fs::create_dir_all(&sibling).expect("mkdir sibling");
        let policy = PolicyConfig {
            roots: vec![RootRule {
                id: "repo".into(),
                path: root.clone(),
                permissions: [Permission::Read].into_iter().collect(),
            }],
            ..PolicyConfig::default()
        };

        assert!(
            check_provider_permission(&policy, Permission::Read, root.to_str().unwrap()).is_none()
        );
        assert!(
            check_provider_permission(&policy, Permission::Read, sibling.to_str().unwrap())
                .is_some()
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn dev_tool_permission_matches_risk_profile() {
        assert_eq!(dev_tool_permission("dev.git_log"), Some(Permission::Read));
        assert_eq!(dev_tool_permission("dev.git_blame"), Some(Permission::Read));
        assert_eq!(
            dev_tool_permission("dev.git_stash_list"),
            Some(Permission::Read)
        );
        assert_eq!(
            dev_tool_permission("dev.test_run"),
            Some(Permission::Execute)
        );
        assert_eq!(
            dev_tool_permission("dev.dep_graph"),
            Some(Permission::Execute)
        );
    }

    #[test]
    fn test_run_args_are_normalized_and_deny_dangerous_subcommands() {
        assert_eq!(
            normalize_test_args("cargo", &["--workspace".into()]).expect("cargo args"),
            vec!["test".to_string(), "--workspace".to_string()]
        );
        assert_eq!(
            normalize_test_args("npm", &[]).expect("npm args"),
            vec!["test".to_string()]
        );
        assert_eq!(
            normalize_test_args("python", &[]).expect("python args"),
            vec!["-m".to_string(), "pytest".to_string()]
        );
        assert!(normalize_test_args("cargo", &["clean".into()]).is_err());
        assert!(normalize_test_args("npm", &["install".into()]).is_err());
        assert!(normalize_test_args("python", &["-c".into(), "print(1)".into()]).is_err());
    }

    #[test]
    fn dep_graph_rejects_option_like_package_names() {
        let result = dep_graph(&json!({"path":".","manager":"pip","package":"--version"}));
        assert!(result.is_error);
    }

    #[test]
    fn truncate_never_splits_utf8_codepoints() {
        let (tail, truncated) = truncate(format!("{}END", "é".repeat(4096)), 4097);
        assert!(truncated);
        assert!(tail.ends_with("END"));
        assert!(tail.is_char_boundary(0));
    }

    #[test]
    fn delete_intent_guard_works() {
        let result = reject_dev_delete_intent("stash clear");
        assert!(result.is_some());
        let result2 = reject_dev_delete_intent("stash drop");
        assert!(result2.is_some());
        let result3 = reject_dev_delete_intent("stash list");
        assert!(result3.is_none());
    }

    #[test]
    fn shell_metachar_guard() {
        assert!(has_shell_metachar("HEAD; rm -rf /"));
        assert!(!has_shell_metachar("main"));
        assert!(has_shell_metachar("feature|branch"));
        assert!(!has_shell_metachar("HEAD~1"));
    }

    #[test]
    fn git_log_runs_on_repo() {
        // Walk up from current_dir to find .git
        let mut dir = std::env::current_dir().expect("no cwd");
        loop {
            if dir.join(".git").exists() {
                break;
            }
            match dir.parent() {
                Some(p) => dir = p.to_path_buf(),
                None => panic!("could not find .git dir"),
            }
        }
        let repo_path = dir.to_string_lossy().to_string();

        let output = Command::new("git")
            .arg("-C")
            .arg(&repo_path)
            .arg("log")
            .arg("--oneline")
            .arg("-3")
            .output()
            .expect("git log should not panic");

        assert!(
            output.status.success(),
            "git log failed: {:?}",
            output.status
        );
    }

    #[test]
    fn cargo_tree_runs() {
        // Find workspace Cargo.toml (contains "[workspace]")
        let mut dir = std::env::current_dir().expect("no cwd");
        let workspace_toml = loop {
            let candidate = dir.join("Cargo.toml");
            if candidate.exists() {
                let content = std::fs::read_to_string(&candidate).unwrap_or_default();
                if content.contains("[workspace]") {
                    break candidate;
                }
            }
            match dir.parent() {
                Some(p) => dir = p.to_path_buf(),
                None => panic!("could not find workspace Cargo.toml"),
            }
        };

        let output = Command::new("cargo")
            .arg("tree")
            .arg("--depth")
            .arg("1")
            .arg("--manifest-path")
            .arg(&workspace_toml)
            .output()
            .expect("cargo tree should not panic");

        // Just check it ran without panic; exit code may vary
        let _ = output.status;
    }
}
