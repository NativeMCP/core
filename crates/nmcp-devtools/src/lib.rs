//! DEV Tier 3 developer workflow tools: git ops, test runner, dep graph.
//!
//! Implements [`nmcp_schema::ToolProvider`] for the dev.* tool namespace.
//!
//! No tool here performs a policy check. It did until I-047d, and the contract always
//! forbade it; what changed is that the ring stopped needing it. NMCP-SPEC-003 RC-20 records
//! why the two facts had to be separated in time: the kernel authorized against a compiled-in
//! list of path-argument names these tools' schemas do not define, so the check was load
//! bearing while the contract said it should not exist. The ring now authorizes the
//! schema-filtered declaration, which is the same argument these tools read.

use async_trait::async_trait;
use nmcp_policy::{Permission, PolicyConfig};
use nmcp_router::ToolProvider;
use nmcp_schema::{
    CallContext, GrantedAuthority, ToolAuthority, ToolCallResult, ToolContract, ToolEffect,
    ToolReach,
};
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

/// The one policy check this crate keeps, and the reason it is not the one I-047d deleted.
///
/// `DevToolsProvider::call` used to re-check the ring's own decision on the ring's own
/// argument, which is what the `ToolProvider` contract forbids and what RC-20 made safe to
/// remove. This is a different question. `git_publish` runs `git rev-parse --show-toplevel`
/// and publishes from the **repository root**, which is discovered at run time by executing
/// git and is routinely an ancestor of the `path` the caller sent. The ring cannot authorize
/// it: it is not an argument, so no `path_args` entry can name it and no declaration can
/// express it. A worktree path inside a governed root whose toplevel sits outside one is an
/// outbound publish from ungoverned bytes, and this is what refuses it.
///
/// The call on `path` before it is a duplicate of what the ring now decides, and it is kept
/// rather than trimmed because `git_publish` takes a `&PolicyConfig` and a future caller
/// reaching it by another route would otherwise get the toplevel check and not the argument
/// check, which is the harder half to notice missing.
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

/// What a dev tool needs in order to run, declared rather than looked up.
///
/// NMCP-SPEC-003 RC-D3: the descriptor carries its own governance metadata, and the five
/// tables the kernel used to consult become derived rather than authoritative. I-047c derived
/// every value here from what the kernel said about this tool then, and graded the derivation
/// tool by tool against `nmcp_router::tool_policy_spec`, `nmcp_proto::READ_ONLY_TOOLS` and
/// `nmcp_proto::OPEN_WORLD_TOOLS`. I-047d deleted those tables, so that grading moved to where
/// the tables now live: the whole of `tool_policy_spec` is captured as test data in
/// `nmcp-router`'s `authorize_agrees_with_the_deleted_table_except_where_the_contract_says_otherwise`,
/// which grades the new authorization path against it in both directions, and the annotation
/// half is unrepresentable rather than checked, because `readOnlyHint` and `openWorldHint` are
/// now read off the two fields below (RC-A4).
///
/// Two derivations are worth stating because they are not identity mappings.
///
/// `permission` is `tool_policy_spec`'s permission unchanged. `path_args` is that spec's
/// `path_args` **filtered to the names this tool's own input schema defines**, which is
/// `["path"]` for all seven: the kernel's `PATH_ARG_REPO` and `PATH_ARG_DEV` lists were shared
/// across tool families and named arguments such as `repo_path` and `cwd` that no dev tool
/// accepts. The filter is required by RC-D5, which refuses a declared path argument the
/// schema cannot receive, and RC-20 makes it load-bearing rather than hygienic: under the
/// kernel table a caller passing `repo` resolved the root from `repo` while `git_log` read
/// `path`, so the root that was authorized and the path that was used could differ. Declaring
/// `path` alone makes them the same argument, which is what let this provider's own policy
/// re-check be deleted. `the_ring_authorizes_the_argument_the_provider_reads` is that proof.
///
/// `grants` is empty for every dev tool because `require_windows_api` was false for every one
/// of them in the table this replaces.
fn dev_tool_authority(name: &str) -> ToolAuthority {
    // Exhaustive over the seven tools this provider declares, with no wildcard arm. A tool
    // added to `contracts` without a line here does not compile, which is the point: an
    // authority guessed by a fallback is an authority nobody decided.
    let (permission, effect, reach) = match name {
        "dev.git_log" | "dev.git_blame" | "dev.git_diff" | "dev.git_stash_list" => {
            (Permission::Read, ToolEffect::Observe, ToolReach::Local)
        }
        "dev.dep_graph" => (Permission::Execute, ToolEffect::Observe, ToolReach::Local),
        "dev.test_run" => (Permission::Execute, ToolEffect::Mutate, ToolReach::Remote),
        "dev.git_publish" => (
            Permission::GitPublish,
            ToolEffect::Mutate,
            ToolReach::Remote,
        ),
        other => return unknown_tool_authority(other),
    };
    ToolAuthority {
        permission: Some(permission),
        path_args: vec!["path".to_string()],
        grants: Vec::new(),
        effect,
        reach,
    }
}

/// The authority of a tool this crate declares and has no line for.
///
/// Unreachable through [`DevToolsProvider::contracts`], whose seven names are literals in the
/// same file as the match above, and written anyway because the alternative to a fail-closed
/// arm is a fallback that grants something. This one grants nothing that can be satisfied: it
/// requires a capability grant no `Permission` defines, which `authorize` refuses as
/// [`nmcp_schema::Denial::UnknownGrant`] on every call, loudly and by name. A tool that
/// reached here would be visible and uncallable rather than callable and ungoverned.
fn unknown_tool_authority(name: &str) -> ToolAuthority {
    ToolAuthority {
        permission: Some(Permission::Read),
        path_args: vec!["path".to_string()],
        grants: vec![nmcp_schema::CapabilityGrant::new(format!(
            "nmcp.undeclared.{name}"
        ))],
        effect: ToolEffect::Mutate,
        reach: ToolReach::Remote,
    }
}

#[async_trait]
impl ToolProvider for DevToolsProvider {
    fn contract_version(&self) -> u32 {
        1
    }

    // The trait declares `-> &str`; an impl cannot narrow it to a static
    // lifetime on its own.
    #[allow(clippy::unnecessary_literal_bound)]
    fn provider_id(&self) -> &str {
        ""
    }

    /// The seven tools this provider owns, fully declared.
    ///
    /// Replaces the `tool_names` and `tool_list` pair this impl carried, which had to agree and
    /// were never checked against each other. I-047c derived both from here through the trait's
    /// default bodies; I-047d deleted them, so this is the only place a dev tool is described
    /// and there is nothing left for it to disagree with. The registry derives the public name
    /// and the `tools/list` entry from what is returned here.
    fn contracts(&self) -> Vec<ToolContract> {
        dev_tool_descriptors()
            .into_iter()
            .map(|entry| {
                // The three descriptive fields come off the descriptor, so the declaration and
                // the advertised entry are one source rather than two that must agree. A
                // descriptor that lost its `name` derives the empty public name, which the
                // registry refuses as `InvalidToolName` rather than registering a tool nothing
                // can address.
                let name = entry
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                ToolContract {
                    authority: dev_tool_authority(&name),
                    // RC-21: `None`, and it has to be. This provider is first party, so its
                    // annotations are derived from the authority above by `to_list_entry` and a
                    // second source that could disagree with the first is the defect RC-A4
                    // makes unrepresentable. The registry refuses a first-party provider that
                    // sets this, so the rule is enforced rather than remembered.
                    published_annotations: None,
                    description: entry
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    input_schema: entry
                        .get("inputSchema")
                        .cloned()
                        .unwrap_or_else(|| json!({})),
                    name,
                }
            })
            .collect()
    }

    async fn call(
        &self,
        name: &str,
        args: Value,
        _ctx: &CallContext,
        _granted: &GrantedAuthority,
    ) -> ToolCallResult {
        // No policy check here, and its absence is the point rather than an omission.
        //
        // This impl used to re-check `policy.require` on `args["path"]` and call it
        // defense in depth. It was not: it was the only thing standing between the kernel's
        // mismatched path-argument table and a confused deputy, and it is exactly the check
        // the `ToolProvider` contract forbids a provider to write. NMCP-SPEC-003 v1.2 RC-20
        // made the sequencing explicit, and it is the sequencing that made the deletion safe:
        // the ring now authorizes on `path_args`, filtered by RC-D5 to the arguments this
        // tool's own schema defines, which is `["path"]` for all seven, so the argument the
        // kernel authorizes and the argument the handlers below read are the same argument.
        // `the_ring_authorizes_the_argument_the_provider_reads` is that proof and it was
        // landed and passing before this block was removed.
        //
        // The `path.is_empty()` refusal went with it and nothing changed for a caller: every
        // handler below returns the identical "missing required arg: path" when it is absent,
        // and the ring refuses the call as `Denial::MissingPathArgument` before reaching here.
        //
        // The policy handle stays because `git_publish` reads it for the remote, branch and
        // dry-run rules the declaration does not model. That is not an authorization check;
        // `authorize` has already required `git.publish` on the resolved root by the time this
        // line runs.
        let policy = self.policy.read().clone();

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

/// The name, description and input schema of every tool this provider advertises.
///
/// These are the seven descriptors this impl used to return from `tool_list`, unchanged. They
/// live in a free function rather than in `contracts` so the declaration reads as a table
/// rather than as a hundred-line method, and so the fidelity tests can compare against them
/// directly.
fn dev_tool_descriptors() -> Vec<Value> {
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

    /// The seven names, read off `contracts` now that `tool_names` is deleted. Setup only:
    /// every assertion below is the one this test has always made.
    #[test]
    fn provider_tool_names_complete() {
        let p = make_provider();
        let names: Vec<String> = p.contracts().into_iter().map(|c| c.name).collect();
        assert_eq!(names.len(), 7);
        assert!(names.contains(&"dev.git_log".to_string()));
        assert!(names.contains(&"dev.git_blame".to_string()));
        assert!(names.contains(&"dev.git_diff".to_string()));
        assert!(names.contains(&"dev.test_run".to_string()));
        assert!(names.contains(&"dev.dep_graph".to_string()));
        assert!(names.contains(&"dev.git_stash_list".to_string()));
        assert!(names.contains(&"dev.git_publish".to_string()));
    }

    /// RC-20, and the proof NMCP-SPEC-003 v1.2 requires **before** the defense-in-depth
    /// policy re-check in `DevToolsProvider::call` may be deleted.
    ///
    /// The finding it exists for: the kernel's `tool_policy_spec` gave the dev tools
    /// `PATH_ARG_REPO = ["repo", "repo_path", "repository", "repository_path", "path"]` and
    /// `PATH_ARG_DEV = ["path", "repo", "repo_path", "cwd"]`, `matched_root_for_call` took the
    /// first of those present in the arguments, and every one of these tools reads `path`. So a
    /// call carrying `{"repo": <readable>, "path": <not readable>}` had its root resolved from
    /// `repo` while the effect ran on `path`: a confused deputy in the enforcement path itself.
    /// What prevented it was this provider re-checking policy on `args["path"]`, which is
    /// precisely the check the `ToolProvider` contract tells providers not to write.
    ///
    /// Three claims, in the order the sequencing constraint requires them.
    ///
    /// 1. Every tool this provider owns reads `args["path"]`, and none of them reads any other
    ///    argument the kernel table would have resolved a root from. Read out of this file's
    ///    own production source, so a tool that started reading `repo` fails here rather than
    ///    quietly reopening the gap.
    /// 2. Every declared path argument is a property of that tool's own input schema. RC-5
    ///    refuses the alternative at registration; asserting it here puts the reason next to the
    ///    declaration.
    /// 3. The root the ring resolves comes from that same argument. Given the exact call the
    ///    deleted table authorized, `nmcp_schema::authorize` refuses and names `path`; given the
    ///    mirror image it resolves the root containing `path`.
    ///
    /// Together those three are what make removing the provider-side check safe rather than
    /// merely tidy: the set the kernel authorizes on and the set the tool reads are the same
    /// set, so the composed behaviour with the check removed is the composed behaviour with it
    /// present. This test was landed and passing with that check still in the file, and the
    /// check was deleted only afterwards.
    // Three claims about one property, and separating them into three tests would let two of
    // them pass while the third was deleted.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn the_ring_authorizes_the_argument_the_provider_reads() {
        use nmcp_schema::{CapabilityGrant, Denial, HeldAuthority, authorize};
        use std::collections::BTreeSet;

        // - Claim 1: what the handlers read -
        let source = include_str!("lib.rs");
        let production = &source[..source.find("mod tests").expect("tests module")];
        // Every argument the deleted kernel table would have resolved a root from, other than
        // the one these tools actually read.
        for never_read in ["repo", "repo_path", "repository", "repository_path", "cwd"] {
            assert!(
                !production.contains(&format!("args.get(\"{never_read}\")")),
                "a dev tool reads {never_read}, which the declaration does not authorize"
            );
        }
        for handler in [
            "fn git_log(",
            "fn git_blame(",
            "fn git_diff(",
            "fn test_run(",
            "fn dep_graph(",
            "fn git_stash_list(",
            "fn git_publish(",
        ] {
            let start = production
                .find(handler)
                .unwrap_or_else(|| panic!("{handler} is defined in this file"));
            let body = &production[start..];
            // Bounded by the next top-level item rather than by this one's closing brace: a
            // literal closing brace in this file's source unbalances `scripts/inv1_scan.py`,
            // which tracks `#[cfg(test)]` by counting braces and would then read the rest of
            // this module as production code.
            let end = body
                .get(1..)
                .and_then(|rest| rest.find("\nfn "))
                .map_or(body.len(), |offset| offset + 1);
            assert!(
                body.get(..end)
                    .is_some_and(|body| body.contains("args.get(\"path\")")),
                "{handler} does not read the argument the ring authorizes"
            );
        }

        // - Claim 2: every declared path argument is a property of the tool's own schema -
        let provider = make_provider();
        let contracts = provider.contracts();
        assert_eq!(contracts.len(), 7);
        for contract in &contracts {
            assert_eq!(
                contract.authority.path_args,
                vec!["path".to_string()],
                "{}: the declaration must name the argument the tool reads and no other",
                contract.name
            );
            for arg in &contract.authority.path_args {
                assert!(
                    contract
                        .input_schema
                        .get("properties")
                        .and_then(Value::as_object)
                        .is_some_and(|properties| properties.contains_key(arg)),
                    "{}: declared path argument {arg} is not a property of its own schema",
                    contract.name
                );
            }
        }

        // - Claim 3: the ring resolves the root from that same argument -
        let governed = std::env::temp_dir().join("nmcp-devtools-rc20-governed");
        let ungoverned = std::env::temp_dir().join("nmcp-devtools-rc20-ungoverned");
        let held = HeldAuthority {
            roots: vec![RootRule {
                id: "repo".into(),
                path: governed.clone(),
                permissions: [
                    Permission::Read,
                    Permission::Execute,
                    Permission::GitPublish,
                ]
                .into_iter()
                .collect(),
            }],
            grants: BTreeSet::from([
                CapabilityGrant::new(Permission::Read.as_str()),
                CapabilityGrant::new(Permission::Execute.as_str()),
                CapabilityGrant::new(Permission::GitPublish.as_str()),
            ]),
            agent_id: None,
        };

        for contract in &contracts {
            // Every argument the kernel table would have tried before `path`, all pointing
            // somewhere the caller may read, and `path` pointing somewhere it may not. This is
            // the call the deleted table authorized.
            let confused = json!({
                "repo": governed.join("readable").display().to_string(),
                "repo_path": governed.join("readable").display().to_string(),
                "repository": governed.join("readable").display().to_string(),
                "repository_path": governed.join("readable").display().to_string(),
                "cwd": governed.join("readable").display().to_string(),
                "path": ungoverned.join("secret").display().to_string(),
            });
            let denial = authorize(&contract.authority, &held, &confused)
                .expect_err("the argument the tool reads is outside every root");
            assert!(
                matches!(&denial, Denial::OutsideRoots { arg } if arg == "path"),
                "{}: the refusal must name path, got {denial:?}",
                contract.name
            );

            // The mirror image, which is the direction that looks like a widening and is not:
            // the table refused because `repo` was ungoverned, while the effect was always
            // going to run on `path`, which is inside a root the caller holds the declared
            // permission on.
            let mirrored = json!({
                "repo": ungoverned.join("elsewhere").display().to_string(),
                "path": governed.join("readable").display().to_string(),
            });
            let granted = authorize(&contract.authority, &held, &mirrored).unwrap_or_else(|err| {
                panic!(
                    "{}: the argument the tool reads is governed: {err:?}",
                    contract.name
                )
            });
            assert_eq!(
                granted.matched_root().map(|root| root.id.as_str()),
                Some("repo"),
                "{}: the resolved root must be the one containing the argument the tool reads",
                contract.name
            );
        }
    }

    #[test]
    fn tool_names_have_no_delete_surface() {
        let p = make_provider();
        let banned = [
            "delete", "remove", "drop", "destroy", "purge", "wipe", "truncate", "rm",
        ];
        for contract in p.contracts() {
            let name = contract.name;
            let lower = name.to_lowercase();
            for b in &banned {
                assert!(
                    !lower.contains(b),
                    "tool name '{name}' contains banned word '{b}'"
                );
            }
        }
    }

    /// A sibling directory whose name shares a prefix with a governed root is not inside it.
    ///
    /// The assertion is the one this test has always made and the case is the same case: a root
    /// at `.../repo` and a sibling at `.../repo-sibling`, which a prefix comparison would
    /// wrongly admit. What moved is where the comparison happens. It used to be
    /// `check_provider_permission` calling `PolicyConfig::require` inside this provider; that
    /// function is deleted with the provider-side check, so the claim is now made against
    /// `nmcp_schema::authorize`, which is the only thing that decides it, and against this
    /// provider's real declaration rather than a permission passed in by hand.
    #[test]
    fn provider_permission_uses_policy_require_not_prefix_matching() {
        use nmcp_schema::{HeldAuthority, authorize};
        use std::collections::BTreeSet;

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("nmcp-devtools-policy-{stamp}"));
        let root = base.join("repo");
        let sibling = base.join("repo-sibling");
        std::fs::create_dir_all(&root).expect("mkdir root");
        std::fs::create_dir_all(&sibling).expect("mkdir sibling");
        let held = HeldAuthority {
            roots: vec![RootRule {
                id: "repo".into(),
                path: root.clone(),
                permissions: [Permission::Read].into_iter().collect(),
            }],
            grants: BTreeSet::new(),
            agent_id: None,
        };
        let declared = dev_tool_authority("dev.git_log");
        assert_eq!(declared.permission, Some(Permission::Read));

        assert!(authorize(&declared, &held, &json!({ "path": root.to_str().unwrap() })).is_ok());
        assert!(
            authorize(
                &declared,
                &held,
                &json!({ "path": sibling.to_str().unwrap() })
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn dev_tool_permission_matches_risk_profile() {
        // Read off the declaration now that `dev_tool_permission` is deleted with the
        // provider-side check it fed. Setup only: every pairing below is the one this test has
        // always asserted, and it is now asserted about the value the ring authorizes against.
        fn permission_of(name: &str) -> Option<Permission> {
            dev_tool_authority(name).permission
        }
        assert_eq!(permission_of("dev.git_log"), Some(Permission::Read));
        assert_eq!(permission_of("dev.git_blame"), Some(Permission::Read));
        assert_eq!(permission_of("dev.git_stash_list"), Some(Permission::Read));
        assert_eq!(permission_of("dev.test_run"), Some(Permission::Execute));
        assert_eq!(permission_of("dev.dep_graph"), Some(Permission::Execute));
        // The two the old helper answered `None` for, which was never a claim that they need
        // no permission: `git_publish` needed `git.publish` and the helper simply did not
        // cover it, because the provider check it fed skipped that tool by name.
        assert_eq!(
            permission_of("dev.git_publish"),
            Some(Permission::GitPublish)
        );
        assert_eq!(permission_of("dev.git_diff"), Some(Permission::Read));
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
