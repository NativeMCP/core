//! `xtask`
//!
//! Workspace maintenance commands for NativeMCP `core`, run as
//! `cargo run -p xtask -- <command>`.
//!
//! Ported from the base workspace with a deliberately reduced command set.
//! Named gaps, each with a reason rather than a silent omission:
//!
//! - `validate-admin-ui` validates the fleet console's JavaScript. That console
//!   is private-layer (NMCP-SPEC-001 NDEC-1), so the asset it checks does not
//!   exist here and will never exist here.
//! - `validate-docs` checked one base operations document that was not ported
//!   (NMCP-SPEC-001 never-port list).
//! - `validate-tracker` validated the base repository's tracker schema. Core's
//!   tracker lives outside the public tree.
//! - `build-installer` builds the `WiX` MSI, which is Windows packaging and
//!   belongs to WinMCP at W3.
//!
//! What is here is what applies to a platform-neutral Rust workspace: the
//! toolchain gates, line endings, and the house no-em-dash rule.

use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser)]
#[command(name = "xtask", about = "nMCP workspace maintenance commands")]
struct Cli {
    #[command(subcommand)]
    command: Xtask,
}

#[derive(Subcommand)]
enum Xtask {
    /// Run every validator below, in order.
    Validate,
    /// `cargo fmt --check`, `clippy -D warnings`, and the test suite.
    ValidateRust,
    /// Line endings per the repository's `.gitattributes` policy.
    ValidateLineEndings,
    /// The house rule: no em dashes in tracked text.
    ValidateNoEmDashes,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Xtask::Validate => {
            validate_line_endings()?;
            validate_no_em_dashes()?;
            validate_rust()
        }
        Xtask::ValidateRust => validate_rust(),
        Xtask::ValidateLineEndings => validate_line_endings(),
        Xtask::ValidateNoEmDashes => validate_no_em_dashes(),
    }
}

fn validate_rust() -> anyhow::Result<()> {
    for cmd in [
        ["cargo", "fmt", "--all", "--", "--check"].as_slice(),
        [
            "cargo",
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ]
        .as_slice(),
        ["cargo", "test", "--workspace"].as_slice(),
    ] {
        println!("running: {}", cmd.join(" "));
        // Slice pattern rather than cmd[0]/cmd[1..]: the arrays above are all
        // non-empty, and this keeps that a property of the code rather than of
        // the reader's attention.
        let [program, args @ ..] = cmd else {
            anyhow::bail!("empty command in the validator table");
        };
        let status = Command::new(program).args(args).status()?;
        if !status.success() {
            anyhow::bail!("command failed: {}", cmd.join(" "));
        }
    }
    Ok(())
}

fn validate_line_endings() -> anyhow::Result<()> {
    let workspace_root = workspace_root()?;
    let mut checked = 0usize;
    let mut failures = Vec::new();
    for path in tracked_files(&workspace_root)? {
        let rel = path
            .strip_prefix(&workspace_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if is_binary_by_policy(&rel) {
            continue;
        }
        let expected = expected_line_ending(&rel);
        let bytes = fs::read(&path)?;
        if bytes.is_empty() {
            continue;
        }
        checked += 1;
        match expected {
            LineEnding::Lf => {
                if bytes.windows(2).any(|pair| pair == b"\r\n") || bytes.contains(&b'\r') {
                    failures.push(format!("{rel}: expected LF but found CR/CRLF"));
                }
            }
            LineEnding::Crlf => {
                if contains_bare_lf(&bytes)
                    || bytes.contains(&b'\r') && !bytes.windows(2).any(|pair| pair == b"\r\n")
                {
                    failures.push(format!("{rel}: expected CRLF but found bare LF/CR"));
                }
            }
        }
    }
    if !failures.is_empty() {
        anyhow::bail!("line ending validation failed:\n{}", failures.join("\n"));
    }
    println!("validated line endings for {checked} tracked text files");
    Ok(())
}

/// House style: this repository does not use em dashes.
///
/// A gate rather than a one-time sweep, for the same reason the line-ending check is a gate.
/// A convention that lives only in a reviewer's head comes back one commit at a time, and the
/// cleanup that removed 258 of these was not worth doing twice.
///
/// The failure names the file and line so the fix is obvious. What to replace it with is a
/// judgement call the author has to make: a comma for an appositive, a colon for a label, a
/// semicolon for two clauses that were being joined.
fn validate_no_em_dashes() -> anyhow::Result<()> {
    const EM_DASH: char = '\u{2014}';
    let workspace_root = workspace_root()?;
    let mut checked = 0usize;
    let mut failures = Vec::new();
    for path in tracked_files(&workspace_root)? {
        let rel = path
            .strip_prefix(&workspace_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if is_binary_by_policy(&rel) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            // Not valid UTF-8, so not prose this rule is about.
            continue;
        };
        checked += 1;
        for (index, line) in text.lines().enumerate() {
            if line.contains(EM_DASH) {
                failures.push(format!("{rel}:{}: em dash", index + 1));
            }
        }
    }
    if !failures.is_empty() {
        anyhow::bail!(
            "em dash check failed ({} occurrences); use a comma, a colon or a semicolon:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
    println!("validated {checked} tracked text files for em dashes");
    Ok(())
}

enum LineEnding {
    Lf,
    Crlf,
}

fn expected_line_ending(rel: &str) -> LineEnding {
    let lower = rel.to_ascii_lowercase();
    if matches_extension(&lower, &["ps1", "psm1", "psd1", "bat", "cmd"]) {
        LineEnding::Crlf
    } else {
        LineEnding::Lf
    }
}

fn is_binary_by_policy(rel: &str) -> bool {
    matches_extension(
        &rel.to_ascii_lowercase(),
        &["png", "jpg", "jpeg", "ico", "zip", "exe", "dll"],
    )
}

fn matches_extension(path: &str, extensions: &[&str]) -> bool {
    extensions
        .iter()
        .any(|ext| path.ends_with(&format!(".{ext}")))
}

fn contains_bare_lf(bytes: &[u8]) -> bool {
    // A bare LF is one not preceded by CR. Expressed over windows(2) plus the
    // first byte rather than by indexing back from the cursor.
    let leading = bytes.first() == Some(&b'\n');
    leading
        || bytes
            .windows(2)
            .any(|pair| pair == b"\n" || matches!(pair, [a, b'\n'] if *a != b'\r'))
}

fn tracked_files(workspace_root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .args(["ls-files"])
        .current_dir(workspace_root)
        .output()?;
    if !output.status.success() {
        anyhow::bail!("git ls-files failed with {}", output.status);
    }
    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| workspace_root.join(line))
        .collect())
}

fn workspace_root() -> anyhow::Result<PathBuf> {
    // Resolve relative to CARGO_MANIFEST_DIR (the xtask crate root), going up one level.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("cannot resolve workspace root from xtask manifest dir"))
}
