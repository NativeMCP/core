//! Bounded repository scanning and search for the nMCP server family.
//!
//! Two operations, both of which walk a filesystem tree: a secret-candidate scan and a
//! content search. Both are bounded, and the bound is the point. A walk that exceeds any
//! ceiling stops and says which one stopped it, because a partial result reported as a
//! complete one is worse than an error: "scanned 0 files, found 0 secret candidates" reads
//! exactly like a clean repository.
//!
//! Part of the NativeMCP `core` workspace. The governance invariants in
//! `docs/GOVERNANCE.md` apply.
//!
//! # This crate performs no policy check
//!
//! The base carried `policy.require(Permission::Scan, root)` inside `scan_repo` and
//! `policy.require(Permission::Search, root)` inside `search_repo`. Those are gone, and
//! their absence is deliberate rather than an oversight in the port.
//!
//! NMCP-SPEC-003 RC-20 established why: a provider-side re-check is forbidden by the
//! `ToolProvider` contract, and when one exists the kernel's guarantee is being held up by
//! a line of code the contract says should not be there. The authorization belongs to the
//! ring, which runs `authorize()` against the tool's declared `ToolAuthority` before
//! `call()` is entered, and hands the provider unforgeable proof that it did.
//!
//! RC-20 also fixed the *order* in which such a check may be removed: the proof that the
//! ring authorizes on the same argument the library reads must land and run green before
//! the redundant check is deleted. That ordering is satisfied here by construction rather
//! than by sequencing. Nothing calls this crate yet. The caller is `LocalProvider`, and the
//! declaration that authorizes it (`Permission::Scan` and `Permission::Search`, each over
//! the `path` argument) lands in the same change that first calls these functions. There is
//! no window in which a reachable tool runs unchecked.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context;
use regex::Regex;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

/// Per-file ceiling. A file larger than this is counted and not opened.
const MAX_REPORT_FILE_BYTES: u64 = 2_000_000;

/// Ceiling on matches returned by one search.
const MAX_SEARCH_MATCHES: usize = 500;

/// Directory names that are machine-generated, VCS internals, or dependency caches.
///
/// These are pruned by default because walking them is both slow and useless: a secret
/// scan over `target` reports build artifacts, not source. Pruning is what turns a repo
/// scan from an effectively unbounded disk walk into something that finishes inside a
/// connector request window.
///
/// Nothing is pruned silently. Every name that was actually pruned is reported in
/// `dirs_skipped`, so a caller can always tell the difference between "found nothing"
/// and "did not look there".
pub const DEFAULT_SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "target",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".next",
    ".nuxt",
    ".gradle",
    ".terraform",
    ".idea",
    ".vs",
    ".vscode",
    "dist",
    "build",
    "coverage",
];

/// Bounds that keep a filesystem walk inside a connector request window.
///
/// A walk that exceeds any bound stops and says so. Reporting a partial result as if it
/// were complete is the failure mode this type exists to prevent: a secret scan that
/// silently stopped halfway reads exactly like a clean repository.
#[derive(Debug, Clone)]
pub struct ScanBudget {
    /// Maximum number of files to open and inspect.
    pub max_files: usize,
    /// Maximum total bytes to inspect.
    pub max_bytes: u64,
    /// Wall-clock ceiling for the whole walk.
    pub deadline: Duration,
    /// Lowercase directory names to prune. Empty means walk everything.
    pub skip_dirs: Vec<String>,
}

impl Default for ScanBudget {
    fn default() -> Self {
        Self {
            max_files: 20_000,
            max_bytes: 512 * 1024 * 1024,
            // Comfortably inside the 60s connector request limit, leaving room for the
            // policy ring, serialization, and transport on either side of the walk.
            deadline: Duration::from_secs(20),
            skip_dirs: DEFAULT_SKIP_DIRS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        }
    }
}

impl ScanBudget {
    /// A budget that walks everything with no practical deadline.
    ///
    /// Not reachable from the tool surface on purpose. A caller that constructs this owns
    /// the runtime cost, and a connector must never be able to remove its own deadline.
    #[must_use]
    pub fn unbounded() -> Self {
        Self {
            max_files: usize::MAX,
            max_bytes: u64::MAX,
            deadline: Duration::from_secs(u64::from(u32::MAX)),
            skip_dirs: Vec::new(),
        }
    }

    /// Which bound, if any, this walk has already reached.
    ///
    /// Checked before each file rather than after, so the count in a truncated report is
    /// the number of files actually inspected.
    #[must_use]
    fn exhausted(&self, files: usize, bytes: u64, started: Instant) -> Option<String> {
        if files >= self.max_files {
            let max = self.max_files;
            return Some(format!("file budget reached ({max} files)"));
        }
        if bytes >= self.max_bytes {
            let max = self.max_bytes;
            return Some(format!("byte budget reached ({max} bytes)"));
        }
        if started.elapsed() >= self.deadline {
            let ms = self.deadline.as_millis();
            return Some(format!("time budget reached ({ms} ms)"));
        }
        None
    }
}

/// Walk `root`, pruning the budget's skip list and recording what was pruned.
fn bounded_walk<'a>(
    root: &Path,
    budget: &'a ScanBudget,
    skipped: &'a RefCell<BTreeSet<String>>,
) -> impl Iterator<Item = walkdir::DirEntry> + 'a {
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(move |entry| {
            if entry.depth() == 0 || !entry.file_type().is_dir() {
                return true;
            }
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if budget.skip_dirs.contains(&name) {
                skipped.borrow_mut().insert(name);
                return false;
            }
            true
        })
        .filter_map(Result::ok)
}

/// Elapsed milliseconds, saturating rather than truncating.
///
/// `Duration::as_millis` is a `u128`. A cast would be a silent wrap on a walk long enough
/// to overflow, which is exactly the class of quiet wrong answer this crate exists to
/// avoid, so it saturates and the caller sees an implausible number instead of a small one.
fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// What a secret-candidate scan found, and what it did not look at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoScanReport {
    /// The scanned root, canonicalized where the filesystem allowed it.
    pub root: String,
    /// Files opened and inspected.
    pub files_scanned: usize,
    /// Total bytes of the inspected files.
    pub bytes_scanned: u64,
    /// Count of inspected files by lowercase extension; `<none>` for extensionless.
    pub extension_counts: BTreeMap<String, usize>,
    /// Every line that matched a detector, redacted.
    pub secret_candidates: Vec<SecretCandidate>,
    /// A sentence stating the result, which says so loudly when the walk stopped early.
    pub summary: String,
    /// Files present but not opened because they exceed the per-file size ceiling.
    #[serde(default)]
    pub files_skipped_large: usize,
    /// Directory names pruned from the walk, deduplicated.
    #[serde(default)]
    pub dirs_skipped: Vec<String>,
    /// True when a budget stopped the walk before it finished the tree.
    #[serde(default)]
    pub truncated: bool,
    /// Which budget stopped the walk. Present exactly when `truncated` is true.
    #[serde(default)]
    pub stopped_because: Option<String>,
    /// Wall-clock duration of the walk.
    #[serde(default)]
    pub elapsed_ms: u64,
}

/// One line that matched a detector or a search pattern, with the line redacted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretCandidate {
    /// The file the line came from.
    pub path: String,
    /// One-based line number.
    pub line: usize,
    /// Which detector matched, or `search_repo` for a content search.
    pub detector: String,
    /// The line, redacted to a head and tail. Never the whole line.
    pub excerpt: String,
}

/// What a content search found, and what it did not look at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchReport {
    /// The searched root, as given.
    pub root: String,
    /// The regular expression that was searched for.
    pub pattern: String,
    /// Matching lines, redacted, capped at the match ceiling.
    pub matches: Vec<SecretCandidate>,
    /// Files opened and inspected.
    #[serde(default)]
    pub files_scanned: usize,
    /// Directory names pruned from the walk, deduplicated.
    #[serde(default)]
    pub dirs_skipped: Vec<String>,
    /// True when a budget or the match ceiling stopped the walk early.
    #[serde(default)]
    pub truncated: bool,
    /// Which limit stopped the walk. Present exactly when `truncated` is true.
    #[serde(default)]
    pub stopped_because: Option<String>,
    /// Wall-clock duration of the walk.
    #[serde(default)]
    pub elapsed_ms: u64,
}

/// Scan a repository root for secret candidates using the default walk budget.
///
/// # Errors
///
/// When a detector's regular expression fails to compile, which is a defect in this crate
/// rather than a caller error and so cannot happen at runtime with the shipped detectors.
pub fn scan_repo(root: impl AsRef<Path>) -> anyhow::Result<RepoScanReport> {
    scan_repo_with(root, &ScanBudget::default())
}

/// Scan a repository root for secret candidates under an explicit walk budget.
///
/// # Errors
///
/// When a detector's regular expression fails to compile. An unreadable file is not an
/// error: it is skipped and the report is one file shorter, because a single locked or
/// access-denied file must not turn a whole-repository scan into a refusal.
pub fn scan_repo_with(
    root: impl AsRef<Path>,
    budget: &ScanBudget,
) -> anyhow::Result<RepoScanReport> {
    let root = root.as_ref();
    let detectors = vec![
        (
            "env_assignment",
            Regex::new(r#"(?i)(api[_-]?key|token|secret|password)\s*=\s*['"]?[A-Za-z0-9_-]{12,}"#)?,
        ),
        (
            "private_key_header",
            Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")?,
        ),
        ("github_pat", Regex::new(r"gh[pousr]_[A-Za-z0-9_]{20,}")?),
    ];
    let started = Instant::now();
    let skipped_dirs = RefCell::new(BTreeSet::new());
    let mut files_scanned = 0usize;
    let mut bytes_scanned = 0u64;
    let mut files_skipped_large = 0usize;
    let mut extension_counts = BTreeMap::new();
    let mut secret_candidates = Vec::new();
    let mut stopped_because: Option<String> = None;
    for entry in bounded_walk(root, budget, &skipped_dirs) {
        if !entry.file_type().is_file() {
            continue;
        }
        if let Some(reason) = budget.exhausted(files_scanned, bytes_scanned, started) {
            stopped_because = Some(reason);
            break;
        }
        let path = entry.path();
        // An unreadable file must not abort the report. This was `fs::metadata(path)?`,
        // so a single locked or access-denied file turned a whole-repo scan into an
        // error rather than into a report with one fewer file in it.
        let Ok(metadata) = fs::metadata(path) else {
            continue;
        };
        if metadata.len() > MAX_REPORT_FILE_BYTES {
            files_skipped_large += 1;
            continue;
        }
        files_scanned += 1;
        bytes_scanned += metadata.len();
        let ext = path
            .extension()
            .and_then(|x| x.to_str())
            .unwrap_or("<none>")
            .to_ascii_lowercase();
        *extension_counts.entry(ext).or_insert(0) += 1;
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for (line_idx, line) in content.lines().enumerate() {
            for (name, re) in &detectors {
                if re.is_match(line) {
                    secret_candidates.push(SecretCandidate {
                        path: path.display().to_string(),
                        line: line_idx + 1,
                        detector: (*name).to_string(),
                        excerpt: redact(line),
                    });
                }
            }
        }
    }
    let dirs_skipped: Vec<String> = skipped_dirs.borrow().iter().cloned().collect();
    let candidate_count = secret_candidates.len();
    // A truncated report must not read like a completed one. This wording is what stops
    // "found 0 secret candidates" from being quoted as evidence a tree is clean when the
    // walk stopped a third of the way in.
    let summary = match &stopped_because {
        Some(reason) => format!(
            "scanned {files_scanned} files and STOPPED EARLY: {reason}; found \
             {candidate_count} secret candidates in the portion scanned, so this is not \
             evidence the rest of the tree is clean"
        ),
        None => format!("scanned {files_scanned} files; found {candidate_count} secret candidates"),
    };
    Ok(RepoScanReport {
        root: root
            .canonicalize()
            .unwrap_or_else(|_| root.to_path_buf())
            .display()
            .to_string(),
        files_scanned,
        bytes_scanned,
        extension_counts,
        summary,
        secret_candidates,
        files_skipped_large,
        dirs_skipped,
        truncated: stopped_because.is_some(),
        stopped_because,
        elapsed_ms: elapsed_ms(started),
    })
}

/// Search file content under a root using the default walk budget.
///
/// # Errors
///
/// When `pattern` is not a valid regular expression. That is a caller error and the
/// message names the pattern.
pub fn search_repo(root: &Path, pattern: &str) -> anyhow::Result<SearchReport> {
    search_repo_with(root, pattern, &ScanBudget::default())
}

/// Search file content under a root with an explicit walk budget.
///
/// # Errors
///
/// When `pattern` is not a valid regular expression.
pub fn search_repo_with(
    root: &Path,
    pattern: &str,
    budget: &ScanBudget,
) -> anyhow::Result<SearchReport> {
    let re = Regex::new(pattern).with_context(|| format!("invalid regex pattern: {pattern}"))?;
    let started = Instant::now();
    let skipped_dirs = RefCell::new(BTreeSet::new());
    let mut matches = Vec::new();
    let mut files_scanned = 0usize;
    let mut bytes_scanned = 0u64;
    let mut stopped_because: Option<String> = None;
    for entry in bounded_walk(root, budget, &skipped_dirs) {
        if !entry.file_type().is_file() {
            continue;
        }
        if let Some(reason) = budget.exhausted(files_scanned, bytes_scanned, started) {
            stopped_because = Some(reason);
            break;
        }
        let path = entry.path();
        let Ok(metadata) = fs::metadata(path) else {
            continue;
        };
        if metadata.len() > MAX_REPORT_FILE_BYTES {
            continue;
        }
        files_scanned += 1;
        bytes_scanned += metadata.len();
        if let Ok(content) = fs::read_to_string(path) {
            for (idx, line) in content.lines().enumerate() {
                if re.is_match(line) {
                    matches.push(SecretCandidate {
                        path: path.display().to_string(),
                        line: idx + 1,
                        detector: "search_repo".to_string(),
                        excerpt: redact(line),
                    });
                    if matches.len() >= MAX_SEARCH_MATCHES {
                        break;
                    }
                }
            }
        }
        if matches.len() >= MAX_SEARCH_MATCHES {
            stopped_because = Some(format!(
                "match budget reached ({MAX_SEARCH_MATCHES} matches)"
            ));
            break;
        }
    }
    Ok(SearchReport {
        root: root.display().to_string(),
        pattern: pattern.to_string(),
        matches,
        files_scanned,
        dirs_skipped: skipped_dirs.borrow().iter().cloned().collect(),
        truncated: stopped_because.is_some(),
        stopped_because,
        elapsed_ms: elapsed_ms(started),
    })
}

/// Reduce a matched line to a head and a tail.
///
/// The whole point of a secret scan is to report *where* a secret is without reproducing
/// it, so nothing here ever returns the middle of the line. Short lines return a constant,
/// because eight of sixteen characters is most of the secret. Character-indexed rather
/// than byte-indexed so a UTF-8 line does not panic on a split boundary.
fn redact(line: &str) -> String {
    let trimmed = line.trim();
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() <= 16 {
        return "<redacted>".to_string();
    }
    let prefix: String = chars.iter().take(8).collect();
    let suffix: String = chars.iter().skip(chars.len().saturating_sub(4)).collect();
    format!("{prefix}...{suffix}")
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

    use super::{
        DEFAULT_SKIP_DIRS, MAX_REPORT_FILE_BYTES, MAX_SEARCH_MATCHES, ScanBudget, redact,
        scan_repo, scan_repo_with, search_repo,
    };
    use std::path::PathBuf;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("{label}-{stamp}"));
        std::fs::create_dir_all(&root).expect("mkdir");
        root
    }

    #[test]
    fn redact_handles_utf8_box_drawing_lines() {
        let line =
            "// ── AuditSink ─────────────────────────────────────────────────────────────────";
        let redacted = redact(line);
        assert!(redacted.starts_with("// ── Au"));
        assert!(redacted.ends_with("────"));
    }

    #[test]
    fn redact_never_returns_the_middle_of_a_line() {
        let secret = "API_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaSECRETMIDDLEbbbbbbbbbbbbbbbb";
        let redacted = redact(secret);
        assert!(
            !redacted.contains("SECRETMIDDLE"),
            "the excerpt must not reproduce what the scan is reporting: {redacted}"
        );
    }

    #[test]
    fn search_repo_skips_large_files() {
        let root = temp_root("nmcp-search-large");
        let huge = root.join("huge.log");
        let file = std::fs::File::create(&huge).expect("create huge");
        file.set_len(MAX_REPORT_FILE_BYTES + 1).expect("set len");
        let report = search_repo(&root, "anything").expect("search");
        assert!(report.matches.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn secret_scan_can_read_sensitive_named_files_inside_the_root_it_was_given() {
        let root = temp_root("nmcp-scan");
        std::fs::write(root.join(".env"), "API_KEY=supersecrettokenvalue123").expect("write");
        let report = scan_repo(&root).expect("scan");
        assert!(report.files_scanned >= 1);
        assert!(
            report
                .secret_candidates
                .iter()
                .any(|c| std::path::Path::new(&c.path).file_name() == Some(".env".as_ref()))
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn scan_repo_prunes_generated_directories_and_says_which() {
        let root = temp_root("nmcp-scan-prune");
        std::fs::create_dir_all(root.join("target").join("debug")).expect("mkdir target");
        std::fs::create_dir_all(root.join("src")).expect("mkdir src");
        std::fs::write(root.join("src").join("main.rs"), "fn main() {}").expect("write src");
        std::fs::write(
            root.join("target").join("debug").join("leak.env"),
            "API_KEY=supersecrettokenvalue123",
        )
        .expect("write artifact");

        let report = scan_repo(&root).expect("scan");
        assert!(report.secret_candidates.is_empty());
        // The prune is reported, so "no candidates" cannot be mistaken for "looked
        // everywhere and found nothing".
        assert!(report.dirs_skipped.iter().any(|dir| dir == "target"));

        // Opting out of pruning reaches the same file.
        let full = scan_repo_with(&root, &ScanBudget::unbounded()).expect("scan");
        assert!(
            full.secret_candidates
                .iter()
                .any(|c| c.path.ends_with("leak.env"))
        );
        assert!(full.dirs_skipped.is_empty());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn scan_repo_stops_at_the_file_budget_and_marks_the_report_truncated() {
        let root = temp_root("nmcp-scan-budget");
        for i in 0..8 {
            std::fs::write(root.join(format!("f{i}.txt")), "nothing here").expect("write");
        }
        let budget = ScanBudget {
            max_files: 3,
            ..ScanBudget::default()
        };
        let report = scan_repo_with(&root, &budget).expect("scan");
        assert!(report.truncated);
        assert_eq!(report.files_scanned, 3);
        assert!(
            report
                .stopped_because
                .as_deref()
                .expect("a truncated report must say why")
                .contains("file budget")
        );
        // A partial result must not read like a completed one.
        assert!(report.summary.contains("STOPPED EARLY"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn scan_repo_stops_at_the_byte_budget_and_says_so() {
        let root = temp_root("nmcp-scan-bytes");
        for i in 0..8 {
            std::fs::write(root.join(format!("f{i}.txt")), "0123456789").expect("write");
        }
        let budget = ScanBudget {
            max_bytes: 15,
            ..ScanBudget::default()
        };
        let report = scan_repo_with(&root, &budget).expect("scan");
        assert!(report.truncated);
        assert!(
            report
                .stopped_because
                .as_deref()
                .expect("a truncated report must say why")
                .contains("byte budget")
        );
        assert!(report.summary.contains("STOPPED EARLY"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn scan_repo_stops_at_the_deadline_against_a_real_walk() {
        // The budget's own unit test grades `exhausted` in isolation, which cannot show
        // that the walk consults it. A zero deadline must stop a walk that has files to
        // find, and the report must still be well formed rather than empty-and-silent.
        let root = temp_root("nmcp-scan-deadline");
        for i in 0..8 {
            std::fs::write(
                root.join(format!("f{i}.env")),
                "API_KEY=supersecrettokenvalue123",
            )
            .expect("write");
        }
        let budget = ScanBudget {
            deadline: Duration::ZERO,
            ..ScanBudget::default()
        };
        let report = scan_repo_with(&root, &budget).expect("scan");
        assert!(report.truncated, "a zero deadline must stop the walk");
        assert_eq!(report.files_scanned, 0);
        assert!(
            report
                .stopped_because
                .as_deref()
                .expect("a truncated report must say why")
                .contains("time budget")
        );
        assert!(report.summary.contains("STOPPED EARLY"));
        assert!(
            report.summary.contains("not"),
            "the summary must refuse to read as evidence the tree is clean: {}",
            report.summary
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn scan_repo_counts_files_it_was_too_large_to_open() {
        let root = temp_root("nmcp-scan-large");
        let huge = root.join("huge.log");
        let file = std::fs::File::create(&huge).expect("create huge");
        file.set_len(MAX_REPORT_FILE_BYTES + 1).expect("set len");
        std::fs::write(root.join("small.txt"), "ok").expect("write small");
        let report = scan_repo(&root).expect("scan");
        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.files_skipped_large, 1);
        assert!(!report.truncated);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn search_repo_prunes_generated_directories() {
        let root = temp_root("nmcp-search-prune");
        std::fs::create_dir_all(root.join("node_modules")).expect("mkdir");
        std::fs::write(root.join("node_modules").join("dep.js"), "needle").expect("write dep");
        std::fs::write(root.join("app.js"), "needle").expect("write app");
        let report = search_repo(&root, "needle").expect("search");
        assert_eq!(report.matches.len(), 1);
        assert!(report.matches[0].path.ends_with("app.js"));
        assert!(report.dirs_skipped.iter().any(|dir| dir == "node_modules"));
        assert!(!report.truncated);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn search_repo_refuses_an_invalid_pattern_and_names_it() {
        let root = temp_root("nmcp-search-badregex");
        let err = search_repo(&root, "(unclosed").expect_err("an invalid regex must refuse");
        assert!(
            format!("{err}").contains("(unclosed"),
            "the refusal must name the pattern: {err}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn search_repo_caps_matches_and_says_it_did() {
        let root = temp_root("nmcp-search-cap");
        let mut body = String::new();
        for _ in 0..(MAX_SEARCH_MATCHES + 50) {
            body.push_str("needle\n");
        }
        std::fs::write(root.join("many.txt"), body).expect("write");
        let report = search_repo(&root, "needle").expect("search");
        assert_eq!(report.matches.len(), MAX_SEARCH_MATCHES);
        assert!(report.truncated);
        assert!(
            report
                .stopped_because
                .as_deref()
                .expect("a capped search must say why")
                .contains("match budget")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn walk_budget_reports_which_bound_it_hit() {
        let budget = ScanBudget::default();
        let started = Instant::now();
        assert!(budget.exhausted(0, 0, started).is_none());
        assert!(
            budget
                .exhausted(budget.max_files, 0, started)
                .expect("file bound")
                .contains("file budget")
        );
        assert!(
            budget
                .exhausted(0, budget.max_bytes, started)
                .expect("byte bound")
                .contains("byte budget")
        );
        let expired = ScanBudget {
            deadline: Duration::ZERO,
            ..ScanBudget::default()
        };
        assert!(
            expired
                .exhausted(0, 0, started)
                .expect("time bound")
                .contains("time budget")
        );
        // The tool surface can raise the file bound but can never remove the deadline.
        assert!(ScanBudget::default().deadline.as_secs() < 60);
    }

    #[test]
    fn the_default_budget_prunes_the_documented_set() {
        let budget = ScanBudget::default();
        assert_eq!(budget.skip_dirs.len(), DEFAULT_SKIP_DIRS.len());
        for name in DEFAULT_SKIP_DIRS {
            assert!(
                budget.skip_dirs.iter().any(|d| d == name),
                "default budget must prune {name}"
            );
        }
        // The escape hatch prunes nothing, which is what makes the prune auditable.
        assert!(ScanBudget::unbounded().skip_dirs.is_empty());
    }
}
