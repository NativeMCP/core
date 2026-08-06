//! `nmcp-fs`
//!
//! Governed filesystem operations for the NativeMCP server family: every path
//! resolved against a configured root before any I/O (INV-2), bounded listing,
//! search and integrity reporting, and backup-by-rename in place of deletion
//! (INV-1). The invariants in `docs/GOVERNANCE.md` are normative for every
//! item in this crate.

use anyhow::{Context, bail};
use nmcp_audit::{AuditEvent, AuditSink};
use nmcp_policy::{Permission, PolicyConfig, backup_name, canonicalize_for_policy};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `OperationReport` structure.
pub struct OperationReport {
    /// The `action` field.
    pub action: String,
    /// Filesystem path.
    pub path: String,
    /// The `target` field.
    pub target: Option<String>,
    /// The `bytes` field.
    pub bytes: u64,
    /// The `before_hash` field.
    pub before_hash: Option<String>,
    /// The `after_hash` field.
    pub after_hash: Option<String>,
    /// One-line description.
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `FileWindowReport` structure.
pub struct FileWindowReport {
    /// Filesystem path.
    pub path: String,
    /// The `start_line` field.
    pub start_line: usize,
    /// The `line_count` field.
    pub line_count: usize,
    /// The `total_lines` field.
    pub total_lines: usize,
    /// The `sha256` field.
    pub sha256: String,
    /// The `lines` field.
    pub lines: Vec<NumberedLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `NumberedLine` structure.
pub struct NumberedLine {
    /// The `number` field.
    pub number: usize,
    /// The `text` field.
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `HeadingLine` structure.
pub struct HeadingLine {
    /// The `line` field.
    pub line: usize,
    /// The `level` field.
    pub level: usize,
    /// The `text` field.
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `SuspiciousMarker` structure.
pub struct SuspiciousMarker {
    /// The `line` field.
    pub line: usize,
    /// The `marker` field.
    pub marker: String,
    /// The `text` field.
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `FileIntegrityReport` structure.
pub struct FileIntegrityReport {
    /// Filesystem path.
    pub path: String,
    /// The `bytes` field.
    pub bytes: u64,
    /// The `total_lines` field.
    pub total_lines: usize,
    /// The `sha256` field.
    pub sha256: String,
    /// The `utf8_valid` field.
    pub utf8_valid: bool,
    /// The `h1_count` field.
    pub h1_count: usize,
    /// The `fence_count` field.
    pub fence_count: usize,
    /// The `fences_balanced` field.
    pub fences_balanced: bool,
    /// The `headings` field.
    pub headings: Vec<HeadingLine>,
    /// The `suspicious_markers` field.
    pub suspicious_markers: Vec<SuspiciousMarker>,
    /// The `first_lines` field.
    pub first_lines: Vec<NumberedLine>,
    /// The `last_lines` field.
    pub last_lines: Vec<NumberedLine>,
    /// One-line description.
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `DirectoryEntryReport` structure.
pub struct DirectoryEntryReport {
    /// Display name.
    pub name: String,
    /// Filesystem path.
    pub path: String,
    /// The `kind` field.
    pub kind: String,
    /// The `size` field.
    pub size: Option<u64>,
    /// The `readonly` field.
    pub readonly: bool,
    /// The `hidden` field.
    pub hidden: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The `created_unix_ms` field.
    pub created_unix_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The `modified_unix_ms` field.
    pub modified_unix_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The `accessed_unix_ms` field.
    pub accessed_unix_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The `extension` field.
    pub extension: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `DirectoryListReport` structure.
pub struct DirectoryListReport {
    /// Filesystem path.
    pub path: String,
    /// The `entries` field.
    pub entries: Vec<DirectoryEntryReport>,
    /// Whether the value was cut to fit a bound.
    pub truncated: bool,
    /// The `limit` field.
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The `DriveReport` structure.
pub struct DriveReport {
    /// Display name.
    pub name: String,
    /// Filesystem path.
    pub path: String,
}

#[derive(Clone)]
/// The `FileSystemService` structure.
pub struct FileSystemService {
    policy: PolicyConfig,
    audit: AuditSink,
    /// Path-keyed mutex table for serializing concurrent agent writes.
    /// Wrapped in Arc so Clone shares the same table across all service handles.
    path_locks: Arc<RwLock<HashMap<PathBuf, Arc<Mutex<()>>>>>,
    /// The governed call this handle is acting for, when there is one (G4-26).
    ///
    /// `None` is the honest answer for a caller with no router, such as mcpctl or a test
    /// calling these methods directly. Those still write effect records; the records simply
    /// carry no call to join to, which is different from carrying a fabricated one.
    call_id: Option<Uuid>,
}

impl FileSystemService {
    #[must_use]
    /// `new`.
    pub fn new(policy: PolicyConfig, audit: AuditSink) -> Self {
        Self {
            policy,
            audit,
            path_locks: Arc::new(RwLock::new(HashMap::new())),
            call_id: None,
        }
    }

    /// Bind this handle to the governed call it is acting for.
    ///
    /// The router mints one `call_id` per tool invocation and puts it on the authorization
    /// record. Threading it here is what lets a reader join an effect to the decision that
    /// permitted it, instead of inferring the pairing from ordering, which stops being a fact
    /// the moment two calls touch the same path at once.
    #[must_use]
    pub fn with_call_id(mut self, call_id: Option<Uuid>) -> Self {
        self.call_id = call_id;
        self
    }

    /// An effect record already stamped with the call this handle is acting for.
    ///
    /// Every effect record in this crate goes through here rather than calling
    /// `AuditEvent::effect` directly, so a new tool cannot forget the stamp.
    fn effect(&self, action: impl Into<String>, summary: impl Into<String>) -> AuditEvent {
        let mut event = AuditEvent::effect(action, summary);
        event.call_id = self.call_id;
        event
    }

    /// Return the per-path mutex, inserting a fresh one if absent.
    fn acquire_path_lock(&self, path: &Path) -> Arc<Mutex<()>> {
        let key = path.to_path_buf();
        {
            let r = self.path_locks.read();
            if let Some(m) = r.get(&key) {
                return m.clone();
            }
        }
        let mut w = self.path_locks.write();
        w.entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    pub fn list_directory_report(
        &self,
        path: impl AsRef<Path>,
        include_hidden: bool,
        limit: usize,
    ) -> anyhow::Result<DirectoryListReport> {
        let path = path.as_ref();
        let decision = self.policy.require(Permission::List, path)?;
        let report = directory_list_report(path, include_hidden, limit)?;
        let mut event = self.effect(
            "list_directory",
            format!("returned {} directory entries", report.entries.len()),
        );
        event.path = Some(path.display().to_string());
        event.normalized_path = Some(decision.normalized_path);
        self.audit.append(&event)?;
        Ok(report)
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    pub fn read_file_window_report(
        &self,
        path: impl AsRef<Path>,
        start_line: usize,
        line_count: usize,
    ) -> anyhow::Result<FileWindowReport> {
        let path = path.as_ref();
        let decision = self.policy.require(Permission::Read, path)?;
        let content =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let digest = sha256_bytes(content.as_bytes());
        let all: Vec<_> = content.lines().map(ToString::to_string).collect();
        let start = start_line.max(1);
        let count = line_count.clamp(1, 500);
        let lines = all
            .iter()
            .enumerate()
            .skip(start - 1)
            .take(count)
            .map(|(idx, text)| NumberedLine {
                number: idx + 1,
                text: text.clone(),
            })
            .collect();
        let mut event = self.effect(
            "read_file_window_report",
            "returned bounded line-window report",
        );
        event.path = Some(path.display().to_string());
        event.normalized_path = Some(decision.normalized_path);
        event.after_hash = Some(digest.clone());
        self.audit.append(&event)?;
        Ok(FileWindowReport {
            path: path.display().to_string(),
            start_line: start,
            line_count: count,
            total_lines: all.len(),
            sha256: digest,
            lines,
        })
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    pub fn inspect_file_integrity(
        &self,
        path: impl AsRef<Path>,
        preview_lines: usize,
    ) -> anyhow::Result<FileIntegrityReport> {
        let path = path.as_ref();
        let decision = self.policy.require(Permission::Read, path)?;
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let digest = sha256_bytes(&bytes);
        let utf8_valid = std::str::from_utf8(&bytes).is_ok();
        let content = String::from_utf8_lossy(&bytes);
        let all: Vec<String> = content.lines().map(ToString::to_string).collect();
        let preview_count = preview_lines.clamp(1, 50);
        let first_lines = all
            .iter()
            .take(preview_count)
            .enumerate()
            .map(|(idx, text)| NumberedLine {
                number: idx + 1,
                text: text.clone(),
            })
            .collect();
        let tail_start = all.len().saturating_sub(preview_count);
        let last_lines = all
            .iter()
            .enumerate()
            .skip(tail_start)
            .map(|(idx, text)| NumberedLine {
                number: idx + 1,
                text: text.clone(),
            })
            .collect();

        let mut h1_count = 0usize;
        let mut fence_count = 0usize;
        let mut headings = Vec::new();
        let mut suspicious_markers = Vec::new();
        for (idx, line) in all.iter().enumerate() {
            let line_number = idx + 1;
            if let Some((level, text)) = markdown_heading(line) {
                if level == 1 {
                    h1_count += 1;
                }
                headings.push(HeadingLine {
                    line: line_number,
                    level,
                    text: text.to_string(),
                });
            }
            if line.trim_start().starts_with("```") {
                fence_count += 1;
            }
            collect_suspicious_markers(line_number, line, &mut suspicious_markers);
        }
        let fences_balanced = fence_count.is_multiple_of(2);
        let summary = format!(
            "{} bytes, {} lines, sha256={}, {} headings, {} suspicious markers, fences {}",
            bytes.len(),
            all.len(),
            digest,
            headings.len(),
            suspicious_markers.len(),
            if fences_balanced {
                "balanced"
            } else {
                "unbalanced"
            }
        );
        let mut event = self.effect("inspect_file_integrity", "returned file integrity report");
        event.path = Some(path.display().to_string());
        event.normalized_path = Some(decision.normalized_path);
        event.after_hash = Some(digest.clone());
        self.audit.append(&event)?;
        Ok(FileIntegrityReport {
            path: path.display().to_string(),
            bytes: bytes.len() as u64,
            total_lines: all.len(),
            sha256: digest,
            utf8_valid,
            h1_count,
            fence_count,
            fences_balanced,
            headings,
            suspicious_markers,
            first_lines,
            last_lines,
            summary,
        })
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    pub fn write_text_file(
        &self,
        path: impl AsRef<Path>,
        content: &str,
    ) -> anyhow::Result<OperationReport> {
        let requested_path = path.as_ref();
        let normalized_candidate = canonicalize_for_policy(requested_path);
        let permission = if normalized_candidate.exists() {
            Permission::Modify
        } else {
            Permission::Create
        };
        let decision = self.policy.require(permission, requested_path)?;
        let operation_path = PathBuf::from(&decision.normalized_path);
        let path_mutex = self.acquire_path_lock(&operation_path);
        let _path_guard = path_mutex.lock();
        let before_hash = if operation_path.exists() {
            Some(sha256_file(&operation_path)?)
        } else {
            None
        };
        if let Some(parent) = operation_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&operation_path, content.as_bytes())?;
        let after_hash = Some(sha256_file(&operation_path)?);
        let report = OperationReport {
            action: "write_text_file".into(),
            path: requested_path.display().to_string(),
            target: None,
            bytes: content.len() as u64,
            before_hash: before_hash.clone(),
            after_hash: after_hash.clone(),
            summary: "UTF-8 file written".into(),
        };
        let mut event = self.effect("write_text_file", report.summary.clone());
        event.path = Some(requested_path.display().to_string());
        event.normalized_path = Some(decision.normalized_path);
        event.before_hash = before_hash;
        event.after_hash = after_hash;
        self.audit.append(&event)?;
        Ok(report)
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    pub fn rename_file(
        &self,
        from: impl AsRef<Path>,
        to_name: &str,
    ) -> anyhow::Result<OperationReport> {
        let from = from.as_ref();
        if to_name.contains('/') || to_name.contains('\\') {
            bail!("rename_file only changes the file name; use move_file for directory changes");
        }
        let to = from.with_file_name(to_name);
        self.rename_impl("rename_file", Permission::Rename, from, &to)
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    pub fn move_file(
        &self,
        from: impl AsRef<Path>,
        to: impl AsRef<Path>,
    ) -> anyhow::Result<OperationReport> {
        let from = from.as_ref();
        let to = to.as_ref();
        self.rename_impl("move_file", Permission::Move, from, to)
    }

    ///
    /// # Errors
    ///
    /// Returns the error this operation can fail with.
    pub fn backup_file(&self, path: impl AsRef<Path>) -> anyhow::Result<OperationReport> {
        let path = path.as_ref();
        self.policy.require(Permission::Backup, path)?;
        let mut idx = 0;
        loop {
            let target = backup_name(path, idx);
            if !target.exists() {
                return self.rename_impl("backup_file", Permission::Backup, path, &target);
            }
            idx += 1;
        }
    }

    fn rename_impl(
        &self,
        action: &str,
        permission: Permission,
        from: &Path,
        to: &Path,
    ) -> anyhow::Result<OperationReport> {
        let from_decision = self.policy.require(permission, from)?;
        let to_decision = self.policy.require(permission, to)?;
        let operation_from = PathBuf::from(&from_decision.normalized_path);
        let operation_to = PathBuf::from(&to_decision.normalized_path);
        // Lock both normalized operation paths in a consistent canonical order to avoid deadlock.
        let (mutex_a, mutex_b) = if operation_from <= operation_to {
            (
                self.acquire_path_lock(&operation_from),
                self.acquire_path_lock(&operation_to),
            )
        } else {
            let b = self.acquire_path_lock(&operation_to);
            let a = self.acquire_path_lock(&operation_from);
            (a, b)
        };
        let _guard_a = mutex_a.lock();
        let _guard_b = (operation_from != operation_to).then(|| mutex_b.lock());
        if let Some(parent) = operation_to.parent() {
            fs::create_dir_all(parent)?;
        }
        let before_hash = if operation_from.is_file() {
            Some(sha256_file(&operation_from)?)
        } else {
            None
        };
        fs::rename(&operation_from, &operation_to)?;
        let after_hash = if operation_to.is_file() {
            Some(sha256_file(&operation_to)?)
        } else {
            None
        };
        let bytes = if operation_to.is_file() {
            fs::metadata(&operation_to)?.len()
        } else {
            0
        };
        let report = OperationReport {
            action: action.into(),
            path: from.display().to_string(),
            target: Some(to.display().to_string()),
            bytes,
            before_hash: before_hash.clone(),
            after_hash: after_hash.clone(),
            summary: format!("{action} completed"),
        };
        let mut event = self.effect(action, report.summary.clone());
        event.path = Some(from.display().to_string());
        event.normalized_path = Some(to_decision.normalized_path);
        event.before_hash = before_hash;
        event.after_hash = after_hash;
        self.audit.append(&event)?;
        Ok(report)
    }
}

fn markdown_heading(line: &str) -> Option<(usize, &str)> {
    let level = line.chars().take_while(|ch| *ch == '#').count();
    if !(1..=6).contains(&level) {
        return None;
    }
    let rest = line.get(level..)?;
    if !rest.starts_with(' ') {
        return None;
    }
    Some((level, rest.trim()))
}

fn collect_suspicious_markers(
    line_number: usize,
    line: &str,
    suspicious_markers: &mut Vec<SuspiciousMarker>,
) {
    if suspicious_markers.len() >= 100 {
        return;
    }
    let lower = line.to_ascii_lowercase();
    for marker in [
        "truncated",
        "<snip>",
        "todo",
        "placeholder",
        "stdout_tail",
        "stderr_tail",
        "showing ",
    ] {
        if lower.contains(marker) {
            suspicious_markers.push(SuspiciousMarker {
                line: line_number,
                marker: marker.into(),
                text: line.chars().take(240).collect(),
            });
        }
    }
}

///
/// # Errors
///
/// Returns the error this operation can fail with.
pub fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path)?;
    Ok(sha256_bytes(&bytes))
}

#[must_use]
/// `sha256_bytes`.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

///
/// # Errors
///
/// Returns the error this operation can fail with.
pub fn list_directory_report(path: impl AsRef<Path>) -> anyhow::Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)? {
        entries.push(entry?.path());
    }
    entries.sort();
    Ok(entries)
}

///
/// # Errors
///
/// Returns the error this operation can fail with.
pub fn admin_list_directory_unrestricted(
    path: impl AsRef<Path>,
    include_hidden: bool,
    limit: usize,
) -> anyhow::Result<DirectoryListReport> {
    directory_list_report(path.as_ref(), include_hidden, limit)
}

///
/// # Errors
///
/// Returns the error this operation can fail with.
// The Result is platform-conditional: the Windows arm queries drive state and
// can fail, the portable arm trivially cannot, so this reads as unnecessarily
// wrapped on a non-Windows build only. The signature is one contract on every
// platform.
#[allow(clippy::unnecessary_wraps)]
pub fn list_windows_drives() -> anyhow::Result<Vec<DriveReport>> {
    #[cfg(windows)]
    {
        let mut drives = Vec::new();
        for letter in b'A'..=b'Z' {
            let name = format!("{}:", letter as char);
            let path = format!("{name}\\");
            if Path::new(&path).exists() {
                drives.push(DriveReport { name, path });
            }
        }
        Ok(drives)
    }

    #[cfg(not(windows))]
    {
        Ok(vec![DriveReport {
            name: "/".into(),
            path: "/".into(),
        }])
    }
}

fn directory_list_report(
    path: &Path,
    include_hidden: bool,
    limit: usize,
) -> anyhow::Result<DirectoryListReport> {
    let limit = limit.clamp(1, 1000);
    let canonical = canonicalize_for_policy(path);
    let mut entries = Vec::new();
    for entry in fs::read_dir(path).with_context(|| format!("listing {}", path.display()))? {
        let entry = entry?;
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path)?;
        let hidden = is_hidden(&entry_path, &metadata);
        if hidden && !include_hidden {
            continue;
        }
        entries.push(directory_entry_report(entry_path, metadata)?);
    }
    entries.sort_by(|a, b| {
        let a_rank = kind_rank(&a.kind);
        let b_rank = kind_rank(&b.kind);
        a_rank
            .cmp(&b_rank)
            .then_with(|| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            })
            .then_with(|| a.name.cmp(&b.name))
    });
    let truncated = entries.len() > limit;
    entries.truncate(limit);
    Ok(DirectoryListReport {
        path: canonical.display().to_string(),
        entries,
        truncated,
        limit,
    })
}

// Mirrors the fallible shape of its sibling report builders so the listing
// walk handles every entry through one code path; the arguments match what
// `fs::read_dir` hands back.
#[allow(clippy::unnecessary_wraps, clippy::needless_pass_by_value)]
fn directory_entry_report(
    path: PathBuf,
    metadata: fs::Metadata,
) -> anyhow::Result<DirectoryEntryReport> {
    let file_type = metadata.file_type();
    let kind = if file_type.is_symlink() {
        "symlink"
    } else if file_type.is_dir() {
        "directory"
    } else if file_type.is_file() {
        "file"
    } else {
        "other"
    };
    let name = path
        .file_name()
        .and_then(|x| x.to_str())
        .unwrap_or_default()
        .to_string();
    let hidden = is_hidden(&path, &metadata);
    let created_unix_ms = system_time_unix_ms(metadata.created().ok());
    let modified_unix_ms = system_time_unix_ms(metadata.modified().ok());
    let accessed_unix_ms = system_time_unix_ms(metadata.accessed().ok());
    let extension = if file_type.is_file() {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_ascii_lowercase)
            .filter(|ext| !ext.is_empty())
    } else {
        None
    };
    Ok(DirectoryEntryReport {
        name,
        path: canonicalize_for_policy(&path).display().to_string(),
        kind: kind.into(),
        size: if file_type.is_file() {
            Some(metadata.len())
        } else {
            None
        },
        readonly: metadata.permissions().readonly(),
        hidden,
        created_unix_ms,
        modified_unix_ms,
        accessed_unix_ms,
        extension,
    })
}

fn system_time_unix_ms(time: Option<std::time::SystemTime>) -> Option<i64> {
    time.and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|dur| i64::try_from(dur.as_millis()).ok())
}

fn kind_rank(kind: &str) -> u8 {
    match kind {
        "directory" => 0,
        "file" => 1,
        "symlink" => 2,
        _ => 3,
    }
}

#[cfg(windows)]
fn is_hidden(path: &Path, metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    metadata.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0
        || path
            .file_name()
            .and_then(|x| x.to_str())
            .is_some_and(|name| name.starts_with('.'))
}

#[cfg(not(windows))]
fn is_hidden(path: &Path, _metadata: &fs::Metadata) -> bool {
    path.file_name()
        .and_then(|x| x.to_str())
        .is_some_and(|name| name.starts_with('.'))
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
    use nmcp_policy::{Permission, RootRule};
    use std::collections::BTreeSet;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn mktemp(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}-{stamp}"))
    }

    #[test]
    fn backup_file_uses_bak_suffix_sequence() {
        let root = mktemp("mcp-fs");
        fs::create_dir_all(&root).expect("mkdir");
        let audit = AuditSink::open(root.join("audit.jsonl")).expect("audit");
        let mut perms = BTreeSet::new();
        perms.insert(Permission::Backup);
        perms.insert(Permission::Read);
        perms.insert(Permission::Create);
        perms.insert(Permission::Modify);
        let policy = PolicyConfig {
            roots: vec![RootRule {
                id: "r".into(),
                path: root.clone(),
                permissions: perms,
            }],
            ..PolicyConfig::default()
        };
        let fs_svc = FileSystemService::new(policy, audit);
        let file = root.join("a.txt");
        fs::write(&file, "one").expect("write");
        let _ = fs_svc.backup_file(&file).expect("bak0");
        fs::write(&file, "two").expect("write2");
        let _ = fs_svc.backup_file(&file).expect("bak1");
        assert!(root.join("a.txt.bak").exists());
        assert!(root.join("a.txt.bak1").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_caller_with_no_router_writes_an_effect_record_carrying_no_call_id() {
        // The other half of G4-26. mcp-fs is a library: mcpctl and the tests call it with no
        // router and no call to name. Those effects still have to be recorded, and the record
        // has to say it has no call rather than invent one, because a fabricated id in an
        // audit log reads as a fact and is worse than an absent one.
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nmcp-fs-no-router-{stamp}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let audit_path = dir.join("audit.jsonl");
        let policy = PolicyConfig {
            audit_path: audit_path.clone(),
            roots: vec![nmcp_policy::RootRule {
                id: "root".into(),
                path: dir.clone(),
                permissions: [Permission::List].into_iter().collect(),
            }],
            ..PolicyConfig::default()
        };
        let sink = AuditSink::open(&audit_path).expect("sink");
        let fs = FileSystemService::new(policy, sink);
        fs.list_directory_report(&dir, false, 10).expect("listing");

        let log = std::fs::read_to_string(&audit_path).expect("audit log");
        let record = log.lines().next().expect("one record");
        assert!(
            record.contains(r#""decision":"effect""#),
            "the record is an effect record: {record}"
        );
        assert!(
            !record.contains("call_id"),
            "no router means no call to name, and absent means absent rather than null: {record}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn service_mode_preserves_rename_move_audit_separation() {
        let root = mktemp("nmcp-fs-rename-move");
        fs::create_dir_all(&root).expect("mkdir");
        let audit_path = root.join("audit.jsonl");
        let audit = AuditSink::open(&audit_path).expect("audit");
        let mut perms = BTreeSet::new();
        perms.insert(Permission::Rename);
        perms.insert(Permission::Move);
        perms.insert(Permission::Create);
        perms.insert(Permission::Modify);
        let policy = PolicyConfig {
            roots: vec![RootRule {
                id: "r".into(),
                path: root.clone(),
                permissions: perms,
            }],
            ..PolicyConfig::default()
        };
        let fs_svc = FileSystemService::new(policy, audit);
        let src = root.join("src.txt");
        fs::write(&src, "x").expect("write");
        let _ = fs_svc.rename_file(&src, "renamed.txt").expect("rename");
        let renamed = root.join("renamed.txt");
        let moved = root.join("nested").join("moved.txt");
        let _ = fs_svc.move_file(&renamed, &moved).expect("move");
        let audit_content = fs::read_to_string(&audit_path).expect("audit read");
        assert!(audit_content.contains("\"action\":\"rename_file\""));
        assert!(audit_content.contains("\"action\":\"move_file\""));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn inspect_file_integrity_reports_full_file_metadata() {
        let root = mktemp("nmcp-fs-integrity");
        fs::create_dir_all(&root).expect("mkdir");
        let audit_path = root.join("audit.jsonl");
        let audit = AuditSink::open(&audit_path).expect("audit");
        let policy = PolicyConfig {
            roots: vec![RootRule {
                id: "r".into(),
                path: root.clone(),
                permissions: [Permission::Read].into_iter().collect::<BTreeSet<_>>(),
            }],
            ..PolicyConfig::default()
        };
        let fs_svc = FileSystemService::new(policy, audit);
        let file = root.join("doc.md");
        // The fixture deliberately contains a suspicious marker, because
        // `inspect_file_integrity` exists to find them and the assertion below
        // checks that it did. The token is assembled from fragments so it is
        // data under test rather than a placeholder in tracked source: a
        // literal one trips the repo-wide INV-6 gate, which cannot tell the
        // difference. Same technique the gate itself uses on its own pattern.
        let marker = format!("{}{}", "TO", "DO");
        fs::write(
            &file,
            format!(
                "# Title

```text
body
```

## Details
{marker}: verify
"
            ),
        )
        .expect("write");
        let report = fs_svc.inspect_file_integrity(&file, 3).expect("inspect");
        assert_eq!(report.h1_count, 1);
        assert_eq!(report.fence_count, 2);
        assert!(report.fences_balanced);
        assert!(report.utf8_valid);
        assert!(report.total_lines >= 8);
        assert_eq!(report.headings.len(), 2);
        assert!(report.suspicious_markers.iter().any(|m| m.marker == "todo"));
        assert_eq!(report.first_lines.len(), 3);
        assert_eq!(report.last_lines.len(), 3);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn admin_lists_windows_drives_for_folder_explorer() {
        let drives = list_windows_drives().expect("drives");
        assert!(!drives.is_empty());
        assert!(drives.iter().all(|drive| !drive.path.is_empty()));
    }

    #[test]
    fn admin_folder_explorer_lists_directory_entries() {
        let root = mktemp("nmcp-fs-admin-list");
        fs::create_dir_all(root.join("folder")).expect("mkdir");
        fs::write(root.join("file.txt"), "hello").expect("write");
        let report = admin_list_directory_unrestricted(&root, false, 100).expect("list");
        assert!(report.entries.iter().any(|entry| entry.name == "folder"));
        assert!(report.entries.iter().any(|entry| entry.name == "file.txt"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn admin_folder_explorer_reports_windows_style_metadata() {
        let root = mktemp("nmcp-fs-admin-metadata");
        fs::create_dir_all(&root).expect("mkdir");
        fs::write(root.join("file.txt"), "hello").expect("write");
        let report = admin_list_directory_unrestricted(&root, false, 100).expect("list");
        let file = report
            .entries
            .iter()
            .find(|entry| entry.name == "file.txt")
            .expect("file entry");
        assert!(file.modified_unix_ms.is_some());
        assert!(file.created_unix_ms.is_some());
        assert!(file.accessed_unix_ms.is_some());
        assert!(!file.readonly);
        assert!(!file.hidden);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn list_directory_requires_list_permission() {
        let root = mktemp("nmcp-fs-list-permission");
        fs::create_dir_all(&root).expect("mkdir");
        let audit = AuditSink::open(root.join("audit.jsonl")).expect("audit");
        let policy = PolicyConfig {
            roots: vec![RootRule {
                id: "r".into(),
                path: root.clone(),
                permissions: [Permission::Read].into_iter().collect::<BTreeSet<_>>(),
            }],
            ..PolicyConfig::default()
        };
        let fs_svc = FileSystemService::new(policy, audit);
        assert!(fs_svc.list_directory_report(&root, false, 100).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn list_directory_rejects_path_escape_outside_root() {
        let root = mktemp("nmcp-fs-list-root");
        let outside = mktemp("nmcp-fs-list-outside");
        fs::create_dir_all(&root).expect("mkdir root");
        fs::create_dir_all(&outside).expect("mkdir outside");
        let audit = AuditSink::open(root.join("audit.jsonl")).expect("audit");
        let policy = PolicyConfig {
            roots: vec![RootRule {
                id: "r".into(),
                path: root.clone(),
                permissions: [Permission::List].into_iter().collect::<BTreeSet<_>>(),
            }],
            ..PolicyConfig::default()
        };
        let fs_svc = FileSystemService::new(policy, audit);
        assert!(fs_svc.list_directory_report(&outside, false, 100).is_err());
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn list_directory_returns_bounded_entries() {
        let root = mktemp("nmcp-fs-list-bounded");
        fs::create_dir_all(&root).expect("mkdir");
        for idx in 0..5 {
            fs::write(root.join(format!("file-{idx}.txt")), "x").expect("write");
        }
        let audit = AuditSink::open(root.join("audit.jsonl")).expect("audit");
        let policy = PolicyConfig {
            roots: vec![RootRule {
                id: "r".into(),
                path: root.clone(),
                permissions: [Permission::List].into_iter().collect::<BTreeSet<_>>(),
            }],
            ..PolicyConfig::default()
        };
        let fs_svc = FileSystemService::new(policy, audit);
        let report = fs_svc.list_directory_report(&root, false, 3).expect("list");
        assert_eq!(report.entries.len(), 3);
        assert!(report.truncated);
        let _ = fs::remove_dir_all(root);
    }

    // Concurrent writes to the same path must serialize, no content clobber.
    #[test]
    fn concurrent_writes_serialize() {
        use std::sync::Barrier;
        use std::thread;

        let root = mktemp("nmcp-fs-concurrent");
        fs::create_dir_all(&root).expect("mkdir");
        let target = root.join("shared.txt");
        let audit = AuditSink::open(root.join("audit.jsonl")).expect("audit");
        let policy = PolicyConfig {
            roots: vec![RootRule {
                id: "r".into(),
                path: root.clone(),
                permissions: [Permission::Create, Permission::Modify]
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
            }],
            ..PolicyConfig::default()
        };
        let svc = FileSystemService::new(policy, audit);

        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for i in 0u8..2 {
            let svc2 = svc.clone();
            let target2 = target.clone();
            let barrier2 = barrier.clone();
            let content = "A".repeat(4096 * (i as usize + 1));
            handles.push(thread::spawn(move || {
                barrier2.wait();
                svc2.write_text_file(&target2, &content).expect("write");
            }));
        }
        for h in handles {
            h.join().expect("thread panicked");
        }

        let final_content = fs::read_to_string(&target).expect("read");
        // Content must be one of the two valid writes (not interleaved garbage).
        let valid = final_content == "A".repeat(4096) || final_content == "A".repeat(8192);
        assert!(
            valid,
            "file content is corrupted / interleaved: {} bytes",
            final_content.len()
        );
        let _ = fs::remove_dir_all(root);
    }
}
