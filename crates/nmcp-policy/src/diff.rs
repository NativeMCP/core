//! What a policy edit actually changes about who may call what (M5).
//!
//! An operator editing a policy is asking one question: after I save this, which calls become
//! possible that were not, and which stop being possible? A textual diff answers a different
//! question and answers it badly. Renaming a root shows as two changed lines and changes no
//! verdict. Adding a narrow root under a broad one shows as one added line and can silently
//! revoke every permission on that subtree, because the most specific root wins and its
//! permissions are authoritative.
//!
//! So this plans over verdicts rather than over text, and it does it exactly rather than by
//! sampling paths.
//!
//! # Why the enumeration is exact and finite
//!
//! [`PolicyConfig::require`] decides a filesystem call by taking the root whose canonical path
//! is the longest prefix of the target, then asking whether that root grants the permission.
//! A path outside every root is denied.
//!
//! Take `S`, the canonical paths of every root in either policy. For any path `p`, the verdict
//! under either policy depends only on which element of `S` is `p`'s longest prefix, because
//! each policy's roots are a subset of `S` and the longest prefix within a subset is determined
//! by the longest prefix within `S`. Two paths with the same longest prefix in `S` therefore
//! receive the same verdict pair. `S` is finite, so the verdict space is finite: one region per
//! element of `S`, plus the region outside all of them.
//!
//! Evaluating a region at its own root path is sound for the same reason: the longest prefix of
//! `r` within `S` is `r` itself, since no strict descendant of `r` is a prefix of `r`.
//!
//! That is the whole argument, and it is why this reports regions rather than example paths. A
//! planner that probed a handful of paths would be right about those paths and silent about the
//! rest, which for a governance tool is worse than saying nothing.

use crate::{Permission, PolicyConfig, canonicalize_for_policy};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

/// Whether a call is permitted, as the policy ring would decide it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The call is permitted.
    Allowed,
    /// The call is refused.
    Denied,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Allowed => write!(f, "allowed"),
            Verdict::Denied => write!(f, "denied"),
        }
    }
}

/// A set of paths that both policies decide identically, named by the root that governs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathRegion {
    /// The canonical path the region is evaluated at. Every path in the region resolves to
    /// this same pair of verdicts.
    pub path: String,
    /// Deeper roots that carve their own regions out of this one. Present so a reader is not
    /// told "everything under D:\dev" when a narrower root governs part of it.
    pub carved_out_by: Vec<String>,
    /// True for the region containing every path under no root at all.
    pub outside_all_roots: bool,
}

impl PathRegion {
    /// One line an operator can act on without reading the struct.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.outside_all_roots {
            return "any path under no configured root".to_string();
        }
        if self.carved_out_by.is_empty() {
            format!("{} and everything under it", self.path)
        } else {
            format!(
                "{} and everything under it, except under {}",
                self.path,
                self.carved_out_by.join(", ")
            )
        }
    }
}

/// One permission whose verdict changes over one region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionChange {
    /// The path region affected.
    pub region: PathRegion,
    /// The capability this concerns.
    pub permission: Permission,
    /// Verdict before the change.
    pub before: Verdict,
    /// Verdict after the change.
    pub after: Verdict,
    /// The root that decided it before, when one did.
    pub before_root: Option<String>,
    /// The root that decides it after, when one does.
    pub after_root: Option<String>,
}

impl PermissionChange {
    /// `describe`.
    #[must_use]
    pub fn describe(&self) -> String {
        let by = match (&self.before_root, &self.after_root) {
            (Some(b), Some(a)) if b != a => format!(" (root {b} -> {a})"),
            (_, Some(a)) => format!(" (root {a})"),
            (Some(b), None) => format!(" (was root {b}, now no root matches)"),
            (None, None) => String::new(),
        };
        format!(
            "{} on {}: {} -> {}{}",
            self.permission,
            self.region.describe(),
            self.before,
            self.after,
            by
        )
    }
}

/// A change to what one named caller may reach, from the deny-by-default tool allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerToolChange {
    /// The caller identity.
    pub caller: String,
    /// Tools newly permitted for the caller.
    pub newly_allowed_tools: Vec<String>,
    /// Tools newly denied to the caller.
    pub newly_denied_tools: Vec<String>,
    /// Set when the caller gains or loses an allowlist entirely, which is the change most
    /// likely to be misread: losing one does not restrict a caller, it unrestricts them.
    pub note: Option<String>,
}

/// A change to who can reach the server at all, which no per-path verdict captures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilityChange {
    /// One-line description.
    pub summary: String,
}

/// A root whose identity changed while its verdicts did not.
///
/// Worth its own category because `root_id` is written into every audit record. Renaming a
/// root changes nothing about who may call what, and changes what the log says about calls
/// made after the rename, which is a real consequence for anyone querying it later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootIdentityChange {
    /// Filesystem path.
    pub path: String,
    /// Root id before the change.
    pub before_id: String,
    /// Root id after the change.
    pub after_id: String,
}

/// The full answer to "what does saving this change".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyChangePlan {
    /// Permissions newly allowed by the change.
    pub newly_allowed: Vec<PermissionChange>,
    /// Permissions newly denied by the change.
    pub newly_denied: Vec<PermissionChange>,
    /// Per-caller tool allowlist changes.
    pub caller_tool_changes: Vec<CallerToolChange>,
    /// Changes to who can reach the server at all.
    pub reachability_changes: Vec<ReachabilityChange>,
    /// Roots renamed without any verdict moving. Not a verdict change, so it does not make a
    /// plan non-neutral, but it does change what future audit records name.
    pub root_identity_changes: Vec<RootIdentityChange>,
    /// Top-level policy fields that differ but decide no call differently. Listed rather than
    /// omitted, because "nothing changed" and "something changed and it was harmless" are
    /// different statements and only one of them is true here.
    pub changed_without_verdict_effect: Vec<String>,
    /// True when the outside-all-roots region could not be represented because every candidate
    /// path fell under some root. Reported rather than skipped silently.
    pub outside_region_unrepresentable: bool,
}

impl PolicyChangePlan {
    /// True when the two policies decide every call the same way.
    #[must_use]
    pub fn is_verdict_neutral(&self) -> bool {
        self.newly_allowed.is_empty()
            && self.newly_denied.is_empty()
            && self.caller_tool_changes.is_empty()
            && self.reachability_changes.is_empty()
    }

    /// A plain-text plan, in the order an operator should read it: what opens first, because
    /// that is what a mistake here costs.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        if self.is_verdict_neutral() {
            out.push_str("No call changes verdict.\n");
        } else {
            if !self.newly_allowed.is_empty() {
                let _ = writeln!(out, "Newly allowed ({}):", self.newly_allowed.len());
                for change in &self.newly_allowed {
                    let _ = writeln!(out, "  + {}", change.describe());
                }
            }
            if !self.newly_denied.is_empty() {
                let _ = writeln!(out, "Newly denied ({}):", self.newly_denied.len());
                for change in &self.newly_denied {
                    let _ = writeln!(out, "  - {}", change.describe());
                }
            }
            for change in &self.caller_tool_changes {
                let _ = writeln!(out, "Caller {}:", change.caller);
                if let Some(note) = &change.note {
                    let _ = writeln!(out, "  ! {note}");
                }
                for tool in &change.newly_allowed_tools {
                    let _ = writeln!(out, "  + may now call {tool}");
                }
                for tool in &change.newly_denied_tools {
                    let _ = writeln!(out, "  - may no longer call {tool}");
                }
            }
            for change in &self.reachability_changes {
                let _ = writeln!(out, "Reachability:\n  ! {}", change.summary);
            }
        }
        for change in &self.root_identity_changes {
            let _ = writeln!(
                out,
                "Root renamed: {} is now '{}', was '{}'. No verdict moves; audit records \
                 written after this name the new id.",
                change.path, change.after_id, change.before_id
            );
        }
        if !self.changed_without_verdict_effect.is_empty() {
            let _ = writeln!(
                out,
                "Changed with no verdict effect: {}",
                self.changed_without_verdict_effect.join(", ")
            );
        }
        if self.outside_region_unrepresentable {
            out.push_str(
                "Note: every candidate path fell under some root, so the outside-all-roots \
                 region was not evaluated.\n",
            );
        }
        out
    }
}

/// Paths tried, in order, when looking for one under no root in either policy. Only the first
/// that qualifies is used. They are deliberately implausible as real roots.
const OUTSIDE_CANDIDATES: &[&str] = &[
    r"Z:\__nativemcp_outside_all_roots__",
    r"Y:\__nativemcp_outside_all_roots__",
    r"\\__nativemcp__\outside\all\roots",
];

fn verdict(policy: &PolicyConfig, permission: Permission, path: &str) -> (Verdict, Option<String>) {
    #[allow(clippy::single_match_else)] // the Err arm carries the explanation below
    match policy.require(permission, path) {
        Ok(decision) => (Verdict::Allowed, decision.root_id),
        Err(_) => {
            // A denial is a denial whether the root refused the permission or no root matched.
            // The root that would have decided it is still worth naming, so the reader can see
            // which rule to edit.
            let deciding = deciding_root(policy, path);
            (Verdict::Denied, deciding)
        }
    }
}

/// The root `require` would select for this path, whether or not it grants anything.
fn deciding_root(policy: &PolicyConfig, path: &str) -> Option<String> {
    let normalized = canonicalize_for_policy(std::path::Path::new(path));
    let mut best: Option<(&str, usize)> = None;
    for root in &policy.roots {
        let root_norm = canonicalize_for_policy(&root.path);
        if normalized.starts_with(&root_norm) {
            let len = root_norm.as_os_str().len();
            if best.is_none_or(|(_, best_len)| len > best_len) {
                best = Some((root.id.as_str(), len));
            }
        }
    }
    best.map(|(id, _)| id.to_string())
}

/// The allowlist each caller is restricted to, if any.
fn caller_allowlists(policy: &PolicyConfig) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for rule in &policy.abac_rules {
        if let crate::AbacRule::CallerToolAllowlist {
            caller,
            allowed_tools,
            ..
        } = rule
        {
            out.entry(caller.clone())
                .or_default()
                .extend(allowed_tools.iter().cloned());
        }
    }
    out
}

/// Plan the change from `before` to `after`.
///
/// Deterministic: regions are ordered by path, permissions by their declaration order, callers
/// by name. Two runs over the same pair produce the same plan, which is what makes it usable as
/// a gate rather than only as a report.
// The plan walks every permission over every region and every caller: long by
// nature, and splitting it would scatter one decision procedure across helpers
// that are only meaningful together.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn plan(before: &PolicyConfig, after: &PolicyConfig) -> PolicyChangePlan {
    let mut plan = PolicyChangePlan::default();

    // The union of root paths is what partitions the path space. Canonical, deduplicated, and
    // sorted so the output order does not depend on the order roots happen to be declared in.
    let mut union: BTreeSet<String> = BTreeSet::new();
    for policy in [before, after] {
        for root in &policy.roots {
            union.insert(canonicalize_for_policy(&root.path).display().to_string());
        }
    }

    let mut regions: Vec<PathRegion> = Vec::new();
    for path in &union {
        let carved_out_by: Vec<String> = union
            .iter()
            .filter(|other| {
                other.as_str() != path.as_str()
                    && std::path::Path::new(other.as_str())
                        .starts_with(std::path::Path::new(path.as_str()))
            })
            .cloned()
            .collect();
        regions.push(PathRegion {
            path: path.clone(),
            carved_out_by,
            outside_all_roots: false,
        });
    }

    match OUTSIDE_CANDIDATES.iter().find(|candidate| {
        deciding_root(before, candidate).is_none() && deciding_root(after, candidate).is_none()
    }) {
        Some(candidate) => regions.push(PathRegion {
            path: (*candidate).to_string(),
            carved_out_by: Vec::new(),
            outside_all_roots: true,
        }),
        None => plan.outside_region_unrepresentable = true,
    }

    for region in &regions {
        for permission in Permission::ALL {
            let (before_verdict, before_root) = verdict(before, permission, &region.path);
            let (after_verdict, after_root) = verdict(after, permission, &region.path);
            if before_verdict == after_verdict {
                continue;
            }
            let change = PermissionChange {
                region: region.clone(),
                permission,
                before: before_verdict,
                after: after_verdict,
                before_root,
                after_root,
            };
            if after_verdict == Verdict::Allowed {
                plan.newly_allowed.push(change);
            } else {
                plan.newly_denied.push(change);
            }
        }
    }

    // Caller allowlists. Losing one is the case worth naming: it does not restrict a caller,
    // it removes the restriction, and reading it as a tightening is the obvious mistake.
    let before_lists = caller_allowlists(before);
    let after_lists = caller_allowlists(after);
    let callers: BTreeSet<&String> = before_lists.keys().chain(after_lists.keys()).collect();
    for caller in callers {
        let before_tools = before_lists.get(caller);
        let after_tools = after_lists.get(caller);
        let (note, newly_allowed_tools, newly_denied_tools) = match (before_tools, after_tools) {
            (Some(b), Some(a)) => (
                None,
                a.difference(b).cloned().collect::<Vec<_>>(),
                b.difference(a).cloned().collect::<Vec<_>>(),
            ),
            (None, Some(a)) => (
                Some(format!(
                    "now restricted to an allowlist of {} tools, and denied every other tool \
                     including tools added later",
                    a.len()
                )),
                Vec::new(),
                Vec::new(),
            ),
            (Some(b), None) => (
                Some(format!(
                    "allowlist removed, so this caller is no longer restricted to its {} \
                     previous tools and reaches whatever the rest of the policy allows",
                    b.len()
                )),
                Vec::new(),
                Vec::new(),
            ),
            (None, None) => (None, Vec::new(), Vec::new()),
        };
        if note.is_none() && newly_allowed_tools.is_empty() && newly_denied_tools.is_empty() {
            continue;
        }
        plan.caller_tool_changes.push(CallerToolChange {
            caller: caller.clone(),
            newly_allowed_tools,
            newly_denied_tools,
            note,
        });
    }

    // Who can reach the listener at all. No per-path verdict captures this, and getting it
    // wrong is how a service ends up published without authentication.
    if before.mcp_require_client_auth != after.mcp_require_client_auth {
        plan.reachability_changes.push(ReachabilityChange {
            summary: if after.mcp_require_client_auth {
                "MCP client authentication is now required; a client with no configured \
                 credential can no longer call anything"
                    .to_string()
            } else {
                "MCP client authentication is no longer required; any caller that can reach \
                 the listener is admitted"
                    .to_string()
            },
        });
    }
    let before_clients: BTreeSet<&str> = before
        .mcp_clients
        .iter()
        .map(|c| c.agent_id.as_str())
        .collect();
    let after_clients: BTreeSet<&str> = after
        .mcp_clients
        .iter()
        .map(|c| c.agent_id.as_str())
        .collect();
    for added in after_clients.difference(&before_clients) {
        plan.reachability_changes.push(ReachabilityChange {
            summary: format!("client credential added for agent '{added}'"),
        });
    }
    for removed in before_clients.difference(&after_clients) {
        plan.reachability_changes.push(ReachabilityChange {
            summary: format!(
                "client credential removed for agent '{removed}'; calls presenting that token \
                 are refused"
            ),
        });
    }

    // A rename is invisible in the verdict analysis by construction, and it is not nothing.
    let root_ids = |policy: &PolicyConfig| -> BTreeMap<String, String> {
        policy
            .roots
            .iter()
            .map(|r| {
                (
                    canonicalize_for_policy(&r.path).display().to_string(),
                    r.id.clone(),
                )
            })
            .collect()
    };
    let before_ids = root_ids(before);
    let after_ids = root_ids(after);
    for (path, before_id) in &before_ids {
        if let Some(after_id) = after_ids.get(path)
            && after_id != before_id
        {
            plan.root_identity_changes.push(RootIdentityChange {
                path: path.clone(),
                before_id: before_id.clone(),
                after_id: after_id.clone(),
            });
        }
    }

    // Everything else that differs. Complete rather than curated: a hand-picked list of fields
    // to compare goes stale the moment a field is added, and going stale silently is the exact
    // failure this planner exists to prevent.
    if let (Ok(before_value), Ok(after_value)) =
        (serde_json::to_value(before), serde_json::to_value(after))
        && let (Some(before_map), Some(after_map)) =
            (before_value.as_object(), after_value.as_object())
    {
        let accounted: BTreeSet<&str> = [
            "roots",
            "abac_rules",
            "mcp_clients",
            "mcp_require_client_auth",
        ]
        .into_iter()
        .collect();
        let keys: BTreeSet<&String> = before_map.keys().chain(after_map.keys()).collect();
        for key in keys {
            if accounted.contains(key.as_str()) {
                continue;
            }
            if before_map.get(key) != after_map.get(key) {
                plan.changed_without_verdict_effect.push(key.clone());
            }
        }
        // A root edit that changes no verdict is worth saying out loud, because it is the case
        // a textual diff shouts about: a rename, or a re-spelling that canonicalizes the same.
        if before_map.get("roots") != after_map.get("roots")
            && plan.newly_allowed.is_empty()
            && plan.newly_denied.is_empty()
        {
            plan.changed_without_verdict_effect
                .push("roots".to_string());
        }
    }

    plan
}

#[cfg(test)]
mod tests {
    // Tests assert on shapes, plans and verdicts, where expect/indexing ARE
    // the assertion: a panic in a test is the failure signal, so the
    // production rationale for the workspace denies does not apply.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;
    use crate::RootRule;
    use std::path::PathBuf;

    fn policy_with(roots: Vec<RootRule>) -> PolicyConfig {
        PolicyConfig {
            roots,
            ..PolicyConfig::default()
        }
    }

    fn root(id: &str, path: &str, permissions: &[Permission]) -> RootRule {
        RootRule {
            id: id.into(),
            path: PathBuf::from(path),
            permissions: permissions.iter().copied().collect(),
        }
    }

    #[test]
    fn adding_a_permission_to_a_root_is_reported_as_newly_allowed() {
        let before = policy_with(vec![root("dev", r"C:\dev", &[Permission::Read])]);
        let after = policy_with(vec![root(
            "dev",
            r"C:\dev",
            &[Permission::Read, Permission::Execute],
        )]);
        let plan = plan(&before, &after);
        assert_eq!(plan.newly_allowed.len(), 1, "{}", plan.render());
        assert_eq!(plan.newly_allowed[0].permission, Permission::Execute);
        assert!(plan.newly_denied.is_empty());
        assert!(!plan.is_verdict_neutral());
    }

    #[test]
    fn renaming_a_root_changes_no_verdict_and_says_so() {
        // The case a textual diff gets loudest about and a verdict planner should shrug at.
        let before = policy_with(vec![root("dev", r"C:\dev", &[Permission::Read])]);
        let after = policy_with(vec![root("workspace", r"C:\dev", &[Permission::Read])]);
        let plan = plan(&before, &after);
        assert!(plan.is_verdict_neutral(), "{}", plan.render());
        assert!(
            plan.changed_without_verdict_effect
                .contains(&"roots".to_string()),
            "a rename is still a change and must not read as nothing: {plan:?}"
        );
        assert!(plan.render().contains("No call changes verdict"));
    }

    #[test]
    fn a_rename_is_reported_even_when_it_hides_among_real_verdict_changes() {
        // The rename test above covers a rename on its own. This is the case that actually
        // happens: a rename lands in the same edit as a widening and a narrowing, and the
        // verdict analysis is silent about it by construction, because no verdict moves. It
        // still changes what every audit record written afterwards says the root was called.
        let before = policy_with(vec![
            root("dev", r"C:\dev", &[Permission::Read]),
            root("llm", r"D:\llm", &[Permission::Read]),
        ]);
        let after = policy_with(vec![
            root("dev", r"C:\dev", &[Permission::Read, Permission::Execute]),
            root("llm-models", r"D:\llm", &[Permission::Read]),
        ]);
        let plan = plan(&before, &after);
        assert_eq!(
            plan.newly_allowed.len(),
            1,
            "the widening is still reported"
        );
        assert_eq!(plan.root_identity_changes.len(), 1, "{}", plan.render());
        let change = &plan.root_identity_changes[0];
        assert_eq!(change.before_id, "llm");
        assert_eq!(change.after_id, "llm-models");
        assert!(plan.render().contains("Root renamed"));
        // A rename alone is not a verdict change, so it must not make the plan look unsafe.
        let rename_only = super::plan(
            &policy_with(vec![root("llm", r"D:\llm", &[Permission::Read])]),
            &policy_with(vec![root("llm-models", r"D:\llm", &[Permission::Read])]),
        );
        assert!(rename_only.is_verdict_neutral());
        assert_eq!(rename_only.root_identity_changes.len(), 1);
    }

    #[test]
    fn a_narrower_root_added_under_a_broad_one_revokes_the_subtree() {
        // The dangerous edit. One added line, and every permission on that subtree is gone,
        // because the most specific root wins and its permissions are authoritative. A reader
        // scanning a textual diff sees an addition and reads it as a widening.
        // Portable fixtures: on Unix, a backslashed C:\ path is one opaque
        // component and the narrow root would not nest under the broad one,
        // so the carve under test would never occur. The base only ever ran
        // this on Windows; the 3-OS matrix runs it everywhere. Assertions
        // are unchanged.
        let (broad, narrow) = if cfg!(windows) {
            (r"C:\dev".to_string(), r"C:\dev\secrets".to_string())
        } else {
            (
                "/dev-fixture".to_string(),
                "/dev-fixture/secrets".to_string(),
            )
        };
        let before = policy_with(vec![root(
            "dev",
            &broad,
            &[Permission::Read, Permission::Write, Permission::Execute],
        )]);
        let after = policy_with(vec![
            root(
                "dev",
                &broad,
                &[Permission::Read, Permission::Write, Permission::Execute],
            ),
            root("secrets", &narrow, &[Permission::List]),
        ]);
        let plan = plan(&before, &after);
        assert!(
            plan.newly_allowed
                .iter()
                .any(|c| c.permission == Permission::List
                    && c.region.path.to_lowercase().contains("secrets"))
        );
        let denied_under_secrets: Vec<_> = plan
            .newly_denied
            .iter()
            .filter(|c| c.region.path.to_lowercase().contains("secrets"))
            .map(|c| c.permission)
            .collect();
        assert!(
            denied_under_secrets.contains(&Permission::Read)
                && denied_under_secrets.contains(&Permission::Write)
                && denied_under_secrets.contains(&Permission::Execute),
            "the narrow root revokes what the broad one granted: {}",
            plan.render()
        );
        // And the parent region keeps what it had, so the report is not over-broad either.
        assert!(
            !plan
                .newly_denied
                .iter()
                .any(|c| !c.region.path.to_lowercase().contains("secrets")),
            "nothing outside the new root changed: {}",
            plan.render()
        );
    }

    #[test]
    fn the_parent_region_names_the_root_that_carves_it() {
        // Same portability note as the carve test above; assertions unchanged.
        let (broad, narrow) = if cfg!(windows) {
            (r"C:\dev".to_string(), r"C:\dev\secrets".to_string())
        } else {
            (
                "/dev-fixture".to_string(),
                "/dev-fixture/secrets".to_string(),
            )
        };
        let after = policy_with(vec![
            root("dev", &broad, &[Permission::Read]),
            root("secrets", &narrow, &[Permission::Read]),
        ]);
        let plan = plan(&policy_with(vec![]), &after);
        let parent = plan
            .newly_allowed
            .iter()
            .find(|c| !c.region.path.to_lowercase().contains("secrets"))
            .expect("a change on the parent region");
        assert!(
            !parent.region.carved_out_by.is_empty(),
            "the parent region must not claim the whole subtree it no longer governs"
        );
        assert!(parent.region.describe().contains("except under"));
    }

    #[test]
    fn removing_a_root_denies_everything_it_granted() {
        let before = policy_with(vec![root("dev", r"C:\dev", &[Permission::Read])]);
        let after = policy_with(vec![]);
        let plan = plan(&before, &after);
        assert_eq!(plan.newly_denied.len(), 1, "{}", plan.render());
        assert_eq!(plan.newly_denied[0].before_root.as_deref(), Some("dev"));
        assert_eq!(plan.newly_denied[0].after_root, None);
    }

    #[test]
    fn the_outside_region_is_evaluated_and_never_changes_on_its_own() {
        let before = policy_with(vec![root("dev", r"C:\dev", &[Permission::Read])]);
        let after = policy_with(vec![root("dev", r"C:\dev", &[Permission::Write])]);
        let plan = plan(&before, &after);
        assert!(!plan.outside_region_unrepresentable);
        assert!(
            !plan
                .newly_allowed
                .iter()
                .chain(plan.newly_denied.iter())
                .any(|c| c.region.outside_all_roots),
            "paths under no root are denied by both policies, always"
        );
    }

    #[test]
    fn losing_an_allowlist_reads_as_unrestricting_rather_than_tightening() {
        let restricted = PolicyConfig {
            abac_rules: vec![crate::AbacRule::CallerToolAllowlist {
                caller: "build-agent".into(),
                allowed_tools: vec!["list_roots".into(), "read_file_window_report".into()],
                action: crate::AbacAction::Deny,
            }],
            ..PolicyConfig::default()
        };
        let unrestricted = PolicyConfig::default();

        let opened = plan(&restricted, &unrestricted);
        let change = opened
            .caller_tool_changes
            .iter()
            .find(|c| c.caller == "build-agent")
            .expect("the caller change");
        let note = change.note.as_deref().expect("a note");
        assert!(
            note.contains("no longer restricted"),
            "removing an allowlist widens: {note}"
        );

        let closed = plan(&unrestricted, &restricted);
        let change = closed
            .caller_tool_changes
            .iter()
            .find(|c| c.caller == "build-agent")
            .expect("the caller change");
        assert!(
            change
                .note
                .as_deref()
                .expect("a note")
                .contains("denied every other tool"),
            "adding one narrows, including for tools that do not exist yet"
        );
    }

    #[test]
    fn adding_a_tool_to_an_existing_allowlist_names_that_tool() {
        let rule = |tools: Vec<&str>| crate::AbacRule::CallerToolAllowlist {
            caller: "build-agent".into(),
            allowed_tools: tools.into_iter().map(String::from).collect(),
            action: crate::AbacAction::Deny,
        };
        let before = PolicyConfig {
            abac_rules: vec![rule(vec!["list_roots"])],
            ..PolicyConfig::default()
        };
        let after = PolicyConfig {
            abac_rules: vec![rule(vec!["list_roots", "execute"])],
            ..PolicyConfig::default()
        };
        let plan = plan(&before, &after);
        let change = &plan.caller_tool_changes[0];
        assert_eq!(change.newly_allowed_tools, vec!["execute".to_string()]);
        assert!(change.newly_denied_tools.is_empty());
    }

    #[test]
    fn turning_client_auth_off_is_a_reachability_change_not_a_permission_one() {
        let before = PolicyConfig {
            mcp_require_client_auth: true,
            ..PolicyConfig::default()
        };
        let after = PolicyConfig {
            mcp_require_client_auth: false,
            ..PolicyConfig::default()
        };
        let plan = plan(&before, &after);
        assert!(plan.newly_allowed.is_empty() && plan.newly_denied.is_empty());
        assert_eq!(plan.reachability_changes.len(), 1);
        assert!(
            plan.reachability_changes[0]
                .summary
                .contains("no longer required")
        );
        assert!(!plan.is_verdict_neutral());
    }

    #[test]
    fn an_identical_policy_plans_to_nothing() {
        let policy = policy_with(vec![root(
            "dev",
            r"C:\dev",
            &[Permission::Read, Permission::Execute],
        )]);
        let plan = plan(&policy, &policy);
        assert!(plan.is_verdict_neutral());
        assert!(
            plan.changed_without_verdict_effect.is_empty(),
            "nothing differs at all, so nothing should be listed: {plan:?}"
        );
        assert_eq!(plan.render(), "No call changes verdict.\n");
    }

    #[test]
    fn a_change_that_touches_no_verdict_is_still_reported_as_a_change() {
        let before = PolicyConfig::default();
        let after = PolicyConfig {
            audit_path: PathBuf::from(r"C:\elsewhere\audit.jsonl"),
            ..PolicyConfig::default()
        };
        let plan = plan(&before, &after);
        assert!(plan.is_verdict_neutral());
        assert!(
            plan.changed_without_verdict_effect
                .contains(&"audit_path".to_string()),
            "{plan:?}"
        );
    }

    #[test]
    fn the_plan_is_deterministic_over_declaration_order() {
        let a = policy_with(vec![
            root("dev", r"C:\dev", &[Permission::Read]),
            root("proj", r"D:\proj", &[Permission::Read]),
        ]);
        let b = policy_with(vec![
            root("proj", r"D:\proj", &[Permission::Read]),
            root("dev", r"C:\dev", &[Permission::Read]),
        ]);
        let empty = policy_with(vec![]);
        assert_eq!(plan(&empty, &a), plan(&empty, &b));
    }
}
