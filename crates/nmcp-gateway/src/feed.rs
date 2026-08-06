//! Catalog feed snapshots and the diff an operator confirms before applying one.
//!
//! This is how catalog entries arrive: a snapshot fetched or filed from somewhere becomes a
//! diff against the current catalog, the diff is shown, and an apply confirms the digest of
//! the diff that was shown. The module is the unwired half the base's own gateway audit
//! pointed at ("the catalog is compiled in; feed.rs exists to fix this"), and in core it is
//! the only source of entries at all: [`crate::default_gateway_catalog`] ships none.

use crate::{CatalogServer, GatewayCatalog};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// One fetched catalog feed: where it came from, when, and what it carries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogFeedSnapshot {
    /// Where the snapshot came from, for provenance.
    pub source: String,
    /// When it was fetched, as the fetcher recorded it.
    pub fetched_at: String,
    /// The feed's own version marker, when it carries one.
    #[serde(default)]
    pub version: Option<String>,
    /// The entries the feed describes.
    pub servers: Vec<CatalogServer>,
}

/// What applying a snapshot would change, entry by entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogFeedDiff {
    /// The snapshot's provenance, carried through.
    pub source: String,
    /// The snapshot's fetch time, carried through.
    pub fetched_at: String,
    /// The snapshot's version marker, carried through.
    #[serde(default)]
    pub version: Option<String>,
    /// Counts per bucket, plus totals.
    pub summary: BTreeMap<String, usize>,
    /// Entries the snapshot has and the current catalog does not.
    pub added: Vec<CatalogFeedDiffEntry>,
    /// Entries the current catalog has and the snapshot does not.
    pub removed: Vec<CatalogFeedDiffEntry>,
    /// Entries present in both whose fields differ, with the fields named.
    pub changed: Vec<CatalogFeedDiffEntry>,
    /// Entries present in both and identical.
    pub unchanged: Vec<CatalogFeedDiffEntry>,
}

/// One entry of a [`CatalogFeedDiff`], reduced to what a review surface shows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogFeedDiffEntry {
    /// The entry's id.
    pub id: String,
    /// The entry's display name.
    pub display_name: String,
    /// The entry's publisher.
    pub publisher: String,
    /// The entry's risk tier, Debug-rendered.
    pub risk_tier: String,
    /// The entry's default mode, Debug-rendered.
    pub default_mode: String,
    /// The entry's profile tags.
    pub profiles: Vec<String>,
    /// For a changed entry, which fields moved. Empty otherwise.
    #[serde(default)]
    pub changed_fields: Vec<String>,
}

/// Diff a snapshot against the current catalog.
///
/// Both sides are validated first, so a malformed feed is refused before any of it is
/// summarized as if it were applicable.
///
/// # Errors
///
/// The validation message from whichever side failed.
pub fn diff_catalog_feed(
    current: &GatewayCatalog,
    snapshot: CatalogFeedSnapshot,
) -> Result<CatalogFeedDiff, String> {
    current.validate()?;
    validate_snapshot(&snapshot)?;

    let current_by_id: BTreeMap<_, _> = current
        .servers
        .iter()
        .map(|server| (server.id.clone(), server))
        .collect();
    let snapshot_by_id: BTreeMap<_, _> = snapshot
        .servers
        .iter()
        .map(|server| (server.id.clone(), server))
        .collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut unchanged = Vec::new();

    for (id, incoming) in &snapshot_by_id {
        match current_by_id.get(id) {
            None => added.push(entry(incoming, Vec::new())),
            Some(existing) => {
                let changed_fields = changed_fields(existing, incoming);
                if changed_fields.is_empty() {
                    unchanged.push(entry(incoming, Vec::new()));
                } else {
                    changed.push(entry(incoming, changed_fields));
                }
            }
        }
    }

    for (id, existing) in &current_by_id {
        if !snapshot_by_id.contains_key(id) {
            removed.push(entry(existing, Vec::new()));
        }
    }

    let mut summary = BTreeMap::new();
    summary.insert("added".to_string(), added.len());
    summary.insert("removed".to_string(), removed.len());
    summary.insert("changed".to_string(), changed.len());
    summary.insert("unchanged".to_string(), unchanged.len());
    summary.insert("snapshot_total".to_string(), snapshot.servers.len());
    summary.insert("current_total".to_string(), current.servers.len());

    Ok(CatalogFeedDiff {
        source: snapshot.source,
        fetched_at: snapshot.fetched_at,
        version: snapshot.version,
        summary,
        added,
        removed,
        changed,
        unchanged,
    })
}

/// The set of ids a snapshot carries, sorted and deduplicated.
#[must_use]
pub fn snapshot_ids(snapshot: &CatalogFeedSnapshot) -> BTreeSet<String> {
    snapshot
        .servers
        .iter()
        .map(|server| server.id.clone())
        .collect()
}

/// The catalog a snapshot describes.
///
/// Shared between validation and installation on purpose. Two functions that each built a
/// catalog from a snapshot would be two answers to what a snapshot means, and the one that
/// drifted would be whichever was not the one under test.
#[must_use]
pub fn catalog_from_snapshot(snapshot: &CatalogFeedSnapshot) -> GatewayCatalog {
    GatewayCatalog {
        schema_version: 1,
        generated_by: format!("catalog feed snapshot: {}", snapshot.source),
        // The admission posture belongs to this build, not to whoever published the feed. A
        // feed supplies entries to browse; what it takes to turn one into a running upstream
        // is not a thing a third party gets to restate.
        default_policy: crate::default_gateway_catalog().default_policy,
        servers: snapshot.servers.clone(),
    }
}

/// A digest over a diff, so an apply can name which diff it is confirming.
///
/// The problem this solves is staleness rather than tampering. An operator who previews a
/// feed, reads what would change, and comes back to confirm should not silently land a
/// different change than the one they read; a catalog that moved underneath them moves this
/// value, and the confirmation stops matching.
///
/// Deterministic because every collection in a diff is ordered: the entry lists are built by
/// walking a `BTreeMap`, and `summary` is one.
#[must_use]
pub fn diff_digest(diff: &CatalogFeedDiff) -> String {
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(diff).unwrap_or_default());
    hex::encode(hasher.finalize())
}

/// Validate a snapshot's own metadata plus the catalog it would produce.
///
/// # Errors
///
/// A message naming the empty metadata field, or the catalog validation failure.
pub fn validate_snapshot(snapshot: &CatalogFeedSnapshot) -> Result<(), String> {
    if snapshot.source.trim().is_empty() {
        return Err("catalog feed snapshot source must not be empty".to_string());
    }
    if snapshot.fetched_at.trim().is_empty() {
        return Err("catalog feed snapshot fetched_at must not be empty".to_string());
    }

    catalog_from_snapshot(snapshot).validate()
}

fn changed_fields(current: &CatalogServer, incoming: &CatalogServer) -> Vec<String> {
    let mut out = Vec::new();
    if current.display_name != incoming.display_name {
        out.push("display_name".to_string());
    }
    if current.publisher != incoming.publisher {
        out.push("publisher".to_string());
    }
    if current.source_type != incoming.source_type {
        out.push("source_type".to_string());
    }
    if current.source_urls != incoming.source_urls {
        out.push("source_urls".to_string());
    }
    if current.capability_domains != incoming.capability_domains {
        out.push("capability_domains".to_string());
    }
    if current.risk_tier != incoming.risk_tier {
        out.push("risk_tier".to_string());
    }
    if current.default_mode != incoming.default_mode {
        out.push("default_mode".to_string());
    }
    if current.default_enabled != incoming.default_enabled {
        out.push("default_enabled".to_string());
    }
    if current.transports != incoming.transports {
        out.push("transports".to_string());
    }
    if current.required_secrets != incoming.required_secrets {
        out.push("required_secrets".to_string());
    }
    if current.profiles != incoming.profiles {
        out.push("profiles".to_string());
    }
    if current.audit_required != incoming.audit_required {
        out.push("audit_required".to_string());
    }
    if current.notes != incoming.notes {
        out.push("notes".to_string());
    }
    out
}

fn entry(server: &CatalogServer, changed_fields: Vec<String>) -> CatalogFeedDiffEntry {
    CatalogFeedDiffEntry {
        id: server.id.clone(),
        display_name: server.display_name.clone(),
        publisher: server.publisher.clone(),
        risk_tier: format!("{:?}", server.risk_tier),
        default_mode: format!("{:?}", server.default_mode),
        profiles: server.profiles.clone(),
        changed_fields,
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
    use crate::{
        CatalogDefaultMode, CatalogRiskTier, CatalogSourceType, CatalogTransport,
        default_gateway_catalog,
    };

    fn synthetic_server(id: &str) -> CatalogServer {
        CatalogServer {
            id: id.to_string(),
            display_name: "Synthetic MCP Server".to_string(),
            publisher: "example".to_string(),
            source_type: CatalogSourceType::ThirdParty,
            source_urls: vec!["https://example.invalid/mcp".to_string()],
            capability_domains: vec!["example".to_string()],
            risk_tier: CatalogRiskTier::Standard,
            default_mode: CatalogDefaultMode::MetadataOnly,
            default_enabled: false,
            transports: vec![CatalogTransport::Unknown],
            required_secrets: vec![],
            profiles: vec!["quarantine".to_string()],
            audit_required: true,
            notes: "Synthetic test entry.".to_string(),
        }
    }

    /// The current catalog here carries entries as if a feed had already been applied,
    /// because the empty default has nothing to remove or change against.
    fn current_with(ids: &[&str]) -> GatewayCatalog {
        let mut catalog = default_gateway_catalog();
        catalog.servers = ids.iter().map(|id| synthetic_server(id)).collect();
        catalog
    }

    #[test]
    fn feed_diff_reports_added_removed_changed_and_unchanged() {
        let current = current_with(&["kept", "dropped", "edited"]);
        let mut servers = current.servers.clone();
        servers.retain(|server| server.id != "dropped");
        servers
            .iter_mut()
            .find(|server| server.id == "edited")
            .unwrap()
            .publisher = "changed-publisher".to_string();
        servers.push(synthetic_server("new-server"));

        let diff = diff_catalog_feed(
            &current,
            CatalogFeedSnapshot {
                source: "unit-test".to_string(),
                fetched_at: "2026-08-06T00:00:00Z".to_string(),
                version: Some("1".to_string()),
                servers,
            },
        )
        .unwrap();

        assert_eq!(diff.summary["added"], 1);
        assert_eq!(diff.summary["removed"], 1);
        assert_eq!(diff.summary["changed"], 1);
        assert_eq!(diff.summary["unchanged"], 1);
        assert!(diff.added.iter().any(|entry| entry.id == "new-server"));
        assert!(diff.removed.iter().any(|entry| entry.id == "dropped"));
        let changed = diff
            .changed
            .iter()
            .find(|entry| entry.id == "edited")
            .unwrap();
        assert_eq!(changed.changed_fields, vec!["publisher".to_string()]);
    }

    #[test]
    fn feed_diff_rejects_invalid_snapshot_metadata() {
        let err = diff_catalog_feed(
            &default_gateway_catalog(),
            CatalogFeedSnapshot {
                source: String::new(),
                fetched_at: "2026-08-06T00:00:00Z".to_string(),
                version: None,
                servers: vec![synthetic_server("new-server")],
            },
        )
        .unwrap_err();

        assert!(err.contains("source"));
    }

    #[test]
    fn snapshot_ids_are_unique_and_sorted() {
        let snapshot = CatalogFeedSnapshot {
            source: "unit-test".to_string(),
            fetched_at: "2026-08-06T00:00:00Z".to_string(),
            version: None,
            servers: vec![synthetic_server("b"), synthetic_server("a")],
        };

        let ids: Vec<_> = snapshot_ids(&snapshot).into_iter().collect();
        assert_eq!(ids, vec!["a".to_string(), "b".to_string()]);
    }

    /// The posture line survives a feed: the snapshot's entries land, and what admission
    /// takes stays this build's sentence rather than the publisher's.
    #[test]
    fn a_snapshot_supplies_entries_and_never_the_admission_posture() {
        let snapshot = CatalogFeedSnapshot {
            source: "unit-test".to_string(),
            fetched_at: "2026-08-06T00:00:00Z".to_string(),
            version: None,
            servers: vec![synthetic_server("fed")],
        };
        let installed = catalog_from_snapshot(&snapshot);
        assert_eq!(installed.servers.len(), 1);
        assert_eq!(
            installed.default_policy,
            default_gateway_catalog().default_policy
        );
        let digest_one =
            diff_digest(&diff_catalog_feed(&default_gateway_catalog(), snapshot.clone()).unwrap());
        let digest_two =
            diff_digest(&diff_catalog_feed(&default_gateway_catalog(), snapshot).unwrap());
        assert_eq!(digest_one, digest_two, "the digest must be deterministic");
    }
}
