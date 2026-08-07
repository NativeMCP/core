//! The gateway catalog as a thing on disk (G6-7).
//!
//! Before this, the catalog was a function: `default_gateway_catalog()` built 32 entries from
//! literals and every request rebuilt it. That is fine for a starting point and useless as a
//! catalog, because a catalog is something that grows. Docker ships 314 entries against this
//! one's 32, and `feed.rs` already implemented snapshot and diff with nothing feeding it.
//!
//! # The base's first property does not hold here, and the difference is deliberate
//!
//! The base states two properties. The first is that the shipped default stays in the binary, so
//! a fresh install has a curated starting point and an operator who deletes the snapshot gets it
//! back. Thirty-two entries, built from literals, to make that true.
//!
//! **Core's [`nmcp_gateway::default_gateway_catalog`] ships none**, and that is a decision taken
//! two waves before this port, recorded on the function: empty is the design, because a
//! compiled-in population is the defect DEC-007's audit names and the feed exists to fix, and
//! because a public tree ships no vendor's name as code.
//!
//! Both are right in their own tree. Carrying the base's sentence across would ship a promise
//! this code cannot keep, in the one file whose whole subject is telling an operator what the
//! catalog in force actually is.
//!
//! **What core keeps from that property is the posture, not the population.** The default carries
//! the admission sentence, which `catalog_from_snapshot` reuses so a feed publisher cannot
//! restate what admission takes. That is the part worth having in the binary.
//!
//! # A malformed feed keeps the prior catalog and says so
//!
//! Same fail-safe as the policy watcher, with the same obligation G4-25 established: a rejection
//! an operator can only find in a log file is a rejection they will not find. This one surfaces
//! in the doctor and in the metrics.
//!
//! **The consequence of the first difference runs the opposite way from how it looks.** In the
//! base a rejected feed falls back to thirty-two curated entries and the operator has a stale
//! browse list. Here it falls back to nothing and they have an empty one, which reads exactly
//! like a feed nobody has installed yet. So the surfacing matters **more** in this tree, not
//! less: it is the only thing that distinguishes "no feed" from "a feed this server refused".
//!
//! **It is still not a readiness failure**, and that asymmetry is the part a later reader is most
//! likely to correct by accident. Readiness fails on a rejected policy because policy governs
//! what runs. A catalog is a list of software an operator could install, and stopping a deploy
//! over a browse list would be the wrong trade whether that list is stale or empty.

use nmcp_gateway::{
    CatalogFeedSnapshot, GatewayCatalog, catalog_from_snapshot, default_gateway_catalog,
};
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// The file name the catalog snapshot lives under, beside the policy file.
pub const CATALOG_FEED_FILE: &str = "catalog-feed.json";

/// A feed that was read and refused, with the prior catalog left in force.
#[derive(Clone)]
pub struct CatalogRejection {
    /// What was wrong, in one sentence an operator can act on.
    pub error: String,
    /// When the feed was refused.
    pub at_unix_ms: u64,
    /// The feed file that was refused, so the operator knows which one to fix.
    pub path: String,
}

/// The catalog in force, and where it came from.
#[derive(Clone)]
pub struct CatalogStore {
    catalog: Arc<RwLock<GatewayCatalog>>,
    source: Arc<RwLock<String>>,
    rejection: Arc<RwLock<Option<CatalogRejection>>>,
}

impl Default for CatalogStore {
    fn default() -> Self {
        Self {
            catalog: Arc::new(RwLock::new(default_gateway_catalog())),
            source: Arc::new(RwLock::new("shipped default".to_string())),
            rejection: Arc::new(RwLock::new(None)),
        }
    }
}

impl CatalogStore {
    /// Load the catalog, falling back to the shipped default and recording why.
    ///
    /// An absent file is not a rejection: it is the ordinary state of a fresh install, and
    /// reporting it as a fault would train an operator to ignore the indicator that matters.
    pub fn load(path: Option<&Path>) -> Self {
        let store = Self::default();
        let Some(path) = path else {
            return store;
        };
        if !path.exists() {
            return store;
        }
        match read_snapshot(path) {
            Ok(snapshot) => {
                let described = format!("{} ({})", snapshot.source, path.display());
                *store.catalog.write() = catalog_from_snapshot(&snapshot);
                *store.source.write() = described;
            }
            Err(error) => {
                tracing::warn!(
                    "gateway catalog feed at {} was rejected; the shipped default is in force: {error}",
                    path.display()
                );
                store.record_rejection(path, error);
            }
        }
        store
    }

    /// The catalog every request should be answering from.
    #[must_use]
    pub fn catalog(&self) -> GatewayCatalog {
        self.catalog.read().clone()
    }

    /// Where the catalog in force came from, for an operator reading a summary payload.
    #[must_use]
    pub fn source(&self) -> String {
        self.source.read().clone()
    }

    /// The outstanding rejection, if the catalog in force is not the feed on disk.
    #[must_use]
    pub fn rejection(&self) -> Option<CatalogRejection> {
        self.rejection.read().clone()
    }

    /// Install a snapshot that has already been validated and persisted.
    pub fn install(&self, snapshot: &CatalogFeedSnapshot, described: String) {
        *self.catalog.write() = catalog_from_snapshot(snapshot);
        *self.source.write() = described;
        *self.rejection.write() = None;
    }

    fn record_rejection(&self, path: &Path, error: String) {
        // A clock this process cannot read is not a reason to lose the rejection. Zero is a
        // visibly wrong timestamp on a record whose value is the error string beside it, which
        // is the right trade: the alternative is dropping the only notice an operator gets.
        let at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            });
        *self.rejection.write() = Some(CatalogRejection {
            error,
            at_unix_ms,
            path: path.display().to_string(),
        });
    }
}

/// Where the snapshot lives: beside the policy file, so it follows `--config` rather than
/// being a second location an operator has to know about.
#[must_use]
pub fn catalog_feed_path(policy_path: Option<&Path>) -> Option<PathBuf> {
    policy_path
        .and_then(|p| p.parent())
        .map(|dir| dir.join(CATALOG_FEED_FILE))
}

/// Read and validate a snapshot from disk.
///
/// # Errors
///
/// One string per failure mode, and a string rather than a typed error on purpose: this value
/// goes straight into [`CatalogRejection::error`], which an operator reads in the doctor. The
/// three modes are a file that cannot be read, JSON that does not parse, and a snapshot that
/// parses into a catalog the gateway refuses. Each one already says what to fix, and wrapping
/// them in a type would mean rendering them back into these same sentences at the surface.
pub fn read_snapshot(path: &Path) -> Result<CatalogFeedSnapshot, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read error: {e}"))?;
    let snapshot: CatalogFeedSnapshot =
        serde_json::from_str(&text).map_err(|e| format!("parse error: {e}"))?;
    nmcp_gateway::validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    // As the other test modules in this crate: a panic here is the assertion.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mcp-catalog-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn snapshot_json(id: &str) -> String {
        format!(
            r#"{{
  "source": "test feed",
  "fetched_at": "2026-08-02T00:00:00Z",
  "servers": [
    {{
      "id": "{id}",
      "display_name": "Test Server",
      "publisher": "test",
      "source_type": "community",
      "source_urls": [],
      "capability_domains": ["test"],
      "risk_tier": "low",
      "default_mode": "disabled",
      "default_enabled": false,
      "transports": ["stdio"],
      "required_secrets": [],
      "profiles": ["developer"],
      "audit_required": true,
      "notes": ""
    }}
  ]
}}"#
        )
    }

    #[test]
    fn no_file_means_the_shipped_default_with_nothing_reported_as_wrong() {
        let dir = temp_dir("absent");
        let store = CatalogStore::load(Some(&dir.join(CATALOG_FEED_FILE)));

        // The base asserts twenty-five or more entries here. That assertion is the module
        // doc's first property, and it does not hold in this tree: core's
        // `default_gateway_catalog` ships the admission posture and no entries, deliberately.
        // Corrected to what is actually true, and to the part that still matters: an absent
        // feed is not a rejection.
        assert!(
            store.catalog().servers.is_empty(),
            "this build ships no entries; a populated default would be the DEC-007 defect the \
             feed exists to fix"
        );
        assert!(
            !store.catalog().default_policy.is_empty(),
            "the posture is what the shipped default carries, and it is the part \
             `catalog_from_snapshot` reuses so a feed publisher cannot restate it"
        );
        assert!(
            store.rejection().is_none(),
            "a fresh install is not a fault, and reporting it as one trains operators to ignore the indicator"
        );
        assert_eq!(store.source(), "shipped default");
    }

    #[test]
    fn a_snapshot_on_disk_replaces_the_compiled_in_catalog() {
        let dir = temp_dir("present");
        let path = dir.join(CATALOG_FEED_FILE);
        std::fs::write(&path, snapshot_json("from-the-feed")).expect("write feed");

        let store = CatalogStore::load(Some(&path));
        let catalog = store.catalog();

        assert_eq!(catalog.servers.len(), 1);
        assert!(catalog.find("from-the-feed").is_some());
        assert!(store.rejection().is_none());
        assert!(store.source().contains("test feed"));
    }

    /// The fail-safe, and the half of it G4-25 exists to insist on: keeping the prior catalog
    /// is only half an answer if nothing says the file was refused.
    #[test]
    fn a_malformed_feed_keeps_the_prior_catalog_and_reports_why() {
        let dir = temp_dir("malformed");
        let path = dir.join(CATALOG_FEED_FILE);
        std::fs::write(&path, "{ not json at all").expect("write feed");

        let store = CatalogStore::load(Some(&path));

        // The base asserts the prior catalog survives with its entries intact. Here the prior
        // catalog is the shipped default, which has none, so what survives is the posture and
        // the fact that nothing from the refused file was applied. **The rejection carries the
        // whole signal in this tree**: an empty list reads exactly like a feed nobody installed,
        // and this is the only thing that tells the two apart.
        assert!(
            store.catalog().servers.is_empty(),
            "nothing from a refused feed may reach the catalog in force"
        );
        let rejection = store
            .rejection()
            .expect("a refused feed must be visible outside the log file");
        assert!(
            rejection.error.contains("parse error"),
            "{}",
            rejection.error
        );
        assert!(rejection.path.contains(CATALOG_FEED_FILE));
    }

    /// A feed that parses but describes an invalid catalog is refused on the same terms. This
    /// is the interesting case, because it is the one a hand-edited or half-migrated feed
    /// actually produces.
    #[test]
    fn a_feed_that_parses_into_an_invalid_catalog_is_refused_too() {
        let dir = temp_dir("invalid");
        let path = dir.join(CATALOG_FEED_FILE);
        // Two servers sharing an id: valid JSON, valid shape, not a valid catalog.
        let one = snapshot_json("duplicate");
        let doubled = one.replace(
            "\"servers\": [",
            "\"servers\": [\n    {\n      \"id\": \"duplicate\",\n      \"display_name\": \"First\",\n      \"publisher\": \"test\",\n      \"source_type\": \"community\",\n      \"source_urls\": [],\n      \"capability_domains\": [\"test\"],\n      \"risk_tier\": \"low\",\n      \"default_mode\": \"disabled\",\n      \"default_enabled\": false,\n      \"transports\": [\"stdio\"],\n      \"required_secrets\": [],\n      \"profiles\": [\"developer\"],\n      \"audit_required\": true,\n      \"notes\": \"\"\n    },",
        );
        std::fs::write(&path, doubled).expect("write feed");

        let store = CatalogStore::load(Some(&path));

        assert!(
            store.catalog().servers.is_empty(),
            "a feed refused at validation must not partially apply"
        );
        let rejection = store
            .rejection()
            .expect("an invalid catalog must be refused");
        assert!(
            rejection.error.contains("duplicate"),
            "the reason must name what is wrong with it: {}",
            rejection.error
        );
    }

    /// The feed follows `--config` rather than being a second location an operator must know.
    ///
    /// The base writes this with a literal Windows path, which passes on Windows and asserts
    /// `Some("")` on Linux, because a backslash is an ordinary character in a POSIX path and
    /// `parent()` of a name with no separator is the empty path. It ran green in a tree that
    /// tested on one platform. This one tests on three, so the path is built with `join` and the
    /// assertion is about being beside the policy file rather than about path syntax.
    #[test]
    fn the_feed_lives_beside_the_policy_file() {
        let config_dir = PathBuf::from("config-root").join("nested");
        let path = catalog_feed_path(Some(&config_dir.join("policy.json")))
            .expect("a policy path yields a feed path");
        assert!(path.ends_with(CATALOG_FEED_FILE));
        assert_eq!(path.parent().map(Path::to_path_buf), Some(config_dir));
        assert!(
            catalog_feed_path(None).is_none(),
            "no policy path means no persistence, the same posture policy editing takes"
        );
    }
}
