//! The admission catalog: what an upstream MCP server is, and what admitting one takes.
//!
//! A catalog entry is governance metadata about somebody else's software: who publishes it,
//! how much risk admitting it carries, what mode it starts in, which transports it speaks,
//! and which secrets it requires. None of it is trusted to describe behaviour; it exists so
//! that admission is a deliberate act an operator performs against stated terms rather than
//! a URL pasted into a form.
//!
//! ## What changed from the base, and why it is not a loss
//!
//! The base compiled a populated catalog of about thirty named third-party servers into this
//! module. Core does not. Two reasons, both structural. First, the base's own gateway audit
//! (DEC-007) records "the catalog is compiled in" as a defect and points at the feed module
//! as the fix; a snapshot loaded through [`crate::feed`] is the supported way entries arrive,
//! and shipping a hardcoded population would re-freeze the thing the feed exists to thaw.
//! Second, every one of those entries named a commercial vendor, and this workspace holds the
//! rule NMCP-SPEC-003 RC-11 and RC-D9 state for the kernel one crate wider on purpose: an
//! integration is an upstream this gateway reaches at runtime, never a name compiled into a
//! public tree. The admission *rules* (risk tiers, guardrails, required-secret gating) are
//! this build's and are all here; the *population* is data and arrives as data.
//!
//! ## Required secrets are consumed here (NMCP-SPEC-002 SB-6)
//!
//! `required_secrets` was pure metadata in the base: nothing read it, and admitting an entry
//! whose credential was never stored produced an upstream that failed forever at refresh
//! time. [`CatalogServer::admit`] is where it becomes load-bearing: admission asks the
//! operator's sealed store whether every declared key exists and has a version in service,
//! and refuses when one does not. Fail closed, naming the key and never any value material
//! (SB-1): the refusal carries names and lifecycle states, which are configuration, and the
//! store surface it reads ([`SealedStore::names`]) cannot return a value at all.

use nmcp_schema::is_valid_public_tool_name;
use nmcp_secrets::{SealedStore, SecretName};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// The identifier shape a catalog server id must satisfy, stated as a pattern for clients.
///
/// The enforcement is [`nmcp_schema::is_valid_public_tool_name`], not this string: a server
/// id becomes the provider prefix of every public tool name the upstream publishes, so it is
/// held to the same shape as the names themselves, by the same function the registry applies.
/// The pattern exists for surfaces that render the rule to a human, and
/// `the_stated_pattern_agrees_with_the_enforcing_validator` keeps the two from drifting.
pub const CATALOG_ID_PATTERN: &str = "^[a-zA-Z0-9_-]{1,64}$";

/// Where a catalog entry's description of an upstream came from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CatalogSourceType {
    /// Published by the vendor of the service the server fronts.
    OfficialVendor,
    /// Published in the vendor's own registry rather than by the vendor directly.
    OfficialRegistry,
    /// A curated third-party registry with review standards.
    CuratedRegistry,
    /// Community software with no curating registry behind it.
    Community,
    /// Third-party software fronting somebody else's service.
    ThirdParty,
    /// An official server is announced and not yet published; metadata only.
    PendingOfficial,
    /// Held out of admission entirely pending review.
    Quarantine,
}

/// How much risk admitting a server carries, in ascending order.
///
/// `Ord` is deliberate: surfaces sort and threshold on this, and the ordering is the
/// declaration order, lowest risk first.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CatalogRiskTier {
    /// Read-only by design when scoped correctly.
    Low,
    /// Ordinary connector risk: mutations exist and stay approval-gated.
    Standard,
    /// High-value credentials or broad mutation surface.
    Elevated,
    /// Identity, security or fleet control surface; operator review before activation.
    High,
    /// Not admissible at all. See [`CatalogServer::is_admissible`].
    Quarantine,
}

/// The mode a newly admitted server starts in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CatalogDefaultMode {
    /// Listed, never called: the entry exists so an operator can see it.
    MetadataOnly,
    /// Read tools reachable; mutations refused.
    ReadOnly,
    /// Every call requires human approval.
    ApprovalRequired,
    /// Admitted and switched off.
    Disabled,
    /// Not admissible at all; the mode form of [`CatalogRiskTier::Quarantine`].
    Quarantine,
}

/// The transports an upstream is distributed over, as the catalog describes them.
///
/// Descriptive, not authoritative: what the runtime can actually reach is
/// [`nmcp_policy::UpstreamTransport::is_implemented`], and policy validation is where a
/// transport the runtime cannot honour is refused. This enum records what the publisher
/// ships so an operator choosing an entry knows what wiring it will take.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CatalogTransport {
    /// A hosted endpoint somebody else runs.
    Remote,
    /// Streamable HTTP, the current MCP remote transport.
    StreamableHttp,
    /// Server-sent events, the older remote transport.
    Sse,
    /// A process this gateway starts and owns (DEC-007).
    Stdio,
    /// A container this gateway starts through a runtime CLI (DEC-007).
    Docker,
    /// The publisher does not say.
    Unknown,
}

/// One upstream MCP server as the catalog describes it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogServer {
    /// Stable identifier; becomes the provider prefix of every tool name.
    pub id: String,
    /// Human-readable name for admin surfaces.
    pub display_name: String,
    /// Who publishes the server software.
    pub publisher: String,
    /// Where the entry's description came from.
    pub source_type: CatalogSourceType,
    /// Where the software and its documentation live.
    pub source_urls: Vec<String>,
    /// What the server is for, as coarse capability domains.
    pub capability_domains: Vec<String>,
    /// How much risk admitting it carries.
    pub risk_tier: CatalogRiskTier,
    /// The mode a fresh admission starts in.
    pub default_mode: CatalogDefaultMode,
    /// Whether admission enables the upstream immediately. Every entry this build ships or
    /// accepts from a feed carries `false`; enabling is an operator act.
    pub default_enabled: bool,
    /// The transports the publisher distributes the server over.
    pub transports: Vec<CatalogTransport>,
    /// Names of secrets the server needs before it can work.
    ///
    /// Consumed by [`CatalogServer::admit`] (NMCP-SPEC-002 SB-6): a declared key absent from
    /// the operator store fails admission closed. Names only, never values, exactly like
    /// every other place policy touches a credential.
    pub required_secrets: Vec<String>,
    /// Catalog profile tags this entry belongs to. A tag is curation, not machine state:
    /// the runtime object is [`nmcp_policy::GatewayProfile`].
    pub profiles: Vec<String>,
    /// Whether calls through this server must be audited. Always `true` in this build; the
    /// field exists so a feed cannot silently claim otherwise without the diff showing it.
    pub audit_required: bool,
    /// Free-text guidance for the operator deciding on admission.
    pub notes: String,
}

impl CatalogServer {
    /// Whether this entry may be admitted at all.
    ///
    /// Quarantine in either dimension is a refusal, not a warning: an entry can be
    /// quarantined by risk tier, by default mode, or both, and any of the three reads the
    /// same way.
    #[must_use]
    pub fn is_admissible(&self) -> bool {
        !matches!(self.risk_tier, CatalogRiskTier::Quarantine)
            && !matches!(self.default_mode, CatalogDefaultMode::Quarantine)
    }

    /// The one-sentence admission guardrail for this entry's risk tier.
    #[must_use]
    pub fn admission_guardrail(&self) -> &'static str {
        match self.risk_tier {
            CatalogRiskTier::Low => "allowlist tools before enablement",
            CatalogRiskTier::Standard => "default read-only; approve mutations explicitly",
            CatalogRiskTier::Elevated => "require scoped credentials and human approval for writes",
            CatalogRiskTier::High => "require operator review, scoped credentials, HITL, and audit",
            CatalogRiskTier::Quarantine => "metadata only; do not enable without code review",
        }
    }

    /// Decide admission for this entry against the operator's sealed store (SB-6).
    ///
    /// Quarantine refuses first, because no stored secret makes a quarantined entry
    /// admissible. Then every name in `required_secrets` must parse as a storable
    /// [`SecretName`] and must be present in `store` with a version in service. All three
    /// failures are refusals rather than warnings, and the missing-key case is the one SB-6
    /// names: registration fails closed when a declared key is absent, because admitting the
    /// entry anyway produces an upstream that fails forever at refresh time with a worse
    /// message than this one.
    ///
    /// Reads [`SealedStore::names`] only: metadata, never material. The refusal names the
    /// key and, for a present-but-unusable key, its lifecycle state; no value or
    /// value-derived byte can appear because none is reachable from here (SB-1).
    ///
    /// # Errors
    ///
    /// The [`AdmissionRefusal`] naming what stops admission and what the operator has to
    /// change.
    pub fn admit(&self, store: &SealedStore) -> Result<(), AdmissionRefusal> {
        if !self.is_admissible() {
            return Err(AdmissionRefusal::Quarantined {
                id: self.id.clone(),
                guardrail: self.admission_guardrail(),
            });
        }
        let held = store.names();
        for key in &self.required_secrets {
            let name = match SecretName::parse(key) {
                Ok(name) => name,
                Err(reason) => {
                    return Err(AdmissionRefusal::UnstorableRequiredSecret {
                        id: self.id.clone(),
                        key: key.clone(),
                        reason: reason.to_string(),
                    });
                }
            };
            let Some(meta) = held.iter().find(|meta| meta.name == name) else {
                return Err(AdmissionRefusal::MissingRequiredSecret {
                    id: self.id.clone(),
                    key: key.clone(),
                });
            };
            if meta.current_version.is_none() {
                return Err(AdmissionRefusal::RequiredSecretNotInService {
                    id: self.id.clone(),
                    key: key.clone(),
                    state: meta.state.as_str().to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Why a catalog entry failed admission.
///
/// Every variant names the entry and the condition an operator has to change. No variant
/// carries secret material or any value derived from it (SB-1): ids, key names, lifecycle
/// states and parse reasons are configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionRefusal {
    /// The entry is quarantined by tier or mode and cannot be admitted at all.
    #[error("catalog server {id:?} is quarantined: {guardrail}")]
    Quarantined {
        /// The refused entry.
        id: String,
        /// The guardrail sentence for its tier.
        guardrail: &'static str,
    },
    /// A declared key is not in the operator store. The SB-6 refusal: fail closed, name the
    /// key, and send the operator to the surface that stores it.
    #[error(
        "catalog server {id:?} requires secret {key:?}, which is not in the operator store; store it through the operator surface before admission"
    )]
    MissingRequiredSecret {
        /// The refused entry.
        id: String,
        /// The declared key that is absent.
        key: String,
    },
    /// A declared key exists and has no version in service, so a resolution against it
    /// would refuse anyway; admission says so up front instead.
    #[error(
        "catalog server {id:?} requires secret {key:?}, which is present but {state} with no version in service"
    )]
    RequiredSecretNotInService {
        /// The refused entry.
        id: String,
        /// The declared key that cannot resolve.
        key: String,
        /// The lifecycle state the key is in.
        state: String,
    },
    /// A declared key is not a name the operator store can hold, so it could never be
    /// satisfied. Refused at admission rather than discovered as an eternal
    /// [`AdmissionRefusal::MissingRequiredSecret`].
    #[error(
        "catalog server {id:?} requires secret {key:?}, which is not a name the operator store can hold: {reason}"
    )]
    UnstorableRequiredSecret {
        /// The refused entry.
        id: String,
        /// The declared key outside the store's grammar.
        key: String,
        /// Why the store cannot hold it.
        reason: String,
    },
}

/// The whole catalog: admission posture plus entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayCatalog {
    /// Schema version of the catalog document shape.
    pub schema_version: u32,
    /// What produced this catalog, for provenance in exports.
    pub generated_by: String,
    /// The admission posture, in prose. Belongs to this build, never to a feed publisher:
    /// see [`crate::feed::catalog_from_snapshot`].
    pub default_policy: String,
    /// The entries.
    pub servers: Vec<CatalogServer>,
}

impl GatewayCatalog {
    /// The entry with this id, if the catalog carries one.
    #[must_use]
    pub fn find(&self, id: &str) -> Option<&CatalogServer> {
        self.servers.iter().find(|server| server.id == id)
    }

    /// Validate the catalog's structural rules.
    ///
    /// Ids must be valid public-tool-name material (they become provider prefixes), unique,
    /// and every entry must carry a display name, a publisher, at least one capability
    /// domain and at least one profile tag. A catalog that fails here is refused whole, the
    /// same all-or-nothing rule registration follows.
    ///
    /// # Errors
    ///
    /// A message naming the first offending entry and the rule it breaks.
    pub fn validate(&self) -> Result<(), String> {
        let mut ids = BTreeSet::new();
        for server in &self.servers {
            if !is_valid_public_tool_name(&server.id) {
                return Err(format!(
                    "catalog server id '{}' violates the MCP-safe identifier shape {CATALOG_ID_PATTERN}",
                    server.id
                ));
            }
            if !ids.insert(server.id.clone()) {
                return Err(format!("duplicate catalog server id '{}'", server.id));
            }
            if server.display_name.trim().is_empty() {
                return Err(format!(
                    "catalog server '{}' has empty display_name",
                    server.id
                ));
            }
            if server.publisher.trim().is_empty() {
                return Err(format!(
                    "catalog server '{}' has empty publisher",
                    server.id
                ));
            }
            if server.capability_domains.is_empty() {
                return Err(format!(
                    "catalog server '{}' has no capability domains",
                    server.id
                ));
            }
            if server.profiles.is_empty() {
                return Err(format!("catalog server '{}' has no profiles", server.id));
            }
        }
        Ok(())
    }

    /// Every entry tagged with `profile`.
    #[must_use]
    pub fn profile(&self, profile: &str) -> Vec<CatalogServer> {
        self.servers
            .iter()
            .filter(|server| server.profiles.iter().any(|p| p == profile))
            .cloned()
            .collect()
    }

    /// Entry count per risk tier, keyed by the tier's `snake_case` name.
    #[must_use]
    pub fn risk_summary(&self) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for server in &self.servers {
            let key = enum_summary_key(&format!("{:?}", server.risk_tier));
            *out.entry(key).or_insert(0) += 1;
        }
        out
    }

    /// Entry count per profile tag.
    #[must_use]
    pub fn profiles_summary(&self) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for server in &self.servers {
            for profile in &server.profiles {
                *out.entry(profile.clone()).or_insert(0) += 1;
            }
        }
        out
    }

    /// Entry count per source type, keyed by the type's `snake_case` name.
    #[must_use]
    pub fn source_summary(&self) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for server in &self.servers {
            let key = enum_summary_key(&format!("{:?}", server.source_type));
            *out.entry(key).or_insert(0) += 1;
        }
        out
    }

    /// The catalog as one JSON document for an admin surface.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "generated_by": self.generated_by,
            "default_policy": self.default_policy,
            "tool_name_pattern": CATALOG_ID_PATTERN,
            "risk_summary": self.risk_summary(),
            "profiles_summary": self.profiles_summary(),
            "source_summary": self.source_summary(),
            "servers": self.servers,
        })
    }
}

/// This build's catalog before any feed has been applied: the admission posture, with no
/// entries.
///
/// Empty is the design, not a placeholder. The module documentation carries the two reasons:
/// a compiled-in population is the defect DEC-007's audit names and the feed exists to fix,
/// and a public tree ships no vendor's name as code. What this function owns is the posture
/// sentence, which [`crate::feed::catalog_from_snapshot`] deliberately reuses so a feed
/// publisher cannot restate what admission takes.
#[must_use]
pub fn default_gateway_catalog() -> GatewayCatalog {
    GatewayCatalog {
        schema_version: 1,
        generated_by: "nMCP Gateway Catalog".to_string(),
        default_policy: "enable nothing by default; admit runtime upstreams only through \
                         policy-gated activation; catalog entries arrive by feed snapshot, \
                         never compiled in"
            .to_string(),
        servers: vec![],
    }
}

/// A Debug-rendered enum variant name as a `snake_case` summary key.
fn enum_summary_key(debug_name: &str) -> String {
    let mut out = String::new();
    for (idx, ch) in debug_name.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if idx > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
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
    use nmcp_secrets::Sealed;

    /// Distinctive material with no English substring, so the no-material assertions below
    /// cannot collide with legitimate prose.
    const MATERIAL: &[u8] = b"qv8xk-3mzp7-wrj2t-secret";

    fn synthetic_server(id: &str, required: &[&str]) -> CatalogServer {
        CatalogServer {
            id: id.to_string(),
            display_name: "Synthetic MCP Server".to_string(),
            publisher: "example".to_string(),
            source_type: CatalogSourceType::ThirdParty,
            source_urls: vec!["https://example.invalid/mcp".to_string()],
            capability_domains: vec!["example".to_string()],
            risk_tier: CatalogRiskTier::Standard,
            default_mode: CatalogDefaultMode::ReadOnly,
            default_enabled: false,
            transports: vec![CatalogTransport::Remote],
            required_secrets: required.iter().map(|s| (*s).to_string()).collect(),
            profiles: vec!["developer".to_string()],
            audit_required: true,
            notes: "Synthetic test entry.".to_string(),
        }
    }

    fn quarantined_server(id: &str) -> CatalogServer {
        let mut server = synthetic_server(id, &[]);
        server.risk_tier = CatalogRiskTier::Quarantine;
        server.default_mode = CatalogDefaultMode::Quarantine;
        server
    }

    #[test]
    fn the_stated_pattern_agrees_with_the_enforcing_validator() {
        // The pattern is prose for humans; the validator is the enforcement. This pins the
        // two to the same answer over the shapes that matter: alphanumerics, underscore and
        // hyphen up to 64 characters pass, and separators, dots, emptiness and length fail.
        for valid in [
            "upstream_list_issues",
            "Example-Server_123",
            "a",
            &"x".repeat(64),
        ] {
            assert!(is_valid_public_tool_name(valid), "{valid} must validate");
        }
        for invalid in ["up::list", "up.list", "", " ", &"x".repeat(65)] {
            assert!(!is_valid_public_tool_name(invalid), "{invalid} must fail");
        }
        assert!(CATALOG_ID_PATTERN.contains("1,64"));
    }

    #[test]
    fn summary_keys_use_snake_case() {
        let mut catalog = default_gateway_catalog();
        let mut server = synthetic_server("summed", &[]);
        server.source_type = CatalogSourceType::CuratedRegistry;
        catalog.servers.push(server);
        let source_summary = catalog.source_summary();
        assert!(source_summary.contains_key("curated_registry"));
        assert!(!source_summary.contains_key("curatedregistry"));
        assert_eq!(catalog.risk_summary().get("standard"), Some(&1));
    }

    #[test]
    fn the_default_catalog_is_valid_empty_and_names_the_feed_as_the_source_of_entries() {
        let catalog = default_gateway_catalog();
        catalog.validate().unwrap();
        assert!(catalog.servers.is_empty());
        assert!(catalog.default_policy.contains("enable nothing by default"));
        assert!(catalog.default_policy.contains("feed"));
        let rendered = catalog.to_json();
        assert_eq!(rendered["tool_name_pattern"], CATALOG_ID_PATTERN);
        assert!(rendered["servers"].as_array().unwrap().is_empty());
    }

    #[test]
    fn validation_refuses_duplicate_and_malformed_ids() {
        let mut catalog = default_gateway_catalog();
        catalog.servers.push(synthetic_server("twice", &[]));
        catalog.servers.push(synthetic_server("twice", &[]));
        assert!(catalog.validate().unwrap_err().contains("duplicate"));

        let mut catalog = default_gateway_catalog();
        catalog
            .servers
            .push(synthetic_server("has::separator", &[]));
        let err = catalog.validate().unwrap_err();
        assert!(err.contains("has::separator"), "{err}");
        assert!(err.contains(CATALOG_ID_PATTERN), "{err}");
    }

    #[test]
    fn quarantine_entries_are_not_admissible_and_admit_says_so() {
        let store = SealedStore::ephemeral();
        let entry = quarantined_server("boxed");
        assert!(!entry.is_admissible());
        let refusal = entry.admit(&store).expect_err("quarantine refuses");
        assert!(matches!(refusal, AdmissionRefusal::Quarantined { .. }));
        assert!(refusal.to_string().contains("boxed"));

        let clean = synthetic_server("clean", &[]);
        assert!(clean.is_admissible());
        clean.admit(&store).expect("no requirements, admissible");
    }

    /// SB-6: a declared key absent from the operator store fails admission closed, the
    /// refusal names the key, and no value material can appear because none is reachable.
    #[test]
    fn admission_fails_closed_naming_a_missing_key_and_never_any_value() {
        let store = SealedStore::ephemeral();
        let present = SecretName::parse("example_token").expect("valid name");
        store
            .set(&present, Sealed::new(MATERIAL.to_vec()))
            .expect("store the present key");

        let entry = synthetic_server("needy", &["example_token", "absent_token"]);
        let refusal = entry.admit(&store).expect_err("one key is absent");
        let AdmissionRefusal::MissingRequiredSecret { id, key } = &refusal else {
            panic!("wrong refusal: {refusal:?}");
        };
        assert_eq!(id, "needy");
        assert_eq!(key, "absent_token");
        let rendered = refusal.to_string();
        assert!(rendered.contains("absent_token"));
        assert!(rendered.contains("operator"));
        let material = String::from_utf8_lossy(MATERIAL).to_string();
        assert!(
            !rendered.contains(&material) && !rendered.contains("24"),
            "a refusal must carry no value material and no value-derived length: {rendered}"
        );
    }

    #[test]
    fn admission_passes_when_every_declared_key_is_in_service() {
        let store = SealedStore::ephemeral();
        for key in ["first_token", "second_token"] {
            store
                .set(
                    &SecretName::parse(key).expect("valid name"),
                    Sealed::new(MATERIAL.to_vec()),
                )
                .expect("store");
        }
        synthetic_server("ready", &["first_token", "second_token"])
            .admit(&store)
            .expect("every declared key is present and in service");
    }

    /// A key that exists and cannot resolve is refused up front with its state named,
    /// because the alternative is admitting an upstream whose every refresh fails with a
    /// message about resolution instead of one about the quarantined key.
    #[test]
    fn admission_refuses_a_key_with_no_version_in_service_naming_its_state() {
        let store = SealedStore::ephemeral();
        let name = SecretName::parse("revoked_token").expect("valid name");
        store
            .set(&name, Sealed::new(MATERIAL.to_vec()))
            .expect("store");
        store.quarantine(&name).expect("quarantine");

        let refusal = synthetic_server("stalled", &["revoked_token"])
            .admit(&store)
            .expect_err("a quarantined key resolves nothing");
        let AdmissionRefusal::RequiredSecretNotInService { key, state, .. } = &refusal else {
            panic!("wrong refusal: {refusal:?}");
        };
        assert_eq!(key, "revoked_token");
        assert_eq!(state, "quarantined");
    }

    /// A declared name outside the store's grammar can never be satisfied, so admission
    /// says so once instead of reporting it missing forever. The reserved namespace is the
    /// sharp case: an entry demanding an `oauth/` name is demanding the broker's own
    /// storage, which no operator can write.
    #[test]
    fn admission_refuses_a_key_name_the_store_cannot_hold() {
        let store = SealedStore::ephemeral();
        for bad in ["oauth/provider", "UPPER_CASE"] {
            let refusal = synthetic_server("misdeclared", &[bad])
                .admit(&store)
                .expect_err("an unstorable name must refuse");
            let AdmissionRefusal::UnstorableRequiredSecret { key, .. } = &refusal else {
                panic!("wrong refusal for {bad}: {refusal:?}");
            };
            assert_eq!(key, bad);
        }
    }
}
