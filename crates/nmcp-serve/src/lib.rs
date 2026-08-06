//! The nMCP served surface: the object graph the daemon is built from.
//!
//! Part of the NativeMCP `core` workspace. The governance invariants in `docs/GOVERNANCE.md`
//! apply.
//!
//! I-073 lands [`AppState`] and the two leaf modules beneath it. The three lanes, diagnostics
//! and the admin surface are I-074 through I-077 and are not here.
//!
//! # Fourteen fields, and why not sixteen
//!
//! NMCP-SPEC-004 section 5.2 freezes seventeen components. Two of them, runtime path
//! resolution (b) and provider registration (q), are things construction *does* rather than
//! things the struct *holds*, which is amendment A-2. That leaves fifteen residents in the
//! table, and the base's struct has sixteen fields: `policy_path` is a resident the component
//! table never listed, which is amendment A-5. It is carried here with its three consumers
//! named on the field, because a port working from the table alone would have dropped it and
//! taken the sealed store's persistence with it.
//!
//! Of those sixteen, fourteen are here. `jwks` is `JwksCache`, which I-074 introduces with
//! `nmcp-authn`; `catalog` is the catalog store, which I-077 introduces. Both issues run after
//! this one, so a struct declaring those fields could not compile when this lands. **A field
//! arrives in the issue that introduces its type.** Declaring one early would mean a
//! placeholder, and a placeholder in a frozen object graph is the thing freezing it prevents.
//! [`AppState::FIELD_COUNT`] is asserted by a test, so those two additions are edits to a
//! stated number rather than quiet growth.
//!
//! # The sealer is a parameter
//!
//! Component (a) reads "Sealed store, opened with the DPAPI sealer, or ephemeral". DPAPI is
//! Windows and this crate is not. Core's own API already made the right shape available:
//! `SealedStore::open` takes `Box<dyn Sealer>` under SB-10, so the platform binding is a
//! parameter rather than a fork. [`AppState::with_policy_path`] binds `FileSealer` and WinMCP
//! binds DPAPI through [`AppState::with_sealer`]. One graph, two bindings.
//!
//! The parameter is a factory rather than a sealer, because a store with nowhere to persist is
//! ephemeral and never opens one. Constructing a sealer to discard it would create key
//! material on disk for a store that does not exist.
//!
//! Component (d)'s platform mirror needs no such treatment. `nmcp-audit` carries `MirrorConfig`
//! and `AuditSink::configure_mirror`, which are the base's `EventLogMirrorConfig` and
//! `configure_event_log_mirror` under this workspace's names, and `nmcp-policy` carries
//! `audit_event_log`. The whole path ports.

mod auth_attempts;
pub mod diagnostics;
mod peer;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use nmcp_abac::{AbacStage, into_abac_check};
use nmcp_audit::{AuditSink, MirrorConfig};
use nmcp_exec::ExecuteJobRegistry;
use nmcp_gateway::GatewayRegistry;
use nmcp_host::IndexedToolRegistry;
use nmcp_oauth::Broker;
use nmcp_policy::PolicyConfig;
use nmcp_policy::machine::{MachinePolicySource, NoFleetPolicy};
use nmcp_router::SharedRouter;
use nmcp_secrets::{FileSealer, SealedStore, Sealer, default_key_dir};
use nmcp_transport::{RedactionPipeline, SessionRegistry, TransportConfig};
use parking_lot::RwLock;

/// How a sealer is obtained for a store directory, when there is one.
///
/// See the module doc: this is a factory rather than a `Box<dyn Sealer>` so that an ephemeral
/// store never causes key material to be written for a store that does not exist.
///
/// # Errors
///
/// Whatever opening the platform's sealer failed with.
pub type SealerFactory = Box<dyn FnOnce(&Path) -> anyhow::Result<Box<dyn Sealer>>>;

/// Whether the policy on disk is the policy actually in force (G4-25).
///
/// The hot-reload watcher keeps the prior policy when an edit will not parse, which is
/// fail-safe and correct. The problem it leaves behind is silence: without somewhere to record
/// the rejection it exists only in a log line, and the policy read surface returns the policy
/// in force, which by construction looks healthy. An operator who edits the file to tighten a
/// rule, sees no error, and checks the admin surface is shown the state they wanted rather than
/// the state they have, and the silence runs in the dangerous direction: a rejected tightening
/// leaves the looser policy live.
///
/// Clone-cheap through an inner `Arc`, like the other pieces of [`AppState`].
#[derive(Clone, Default)]
pub struct PolicyLoadState {
    inner: Arc<RwLock<Option<PolicyRejection>>>,
}

/// The most recent rejected attempt to load the policy file.
#[derive(Clone, Debug)]
pub struct PolicyRejection {
    /// What the loader refused it with.
    pub error: String,
    /// When the refusal happened, unix milliseconds.
    pub at_unix_ms: u64,
}

impl PolicyLoadState {
    /// The file parsed and is now in force. Clears any previous rejection.
    pub fn record_applied(&self) {
        *self.inner.write() = None;
    }

    /// The file could not be read or parsed, so the prior policy is still in force.
    pub fn record_rejected(&self, error: impl Into<String>) {
        let at_unix_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or_default(),
        )
        .unwrap_or(u64::MAX);
        *self.inner.write() = Some(PolicyRejection {
            error: error.into(),
            at_unix_ms,
        });
    }

    /// The rejection in force, if the policy on disk is not the policy running.
    #[must_use]
    pub fn rejection(&self) -> Option<PolicyRejection> {
        self.inner.read().clone()
    }
}

/// Which transport pair should receive lifecycle events for an async execution job.
///
/// Clone-safe through an inner `Arc`.
///
/// The base's `register` and `unregister` are both `#[cfg(test)]`, so `active_count` can never
/// be nonzero in a production build while diagnostics reports it as a live metric. That is
/// finding F-2's corroborating half and it is not fixed here: the writers belong with the lanes
/// that would call them, which is I-075. Carried in this shape deliberately so the port does not
/// invent a wiring the base does not have.
#[derive(Clone, Default)]
pub struct ExecutionEventEmitter {
    inner: Arc<parking_lot::Mutex<std::collections::BTreeMap<String, (u64, u64)>>>,
}

impl ExecutionEventEmitter {
    /// How many jobs are currently routed. The diagnostics surface reads this.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.inner.lock().len()
    }
}

/// The absolute URL of this resource's metadata document (G3-11, RS-6).
///
/// RFC 9728 Section 3.1 builds it by inserting `/.well-known/oauth-protected-resource` between
/// the resource identifier's authority and its path, so `https://mcp.example.com/mcp` becomes
/// `https://mcp.example.com/.well-known/oauth-protected-resource/mcp`. That is the second of
/// the two routes this server registers, which is why both exist.
///
/// At the crate root rather than in `diagnostics`, because the doctor is only its first caller:
/// the lanes' `WWW-Authenticate` challenge is the other, and that lands with I-075.
///
/// Policy validation guarantees the identifier is absolute and carries no fragment, so the
/// parse below has no failure case a loaded policy can reach.
#[must_use]
pub fn resource_metadata_url(resource: &str) -> String {
    // A query string is not part of a resource identifier under RFC 8707 and is dropped here
    // rather than carried into a well-known URL where it would mean nothing.
    let trimmed = resource.split('?').next().unwrap_or(resource);
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return format!("{trimmed}/.well-known/oauth-protected-resource");
    };
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, path.trim_end_matches('/')),
        None => (rest, ""),
    };
    if path.is_empty() {
        format!("{scheme}://{authority}/.well-known/oauth-protected-resource")
    } else {
        format!("{scheme}://{authority}/.well-known/oauth-protected-resource/{path}")
    }
}

/// A fleet-policy reader the daemon was given, shared across requests.
///
/// `Send + Sync` because [`AppState`] is cloned into every handler and read concurrently.
pub type SharedMachinePolicySource = Arc<dyn MachinePolicySource + Send + Sync>;

/// The object graph NMCP-SPEC-004 section 5.2 freezes.
///
/// See the module doc for why fourteen fields rather than sixteen or seventeen.
#[derive(Clone)]
pub struct AppState {
    /// Failed authentication attempts, coalesced (G3-13, AF-2). Component (o).
    ///
    /// On the state rather than a global, because a test builds its own server and must not
    /// share a ledger with another test running beside it.
    ///
    /// Read by the lanes' authentication path, which is I-075. `expect` rather than `allow`,
    /// and this one attribute is the crate's single enforcement point: it is dead in both the
    /// lib and lib-test targets, so it stops applying the moment a lane reads it and the
    /// compiler says so. The module-level `allow`s in `peer` and `auth_attempts` exist because
    /// their own tests use everything they declare, which makes `expect` unfulfillable there.
    #[expect(
        dead_code,
        reason = "read by the lanes' auth path, which lands in I-075"
    )]
    auth_attempts: Arc<auth_attempts::AuthAttemptLedger>,
    /// Component (h). Read per request by every provider.
    policy: Arc<RwLock<PolicyConfig>>,
    /// Not in section 5.2's component table, and a resident all the same (A-5).
    ///
    /// Three consumers, one of which governs another component's stated constraint. It decides
    /// whether component (a) is a persistent store or an ephemeral one; it locates component
    /// (n)'s feed file; and it is what the doctor reports as the policy actually in force.
    policy_path: Option<PathBuf>,
    /// Component (j). Serialises policy writes against each other.
    policy_update_lock: Arc<parking_lot::Mutex<()>>,
    /// Component (d), with its platform mirror configured from policy.
    audit: AuditSink,
    /// Component (f).
    exec_jobs: ExecuteJobRegistry,
    /// Component (e), session registry with the redaction pipeline.
    transport: SessionRegistry,
    /// Component (g).
    event_emitter: ExecutionEventEmitter,
    /// Component (p). `IndexedToolRegistry` with ABAC wired, before any provider registers.
    ///
    /// Registration itself is component (q), which A-2 establishes is an action rather than a
    /// resident, and section 5.3 gives its order. It belongs to the composition root in I-078,
    /// so what this constructor produces is the router a provider can register *into*.
    pub router: SharedRouter,
    /// Component (k). Upstream MCP proxy providers.
    pub gateway: GatewayRegistry,
    /// Component (l). Rules, HITL registry, signing.
    pub abac: AbacStage,
    /// Component (i). The rejection state readiness and the metric surface read.
    pub policy_load: PolicyLoadState,
    /// Component (a). Named secrets, sealed at rest and never in policy (G6-4).
    ///
    /// Behind an `Arc` because `SealedStore` is deliberately not `Clone` and [`AppState`] is.
    /// The base's store was `Clone`, which meant every request handler held a copy of a type
    /// whose whole job is to be the one authority over sealed material. Core's is a `Mutex`
    /// over a document, so sharing the handle is the only shape that keeps one authority.
    pub secrets: Arc<SealedStore>,
    /// The fleet-policy source the doctor reads. Amendment A-6, not in section 5.2's table.
    ///
    /// The base's doctor called `MachinePolicy::from_registry()`, a free function with nothing
    /// to inject, so WD-8's acceptance criterion, a doctor check on a **managed** machine, could
    /// not be written. `nmcp-policy` already carries `MachinePolicySource` for exactly this and
    /// nothing was reading it: in core `from_registry` reads no registry and hardcodes
    /// `NoFleetPolicy`, so the doctor answered "the fleet has no opinion" on every platform with
    /// no way to show it otherwise.
    ///
    /// Held rather than passed because the doctor reads it per request, which is how the base
    /// read the registry, and because WinMCP binds its Group Policy reader once at construction
    /// (NMCP-SPEC-001 R-3).
    pub machine_policy: SharedMachinePolicySource,
    /// Component (c). OAuth grants, brokered to every upstream that names a provider (G6-9).
    ///
    /// One per process. Two brokers over the same providers would each run a sweep, and two
    /// sweeps refreshing one grant at the same moment is the double-refresh that costs the
    /// whole grant at a provider that rotates its refresh token.
    pub oauth: Arc<Broker>,
}

impl AppState {
    /// The number of fields this graph carries today.
    ///
    /// Stated rather than inferred, and asserted by a test, because more arrive later:
    /// `jwks` with I-074 and `catalog` with I-077. A frozen graph that grows without anyone
    /// editing a number is a graph that is not frozen, and this constant moving is the whole
    /// mechanism: `machine_policy` took it from fourteen to fifteen at I-076 and that edit is
    /// visible in the diff rather than inferred from a compile.
    pub const FIELD_COUNT: usize = 15;

    /// Build the graph with no policy file, so every store is ephemeral.
    ///
    /// # Errors
    ///
    /// As [`AppState::with_sealer`].
    pub fn new(policy: PolicyConfig) -> anyhow::Result<Self> {
        Self::with_policy_path(policy, None)
    }

    /// Build the graph, binding this platform's default sealer.
    ///
    /// Core's default is [`FileSealer`], whose key directory is the store's sibling under
    /// SB-11: a backup that captures the store does not necessarily capture the key.
    ///
    /// # Errors
    ///
    /// As [`AppState::with_sealer`].
    pub fn with_policy_path(
        policy: PolicyConfig,
        policy_path: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        Self::with_sealer(
            policy,
            policy_path,
            Box::new(|store_dir: &Path| {
                let sealer = FileSealer::open(&default_key_dir(store_dir))?;
                Ok(Box::new(sealer) as Box<dyn Sealer>)
            }),
        )
    }

    /// Build the graph with the sealer this platform binds. See the module doc.
    ///
    /// `sealer_for` is consulted only when there is a directory to persist into. With no policy
    /// path there is nowhere, and an ephemeral store is the honest answer rather than a surprise
    /// write to a platform data directory.
    ///
    /// # Errors
    ///
    /// When the sealer cannot be opened, the sealed store cannot be read, the audit sink cannot
    /// be opened, or the session registry refuses its configuration.
    pub fn with_sealer(
        policy: PolicyConfig,
        policy_path: Option<PathBuf>,
        sealer_for: SealerFactory,
    ) -> anyhow::Result<Self> {
        Self::with_sealer_and_fleet(policy, policy_path, sealer_for, Arc::new(NoFleetPolicy))
    }

    /// Build the graph binding both platform concerns: the sealer and the fleet-policy reader.
    ///
    /// This is the constructor WinMCP calls. Core's other constructors bind `FileSealer` and
    /// [`NoFleetPolicy`], which is exactly the behaviour the base gave every non-Windows build.
    ///
    /// # Errors
    ///
    /// As [`AppState::with_sealer`].
    pub fn with_sealer_and_fleet(
        policy: PolicyConfig,
        policy_path: Option<PathBuf>,
        sealer_for: SealerFactory,
        machine_policy: SharedMachinePolicySource,
    ) -> anyhow::Result<Self> {
        // (a) Sealed store, or ephemeral where there is nowhere to persist.
        let secrets = match policy_path.as_deref().and_then(Path::parent) {
            Some(dir) => {
                let store_dir = dir.join(nmcp_secrets::SECRETS_DIR);
                SealedStore::open(&store_dir, sealer_for(&store_dir)?)?
            }
            None => SealedStore::ephemeral(),
        };
        let secrets = Arc::new(secrets);
        // (b) Runtime paths resolved. An action, not a resident (A-2).
        let policy = policy.with_runtime_paths(policy_path.as_deref());
        // (c) OAuth broker, then reconfigure. Before providers: an upstream that brokers needs a
        // broker that already knows its provider by the time it first refreshes.
        let oauth = Broker::with_default_client(grant_store(policy_path.as_deref())?)?;
        oauth.reconfigure(policy.oauth_providers.clone());
        // (d) Audit sink, then platform mirror configured from policy.
        let audit = AuditSink::open(&policy.audit_path)?;
        audit.configure_mirror(mirror_config(&policy));
        // (e) Session registry with the redaction pipeline.
        let transport = SessionRegistry::new(
            TransportConfig::default(),
            RedactionPipeline::with_default_redactors(),
        )
        .map_err(|e| anyhow::anyhow!("transport registry init: {e}"))?;
        // (f) Exec job registry.
        let exec_jobs = ExecuteJobRegistry::default();
        // (h) Shared policy handle, built before everything that reads policy per request.
        let policy_arc = Arc::new(RwLock::new(policy));
        // (k) Gateway registry.
        let gateway = GatewayRegistry::new();
        // (l) ABAC stage.
        let abac = AbacStage::new(audit.clone(), policy_arc.clone());
        // (p) The registry, then the router over it, with ABAC wired before any provider
        // registers. Registration is (q) and belongs to the composition root.
        let registry = Arc::new(IndexedToolRegistry::new(policy_arc.clone()));
        let router: SharedRouter = {
            let r = nmcp_router::Router::new(policy_arc.clone(), audit.clone(), registry);
            r.set_abac(into_abac_check(abac.clone()));
            Arc::new(r)
        };
        Ok(Self {
            machine_policy,
            auth_attempts: Arc::new(auth_attempts::AuthAttemptLedger::new()),
            policy: policy_arc,
            policy_path,
            policy_update_lock: Arc::new(parking_lot::Mutex::new(())),
            audit,
            exec_jobs,
            transport,
            event_emitter: ExecutionEventEmitter::default(),
            router,
            gateway,
            abac,
            policy_load: PolicyLoadState::default(),
            secrets,
            oauth,
        })
    }

    /// The policy in force, cloned.
    #[must_use]
    pub fn policy(&self) -> PolicyConfig {
        self.policy.read().clone()
    }

    /// The shared handle itself, for the pieces that must observe a reload rather than a
    /// snapshot.
    #[must_use]
    pub fn policy_handle(&self) -> Arc<RwLock<PolicyConfig>> {
        self.policy.clone()
    }

    /// The policy file backing this state, when there is one (A-5).
    #[must_use]
    pub fn policy_path(&self) -> Option<&Path> {
        self.policy_path.as_deref()
    }

    /// The lock every policy write takes. Component (j).
    #[must_use]
    pub fn policy_update_lock(&self) -> &Arc<parking_lot::Mutex<()>> {
        &self.policy_update_lock
    }

    /// The audit sink. Component (d).
    #[must_use]
    pub fn audit(&self) -> &AuditSink {
        &self.audit
    }

    /// The durable job registry. Component (f).
    #[must_use]
    pub fn exec_jobs(&self) -> &ExecuteJobRegistry {
        &self.exec_jobs
    }

    /// The session registry. Component (e).
    #[must_use]
    pub fn transport(&self) -> &SessionRegistry {
        &self.transport
    }

    /// The job-to-stream routing table. Component (g).
    #[must_use]
    pub fn event_emitter(&self) -> &ExecutionEventEmitter {
        &self.event_emitter
    }

    /// The failed-authentication ledger. Component (o).
    #[must_use]
    #[expect(
        dead_code,
        reason = "called by the lanes' auth path, which lands in I-075"
    )]
    pub(crate) fn auth_attempts(&self) -> &auth_attempts::AuthAttemptLedger {
        &self.auth_attempts
    }
}

/// The broker's own sealed grant store, beside the secret store rather than inside it.
///
/// A divergence from the base worth naming: there, `Broker::with_default_client` took the
/// secret store itself. Core's broker owns a `GrantStore` with its own document, so a grant and
/// a named secret are not two things in one file. Ephemeral for the same reason the secret store
/// is: with no policy path there is nowhere to persist and writing anyway would be a surprise.
fn grant_store(policy_path: Option<&Path>) -> anyhow::Result<nmcp_oauth::store::GrantStore> {
    match policy_path.and_then(Path::parent) {
        Some(dir) => {
            let store_dir = dir.join("grants");
            let sealer = FileSealer::open(&default_key_dir(&store_dir))?;
            Ok(nmcp_oauth::store::GrantStore::open(
                &store_dir,
                Box::new(sealer),
            )?)
        }
        None => Ok(nmcp_oauth::store::GrantStore::ephemeral()),
    }
}

/// Policy overrides the legacy environment switch when policy says anything at all.
///
/// The shape matters and the base's comment says why: a security surface must not appear, or
/// vanish, on upgrade. An install that turned the mirror on through the legacy service switch
/// keeps working when policy is silent.
fn mirror_config(policy: &PolicyConfig) -> MirrorConfig {
    match &policy.audit_event_log {
        Some(configured) => MirrorConfig {
            enabled: configured.enabled,
            source: configured.source.clone(),
        },
        None => MirrorConfig::from_env(),
    }
}

#[cfg(test)]
mod tests {
    // Tests assert on shapes and counts, where expect/panic ARE the assertion: a panic in a
    // test is the failure signal, so the production rationale for the workspace denies
    // (availability plus an audit gap) does not apply. Scoped to the test module, named in
    // the PR.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{AppState, PolicyLoadState, SealerFactory};
    use nmcp_policy::PolicyConfig;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("nmcp-serve-{label}-{stamp}"));
        std::fs::create_dir_all(&root).expect("mkdir");
        root
    }

    fn policy_in(root: &Path) -> PolicyConfig {
        PolicyConfig {
            audit_path: root.join("audit.jsonl"),
            ..PolicyConfig::default()
        }
    }

    /// The acceptance criterion NMCP-PLAN-002 adds for I-073.
    ///
    /// `jwks` arrives with I-074 and `catalog` with I-077, and a frozen object graph that grows
    /// without anyone editing a number is a graph that is not frozen. The pattern is exhaustive,
    /// so adding a field stops this compiling rather than merely failing, and the names are
    /// listed so the count is checked against something real instead of against itself.
    #[test]
    fn the_graph_carries_exactly_the_fields_it_declares() {
        let root = temp_root("fields");
        let state = AppState::new(policy_in(&root)).expect("state");
        let AppState {
            machine_policy: _,
            auth_attempts: _,
            policy: _,
            policy_path: _,
            policy_update_lock: _,
            audit: _,
            exec_jobs: _,
            transport: _,
            event_emitter: _,
            router: _,
            gateway: _,
            abac: _,
            policy_load: _,
            secrets: _,
            oauth: _,
        } = state;
        let named = [
            "machine_policy",
            "auth_attempts",
            "policy",
            "policy_path",
            "policy_update_lock",
            "audit",
            "exec_jobs",
            "transport",
            "event_emitter",
            "router",
            "gateway",
            "abac",
            "policy_load",
            "secrets",
            "oauth",
        ];
        assert_eq!(
            named.len(),
            AppState::FIELD_COUNT,
            "the destructuring above is exhaustive, so this list is the graph. Adding a field \
             without moving FIELD_COUNT is the quiet growth the spec froze this against."
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// The sealer is a parameter, and a store with nowhere to persist never opens one.
    ///
    /// Constructing a sealer to discard it would create key material on disk for a store that
    /// does not exist, which is the surprise write the ephemeral branch exists to avoid. The
    /// factory panics, so calling it at all fails the test rather than being invisible.
    #[test]
    fn an_ephemeral_store_never_consults_the_sealer_factory() {
        let root = temp_root("ephemeral");
        let factory: SealerFactory = Box::new(|_| {
            panic!("a store with nowhere to persist must not cause key material to be written")
        });
        let state = AppState::with_sealer(policy_in(&root), None, factory).expect("state");
        assert!(
            state.policy_path().is_none(),
            "the premise: no policy path is what makes the store ephemeral"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A-5. `policy_path` is a resident the component table never listed, and it is what the
    /// doctor reports as the policy in force. Asserting it survives construction is what keeps a
    /// later reader from removing a field the table does not mention.
    #[test]
    fn the_policy_path_survives_construction_because_three_consumers_read_it() {
        let root = temp_root("policy-path");
        let path = root.join("policy.json");
        let state =
            AppState::with_policy_path(policy_in(&root), Some(path.clone())).expect("state");
        assert_eq!(state.policy_path(), Some(path.as_path()));
        let _ = std::fs::remove_dir_all(root);
    }

    /// G4-25. The rejection has to be readable, because the policy read surface returns the
    /// policy in force and by construction that looks healthy.
    #[test]
    fn a_rejected_policy_load_is_recorded_and_cleared_by_a_successful_one() {
        let load = PolicyLoadState::default();
        assert!(load.rejection().is_none());

        load.record_rejected("expected `,` at line 4");
        let rejected = load.rejection().expect("a rejection is in force");
        assert_eq!(rejected.error, "expected `,` at line 4");
        assert!(rejected.at_unix_ms > 0);

        load.record_applied();
        assert!(
            load.rejection().is_none(),
            "a file that parses clears the rejection, or the surface reports a stale one \
             forever"
        );
    }

    /// Component (p) before component (q). The router exists with ABAC wired and no provider
    /// registered, which is the router a composition root registers into (I-078).
    #[test]
    fn the_router_is_built_with_no_provider_registered() {
        let root = temp_root("router");
        let state = AppState::new(policy_in(&root)).expect("state");
        assert!(
            state.router.merged_tool_list().is_empty(),
            "registration is component (q) and belongs to the composition root, not here. An \
             empty catalogue is what a router with ABAC wired and no provider looks like."
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
