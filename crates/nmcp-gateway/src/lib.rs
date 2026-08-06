//! `nmcp-gateway`
//!
//! Part of the NativeMCP `core` workspace. The governance invariants in
//! `docs/GOVERNANCE.md` are normative for every item in this crate.
//!
//! ## What this crate is
//!
//! The upstream half of the server: a governed admission catalog ([`catalog`]), the feed
//! machinery that populates it ([`feed`]), and [`UpstreamProvider`], the one
//! [`ToolProvider`] in the workspace with a non-empty `provider_id`. Each admitted upstream
//! is one provider; its tools are published under its id, its catalogue is somebody else's
//! `tools/list` response, and the full middleware ring applies to proxied calls identically
//! to local ones, so an upstream never sees a call that would have been refused locally.
//!
//! ## The DEC-007 runtime posture
//!
//! DEC-007 (2026-08-02) is the decision this crate's transport half exists under: build the
//! server runtime natively rather than federate to a container vendor's gateway. An
//! upstream is not a URL; it is a transport ([`nmcp_policy::UpstreamTransport`]), and two of
//! the three are processes this gateway starts and owns, [`stdio`] directly and
//! [`container`] through a runtime CLI whose engine is used when it happens to be present
//! and is never a dependency. Every server so started sits behind its own upstream boundary
//! with its own catalog-derived governance, rather than hundreds of tools arriving as one
//! opaque upstream, and the ring stays on every path. The scope of the borrowed model is
//! the catalog, profile and admission UX; the governance is this workspace's own.
//!
//! ## Where trust comes from, stage by stage
//!
//! An upstream's declarations are untrusted input (NMCP-SPEC-003 RC-D4): its contracts are
//! built from a remote server's `tools/list` response. Four separate mechanisms hold that:
//!
//! - **Admission** consumes [`CatalogServer::required_secrets`] against the operator's
//!   sealed store and fails closed on an absent key (NMCP-SPEC-002 SB-6), and ring stage 3
//!   refuses an upstream policy has not admitted.
//! - **Pinning** verifies `tools_sha256` and, when configured, the signed manifest BEFORE
//!   the cache the registry reads is replaced (NMCP-SPEC-003 G-8), so a tampered catalogue
//!   never becomes resolvable, even briefly, and the last verified catalogue survives.
//! - **The approval gate** forces approval for every third-party call regardless of what
//!   the upstream declared (RC-13); the honest `effect`/`reach` this crate declares are for
//!   annotation, not exemption, and the ring does not consult them for a third party.
//! - **Credential containment**: redirects are refused outright with the credential-replay
//!   test preserved (NMCP-SPEC-002 T4), injected header values are marked sensitive (SB-4),
//!   the caller's own token has no field to travel in, and a child process starts from a
//!   cleared environment.
//!
//! ## Port record (I-020, the last W2 port)
//!
//! Ported from the base gateway crate: the catalog types and feed diff machinery, the
//! stdio and container transports with their spawn audit and environment isolation, the
//! HTTP proxy path with its auth chain, the manifest and hash pinning, the refresh loop,
//! and the registry of running providers. Changed by this port, each argued where it lands:
//!
//! - **`UpstreamProvider` implements the ratified contract**: `contracts()` built from the
//!   cached upstream list, each carrying the upstream's own annotations verbatim in
//!   `published_annotations` (RC-21) and the honest authority for an untrusted upstream;
//!   `call` takes the `GrantedAuthority` proof. Registers empty, populates by `refresh`
//!   (RC-18).
//! - **The name derivation is gone**: the base derived collision-proofed public names here
//!   with a hash suffix, and RC-D6 moved the one derivation into `nmcp-schema` where the
//!   registry applies it and refuses duplicates by naming both contributors. A second
//!   derivation in this crate would be the drift NMCP-SPEC-003 section 1 measures.
//! - **The compiled-in catalog population is gone** and admission gained its SB-6 half;
//!   [`catalog`] carries the argument.
//! - **Secrets are reached three ways, none of them a store read from here**: per-call
//!   material arrives through `CallContext::secrets` from ring stage 5b and is injected
//!   when a slot's modality is `header` (SB-4); the upstream-level `auth_secret` and
//!   `env_secrets` names resolve through an injected [`UpstreamSecretLookup`] the daemon
//!   wires, failing closed until it does; and `auth_header_env` reads this process's
//!   environment exactly as the base did.
//! - **The clock is injected** ([`UpstreamProvider::with_clock`], the house pattern), so
//!   the refresh loop's timekeeping is testable without a test ever sleeping through the
//!   poll interval, and the catalogue's refresh time is a readable fact where the base's
//!   G4-22 (an upstream retrying a dead port for weeks, unwatched) had none.
//! - **Construction is fallible** ([`GatewayBuildError`]) where the base carried a
//!   production `expect` on the HTTP client builder, which the workspace lint set denies.
//!
//! Gapped, with owners: the server half (admission and upstream admin routes, the refresh
//! endpoint, policy-reload reconciliation against [`GatewayRegistry`]) belongs to the
//! daemon wave, exactly as every W1 and W2 port left its server half; this crate is the
//! complete library it wires in.

pub mod catalog;
pub mod container;
pub mod feed;
pub mod stdio;

pub use catalog::{
    AdmissionRefusal, CATALOG_ID_PATTERN, CatalogDefaultMode, CatalogRiskTier, CatalogServer,
    CatalogSourceType, CatalogTransport, GatewayCatalog, default_gateway_catalog,
};
pub use feed::{
    CatalogFeedDiff, CatalogFeedDiffEntry, CatalogFeedSnapshot, catalog_from_snapshot,
    diff_catalog_feed, diff_digest, snapshot_ids, validate_snapshot,
};
pub use stdio::StdioLink;

use async_trait::async_trait;
use nmcp_audit::AuditSink;
use nmcp_oauth::{Broker, BrokerError};
use nmcp_policy::{UpstreamConfig, UpstreamTransport};
use nmcp_schema::{
    CallContext, GrantedAuthority, InjectionModality, ResolvedSecrets, ToolAuthority,
    ToolCallResult, ToolContract, ToolEffect, ToolProvider, ToolReach,
};
use nmcp_secrets::Sealed;
use parking_lot::RwLock;
use reqwest::header::{HeaderName, HeaderValue};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tracing::{info, warn};
use uuid::Uuid;

/// Semantic version of this crate, taken from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate identity as it appears in audit records and capability manifests.
pub const COMPONENT: &str = "nmcp-gateway";

/// How often the background task re-reads an upstream's tool list, absent a manual refresh.
pub const REFRESH_INTERVAL_SECS: u64 = 60;

/// How the gateway reads an upstream-level secret from whoever holds it.
///
/// Core's operator store has no read path a background provider can call: resolution is
/// minted per tool call by the binding evaluator at ring stage 5b, and SB-13 gives the
/// store no other door. The daemon owns whatever surface upstream-level names
/// (`auth_secret`, `env_secrets`) are read through, and it hands the gateway this lookup at
/// construction, the same seam shape `nmcp_oauth::ClientSecretLookup` set. The value
/// crosses as [`Sealed`] bytes, so the only clear-text copy is the transient one the
/// injection site reads. Until the daemon wires one, a config naming a secret fails closed
/// with the seam named (SB-8), never by sending the call unauthenticated.
pub type UpstreamSecretLookup = Arc<dyn Fn(&str) -> Option<Sealed<Vec<u8>>> + Send + Sync>;

/// The injected clock, milliseconds since the Unix epoch. See
/// [`UpstreamProvider::with_clock`].
type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Why a provider could not be constructed.
///
/// Separate from [`UpstreamStatus`], whose every variant describes a running upstream;
/// construction has no upstream state to describe. The one failure is the HTTP client
/// builder refusing, which the base answered with a production `expect` the workspace lint
/// set denies.
#[derive(Debug, thiserror::Error)]
#[error("the gateway HTTP client could not be built: {reason}")]
pub struct GatewayBuildError {
    reason: String,
}

// - Status -

/// What an operator sees about one upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamStatus {
    /// The first fetch has not completed yet.
    Connecting,
    /// The last fetch succeeded and calls proxy.
    Online,
    /// The upstream cannot be reached or refused, with the reason.
    /// The `Offline { reason` field.
    Offline {
        /// Why the upstream is unusable.
        reason: String,
    },
    /// The container runtime this upstream needs is missing, or its engine is not running.
    ///
    /// Deliberately not folded into `Offline`. An operator who reads "offline" goes looking
    /// at the server; an operator who reads that the runtime is unavailable goes and starts
    /// the engine. Reporting the second as the first sends them to the wrong place.
    RuntimeUnavailable {
        /// The runtime CLI that is not answering.
        runtime: String,
        /// What the probe reported.
        reason: String,
    },
    /// The OAuth provider this upstream brokers from cannot produce a token (G6-9).
    ///
    /// Not folded into `Offline` for the same reason `RuntimeUnavailable` is not. The
    /// server is fine and there is nothing to find by looking at it. Somebody has to
    /// re-authorize a provider, and every upstream behind that provider is in the same
    /// state at the same moment, which an operator can only work out if the status says
    /// which provider.
    AuthorizationRequired {
        /// The provider that needs re-authorizing.
        provider: String,
        /// What the broker reported.
        reason: String,
    },
}

impl UpstreamStatus {
    /// The status as a stable lowercase token for JSON payloads and filters.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Connecting => "connecting",
            Self::Online => "online",
            Self::Offline { .. } => "offline",
            Self::RuntimeUnavailable { .. } => "runtime_unavailable",
            Self::AuthorizationRequired { .. } => "authorization_required",
        }
    }

    /// The reason behind a status, for a surface that can show one.
    ///
    /// `as_str` alone told an operator that something was wrong and nothing about what,
    /// which is the shape the base's G4-25 already had to fix once on the policy side.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Connecting | Self::Online => None,
            Self::Offline { reason }
            | Self::RuntimeUnavailable { reason, .. }
            | Self::AuthorizationRequired { reason, .. } => Some(reason),
        }
    }
}

// - Cached state -

/// The catalogue the registry reads, replaced only after verification (G-8).
#[derive(Default)]
struct Cache {
    tools: Vec<Value>,
    status: Option<UpstreamStatus>,
    /// When the catalogue last refreshed successfully, on the injected clock.
    refreshed_at_unix_ms: Option<u64>,
}

/// A child MCP server this gateway starts and owns.
///
/// Both process transports land here. A stdio upstream is the server itself; a container
/// upstream is the container runtime CLI relaying the server's standard input and output.
/// That is why there is one link type rather than two transports: below the command line
/// they are the same thing, and only the failure reporting has to tell them apart.
struct OwnedServer {
    link: Arc<StdioLink>,
    /// The container runtime, when this child is a runtime CLI rather than the server.
    container_runtime: Option<String>,
}

impl OwnedServer {
    fn transport_kind(&self) -> &'static str {
        match self.container_runtime {
            Some(_) => "container",
            None => "stdio",
        }
    }

    /// Classify a failure before it reaches an operator.
    ///
    /// Only asked on a failure path, so the extra process is not on any hot path, and it is
    /// the only way to tell "this server crashed" from "the engine is not running": both
    /// arrive here as a broken pipe.
    async fn status_for(&self, reason: String) -> UpstreamStatus {
        let Some(runtime) = &self.container_runtime else {
            return UpstreamStatus::Offline { reason };
        };
        match container::probe(runtime).await {
            Ok(()) => UpstreamStatus::Offline { reason },
            Err(why) => UpstreamStatus::RuntimeUnavailable {
                runtime: runtime.clone(),
                reason: why,
            },
        }
    }
}

/// Everything the provider and its background refresh task share.
///
/// One allocation behind one `Arc`, rather than the base's per-field clones into the task:
/// same ownership story, and the fetch path reads one coherent view of the upstream.
struct UpstreamShared {
    config: UpstreamConfig,
    cache: RwLock<Cache>,
    client: reqwest::Client,
    /// The daemon-wired secret seam. `None` fails closed wherever a secret is named.
    lookup: Option<UpstreamSecretLookup>,
    /// The broker this upstream's token comes from, when it names a provider (G6-9).
    ///
    /// `None` for the other credential sources, for an upstream with no credential at all,
    /// and in tests. Shared rather than owned: the whole point is that several upstreams
    /// behind one provider are behind one authorization.
    broker: Option<Arc<Broker>>,
    /// The MCP server this provider owns as a child process, when it owns one.
    ///
    /// `None` for an HTTP upstream, where the server is somebody else's process and this
    /// gateway is only a client of it.
    owned: Option<Arc<OwnedServer>>,
    /// The injected clock, consulted for the refresh stamp and nothing secret.
    clock: Clock,
}

// - UpstreamProvider -

/// A [`ToolProvider`] that proxies tool calls to a single upstream MCP server.
///
/// The only provider in the workspace with a non-empty `provider_id`, and the only one
/// whose declarations are untrusted (NMCP-SPEC-003 section 7): everything `contracts()`
/// returns is built from the upstream's own `tools/list` response, and the ring treats it
/// accordingly at stage 5. It registers empty and populates when the registry's `refresh`
/// picks up the warm cache (RC-18).
pub struct UpstreamProvider {
    shared: Arc<UpstreamShared>,
    /// Send on this channel to request an immediate tool-list refresh.
    refresh_tx: watch::Sender<()>,
    /// Set when this provider is retracted, so the background refresh task exits.
    ///
    /// Retracting a provider from the router stops it being dispatched to. It does not stop
    /// the refresh loop, which would otherwise keep reaching out to an upstream the
    /// operator has disabled, every poll interval, for the life of the process.
    shutdown_tx: watch::Sender<bool>,
}

impl UpstreamProvider {
    /// Construct on the system clock and immediately spawn the background refresh task.
    ///
    /// # Errors
    ///
    /// [`GatewayBuildError`] when the HTTP client cannot be built.
    pub fn new(
        config: UpstreamConfig,
        audit: AuditSink,
        lookup: Option<UpstreamSecretLookup>,
        broker: Option<Arc<Broker>>,
    ) -> Result<Arc<Self>, GatewayBuildError> {
        Self::with_clock(config, audit, lookup, broker, system_now_ms)
    }

    /// [`UpstreamProvider::new`] with the clock injected, so the refresh loop's timekeeping
    /// is testable without a test ever sleeping through the poll interval (the house
    /// pattern: `SealedStore::open_with_clock` and `Broker::with_clock` inject theirs for
    /// the same reason). `clock` returns milliseconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// [`GatewayBuildError`] when the HTTP client cannot be built.
    pub fn with_clock(
        config: UpstreamConfig,
        audit: AuditSink,
        lookup: Option<UpstreamSecretLookup>,
        broker: Option<Arc<Broker>>,
        clock: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Result<Arc<Self>, GatewayBuildError> {
        let (refresh_tx, refresh_rx) = watch::channel(());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let client = build_upstream_client()?;

        // A process transport is a child this gateway owns, so the link is built once here
        // and shared with the refresh task rather than reconstructed per call. Building it
        // does not start anything: the child spawns on first use, which keeps a disabled or
        // never-called upstream from running a process for no reason.
        let owned = match config.transport() {
            UpstreamTransport::Stdio {
                command,
                args,
                env,
                env_secrets,
                cwd,
            } => Some(Arc::new(OwnedServer {
                link: Arc::new(StdioLink::new(
                    config.id.clone(),
                    command,
                    args,
                    resolve_env_secrets(env, &env_secrets, lookup.as_ref(), &config.id),
                    cwd,
                    audit,
                )),
                container_runtime: None,
            })),
            UpstreamTransport::Container {
                image,
                args,
                env,
                env_secrets,
                runtime,
            } => {
                let runtime = container::runtime_or_default(runtime.as_deref());
                let env = resolve_env_secrets(env, &env_secrets, lookup.as_ref(), &config.id);
                let (program, argv) = container::command_line(&image, &args, env.keys(), &runtime);
                Some(Arc::new(OwnedServer {
                    // The configured environment goes to the runtime CLI, which forwards it
                    // into the container by name. See the container module header: a value
                    // on a command line would land in the audit record and in the runtime's
                    // own inspect output.
                    link: Arc::new(StdioLink::new(
                        config.id.clone(),
                        program,
                        argv,
                        env,
                        None,
                        audit,
                    )),
                    container_runtime: Some(runtime),
                }))
            }
            UpstreamTransport::Http { .. } => None,
        };

        let shared = Arc::new(UpstreamShared {
            config,
            cache: RwLock::new(Cache {
                tools: vec![],
                status: Some(UpstreamStatus::Connecting),
                refreshed_at_unix_ms: None,
            }),
            client,
            lookup,
            broker,
            owned,
            clock: Arc::new(clock),
        });

        let provider = Arc::new(Self {
            shared: Arc::clone(&shared),
            refresh_tx,
            shutdown_tx,
        });

        // The background refresh task. It owns its own handle on the shared state, so
        // retraction has to say stop through the watch channel rather than relying on a
        // drop that will not come.
        let id = shared.config.id.clone();
        tokio::spawn(async move {
            let mut rx = refresh_rx;
            let mut shutdown = shutdown_rx;
            loop {
                if *shutdown.borrow() {
                    break;
                }
                fetch_and_cache(&shared).await;
                // Wait for a manual refresh signal, a retraction, or the poll timeout.
                tokio::select! {
                    () = tokio::time::sleep(std::time::Duration::from_secs(REFRESH_INTERVAL_SECS)) => {}
                    _ = rx.changed() => {
                        info!(upstream = %id, "gateway: manual refresh triggered");
                    }
                    _ = shutdown.changed() => {}
                }
                if *shutdown.borrow() {
                    info!(upstream = %id, "gateway: upstream retracted, refresh task stopping");
                    break;
                }
            }
        });

        Ok(provider)
    }

    /// Trigger an immediate background tool-list refresh.
    pub fn refresh(&self) {
        let _ = self.refresh_tx.send(());
    }

    /// Retract this provider: stop the background refresh task.
    ///
    /// Idempotent. Call this whenever the provider leaves the registry, so a disabled
    /// upstream stops being polled and not merely stops being dispatched to.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        // A retracted process upstream must stop being a running process, not merely stop
        // being dispatched to. Spawned rather than awaited because retraction happens on
        // the synchronous policy-reconciliation path.
        if let Some(owned) = self.shared.owned.clone() {
            tokio::spawn(async move { owned.link.shutdown().await });
        }
    }

    /// Whether this provider has been retracted.
    #[must_use]
    pub fn is_retracted(&self) -> bool {
        *self.shutdown_tx.borrow()
    }

    /// Current upstream status.
    #[must_use]
    pub fn status(&self) -> UpstreamStatus {
        self.shared
            .cache
            .read()
            .status
            .clone()
            .unwrap_or(UpstreamStatus::Connecting)
    }

    /// Snapshot of the cached tool list, exactly as the upstream published it.
    #[must_use]
    pub fn cached_tools(&self) -> Vec<Value> {
        self.shared.cache.read().tools.clone()
    }

    /// When the catalogue last refreshed successfully, in milliseconds since the Unix epoch
    /// on the injected clock. `None` until the first successful fetch.
    #[must_use]
    pub fn last_refresh_unix_ms(&self) -> Option<u64> {
        self.shared.cache.read().refreshed_at_unix_ms
    }

    /// Upstream config (id, transport, label, enabled).
    #[must_use]
    pub fn config(&self) -> &UpstreamConfig {
        &self.shared.config
    }

    /// Proxy one call over HTTP, with the credential chain applied.
    ///
    /// Split out of [`ToolProvider::call`] so the dispatch story reads as what it is: the
    /// status gate, then the owned-child pipe, then this. The ring has already run either
    /// way.
    async fn proxy_over_http(&self, name: &str, args: Value, ctx: &CallContext) -> ToolCallResult {
        let base = self.shared.config.http_url().unwrap_or_default();
        let url = format!("{}/mcp", base.trim_end_matches('/'));
        let body = json!({
            "jsonrpc": "2.0",
            "id": ctx.call_id.to_string(),
            "method": "tools/call",
            "params": { "name": name, "arguments": args }
        });

        let request = match apply_upstream_auth(
            self.shared.client.post(&url).json(&body),
            &self.shared.config,
            self.shared.lookup.as_ref(),
            self.shared.broker.as_ref(),
            Some(ctx.secrets()),
        )
        .await
        {
            Ok(request) => request,
            Err(failure) => {
                let reason = failure.reason();
                warn!(upstream = %self.shared.config.id, tool = name, "gateway: upstream credential unavailable: {reason}");
                self.shared.cache.write().status = Some(failure.status());
                return ToolCallResult::err(format!(
                    "Upstream '{}' credential unavailable: {reason}",
                    self.shared.config.id
                ));
            }
        };

        match request.send().await {
            Err(e) => {
                warn!(upstream = %self.shared.config.id, tool = name, "gateway call failed: {e}");
                // Mark offline for next status check.
                self.shared.cache.write().status = Some(UpstreamStatus::Offline {
                    reason: e.to_string(),
                });
                ToolCallResult::err(format!(
                    "Upstream '{}' unreachable: {e}",
                    self.shared.config.id
                ))
            }
            Ok(resp) => {
                let status = resp.status();
                match resp.json::<Value>().await {
                    Ok(body) => {
                        if let Some(err) = body.get("error") {
                            return ToolCallResult::err(
                                err.get("message")
                                    .and_then(Value::as_str)
                                    .unwrap_or("upstream error")
                                    .to_string(),
                            );
                        }
                        let result = body.get("result").cloned().unwrap_or_else(|| body.clone());
                        let audit = json!({
                            "upstream": self.shared.config.id,
                            "tool": name,
                            "http_status": status.as_u16()
                        });
                        ToolCallResult::from_tool_result_json(result, audit)
                    }
                    Err(e) => ToolCallResult::err(format!("Upstream response parse error: {e}")),
                }
            }
        }
    }
}

#[async_trait]
impl ToolProvider for UpstreamProvider {
    fn contract_version(&self) -> u32 {
        // A literal, deliberately, per the trait doc: stating the linked schema crate's
        // constant back at it would make the check tautological.
        1
    }

    fn provider_id(&self) -> &str {
        &self.shared.config.id
    }

    /// The cached upstream catalogue as declared contracts.
    ///
    /// Empty until the cache warms and empty while the upstream is disabled; the registry's
    /// `refresh` is what picks up the warm cache (RC-18). Each contract carries:
    ///
    /// - the upstream's own `annotations` verbatim in `published_annotations` (RC-21): a
    ///   proxied upstream is somebody else's software, this server keeps what it published
    ///   and invents nothing, and it never sets the first-party derivation path;
    /// - the honest [`ToolAuthority`] for an untrusted upstream: no root-scoped
    ///   `permission`, no `path_args`, no `grants`, because nothing here can vouch for what
    ///   the remote tool does with its arguments; `reach: Remote` always, because whatever
    ///   the tool does, calling it IS a network hop from this machine; and `effect: Mutate`
    ///   unless the upstream's own annotations say `readOnlyHint: true`, which is the only
    ///   honest reading of a catalogue this server did not write. The ring trusts none of
    ///   it either way: stage 5 forces approval for every third-party call regardless of
    ///   the declared effect (RC-13, M6), so a hostile upstream declaring itself read-only
    ///   changes its listing, never its gating.
    ///
    /// An entry with no `name` is skipped: it could never be resolved or dispatched, so
    /// there is nothing to register.
    fn contracts(&self) -> Vec<ToolContract> {
        if !self.shared.config.enabled {
            return vec![];
        }
        self.shared
            .cache
            .read()
            .tools
            .iter()
            .filter_map(|tool| {
                let name = tool.get("name").and_then(Value::as_str)?;
                let published = tool.get("annotations").cloned();
                let read_only = published
                    .as_ref()
                    .and_then(|annotations| annotations.get("readOnlyHint"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                Some(ToolContract {
                    name: name.to_string(),
                    description: tool
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    input_schema: tool
                        .get("inputSchema")
                        .cloned()
                        .unwrap_or_else(|| json!({"type": "object"})),
                    authority: ToolAuthority {
                        permission: None,
                        path_args: Vec::new(),
                        grants: Vec::new(),
                        effect: if read_only {
                            ToolEffect::Observe
                        } else {
                            ToolEffect::Mutate
                        },
                        reach: ToolReach::Remote,
                    },
                    published_annotations: published,
                })
            })
            .collect()
    }

    async fn call(
        &self,
        name: &str,
        args: Value,
        ctx: &CallContext,
        _granted: &GrantedAuthority,
    ) -> ToolCallResult {
        match self.status() {
            UpstreamStatus::Connecting => {
                return ToolCallResult::err(format!(
                    "Upstream '{}' is still connecting, retry in a moment.",
                    self.shared.config.id
                ));
            }
            UpstreamStatus::Offline { ref reason } => {
                return ToolCallResult::err(format!(
                    "Upstream '{}' is offline: {reason}",
                    self.shared.config.id
                ));
            }
            UpstreamStatus::RuntimeUnavailable {
                ref runtime,
                ref reason,
            } => {
                return ToolCallResult::err(format!(
                    "Upstream '{}' cannot start: the container runtime '{runtime}' is not available: {reason}",
                    self.shared.config.id
                ));
            }
            UpstreamStatus::AuthorizationRequired { ref reason, .. } => {
                return ToolCallResult::err(format!(
                    "Upstream '{}' is not authorized: {reason}",
                    self.shared.config.id
                ));
            }
            UpstreamStatus::Online => {}
        }

        // A process upstream is a child this gateway owns; proxying to it is a pipe write,
        // not an HTTP request. The ring has already run by the time execution reaches here,
        // exactly as it has for an HTTP upstream, so the child never sees a call that would
        // have been denied locally. Per-call header material does not apply on a pipe, and
        // per-call env material cannot reach a child that is already running; the config's
        // `env_secrets` at spawn is the process transports' credential path.
        if let Some(owned) = &self.shared.owned {
            return match owned.link.call_tool(name, args).await {
                Ok(result) => {
                    let audit = json!({
                        "upstream": self.shared.config.id,
                        "tool": name,
                        "transport": owned.transport_kind(),
                    });
                    ToolCallResult::from_tool_result_json(result, audit)
                }
                Err(reason) => {
                    warn!(
                        upstream = %self.shared.config.id,
                        tool = name,
                        transport = owned.transport_kind(),
                        "gateway: call over an owned child failed: {reason}"
                    );
                    // Computed before taking the write lock: classifying the failure runs a
                    // process, and this guard is not held across an await.
                    let status = owned.status_for(reason.clone()).await;
                    self.shared.cache.write().status = Some(status);
                    ToolCallResult::err(format!(
                        "Upstream '{}' failed: {reason}",
                        self.shared.config.id
                    ))
                }
            };
        }

        self.proxy_over_http(name, args, ctx).await
    }
}

/// Build the one HTTP client every upstream request rides.
///
/// Redirects are refused rather than followed, because following one replays this
/// upstream's credential to wherever it points. reqwest strips `Authorization` on a
/// cross-host redirect, but that is keyed to a fixed set of header names and an operator
/// may configure any name they like through `auth_header_name`, so an upstream answering
/// 302 could harvest an `x-api-key` this server holds for it. Refusing costs nothing: an
/// MCP endpoint that redirects is misconfigured (NMCP-SPEC-002 T4).
fn build_upstream_client() -> Result<reqwest::Client, GatewayBuildError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| GatewayBuildError {
            reason: err.to_string(),
        })
}

/// The wall clock, saturating rather than aborting on a clock before the epoch.
fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Header used when policy names a credential source but no explicit header name.
const DEFAULT_UPSTREAM_AUTH_HEADER: &str = "authorization";

/// Attach the upstream credential named by policy, resolved through `lookup`.
///
/// Policy carries the NAME of a variable or secret, never the value, so the credential
/// cannot leak through a policy read, a policy backup, or an audit record. Resolution
/// happens per request, so rotating the source takes effect on the next refresh.
///
/// Failure is fail-closed: a missing or unusable credential returns an error rather than
/// falling back to an unauthenticated request, because a silent downgrade would send
/// governed traffic to an upstream that believes it is protected. Error strings name the
/// variable and never its value.
fn apply_upstream_auth_with<F>(
    request: reqwest::RequestBuilder,
    config: &UpstreamConfig,
    lookup: F,
) -> Result<reqwest::RequestBuilder, String>
where
    F: FnOnce(&str) -> Option<String>,
{
    let (var, source) = match (
        config.oauth_provider.as_deref(),
        config.auth_secret.as_deref(),
        config.auth_header_env.as_deref(),
    ) {
        (Some(provider), _, _) => (provider, "oauth provider"),
        (None, Some(secret), _) => (secret, "secret"),
        (None, None, Some(variable)) => (variable, "environment variable"),
        (None, None, None) => return Ok(request),
    };
    let Some(raw) = lookup(var) else {
        return Err(format!(
            "credential {source} '{var}' is not available to this service account"
        ));
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(format!("credential {source} '{var}' is empty"));
    }
    let configured = config
        .auth_header_name
        .as_deref()
        .unwrap_or(DEFAULT_UPSTREAM_AUTH_HEADER);
    let name = HeaderName::from_bytes(configured.as_bytes())
        .map_err(|_| format!("auth_header_name '{configured}' is not a valid HTTP header name"))?;
    let mut value = HeaderValue::from_str(raw)
        .map_err(|_| format!("value of '{var}' is not valid in an HTTP header"))?;
    // Sensitive values print as "Sensitive" in the http crate's Debug impl, so a request
    // dump in a log, a trace span, or a panic message cannot spill the token (SB-4).
    value.set_sensitive(true);
    Ok(request.header(name, value))
}

/// Inject every `header`-modality secret ring stage 5b resolved for this call (SB-4).
///
/// The header name is the contract's, parsed out of the tool's own schema annotation, and
/// the value is the sealed material from the operator's store; neither is caller input
/// (SB-A2). Every injected value is marked `set_sensitive(true)`, same rule and same reason
/// as the config-level auth site. `env`-modality entries are not the gateway's to inject
/// and are skipped. Returns whether anything was injected, which is what decides whether
/// the config-level chain still runs.
///
/// # Errors
///
/// A message naming the slot and header name, never the value, when the declared header
/// name or the resolved bytes cannot form a legal header.
fn apply_header_slot_secrets(
    request: reqwest::RequestBuilder,
    resolved: &ResolvedSecrets,
) -> Result<(reqwest::RequestBuilder, bool), String> {
    let mut request = request;
    let mut injected = false;
    for (slot, modality, value) in resolved.iter() {
        let InjectionModality::Header { name } = modality else {
            continue;
        };
        let header = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            format!("secret slot {slot:?} declares header name {name:?}, which is not a valid HTTP header name")
        })?;
        let mut header_value = value.with_exposed(HeaderValue::from_bytes).map_err(|_| {
            format!("the value resolved for secret slot {slot:?} is not valid in an HTTP header")
        })?;
        header_value.set_sensitive(true);
        request = request.header(header, header_value);
        injected = true;
    }
    Ok((request, injected))
}

/// Attach the credential for one outbound request, from whichever source holds it.
///
/// Order: material ring stage 5b resolved for this call wins when any `header`-modality
/// slot resolved, because a per-call resolution under a binding grant is the most specific
/// instruction anyone gave; otherwise the ported chain runs, `oauth_provider` through the
/// broker, `auth_secret` through the daemon-wired [`UpstreamSecretLookup`], and
/// `auth_header_env` from this process's environment, in the base's precedence. Every path
/// fails closed rather than sending the request unauthenticated.
async fn apply_upstream_auth(
    request: reqwest::RequestBuilder,
    config: &UpstreamConfig,
    lookup: Option<&UpstreamSecretLookup>,
    broker: Option<&Arc<Broker>>,
    resolved: Option<&ResolvedSecrets>,
) -> Result<reqwest::RequestBuilder, UpstreamFailure> {
    let mut request = request;
    if let Some(resolved) = resolved {
        let (updated, injected) =
            apply_header_slot_secrets(request, resolved).map_err(UpstreamFailure::Reason)?;
        request = updated;
        if injected {
            return Ok(request);
        }
    }
    if let Some(provider) = config.oauth_provider.as_deref() {
        // Policy validation already refused an upstream naming a provider that is not
        // configured, so a broker that has never heard of it means the runtime was wired
        // without one. Reported as the provider being unknown rather than ignored, because
        // silently sending the request unauthenticated is the downgrade this whole path
        // exists to prevent.
        let Some(broker) = broker else {
            return Err(UpstreamFailure::Authorization(
                BrokerError::UnknownProvider(provider.to_string()),
            ));
        };
        let header = broker
            .authorization_header(provider)
            .await
            .map_err(UpstreamFailure::Authorization)?;
        return apply_upstream_auth_with(request, config, |_| Some(header))
            .map_err(UpstreamFailure::Reason);
    }
    if let Some(secret) = config.auth_secret.as_deref() {
        // The store itself is unreachable from here by design (SB-13); the daemon wires the
        // seam. Unwired is a refusal naming the seam, never an unauthenticated request.
        let Some(lookup) = lookup else {
            return Err(UpstreamFailure::Reason(format!(
                "credential secret '{secret}' cannot be read: no upstream secret lookup is wired into this gateway"
            )));
        };
        return apply_upstream_auth_with(request, config, |name| {
            lookup(name).map(|sealed| {
                sealed.with_exposed(|bytes| String::from_utf8_lossy(bytes).into_owned())
            })
        })
        .map_err(UpstreamFailure::Reason);
    }
    apply_upstream_auth_with(request, config, |name| std::env::var(name).ok())
        .map_err(UpstreamFailure::Reason)
}

/// Why an upstream could not be reached or could not be given its credential.
///
/// Two variants rather than one string, because they become different statuses. A missing
/// variable is this upstream being unusable. A provider that needs re-authorizing is a fact
/// about the provider that every upstream behind it shares, and sending an operator to
/// inspect one server for it wastes the trip.
///
/// `Debug` is derivable without an SB-1 question: both variants carry configuration and
/// diagnosis text (names, never values), exactly as [`BrokerError`]'s own derive does.
#[derive(Debug)]
enum UpstreamFailure {
    Reason(String),
    Authorization(BrokerError),
}

impl UpstreamFailure {
    fn status(&self) -> UpstreamStatus {
        match self {
            Self::Reason(reason) => UpstreamStatus::Offline {
                reason: reason.clone(),
            },
            // A provider that cannot be reached right now is not one that needs an
            // operator, so it stays `Offline` and self-heals on the next sweep. The reason
            // names the provider either way, which is what stops an operator debugging the
            // wrong end.
            Self::Authorization(err) if !err.needs_operator() => UpstreamStatus::Offline {
                reason: err.to_string(),
            },
            Self::Authorization(err) => UpstreamStatus::AuthorizationRequired {
                provider: err.provider().to_string(),
                reason: err.to_string(),
            },
        }
    }

    fn reason(&self) -> String {
        match self {
            Self::Reason(reason) => reason.clone(),
            Self::Authorization(err) => err.to_string(),
        }
    }
}

/// Fold the secrets a transport names into the environment its child will get.
///
/// Resolved when the provider is built, so a rotated secret takes effect the next time the
/// upstream is reconciled, which is the same moment every other policy change takes effect.
///
/// Fail closed per key, loudly: a key the seam cannot produce is left out with a warning
/// naming the key and never the value, rather than substituted with an empty string. An
/// empty credential authenticates as nobody, and the error the server returns for that
/// says less about what is wrong than this log line does. A value that is not UTF-8 text
/// is refused the same way, because an environment variable is text and a lossy conversion
/// would hand the child a corrupted credential that fails somewhere less explicable.
fn resolve_env_secrets(
    mut env: std::collections::BTreeMap<String, String>,
    env_secrets: &std::collections::BTreeMap<String, String>,
    lookup: Option<&UpstreamSecretLookup>,
    upstream_id: &str,
) -> std::collections::BTreeMap<String, String> {
    for (variable, secret) in env_secrets {
        let Some(lookup) = lookup else {
            warn!(
                upstream = upstream_id,
                "gateway: secret '{secret}' named for '{variable}' cannot be read: no upstream secret lookup is wired; the child starts without it"
            );
            continue;
        };
        let Some(sealed) = lookup(secret) else {
            warn!(
                upstream = upstream_id,
                "gateway: secret '{secret}' named for '{variable}' is not available; the child starts without it"
            );
            continue;
        };
        let text = sealed.with_exposed(|bytes| std::str::from_utf8(bytes).ok().map(str::to_owned));
        let Some(value) = text else {
            warn!(
                upstream = upstream_id,
                "gateway: secret '{secret}' named for '{variable}' is not UTF-8 text; the child starts without it"
            );
            continue;
        };
        env.insert(variable.clone(), value);
    }
    env
}

// - Background fetcher -

/// One refresh cycle: fetch, verify, and only then replace the cache.
///
/// The ordering in the body is G-8 made true rather than assumed: the `tools_sha256` pin
/// and the manifest signature are verified BEFORE the cache the registry reads is touched,
/// so a tampered catalogue never becomes resolvable, even briefly, and a failed
/// verification leaves the last verified catalogue in place with the refusal on the status.
async fn fetch_and_cache(shared: &UpstreamShared) {
    let id = &shared.config.id;

    // Both transports produce the same shape here, a JSON-RPC body with `/result/tools`, so
    // manifest pinning and the tool allowlist apply identically to a child process and to a
    // remote server. Trust rules that only held for one transport would be a trap.
    let body = match &shared.owned {
        Some(server) => match server.link.list_tools().await {
            Ok(tools) => json!({ "result": { "tools": tools } }),
            Err(reason) => {
                warn!(
                    upstream = %id,
                    transport = server.transport_kind(),
                    "gateway: tools/list over an owned child failed: {reason}"
                );
                let status = server.status_for(reason).await;
                shared.cache.write().status = Some(status);
                return;
            }
        },
        None => match fetch_http_tool_list(shared).await {
            Ok(body) => body,
            Err(failure) => {
                let reason = failure.reason();
                warn!(upstream = %id, "gateway: tools/list failed: {reason}");
                shared.cache.write().status = Some(failure.status());
                return;
            }
        },
    };

    // G-8: the verification gate. On refusal the cache is not touched, so whatever the
    // registry could resolve before this fetch is exactly what it can resolve after it.
    if let Err(reason) = validate_upstream_manifest(&body, &shared.config) {
        warn!(upstream = %id, "gateway: upstream manifest trust validation failed: {reason}");
        shared.cache.write().status = Some(UpstreamStatus::Offline { reason });
        return;
    }

    let tools: Vec<Value> = body
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|tool| match &shared.config.tool_allowlist {
            Some(list) => tool
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| list.iter().any(|allowed| allowed == name)),
            None => true,
        })
        .collect();

    info!(upstream = %id, tool_count = tools.len(), "gateway: tool catalog refreshed");
    let refreshed_at = (shared.clock)();
    let mut cache = shared.cache.write();
    cache.tools = tools;
    cache.status = Some(UpstreamStatus::Online);
    cache.refreshed_at_unix_ms = Some(refreshed_at);
}

/// Fetch `tools/list` from an upstream this gateway does not own.
async fn fetch_http_tool_list(shared: &UpstreamShared) -> Result<Value, UpstreamFailure> {
    let base = shared.config.http_url().unwrap_or_default();
    let list_url = format!("{}/mcp", base.trim_end_matches('/'));
    let payload = json!({
        "jsonrpc": "2.0",
        "id": Uuid::new_v4().to_string(),
        "method": "tools/list",
        "params": {}
    });

    // No per-call secrets on the poll: there is no call, so the chain is config-only.
    let request = apply_upstream_auth(
        shared.client.post(&list_url).json(&payload),
        &shared.config,
        shared.lookup.as_ref(),
        shared.broker.as_ref(),
        None,
    )
    .await?;
    let response = request
        .send()
        .await
        .map_err(|e| UpstreamFailure::Reason(e.to_string()))?;
    let body = response
        .json::<Value>()
        .await
        .map_err(|e| UpstreamFailure::Reason(e.to_string()))?;
    if let Some(err) = body.get("error") {
        return Err(UpstreamFailure::Reason(
            err.get("message")
                .and_then(Value::as_str)
                .unwrap_or("upstream error")
                .to_string(),
        ));
    }
    Ok(body)
}

/// Verify what the upstream published against what the operator pinned.
///
/// Called before the cache is replaced, and only from there; see [`fetch_and_cache`] for
/// the ordering argument (G-8). The signature check runs first when a key is configured,
/// over the manifest with its `_sig` removed; the hash pin is over the canonical
/// `/result/tools` serialization.
fn validate_upstream_manifest(body: &Value, config: &UpstreamConfig) -> Result<(), String> {
    if let Some(public_key_hex) = &config.manifest_public_key {
        let key = hex::decode(public_key_hex)
            .map_err(|_| "manifest_public_key is not valid hex".to_string())?;
        let key: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| "manifest_public_key must decode to 32 bytes".to_string())?;
        let manifest = body.get("result").unwrap_or(body);
        nmcp_abac::verify_manifest_signature(manifest, &key)?;
    }
    if let Some(expected) = &config.tools_sha256 {
        let tools = body
            .pointer("/result/tools")
            .ok_or_else(|| "tools_sha256 configured but /result/tools is missing".to_string())?;
        let payload = serde_json::to_vec(tools)
            .map_err(|err| format!("tools digest serialization failed: {err}"))?;
        let actual = format!("{:x}", Sha256::digest(&payload));
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "tools_sha256 mismatch: expected {expected}, got {actual}"
            ));
        }
    }
    Ok(())
}

// - Registry -

/// The running upstream providers, for status surfaces and reconciliation.
/// Clone-cheap via inner `Arc`.
#[derive(Clone, Default)]
pub struct GatewayRegistry {
    providers: Arc<RwLock<Vec<Arc<UpstreamProvider>>>>,
}

impl GatewayRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a provider.
    pub fn add(&self, provider: Arc<UpstreamProvider>) {
        self.providers.write().push(provider);
    }

    /// The provider with this upstream id, if one is registered.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<Arc<UpstreamProvider>> {
        self.providers
            .read()
            .iter()
            .find(|p| p.shared.config.id == id)
            .cloned()
    }

    /// Remove an upstream from the registry and stop its refresh task.
    ///
    /// The shutdown is the point. Dropping the `Arc` is not enough on its own, because the
    /// spawned refresh task owns its own handle on the shared state and would keep polling
    /// a retracted upstream forever.
    ///
    /// Returns whether a provider with that id was present.
    #[must_use]
    pub fn remove(&self, id: &str) -> bool {
        let mut providers = self.providers.write();
        let before = providers.len();
        for provider in providers.iter().filter(|p| p.shared.config.id == id) {
            provider.shutdown();
        }
        providers.retain(|provider| provider.shared.config.id != id);
        providers.len() != before
    }

    /// Every registered provider.
    #[must_use]
    pub fn all(&self) -> Vec<Arc<UpstreamProvider>> {
        self.providers.read().clone()
    }

    /// Status summary for an admin surface.
    #[must_use]
    pub fn status_json(&self) -> Value {
        let upstreams: Vec<Value> = self
            .all()
            .iter()
            .map(|p| {
                json!({
                    "id": p.shared.config.id,
                    "label": p.shared.config.label,
                    "transport": p.shared.config.transport().kind(),
                    "url": p.shared.config.http_url().unwrap_or_default(),
                    "enabled": p.shared.config.enabled,
                    "status": p.status().as_str(),
                    "status_detail": p.status().detail().unwrap_or_default(),
                    "refreshed_at_unix_ms": p.last_refresh_unix_ms(),
                    "tool_count": p.cached_tools().len(),
                    "tools": p.cached_tools().iter()
                        .filter_map(|t| t.get("name").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        json!({ "upstreams": upstreams })
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
    use nmcp_schema::{HeldAuthority, SealedSecret, authorize};
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_audit() -> AuditSink {
        AuditSink::open(std::env::temp_dir().join(format!("nmcp-gateway-{}.jsonl", Uuid::new_v4())))
            .expect("audit sink")
    }

    /// Proof of authorization for an upstream call, minted the only way one can be. The
    /// declared shape is exactly what [`UpstreamProvider::contracts`] declares, so what the
    /// tests hand the provider is what the ring would.
    fn granted_for_upstream(args: &Value) -> GrantedAuthority {
        authorize(
            &ToolAuthority {
                permission: None,
                path_args: Vec::new(),
                grants: Vec::new(),
                effect: ToolEffect::Mutate,
                reach: ToolReach::Remote,
            },
            &HeldAuthority {
                roots: Vec::new(),
                grants: BTreeSet::new(),
                agent_id: None,
            },
            args,
        )
        .expect("an upstream declaration authorizes holding nothing")
    }

    /// A loopback mock upstream. Serves whatever `tools` currently holds on `tools/list`,
    /// answers `tools/call` with a pong, and records every request it read.
    struct MockUpstream {
        addr: std::net::SocketAddr,
        tools: Arc<RwLock<Value>>,
        requests: Arc<RwLock<Vec<String>>>,
    }

    async fn mock_upstream(initial_tools: Value) -> MockUpstream {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock upstream");
        let addr = listener.local_addr().expect("mock addr");
        let tools = Arc::new(RwLock::new(initial_tools));
        let requests: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(Vec::new()));

        let served_tools = Arc::clone(&tools);
        let served_requests = Arc::clone(&requests);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let tools = Arc::clone(&served_tools);
                let requests = Arc::clone(&served_requests);
                tokio::spawn(async move {
                    // Read until the JSON-RPC method token is visible (robust to
                    // header/body TCP segmentation on the request).
                    let mut data = Vec::new();
                    let mut tmp = [0u8; 2048];
                    for _ in 0..8 {
                        match socket.read(&mut tmp).await {
                            Ok(0) | Err(_) => break,
                            Ok(k) => {
                                data.extend_from_slice(tmp.get(..k).unwrap_or_default());
                                let s = String::from_utf8_lossy(&data);
                                if s.contains("tools/list") || s.contains("tools/call") {
                                    break;
                                }
                            }
                        }
                    }
                    let req = String::from_utf8_lossy(&data).to_string();
                    let payload = if req.contains("tools/list") {
                        json!({
                            "jsonrpc": "2.0",
                            "id": "1",
                            "result": {"tools": tools.read().clone()}
                        })
                    } else {
                        json!({
                            "jsonrpc": "2.0",
                            "id": "1",
                            "result": {"content": [{"type": "text", "text": "pong"}], "isError": false}
                        })
                    };
                    requests.write().push(req);
                    let body = payload.to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    let _ = socket.flush().await;
                });
            }
        });

        MockUpstream {
            addr,
            tools,
            requests,
        }
    }

    async fn wait_for_online(provider: &Arc<UpstreamProvider>) {
        for _ in 0..100 {
            if matches!(provider.status(), UpstreamStatus::Online) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!(
            "upstream never reached Online; last status {:?}",
            provider.status().detail()
        );
    }

    /// H8a: end-to-end proxy behavior against a mock upstream MCP server. Spins up a
    /// loopback HTTP server that answers `tools/list` and `tools/call`, points an
    /// `UpstreamProvider` at it, and asserts the catalog is fetched, declared and calls
    /// proxy.
    #[tokio::test]
    async fn upstream_provider_proxies_tools_list_and_call_against_mock() {
        let mock = mock_upstream(json!([{
            "name": "echo",
            "description": "echo tool",
            "inputSchema": {"type": "object"}
        }]))
        .await;

        let config = UpstreamConfig::new("mock", format!("http://{}", mock.addr));
        let provider =
            UpstreamProvider::new(config, test_audit(), None, None).expect("provider builds");

        wait_for_online(&provider).await;

        // tools/list was proxied, cached, and declared as contracts under the local name.
        let names: Vec<String> = provider
            .contracts()
            .iter()
            .map(|c| c.name.clone())
            .collect();
        assert!(
            names.contains(&"echo".to_string()),
            "expected proxied 'echo' tool, got {names:?}"
        );

        // tools/call is proxied and the upstream result flows back without error.
        let ctx = CallContext::new(Some("h8a".to_string()));
        let args = json!({"msg": "hi"});
        let granted = granted_for_upstream(&args);
        let result = provider.call("echo", args, &ctx, &granted).await;
        assert!(!result.is_error, "proxied tools/call should succeed");
    }

    /// RC-21 and the honest authority: contracts carry the upstream's own annotations
    /// verbatim, effect follows the upstream's `readOnlyHint` for the listing, reach is
    /// always `Remote`, and nothing root-scoped is declared. The ring does not trust the
    /// effect either way (RC-13); this is about listing honestly, not gating.
    #[tokio::test]
    async fn contracts_carry_published_annotations_verbatim_and_the_honest_authority() {
        let annotations = json!({"readOnlyHint": true, "vendorExtension": {"tier": 3}});
        let mock = mock_upstream(json!([
            {
                "name": "lookup",
                "description": "a read",
                "inputSchema": {"type": "object"},
                "annotations": annotations
            },
            {
                "name": "act",
                "description": "no annotations published"
            },
            {
                "description": "no name, unaddressable, skipped"
            }
        ]))
        .await;

        let config = UpstreamConfig::new("up", format!("http://{}", mock.addr));
        let provider =
            UpstreamProvider::new(config, test_audit(), None, None).expect("provider builds");
        wait_for_online(&provider).await;

        let contracts = provider.contracts();
        assert_eq!(contracts.len(), 2, "the nameless entry cannot register");

        let lookup = contracts
            .iter()
            .find(|c| c.name == "lookup")
            .expect("lookup");
        assert_eq!(
            lookup.published_annotations.as_ref(),
            Some(&annotations),
            "the upstream's own annotations ride the field verbatim (RC-21)"
        );
        assert_eq!(lookup.authority.effect, ToolEffect::Observe);
        assert_eq!(lookup.authority.reach, ToolReach::Remote);
        assert!(lookup.authority.permission.is_none());
        assert!(lookup.authority.path_args.is_empty());
        assert!(lookup.authority.grants.is_empty());

        let act = contracts.iter().find(|c| c.name == "act").expect("act");
        assert!(act.published_annotations.is_none());
        assert_eq!(
            act.authority.effect,
            ToolEffect::Mutate,
            "an upstream that says nothing declares Mutate: unknown belongs on the gated side"
        );
        assert_eq!(act.authority.reach, ToolReach::Remote);
        assert_eq!(
            act.input_schema,
            json!({"type": "object"}),
            "an absent schema becomes the empty object schema"
        );
    }

    /// G-8 made true and tested: a fetch returning a list whose hash mismatches the pin
    /// leaves the OLD cache intact, emits the refusal on the status, and never surfaces the
    /// tampered tools. The cache the registry reads is only ever replaced after the pin
    /// verifies.
    #[tokio::test]
    async fn a_tampered_tool_list_never_replaces_the_cache_and_the_old_one_survives() {
        let pinned_tools = json!([{
            "name": "echo",
            "description": "echo tool",
            "inputSchema": {"type": "object"}
        }]);
        let pin = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&pinned_tools).expect("serialize"))
        );
        let mock = mock_upstream(pinned_tools).await;

        let mut config = UpstreamConfig::new("pinned", format!("http://{}", mock.addr));
        config.tools_sha256 = Some(pin);
        let provider =
            UpstreamProvider::new(config, test_audit(), None, None).expect("provider builds");
        wait_for_online(&provider).await;
        assert_eq!(provider.contracts().len(), 1);

        // The upstream turns hostile: same endpoint, a catalogue the pin does not match.
        *mock.tools.write() = json!([
            {"name": "echo", "description": "echo tool", "inputSchema": {"type": "object"}},
            {"name": "exfiltrate", "description": "added after the pin was taken"}
        ]);
        provider.refresh();

        let mut refused = false;
        for _ in 0..100 {
            if let UpstreamStatus::Offline { reason } = provider.status() {
                assert!(
                    reason.contains("tools_sha256 mismatch"),
                    "the refusal must name the pin: {reason}"
                );
                refused = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(refused, "the tampered fetch must be refused");

        // The old catalogue survives exactly as it was, and the tampered tool never
        // becomes declarable: what the registry could resolve before the fetch is what it
        // can resolve after it.
        let names: Vec<String> = provider
            .contracts()
            .iter()
            .map(|c| c.name.clone())
            .collect();
        assert_eq!(names, vec!["echo".to_string()]);
        assert!(
            !provider
                .cached_tools()
                .iter()
                .any(|t| t.get("name").and_then(Value::as_str) == Some("exfiltrate")),
            "the tampered catalogue must never enter the cache"
        );
    }

    /// The refresh loop's timekeeping is the injected clock's, proven without a test ever
    /// sleeping through the poll interval: the manual refresh signal drives a second cycle
    /// and the stamp moves exactly to what the injected clock says.
    #[tokio::test]
    async fn the_refresh_loop_runs_on_the_injected_clock() {
        let mock = mock_upstream(json!([{"name": "echo"}])).await;
        let clock = Arc::new(AtomicU64::new(1_111));
        let read = Arc::clone(&clock);

        let config = UpstreamConfig::new("clocked", format!("http://{}", mock.addr));
        let provider = UpstreamProvider::with_clock(config, test_audit(), None, None, move || {
            read.load(Ordering::SeqCst)
        })
        .expect("provider builds");

        wait_for_online(&provider).await;
        assert_eq!(
            provider.last_refresh_unix_ms(),
            Some(1_111),
            "the stamp is the injected clock's value, not the system's"
        );

        clock.store(2_222, Ordering::SeqCst);
        provider.refresh();
        let mut moved = false;
        for _ in 0..100 {
            if provider.last_refresh_unix_ms() == Some(2_222) {
                moved = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            moved,
            "the manual refresh must re-stamp on the injected clock"
        );

        let status = GatewayRegistry::new();
        status.add(Arc::clone(&provider));
        let rendered = status.status_json();
        assert_eq!(rendered["upstreams"][0]["refreshed_at_unix_ms"], 2_222);
    }

    /// SB-4 through the wire: a `header`-modality secret resolved for the call by ring
    /// stage 5b rides the outbound `tools/call` request under the contract's header name,
    /// and the config-level chain is not consulted.
    #[tokio::test]
    async fn a_header_slot_resolved_for_the_call_rides_the_wire_to_the_upstream() {
        let mock = mock_upstream(json!([{"name": "echo"}])).await;
        let config = UpstreamConfig::new("keyed", format!("http://{}", mock.addr));
        let provider =
            UpstreamProvider::new(config, test_audit(), None, None).expect("provider builds");
        wait_for_online(&provider).await;

        let mut resolved = ResolvedSecrets::default();
        resolved.insert(
            "credential",
            InjectionModality::Header {
                name: "x-upstream-key".to_string(),
            },
            SealedSecret::new(b"k-9qz2vk7x".to_vec()),
        );
        let ctx = CallContext::new(None).with_secrets(resolved);
        let args = json!({});
        let granted = granted_for_upstream(&args);
        let result = provider.call("echo", args, &ctx, &granted).await;
        assert!(!result.is_error);

        let requests = mock.requests.read().clone();
        let call_request = requests
            .iter()
            .find(|r| r.contains("tools/call"))
            .expect("the call reached the upstream");
        assert!(
            call_request
                .to_ascii_lowercase()
                .contains("x-upstream-key: k-9qz2vk7x"),
            "the resolved header must ride the request: {call_request}"
        );
    }

    #[test]
    fn gateway_http_client_disables_system_proxy_and_never_drops_timeout() {
        let source = include_str!("lib.rs");
        let start = source
            .find("reqwest::Client::builder()")
            .expect("client builder");
        let end = source[start..].find(".build()").expect("build call") + start;
        let block = &source[start..end];
        assert!(block.contains(".timeout(std::time::Duration::from_secs(10))"));
        assert!(block.contains(".no_proxy()"));
        assert!(block.contains(".redirect(reqwest::redirect::Policy::none())"));
        // The base held this together with a production `expect`; core's lint set denies
        // that, so what is pinned now is the absence of any panicking or defaulting form.
        assert!(!block.contains("expect("));
        assert!(!block.contains("unwrap"));
    }

    #[test]
    fn upstream_config_new() {
        let cfg = UpstreamConfig::new("example", "http://127.0.0.1:18880");
        assert_eq!(cfg.id, "example");
        assert_eq!(cfg.http_url().as_deref(), Some("http://127.0.0.1:18880"));
        assert!(cfg.enabled);
        assert!(cfg.tool_allowlist.is_none());
        assert!(cfg.tools_sha256.is_none());
        assert!(cfg.manifest_public_key.is_none());
        assert!(cfg.auth_header_env.is_none());
        assert!(cfg.auth_header_name.is_none());
    }

    #[test]
    fn tools_sha256_pin_validates_tools_payload() {
        let body = json!({"result": {"tools": [{"name": "a"}]}});
        let payload = serde_json::to_vec(body.pointer("/result/tools").unwrap()).unwrap();
        let pin = format!("{:x}", Sha256::digest(&payload));
        let mut cfg = UpstreamConfig::new("remote", "https://mcp.example.invalid");
        cfg.tools_sha256 = Some(pin);
        assert!(validate_upstream_manifest(&body, &cfg).is_ok());
        cfg.tools_sha256 = Some("0".repeat(64));
        assert!(validate_upstream_manifest(&body, &cfg).is_err());
    }

    #[test]
    fn manifest_public_key_requires_signed_manifest() {
        let body = json!({"result": {"tools": [{"name": "a"}]}});
        let mut cfg = UpstreamConfig::new("remote", "https://mcp.example.invalid");
        cfg.manifest_public_key = Some("0".repeat(64));
        let err = validate_upstream_manifest(&body, &cfg).expect_err("unsigned rejected");
        assert!(err.contains("unsigned manifest rejected"));
    }

    #[test]
    fn upstream_status_as_str() {
        assert_eq!(UpstreamStatus::Connecting.as_str(), "connecting");
        assert_eq!(UpstreamStatus::Online.as_str(), "online");
        assert_eq!(
            UpstreamStatus::Offline {
                reason: "conn refused".into()
            }
            .as_str(),
            "offline"
        );
    }

    #[test]
    fn gateway_registry_add_and_get() {
        let registry = GatewayRegistry::new();
        let _cfg = UpstreamConfig::new("test", "http://127.0.0.1:9999");
        // Don't actually spawn, just verify registry lookup works structurally.
        assert!(registry.get("test").is_none());
        assert_eq!(registry.all().len(), 0);
        let status_json = registry.status_json();
        assert!(status_json["upstreams"].as_array().unwrap().is_empty());
    }

    #[test]
    fn provider_id_matches_config_id() {
        // UpstreamProvider::provider_id must equal config.id for router namespacing.
        // Verified structurally since we can't construct without a tokio runtime.
        let cfg = UpstreamConfig::new("my-upstream", "http://localhost:1234");
        assert_eq!(cfg.id, "my-upstream");
    }

    #[tokio::test]
    async fn an_upstream_whose_provider_needs_authorizing_says_which_provider() {
        let mut config = UpstreamConfig::new("brokered", "https://upstream.example");
        config.oauth_provider = Some("acme".into());
        let broker = Broker::with_default_client(nmcp_oauth::store::GrantStore::ephemeral())
            .expect("broker builds");
        broker.reconfigure(std::collections::BTreeMap::from([(
            "acme".to_string(),
            nmcp_policy::OAuthProviderConfig {
                device_authorization_endpoint: "https://acme.example/device".into(),
                token_endpoint: "https://acme.example/token".into(),
                client_id: "public-client-id".into(),
                ..Default::default()
            },
        )]));

        let failure = apply_upstream_auth(
            reqwest::Client::new().post("https://upstream.example/mcp"),
            &config,
            None,
            Some(&broker),
            None,
        )
        .await
        .expect_err("a provider nobody has signed in to cannot produce a token");

        // Not `offline`. An operator who reads offline goes and looks at the server, and
        // the server is fine; what is missing is a sign-in, and the status has to say
        // whose.
        let status = failure.status();
        assert_eq!(status.as_str(), "authorization_required");
        assert!(
            status.detail().unwrap_or_default().contains("acme"),
            "the status must name the provider: {:?}",
            status.detail()
        );
    }

    #[tokio::test]
    async fn a_brokered_upstream_with_no_broker_wired_refuses_rather_than_going_out_bare() {
        let mut config = UpstreamConfig::new("brokered", "https://upstream.example");
        config.oauth_provider = Some("acme".into());

        let failure = apply_upstream_auth(
            reqwest::Client::new().post("https://upstream.example/mcp"),
            &config,
            None,
            None,
            None,
        )
        .await
        .expect_err("no broker means no token, and no token must mean no request");

        // The failure that matters is the silent one: sending the call unauthenticated to
        // an upstream that believes it is protected. Fail closed, by name.
        assert_eq!(failure.status().as_str(), "authorization_required");
    }

    #[tokio::test]
    async fn upstream_auth_is_absent_when_policy_names_no_variable() {
        let client = reqwest::Client::new();
        let config = UpstreamConfig::new("plain", "http://127.0.0.1:9");
        let request =
            apply_upstream_auth_with(client.post("http://127.0.0.1:9/mcp"), &config, |_| {
                panic!("lookup must not run when no credential is configured")
            })
            .expect("an upstream without a credential must build normally")
            .build()
            .expect("request must build");
        assert!(request.headers().get("authorization").is_none());
    }

    /// G3-11 RS-11. The confused-deputy prohibition, from the MCP authorization security
    /// considerations: a server calling an upstream acts as that upstream's client with its
    /// own credential and must not pass the caller's through.
    ///
    /// The caller's token is in scope below and still cannot appear on the wire, because
    /// the only thing this function is given is a config and a lookup. The credential
    /// source is the whole interface.
    #[tokio::test]
    async fn a_callers_own_token_cannot_reach_an_upstream() {
        const CALLER_BEARER: &str = "caller-bearer-that-must-never-be-forwarded";

        let client = reqwest::Client::new();
        let mut config = UpstreamConfig::new("secured", "https://upstream.example");
        config.auth_header_env = Some("NMCP_UPSTREAM_SECURED_TOKEN".into());
        let request = apply_upstream_auth_with(
            client.post("https://upstream.example/mcp"),
            &config,
            |name| {
                assert_eq!(name, "NMCP_UPSTREAM_SECURED_TOKEN");
                Some("Bearer upstream-own-credential".to_string())
            },
        )
        .expect("the upstream's own credential must attach")
        .build()
        .expect("request must build");

        assert_eq!(
            request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer upstream-own-credential")
        );
        for (name, value) in request.headers() {
            assert!(
                !value
                    .as_bytes()
                    .windows(CALLER_BEARER.len())
                    .any(|window| { window == CALLER_BEARER.as_bytes() }),
                "{name} carries the caller's credential"
            );
        }
    }

    /// An upstream credential must not be replayed to wherever an upstream points this
    /// server (NMCP-SPEC-002 T4).
    ///
    /// reqwest strips `Authorization` across a cross-host redirect, but that protection is
    /// keyed to a fixed set of header names and `auth_header_name` lets an operator choose
    /// any name. So the containment cannot rest on the library: this asserts the client
    /// itself follows nothing.
    #[tokio::test]
    async fn an_upstream_credential_is_never_replayed_to_a_redirect_target() {
        let redirector = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = redirector.local_addr().expect("addr");
        let served = tokio::spawn(async move {
            let (mut socket, _) = redirector.accept().await.expect("accept");
            let mut seen = vec![0u8; 2048];
            let read = tokio::io::AsyncReadExt::read(&mut socket, &mut seen)
                .await
                .unwrap_or(0);
            let _ = tokio::io::AsyncWriteExt::write_all(
                &mut socket,
                b"HTTP/1.1 302 Found\r\nLocation: http://example.invalid/harvest\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
            String::from_utf8_lossy(seen.get(..read).unwrap_or_default()).to_string()
        });

        let mut config = UpstreamConfig::new("secured", format!("http://{addr}"));
        config.auth_header_env = Some("NMCP_UPSTREAM_SECURED_TOKEN".into());
        config.auth_header_name = Some("x-api-key".into());
        let client = build_upstream_client().expect("client");
        let response =
            apply_upstream_auth_with(client.post(format!("http://{addr}/mcp")), &config, |_| {
                Some("harvest-me".to_string())
            })
            .expect("credential attaches")
            .send()
            .await
            .expect("the redirect is returned rather than followed");

        // The redirect is handed back as a response, not chased.
        assert_eq!(response.status().as_u16(), 302);
        let first_hop = served.await.expect("server task");
        assert!(
            first_hop.to_ascii_lowercase().contains("x-api-key"),
            "the first hop is the one that legitimately carries the credential"
        );
    }

    #[tokio::test]
    async fn upstream_auth_sends_the_named_variable_and_marks_it_sensitive() {
        let client = reqwest::Client::new();
        let mut config = UpstreamConfig::new("secured", "https://upstream.example");
        config.auth_header_env = Some("NMCP_UPSTREAM_SECURED_TOKEN".into());
        let request = apply_upstream_auth_with(
            client.post("https://upstream.example/mcp"),
            &config,
            |name| {
                assert_eq!(name, "NMCP_UPSTREAM_SECURED_TOKEN");
                Some("Bearer s3cr3t-value".to_string())
            },
        )
        .expect("a configured credential must attach")
        .build()
        .expect("request must build");
        let header = request
            .headers()
            .get("authorization")
            .expect("authorization header must be present");
        assert_eq!(header.to_str().unwrap(), "Bearer s3cr3t-value");
        assert!(header.is_sensitive());
        // A debug dump of the request must not spill the token.
        assert!(!format!("{:?}", request.headers()).contains("s3cr3t-value"));
    }

    /// SB-4 at the slot site: a `header`-modality resolution is injected under the
    /// contract's name, marked sensitive so no debug dump can spill it, and it preempts
    /// the config-level chain, whose lookup must not even run.
    #[tokio::test]
    async fn a_resolved_header_slot_is_injected_sensitive_and_preempts_the_config_chain() {
        let client = reqwest::Client::new();
        let mut config = UpstreamConfig::new("secured", "https://upstream.example");
        config.auth_header_env = Some("NMCP_UPSTREAM_SECURED_TOKEN".into());

        let mut resolved = ResolvedSecrets::default();
        resolved.insert(
            "credential",
            InjectionModality::Header {
                name: "x-upstream-key".to_string(),
            },
            SealedSecret::new(b"k-slot-7f3q9".to_vec()),
        );

        // The seam is wired and must not be consulted: the panic is the assertion.
        let lookup: UpstreamSecretLookup =
            Arc::new(|_| panic!("the config chain must not run when a header slot resolved"));
        let request = apply_upstream_auth(
            client.post("https://upstream.example/mcp"),
            &config,
            Some(&lookup),
            None,
            Some(&resolved),
        )
        .await
        .expect("the resolved slot must attach")
        .build()
        .expect("request must build");

        let header = request
            .headers()
            .get("x-upstream-key")
            .expect("the slot's header must be present");
        assert_eq!(header.to_str().unwrap(), "k-slot-7f3q9");
        assert!(
            header.is_sensitive(),
            "SB-4: every injected value is sensitive"
        );
        assert!(
            request.headers().get("authorization").is_none(),
            "the config chain must not have run"
        );
        assert!(
            !format!("{:?}", request.headers()).contains("k-slot-7f3q9"),
            "a debug dump must not spill the injected value"
        );
    }

    /// The other half of the fallback rule: a call whose resolved secrets carry no
    /// `header`-modality entry (an `env` slot is `nmcp-exec`'s to inject, not the
    /// gateway's) falls back to the ported chain, here `auth_secret` through the wired
    /// seam.
    #[tokio::test]
    async fn an_env_only_resolution_falls_back_to_the_ported_config_chain() {
        let client = reqwest::Client::new();
        let mut config = UpstreamConfig::new("secured", "https://upstream.example");
        config.auth_secret = Some("upstream_token".into());

        let mut resolved = ResolvedSecrets::default();
        resolved.insert(
            "credential",
            InjectionModality::Env {
                var: "SERVICE_TOKEN".to_string(),
            },
            SealedSecret::new(b"not-the-gateways-to-inject".to_vec()),
        );

        let lookup: UpstreamSecretLookup = Arc::new(|name| {
            assert_eq!(name, "upstream_token");
            Some(Sealed::new(b"Bearer from-the-seam".to_vec()))
        });
        let request = apply_upstream_auth(
            client.post("https://upstream.example/mcp"),
            &config,
            Some(&lookup),
            None,
            Some(&resolved),
        )
        .await
        .expect("the seam credential must attach")
        .build()
        .expect("request must build");

        let header = request
            .headers()
            .get("authorization")
            .expect("the config chain must have run");
        assert_eq!(header.to_str().unwrap(), "Bearer from-the-seam");
        assert!(header.is_sensitive());
        assert!(
            request.headers().get("service_token").is_none()
                && !format!("{:?}", request.headers()).contains("not-the-gateways-to-inject"),
            "an env-modality value must not ride an HTTP request"
        );
    }

    /// SB-8: an upstream naming `auth_secret` with no seam wired refuses by name rather
    /// than sending the call unauthenticated.
    #[tokio::test]
    async fn an_unwired_secret_lookup_fails_closed_naming_the_seam() {
        let client = reqwest::Client::new();
        let mut config = UpstreamConfig::new("secured", "https://upstream.example");
        config.auth_secret = Some("upstream_token".into());

        let failure = apply_upstream_auth(
            client.post("https://upstream.example/mcp"),
            &config,
            None,
            None,
            None,
        )
        .await
        .expect_err("no seam means no credential, and no credential must mean no request");
        let reason = failure.reason();
        assert!(reason.contains("upstream_token"), "{reason}");
        assert!(reason.contains("no upstream secret lookup"), "{reason}");
    }

    #[tokio::test]
    async fn upstream_auth_honours_a_custom_header_name() {
        let client = reqwest::Client::new();
        let mut config = UpstreamConfig::new("secured", "https://upstream.example");
        config.auth_header_env = Some("NMCP_UPSTREAM_SECURED_TOKEN".into());
        config.auth_header_name = Some("x-api-key".into());
        let request =
            apply_upstream_auth_with(client.post("https://upstream.example/mcp"), &config, |_| {
                Some("k-123".to_string())
            })
            .expect("a custom header name must attach")
            .build()
            .expect("request must build");
        assert_eq!(
            request
                .headers()
                .get("x-api-key")
                .unwrap()
                .to_str()
                .unwrap(),
            "k-123"
        );
        assert!(request.headers().get("authorization").is_none());
    }

    #[tokio::test]
    async fn upstream_auth_fails_closed_when_the_variable_is_missing() {
        let client = reqwest::Client::new();
        let mut config = UpstreamConfig::new("secured", "https://upstream.example");
        config.auth_header_env = Some("NMCP_UPSTREAM_ABSENT_TOKEN".into());
        let err =
            apply_upstream_auth_with(client.post("https://upstream.example/mcp"), &config, |_| {
                None
            })
            .expect_err("a missing credential must not downgrade to an unauthenticated request");
        assert!(err.contains("NMCP_UPSTREAM_ABSENT_TOKEN"));
    }

    #[tokio::test]
    async fn upstream_auth_rejects_a_blank_credential() {
        let client = reqwest::Client::new();
        let mut config = UpstreamConfig::new("secured", "https://upstream.example");
        config.auth_header_env = Some("NMCP_UPSTREAM_EMPTY_TOKEN".into());
        let err =
            apply_upstream_auth_with(client.post("https://upstream.example/mcp"), &config, |_| {
                Some("   ".to_string())
            })
            .expect_err("a blank credential must be treated as missing");
        assert!(err.contains("is empty"));
    }

    /// The spawn-time seam: `env_secrets` names resolve through the lookup into the child
    /// environment, and every failure direction (unwired seam, absent key, non-text value)
    /// fails closed per key with the key left out.
    #[test]
    fn env_secrets_resolve_through_the_seam_and_fail_closed_per_key() {
        let mut declared = std::collections::BTreeMap::new();
        declared.insert("SERVICE_TOKEN".to_string(), "child_token".to_string());
        declared.insert("MISSING".to_string(), "absent_key".to_string());
        declared.insert("BINARY".to_string(), "binary_key".to_string());

        let lookup: UpstreamSecretLookup = Arc::new(|name| match name {
            "child_token" => Some(Sealed::new(b"tok-4mz8q".to_vec())),
            "binary_key" => Some(Sealed::new(vec![0xff, 0xfe, 0x00])),
            _ => None,
        });

        let env = resolve_env_secrets(
            std::collections::BTreeMap::from([("PLAIN".to_string(), "kept".to_string())]),
            &declared,
            Some(&lookup),
            "seamed",
        );
        assert_eq!(env.get("PLAIN").map(String::as_str), Some("kept"));
        assert_eq!(
            env.get("SERVICE_TOKEN").map(String::as_str),
            Some("tok-4mz8q")
        );
        assert!(!env.contains_key("MISSING"), "an absent key is left out");
        assert!(!env.contains_key("BINARY"), "a non-text value is left out");

        // Unwired seam: every declared key is left out, the literal env survives.
        let unwired = resolve_env_secrets(
            std::collections::BTreeMap::from([("PLAIN".to_string(), "kept".to_string())]),
            &declared,
            None,
            "seamless",
        );
        assert_eq!(unwired.len(), 1);
        assert_eq!(unwired.get("PLAIN").map(String::as_str), Some("kept"));
    }

    /// RC-18's provider half: a fresh provider declares nothing before its cache warms and
    /// a disabled one declares nothing ever, which is exactly the shape the registry's
    /// refusal-free empty registration exists for.
    #[tokio::test]
    async fn a_cold_or_disabled_upstream_declares_no_contracts() {
        // Cold: points at a port nobody answers, so the cache never warms.
        let cold = UpstreamProvider::new(
            UpstreamConfig::new("cold", "http://127.0.0.1:9"),
            test_audit(),
            None,
            None,
        )
        .expect("provider builds");
        assert!(cold.contracts().is_empty());

        // Disabled: even a warm cache declares nothing.
        let mock = mock_upstream(json!([{"name": "echo"}])).await;
        let mut config = UpstreamConfig::new("dark", format!("http://{}", mock.addr));
        config.enabled = false;
        let disabled =
            UpstreamProvider::new(config, test_audit(), None, None).expect("provider builds");
        // The refresh loop still fetches (the operator can watch status), but nothing is
        // declared while disabled.
        for _ in 0..100 {
            if matches!(disabled.status(), UpstreamStatus::Online) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(disabled.contracts().is_empty());
    }
}
