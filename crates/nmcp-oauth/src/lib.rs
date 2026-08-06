//! `nmcp-oauth`
//!
//! The OAuth broker (G6-9) for the NativeMCP server family: one authorization, many servers.
//! The governance invariants in `docs/GOVERNANCE.md` are normative for every item in this
//! crate.
//!
//! ## What this is for
//!
//! The sealed store gave policy a second thing it can name: a secret held sealed on disk
//! instead of in an environment variable an operator cannot set on a service account. That
//! covers a static credential. It does not cover the case a catalog is mostly made of, which
//! is a provider an operator signs in to once and several servers then need a live token for.
//!
//! An OAuth access token is a secret with two extra properties: it expires, and it can be
//! replaced without a human. So it needs something that owns the replacing, and that
//! something is here.
//!
//! ## The three properties this holds
//!
//! **Authorize once, broker to many.** A provider is named in policy and an upstream declares
//! which one it uses. Six servers behind one authorization at one provider is one sign-in,
//! not six.
//!
//! **Nothing here reaches policy.** Policy carries endpoints, a client id, scopes and the
//! *name* of a secret. Both tokens live sealed under the broker's reserved namespace and
//! reach exactly one place: the authorization header of a request going out. Not a policy
//! read, not a policy backup, not an audit record, and not a `Debug` line, which is why
//! [`grant::Grant`] has a hand-written one.
//!
//! **A refresh failure is a fact, not a stall.** A revoked or expired refresh token becomes a
//! named upstream status an operator can read and act on. The alternative, which is what a
//! purely lazy refresh on the calling path gives you, is a server that reports online and
//! returns authorization errors for every call. That is the shape of G4-22, where an upstream
//! retried a dead port for weeks because nothing was watching, and of G6-3, where "the
//! container runtime is not running" had to stop being reported as "the server is offline".
//!
//! ## Port record (I-017, deferred from W1 to the W2 tail)
//!
//! Ported from the base's OAuth crate: the RFC 8628 device flow ([`device`]), the grant type
//! and its redacted `Debug` ([`grant`]), and the broker with its sweep, backoff, device poll
//! and reconfigure semantics, behaviour-preserving except where named below. Changed by this
//! port, each argued at the definition:
//!
//! - **Grant storage is the broker's own sealed store** ([`store::GrantStore`]), because the
//!   base wrote and hard-deleted grants inside the operator secret store and NMCP-SPEC-002
//!   SB-10's carve-out replaces that with a namespace the broker owns outright. The module
//!   documentation on [`store`] carries the whole design: one sealed document, the operator
//!   store's own restriction and atomic-write discipline, and revocation that destroys
//!   material by tombstone-and-overwrite rather than by a delete primitive (INV-1).
//! - **`GRANT_PREFIX` became [`grant::GRANT_NAMESPACE`]**, a re-export of the one namespace
//!   definition in `nmcp-schema`, so the reserving grammar and the owning broker cannot
//!   drift (SB-2).
//! - **The clock is injected** ([`Broker::with_clock`]), the house pattern the sealed store
//!   set, so expiry, skew and backoff are tested without sleeping. The base read the system
//!   clock inline.
//! - **A configured client secret that cannot be produced is a refusal, not an omission.**
//!   The base silently sent the form without `client_secret` when the store had no value,
//!   which turns a configuration error into a provider-side mystery. Core has no broker-
//!   reachable read path into the operator store (SB-13 gives the store no such door), so
//!   the daemon wires a [`ClientSecretLookup`] in; until it does, a provider configured with
//!   `client_secret_secret` fails closed with the rule named (SB-8).
//! - **`forget` reports a revocation that could not destroy the sealed copy** instead of
//!   logging and returning success, because silent survival of material is the one failure
//!   the carve-out's deletion right exists to prevent.
//!
//! Gapped, with owners: the base's server half, which is broker construction and
//! `reconfigure` on policy load, the sweeper's lifetime, and the operator-facing begin,
//! forget and status routes, belongs to the daemon wave, and header injection into upstream
//! calls belongs to the gateway port (I-020); this crate is the complete library both wire
//! in, exactly as every W1 port left its server half. The base's `secrets_list` filter on
//! the grant prefix has no port target at all: the operator store cannot represent a
//! reserved name, so there is nothing to filter (SB-R2, by construction). The base's unused
//! `anyhow` dependency was dropped, and its vendor-named doc references were generalised
//! (RC-D9): the flow is generic OIDC device authorization and carries no vendor default.
//!
//! ## One broker per process
//!
//! The provider map is swapped by [`Broker::reconfigure`] on a policy reload rather than the
//! broker being rebuilt. Two brokers over the same providers would each run a sweep, and two
//! sweeps refreshing one grant at the same moment is exactly the double-refresh that costs
//! the whole grant at a provider that rotates. Per-provider locks only serialize within a
//! broker, so there has to be one broker.

pub mod device;
pub mod grant;
pub mod store;

use device::{DeviceAuthorization, DeviceInstruction, PollOutcome};
use grant::{Grant, now_unix};
use nmcp_policy::OAuthProviderConfig;
use nmcp_secrets::Sealed;
use parking_lot::RwLock;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use store::GrantStore;
use tokio::sync::Mutex;
use tracing::{info, warn};
use zeroize::Zeroizing;

/// How often the background task looks for grants coming due.
pub const SWEEP_INTERVAL_SECS: u64 = 60;
/// The first wait after a failed refresh, doubling up to [`MAX_BACKOFF_SECS`].
///
/// Without this, a revoked refresh token produces one request a minute at the provider for as
/// long as the service runs, which is useless and is the kind of traffic that gets a client id
/// rate limited or blocked outright.
pub const BASE_BACKOFF_SECS: u64 = 60;
/// The ceiling on the failure backoff.
pub const MAX_BACKOFF_SECS: u64 = 3_600;

/// How the broker reads a provider's client secret from whoever holds it.
///
/// Core's operator store has no read path a background broker can call: resolution is minted
/// per tool call by the binding evaluator, and SB-13 gives the store no other door. The
/// daemon owns whatever surface an operator-held client secret is read through, and it hands
/// the broker this lookup at construction. The value crosses as [`Sealed`] bytes, so the
/// only clear-text copy is the transient one the form serializer reads.
pub type ClientSecretLookup = Arc<dyn Fn(&str) -> Option<Sealed<Vec<u8>>> + Send + Sync>;

/// Why a token could not be produced. Every variant names the provider, because an operator
/// reading one is deciding which provider to go and re-authorize.
///
/// No variant carries material or any value derived from material (SB-1): provider ids,
/// secret names and provider-sent error strings are configuration and diagnosis, not values.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum BrokerError {
    /// No provider with this id is configured.
    #[error("no OAuth provider named '{0}' is configured")]
    UnknownProvider(String),
    /// The provider is configured and no operator has authorized it.
    #[error("OAuth provider '{provider}' has not been authorized")]
    NotAuthorized {
        /// The provider needing an operator.
        provider: String,
    },
    /// The provider issued no refresh token, so the access token cannot be renewed.
    #[error(
        "OAuth provider '{provider}' issued no refresh token, so its access token cannot be renewed; authorize it again"
    )]
    NoRefreshToken {
        /// The provider needing an operator.
        provider: String,
    },
    /// The token endpoint answered and said no.
    #[error("OAuth provider '{provider}' could not be refreshed: {reason}")]
    RefreshFailed {
        /// The provider that refused.
        provider: String,
        /// The provider's own words, safe to show an operator.
        reason: String,
    },
    /// The token endpoint could not be reached at all.
    #[error("OAuth provider '{provider}' could not be reached: {reason}")]
    Unreachable {
        /// The provider that was unreachable.
        provider: String,
        /// The transport's description of the failure.
        reason: String,
    },
    /// The provider names a client secret this broker cannot produce.
    ///
    /// Deliberately a refusal rather than the base's silent omission of the form field: a
    /// request sent without a configured client secret fails at the provider with an error
    /// that points away from the actual cause, and SB-8 wants the governing fact named at
    /// the refusal. Carries the secret's name, never its value.
    #[error(
        "OAuth provider '{provider}' names client secret '{secret}', which this broker cannot produce: {reason}"
    )]
    ClientSecretUnavailable {
        /// The provider whose configuration names the secret.
        provider: String,
        /// The name policy carries.
        secret: String,
        /// Why no value could be produced.
        reason: String,
    },
    /// The in-memory grant was dropped and the sealed copy could not be destroyed.
    ///
    /// The runtime has already stopped presenting the token; what failed is the SB-10
    /// carve-out's destruction of the sealed material, and an operator revoking a grant is
    /// owed that fact rather than a log line (the base warned and reported success).
    #[error(
        "OAuth provider '{provider}' was forgotten in memory, but its sealed grant could not be destroyed: {reason}"
    )]
    RevocationIncomplete {
        /// The provider whose sealed grant survived.
        provider: String,
        /// What the grant store said.
        reason: String,
    },
}

impl BrokerError {
    /// The provider this error is about.
    #[must_use]
    pub fn provider(&self) -> &str {
        match self {
            Self::UnknownProvider(id) => id,
            Self::NotAuthorized { provider }
            | Self::NoRefreshToken { provider }
            | Self::RefreshFailed { provider, .. }
            | Self::Unreachable { provider, .. }
            | Self::ClientSecretUnavailable { provider, .. }
            | Self::RevocationIncomplete { provider, .. } => provider,
        }
    }

    /// Whether an operator has to go and act, as opposed to waiting it out.
    ///
    /// A network fault and a revoked grant both stop tokens coming out of here, and telling
    /// them apart is the difference between an operator waiting five minutes and an operator
    /// re-authorizing six servers for nothing.
    #[must_use]
    pub fn needs_operator(&self) -> bool {
        !matches!(self, Self::Unreachable { .. })
    }
}

/// Why a broker could not be constructed.
///
/// Separate from [`BrokerError`], whose every variant names a provider; construction has no
/// provider to name.
#[derive(Debug, thiserror::Error)]
#[error("the broker's HTTP client could not be built: {reason}")]
pub struct BrokerBuildError {
    reason: String,
}

/// What the console may know about a provider. No token appears in this type.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProviderStatus {
    /// The provider's id, which is its key in policy.
    pub id: String,
    /// What the console calls it.
    pub label: String,
    /// Whether a grant is held.
    pub authorized: bool,
    /// When the held token expires, when it is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    /// The scopes the provider actually granted, when it said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The last failure, safe to show an operator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Set while a device authorization is waiting on the operator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<DeviceInstruction>,
}

#[derive(Default)]
struct ProviderState {
    grant: Option<Grant>,
    last_error: Option<String>,
    pending: Option<DeviceAuthorization>,
    /// Set after a failed refresh; the sweep leaves this provider alone until then.
    next_attempt_unix: u64,
    consecutive_failures: u32,
}

impl ProviderState {
    fn note_failure(&mut self, reason: String, now: u64) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let backoff = BASE_BACKOFF_SECS
            .saturating_mul(1_u64 << self.consecutive_failures.min(6))
            .min(MAX_BACKOFF_SECS);
        self.next_attempt_unix = now.saturating_add(backoff);
        self.last_error = Some(reason);
    }

    fn note_success(&mut self) {
        self.consecutive_failures = 0;
        self.next_attempt_unix = 0;
        self.last_error = None;
    }
}

/// Holds the authorizations and hands out live tokens.
pub struct Broker {
    providers: RwLock<BTreeMap<String, OAuthProviderConfig>>,
    /// One lock per provider, so a refresh serializes against itself and against nothing else.
    ///
    /// Serializing matters beyond tidiness. Many providers rotate the refresh token on use and
    /// treat a second presentation of the old one as theft, revoking the whole family. Two
    /// upstreams asking at the same moment for a token that just came due is the ordinary case
    /// rather than a rare one, so an unsynchronized refresh would break the grant on a normal
    /// Tuesday and look like the provider's fault.
    state: RwLock<BTreeMap<String, Arc<Mutex<ProviderState>>>>,
    grants: GrantStore,
    http: reqwest::Client,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    client_secrets: Option<ClientSecretLookup>,
}

impl Broker {
    /// An empty broker on the system clock. Providers arrive through [`Broker::reconfigure`].
    pub fn new(grants: GrantStore, http: reqwest::Client) -> Arc<Self> {
        Self::with_parts(grants, http, now_unix, None)
    }

    /// A broker with the clock injected, so expiry, skew and backoff are testable without a
    /// test ever sleeping (the house pattern: `SealedStore::open_with_clock` injects its
    /// clock for the rotation overlap window for the same reason).
    ///
    /// `clock` returns seconds since the Unix epoch, the unit every grant expiry is recorded
    /// in. It is consulted outside any lock and must not call back into the broker.
    pub fn with_clock(
        grants: GrantStore,
        http: reqwest::Client,
        clock: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Arc<Self> {
        Self::with_parts(grants, http, clock, None)
    }

    /// The full constructor: clock and client-secret lookup both injected.
    ///
    /// The daemon wave calls this with the lookup wired to whatever surface holds operator
    /// client secrets. A broker built without a lookup refuses, by name, any provider whose
    /// configuration names one; see [`BrokerError::ClientSecretUnavailable`].
    pub fn with_parts(
        grants: GrantStore,
        http: reqwest::Client,
        clock: impl Fn() -> u64 + Send + Sync + 'static,
        client_secrets: Option<ClientSecretLookup>,
    ) -> Arc<Self> {
        Arc::new(Self {
            providers: RwLock::new(BTreeMap::new()),
            state: RwLock::new(BTreeMap::new()),
            grants,
            http,
            clock: Box::new(clock),
            client_secrets,
        })
    }

    /// A broker with the HTTP client this runtime uses everywhere: a fixed timeout, no proxy.
    ///
    /// No proxy deliberately. A token endpoint request that silently went through whatever
    /// proxy variable happened to be set on the service account would hand that proxy a
    /// device code and a refresh token.
    ///
    /// # Errors
    ///
    /// [`BrokerBuildError`] when the HTTP client cannot be built, which on some platforms is
    /// a TLS backend failing to initialise. The base unwrapped here; this workspace denies
    /// that, and a caller with no HTTP client has a real decision to make.
    pub fn with_default_client(grants: GrantStore) -> Result<Arc<Self>, BrokerBuildError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .no_proxy()
            .build()
            .map_err(|err| BrokerBuildError {
                reason: err.to_string(),
            })?;
        Ok(Self::new(grants, http))
    }

    /// Adopt a new set of providers, keeping the live state of any that survive.
    ///
    /// Called on every policy load and reload. A provider still present keeps its in-memory
    /// grant, its backoff and any device authorization in flight, because none of that changed
    /// just because an unrelated part of policy did. A new one loads whatever grant is already
    /// sealed on disk, which is what makes an authorization survive a restart.
    pub fn reconfigure(&self, providers: BTreeMap<String, OAuthProviderConfig>) {
        let mut states = self.state.write();
        states.retain(|id, _| providers.contains_key(id));
        for id in providers.keys() {
            if states.contains_key(id) {
                continue;
            }
            let restored = self.grants.load(id);
            if restored.is_some() {
                info!(provider = id.as_str(), "oauth: restored a sealed grant");
            }
            states.insert(
                id.clone(),
                Arc::new(Mutex::new(ProviderState {
                    grant: restored,
                    ..Default::default()
                })),
            );
        }
        *self.providers.write() = providers;
    }

    /// The configured provider ids.
    #[must_use]
    pub fn provider_ids(&self) -> Vec<String> {
        self.providers.read().keys().cloned().collect()
    }

    /// Whether a provider with this id is configured.
    #[must_use]
    pub fn knows(&self, provider: &str) -> bool {
        self.providers.read().contains_key(provider)
    }

    /// The value for an upstream's authorization header, refreshing first if it is due.
    ///
    /// This is the brokering. Every upstream that names the same provider arrives here and
    /// leaves with the same token, and the one authorization behind it happened once.
    ///
    /// # Errors
    ///
    /// [`BrokerError`], naming the provider and whether an operator is needed.
    pub async fn authorization_header(&self, provider: &str) -> Result<String, BrokerError> {
        let config = self.config(provider)?;
        let cell = self.cell(provider)?;
        let mut state = cell.lock().await;
        let now = self.now();

        if let Some(grant) = &state.grant
            && !grant.is_due(now)
        {
            return Ok(grant.authorization_header());
        }
        if state.grant.is_none() {
            return Err(BrokerError::NotAuthorized {
                provider: provider.to_string(),
            });
        }
        // Due, and the sweep has not got to it yet. Refreshing here as well as on the sweep is
        // not redundant: the first call after a long idle period, or after the service starts
        // holding a grant that aged on disk, arrives before any sweep would have run.
        self.refresh_locked(provider, &config, &mut state, now)
            .await?;
        // A successful refresh leaves a grant; the base asserted that with an `expect`, which
        // this workspace denies. Reported as this broker's own defect if it ever stops
        // holding, rather than a panic in a privileged service.
        state
            .grant
            .as_ref()
            .map(Grant::authorization_header)
            .ok_or_else(|| BrokerError::RefreshFailed {
                provider: provider.to_string(),
                reason: "the refresh reported success and left no grant, which is a defect in this broker".to_string(),
            })
    }

    /// Refresh every grant that is due. The background task's whole job.
    ///
    /// Returns the providers it refreshed, for a caller that wants to log or assert on it.
    pub async fn sweep(&self) -> Vec<String> {
        let now = self.now();
        let mut refreshed = vec![];
        for id in self.provider_ids() {
            let (Ok(config), Ok(cell)) = (self.config(&id), self.cell(&id)) else {
                continue;
            };
            let mut state = cell.lock().await;
            if now < state.next_attempt_unix {
                continue;
            }
            if !state.grant.as_ref().is_some_and(|g| g.is_due(now)) {
                continue;
            }
            match self.refresh_locked(&id, &config, &mut state, now).await {
                Ok(()) => {
                    info!(provider = id.as_str(), "oauth: refreshed ahead of expiry");
                    refreshed.push(id.clone());
                }
                Err(err) => warn!(
                    provider = id.as_str(),
                    "oauth: scheduled refresh failed: {err}"
                ),
            }
        }
        refreshed
    }

    /// Run [`Broker::sweep`] until the shutdown channel goes true.
    ///
    /// A token is refreshed because it is about to expire, not because somebody happened to
    /// call a tool. That is the difference between a grant that survives a quiet weekend and
    /// one that is dead on Monday because its refresh token aged out untouched.
    pub fn spawn_sweeper(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(SWEEP_INTERVAL_SECS));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => { self.sweep().await; }
                    // An error means every sender is gone, which is the owning process on its
                    // way out. Treated as a stop rather than ignored, because `changed()` on a
                    // closed channel returns immediately and ignoring it is a busy loop.
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() { return; }
                    }
                }
            }
        })
    }

    /// Start a device authorization and return what to show the operator.
    ///
    /// The poll runs in the background, so the caller is not held open for however long a
    /// human takes to find their phone.
    ///
    /// # Errors
    ///
    /// [`BrokerError`] when the provider is unknown, unreachable, refuses the request, or
    /// answers with something that is not a device authorization.
    pub async fn begin_authorization(
        self: &Arc<Self>,
        provider: &str,
    ) -> Result<DeviceInstruction, BrokerError> {
        let config = self.config(provider)?;
        let cell = self.cell(provider)?;
        let scope = config.scopes.join(" ");
        let (status, body) = self
            .post_form(
                provider,
                &config.device_authorization_endpoint,
                &device::device_authorization_form(&config.client_id, &scope),
                &config,
            )
            .await?;
        if status >= 400 {
            return Err(BrokerError::RefreshFailed {
                provider: provider.to_string(),
                reason: device::error_reason(&body, status),
            });
        }
        let authorization =
            device::parse_device_authorization(&body, self.now()).map_err(|reason| {
                BrokerError::RefreshFailed {
                    provider: provider.to_string(),
                    reason,
                }
            })?;
        let instruction = authorization.instruction();
        {
            let mut state = cell.lock().await;
            state.pending = Some(authorization.clone());
            state.last_error = None;
        }
        let broker = Arc::clone(self);
        let id = provider.to_string();
        tokio::spawn(async move { broker.poll_device(id, authorization).await });
        Ok(instruction)
    }

    /// Drop a provider's grant and destroy the sealed copy (the SB-10 carve-out).
    ///
    /// For an operator who revoked at the provider and wants the runtime to stop presenting a
    /// token it no longer owns, rather than discovering it on the next call. Returns whether
    /// a grant was held.
    ///
    /// # Errors
    ///
    /// [`BrokerError::UnknownProvider`] for a provider policy does not carry, and
    /// [`BrokerError::RevocationIncomplete`] when the in-memory grant is gone but the sealed
    /// copy could not be destroyed; the base logged that case and reported success, and an
    /// operator revoking a credential is owed the failure.
    pub async fn forget(&self, provider: &str) -> Result<bool, BrokerError> {
        let cell = self.cell(provider)?;
        let mut state = cell.lock().await;
        let had = state.grant.take().is_some();
        state.pending = None;
        state.note_success();
        match self.grants.revoke(provider) {
            Ok(revoked) => Ok(had || revoked),
            Err(err) => Err(BrokerError::RevocationIncomplete {
                provider: provider.to_string(),
                reason: err.to_string(),
            }),
        }
    }

    /// Everything the console may see, which is everything except the tokens.
    pub async fn statuses(&self) -> Vec<ProviderStatus> {
        let configs = self.providers.read().clone();
        let mut out = vec![];
        for (id, config) in configs {
            let Ok(cell) = self.cell(&id) else { continue };
            let state = cell.lock().await;
            out.push(ProviderStatus {
                label: if config.label.is_empty() {
                    id.clone()
                } else {
                    config.label.clone()
                },
                authorized: state.grant.is_some(),
                expires_at_unix: state.grant.as_ref().and_then(|g| g.expires_at_unix),
                scope: state.grant.as_ref().and_then(|g| g.scope.clone()),
                last_error: state.last_error.clone(),
                pending: state.pending.as_ref().map(DeviceAuthorization::instruction),
                id,
            });
        }
        out
    }

    /// Seed a grant directly. Test seam, and the path a migration would use.
    ///
    /// # Errors
    ///
    /// [`BrokerError::UnknownProvider`] for a provider policy does not carry. A sealing or
    /// persistence failure is not an error here: the in-memory grant works for the life of
    /// the process, and the failure to persist is logged loudly, exactly as a refresh
    /// handles the same case.
    pub async fn install_grant(&self, provider: &str, grant: Grant) -> Result<(), BrokerError> {
        let cell = self.cell(provider)?;
        self.store(provider, &grant);
        let mut state = cell.lock().await;
        state.grant = Some(grant);
        state.note_success();
        Ok(())
    }

    // ── internals ──────────────────────────────────────────────────────────────

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// A clone rather than a borrow, so no lock is held across the await that follows.
    fn config(&self, provider: &str) -> Result<OAuthProviderConfig, BrokerError> {
        self.providers
            .read()
            .get(provider)
            .cloned()
            .ok_or_else(|| BrokerError::UnknownProvider(provider.to_string()))
    }

    fn cell(&self, provider: &str) -> Result<Arc<Mutex<ProviderState>>, BrokerError> {
        self.state
            .read()
            .get(provider)
            .cloned()
            .ok_or_else(|| BrokerError::UnknownProvider(provider.to_string()))
    }

    /// Exchange the refresh token. The caller holds the provider's lock.
    async fn refresh_locked(
        &self,
        provider: &str,
        config: &OAuthProviderConfig,
        state: &mut ProviderState,
        now: u64,
    ) -> Result<(), BrokerError> {
        let Some(refresh_token) = state.grant.as_ref().and_then(|g| g.refresh_token.clone()) else {
            let err = BrokerError::NoRefreshToken {
                provider: provider.to_string(),
            };
            state.note_failure(err.to_string(), now);
            return Err(err);
        };
        let scope = config.scopes.join(" ");
        let form = device::refresh_form(&config.client_id, &refresh_token, &scope);
        let (status, body) = match self
            .post_form(provider, &config.token_endpoint, &form, config)
            .await
        {
            Ok(pair) => pair,
            Err(err) => {
                // A provider that could not be reached is not a provider that said no.
                // Recorded so the next sweep backs off, but reported as its own kind, because
                // sending an operator to re-authorize over a transient network fault wastes
                // their time and, at a provider that rotates, costs them a working grant. A
                // missing client secret backs off the same way: retrying will not conjure one.
                state.note_failure(err.to_string(), now);
                return Err(err);
            }
        };
        if status >= 400 {
            let reason = device::error_reason(&body, status);
            state.note_failure(reason.clone(), now);
            return Err(BrokerError::RefreshFailed {
                provider: provider.to_string(),
                reason,
            });
        }
        let mut fresh = match device::parse_token_response(&body, now) {
            Ok(grant) => grant,
            Err(reason) => {
                state.note_failure(reason.clone(), now);
                return Err(BrokerError::RefreshFailed {
                    provider: provider.to_string(),
                    reason,
                });
            }
        };
        // A provider that does not rotate returns no refresh token, and dropping the one
        // already held would turn a working grant into a dead one on the very first refresh.
        if fresh.refresh_token.is_none() {
            fresh.refresh_token = Some(refresh_token);
        }
        self.store(provider, &fresh);
        state.grant = Some(fresh);
        state.note_success();
        Ok(())
    }

    async fn poll_device(&self, provider: String, authorization: DeviceAuthorization) {
        let mut interval = authorization.interval_secs;
        loop {
            tokio::time::sleep(Duration::from_secs(interval)).await;
            // Re-read every pass, so a provider removed by a policy reload stops being polled.
            let (Ok(config), Ok(cell)) = (self.config(&provider), self.cell(&provider)) else {
                return;
            };
            let now = self.now();
            if authorization.is_expired(now) {
                let mut state = cell.lock().await;
                state.pending = None;
                state.last_error = Some("the device code expired before it was used".to_string());
                warn!(provider = provider.as_str(), "oauth: device code expired");
                return;
            }
            let form = device::device_token_form(&config.client_id, &authorization.device_code);
            let outcome = match self
                .post_form(&provider, &config.token_endpoint, &form, &config)
                .await
            {
                Ok((_, body)) => device::classify_poll(&body, now),
                // A poll that could not reach the provider is not an answer from it, so it is
                // not terminal. The device code's own expiry ends the loop if this keeps up.
                Err(reason) => {
                    warn!(provider = provider.as_str(), "oauth: poll failed: {reason}");
                    PollOutcome::Pending
                }
            };
            interval = device::next_interval(interval, &outcome);
            match outcome {
                PollOutcome::Pending | PollOutcome::SlowDown => {}
                PollOutcome::Granted(grant) => {
                    self.store(&provider, &grant);
                    let mut state = cell.lock().await;
                    state.grant = Some(*grant);
                    state.pending = None;
                    state.note_success();
                    info!(provider = provider.as_str(), "oauth: authorized");
                    return;
                }
                PollOutcome::Failed(reason) => {
                    let mut state = cell.lock().await;
                    state.pending = None;
                    state.last_error = Some(reason.clone());
                    warn!(
                        provider = provider.as_str(),
                        "oauth: authorization failed: {reason}"
                    );
                    return;
                }
            }
        }
    }

    /// Persist a grant, sealed, under the reserved namespace.
    fn store(&self, provider: &str, grant: &Grant) {
        if let Err(err) = self.grants.store(provider, grant) {
            // Not fatal to this refresh: the in-memory grant still works for the life of the
            // process. Loud, though, because it means a restart silently loses the
            // authorization and the operator gets asked to sign in again for no visible
            // reason.
            warn!(provider, "oauth: could not seal the grant to disk: {err}");
        }
    }

    /// The provider's client secret, when its configuration names one.
    ///
    /// Fails closed with the secret's name when the configuration names one and no value can
    /// be produced, whether because no lookup is wired or because the lookup has nothing
    /// under the name. The returned buffer zeroizes on drop; its only reader is the form
    /// serializer.
    fn client_secret_for(
        &self,
        provider: &str,
        config: &OAuthProviderConfig,
    ) -> Result<Option<Zeroizing<String>>, BrokerError> {
        let Some(name) = config.client_secret_secret.as_deref() else {
            return Ok(None);
        };
        let refusal = |reason: &str| BrokerError::ClientSecretUnavailable {
            provider: provider.to_string(),
            secret: name.to_string(),
            reason: reason.to_string(),
        };
        let Some(lookup) = &self.client_secrets else {
            return Err(refusal(
                "no client-secret lookup is wired into this broker; the daemon supplies one",
            ));
        };
        let Some(sealed) = lookup(name) else {
            return Err(refusal("the lookup produced no value under that name"));
        };
        // Validity is checked on the borrowed bytes, so an invalid value never moves into an
        // error the way `String::from_utf8`'s would (SB-1: errors carry no material).
        let text = sealed.with_exposed(|bytes| {
            std::str::from_utf8(bytes)
                .ok()
                .map(|value| Zeroizing::new(value.to_string()))
        });
        match text {
            Some(value) => Ok(Some(value)),
            None => Err(refusal("the value under that name is not text")),
        }
    }

    /// POST a form and read the JSON body, whatever the status.
    ///
    /// The status comes back rather than being turned into an error, because a token endpoint
    /// answers a revoked refresh token with a 400 whose body is the only thing that says so.
    async fn post_form(
        &self,
        provider: &str,
        url: &str,
        form: &[(&str, &str)],
        config: &OAuthProviderConfig,
    ) -> Result<(u16, Value), BrokerError> {
        let mut form = form.to_vec();
        let secret = self.client_secret_for(provider, config)?;
        if let Some(value) = secret.as_deref() {
            form.push(("client_secret", value));
        }
        let response = self
            .http
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|err| BrokerError::Unreachable {
                provider: provider.to_string(),
                reason: err.to_string(),
            })?;
        let status = response.status().as_u16();
        let text = response
            .text()
            .await
            .map_err(|err| BrokerError::Unreachable {
                provider: provider.to_string(),
                reason: err.to_string(),
            })?;
        let body = serde_json::from_str::<Value>(&text).unwrap_or(Value::Null);
        Ok((status, body))
    }
}

#[cfg(test)]
mod tests {
    //! The acceptance for G6-9, run against a token endpoint answering on loopback.
    //!
    //! The unit tests in `device` cover reading what a provider sends back and the ones in
    //! `store` cover the carve-out's storage. These cover what the item is for: one
    //! authorization reaching several servers, a token replaced ahead of expiry with nobody
    //! calling, neither token appearing in policy, a refresh failure arriving as a named
    //! fact, and the port's additions: the injected clock driving the sweep and the backoff,
    //! the client-secret refusal, and the device flow end to end.
    //!
    //! In-crate rather than a `tests/` directory for the workspace's standing reason: an
    //! integration-test crate compiles without `cfg(test)`, which would move test scaffolding
    //! into the INV-1 scanner's production scope.

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

    use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
    use nmcp_policy::{OAuthProviderConfig, PolicyConfig, UpstreamConfig};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;

    use crate::grant::{Grant, grant_secret_name, now_unix};
    use crate::store::GrantStore;
    use crate::{Broker, BrokerError, ClientSecretLookup};

    /// Distinctive enough that finding either one anywhere is unambiguous.
    const ORIGINAL_ACCESS: &str = "sentinel-original-access-token";
    const ORIGINAL_REFRESH: &str = "sentinel-original-refresh-token";

    // ── A token endpoint ─────────────────────────────────────────────────────────

    #[derive(Clone, Default)]
    struct TokenEndpoint {
        exchanges: Arc<AtomicUsize>,
        reject: Arc<AtomicBool>,
        /// When set, answer without a `refresh_token`, the way a provider that does not
        /// rotate does.
        withhold_refresh: Arc<AtomicBool>,
        /// When set, the device poll is answered with a grant; until then, pending.
        approve_device: Arc<AtomicBool>,
        /// Every form body the token endpoint received.
        bodies: Arc<StdMutex<Vec<String>>>,
    }

    async fn token_route(
        State(endpoint): State<TokenEndpoint>,
        body: String,
    ) -> (StatusCode, Json<Value>) {
        endpoint
            .bodies
            .lock()
            .expect("bodies lock")
            .push(body.clone());
        if endpoint.reject.load(Ordering::SeqCst) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_grant",
                    "error_description": "the refresh token was revoked"
                })),
            );
        }
        if body.contains("device_code") && !endpoint.approve_device.load(Ordering::SeqCst) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "authorization_pending"})),
            );
        }
        let n = endpoint.exchanges.fetch_add(1, Ordering::SeqCst) + 1;
        let mut body = json!({
            "access_token": format!("access-{n}"),
            "token_type": "Bearer",
            "expires_in": 3600,
        });
        if !endpoint.withhold_refresh.load(Ordering::SeqCst) {
            body["refresh_token"] = json!(format!("refresh-{n}"));
        }
        (StatusCode::OK, Json(body))
    }

    async fn spawn_endpoint() -> (String, TokenEndpoint) {
        let endpoint = TokenEndpoint::default();
        let device = || async {
            (
                StatusCode::OK,
                Json(json!({
                    "device_code": "sentinel-device-code",
                    "user_code": "WDJB-MJHT",
                    "verification_uri": "https://example.test/device",
                    "expires_in": 900,
                    "interval": 1
                })),
            )
        };
        let app = Router::new()
            .route("/token", post(token_route))
            .route("/device", post(device))
            .with_state(endpoint.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}/token"), endpoint)
    }

    fn providers(token_url: &str) -> BTreeMap<String, OAuthProviderConfig> {
        BTreeMap::from([(
            "acme".to_string(),
            OAuthProviderConfig {
                label: "Acme".into(),
                device_authorization_endpoint: token_url.replace("/token", "/device"),
                token_endpoint: token_url.to_string(),
                client_id: "public-client-id".into(),
                client_secret_secret: None,
                scopes: vec!["read".into(), "write".into()],
            },
        )])
    }

    /// A grant with plenty of life left in it.
    fn live_grant() -> Grant {
        Grant {
            access_token: ORIGINAL_ACCESS.into(),
            refresh_token: Some(ORIGINAL_REFRESH.into()),
            expires_at_unix: Some(now_unix() + 86_400),
            scope: Some("read write".into()),
            token_type: "Bearer".into(),
        }
    }

    /// A grant inside the refresh window but not yet expired, which is the whole point:
    /// replacing it is what "before expiry" means, and a test that used an already dead token
    /// would prove only that a dead token gets replaced.
    fn due_grant() -> Grant {
        Grant {
            expires_at_unix: Some(now_unix() + 60),
            ..live_grant()
        }
    }

    /// The default-shaped client without the default constructor, for brokers that also need
    /// an injected clock or lookup. `no_proxy` matters in this environment too: the tests
    /// speak to loopback and must not be routed through any ambient proxy variable.
    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .no_proxy()
            .build()
            .expect("test client builds")
    }

    fn broker_with(token_url: &str) -> (Arc<Broker>, GrantStore) {
        let grants = GrantStore::ephemeral();
        let broker = Broker::with_default_client(grants.clone()).expect("broker builds");
        broker.reconfigure(providers(token_url));
        (broker, grants)
    }

    // ── The acceptance, as the base had it ───────────────────────────────────────

    #[tokio::test]
    async fn one_authorization_is_brokered_to_every_server_that_names_the_provider() {
        let (token_url, endpoint) = spawn_endpoint().await;
        let (broker, _grants) = broker_with(&token_url);
        broker
            .install_grant("acme", live_grant())
            .await
            .expect("install");

        // Two upstreams, two asks, one authorization behind both. This is the item: six
        // servers behind one sign-in is one sign-in.
        let first = broker.authorization_header("acme").await.expect("first");
        let second = broker.authorization_header("acme").await.expect("second");

        assert_eq!(first, second);
        assert_eq!(first, format!("Bearer {ORIGINAL_ACCESS}"));
        assert_eq!(
            endpoint.exchanges.load(Ordering::SeqCst),
            0,
            "a live token must be handed out, not re-fetched, or every call costs a round trip"
        );
    }

    #[tokio::test]
    async fn an_upstream_naming_a_provider_that_was_never_authorized_is_told_so() {
        let (token_url, _endpoint) = spawn_endpoint().await;
        let (broker, _grants) = broker_with(&token_url);

        let err = broker
            .authorization_header("acme")
            .await
            .expect_err("an unauthorized provider cannot produce a token");

        assert_eq!(
            err,
            BrokerError::NotAuthorized {
                provider: "acme".into()
            }
        );
        assert!(err.needs_operator());
        assert_eq!(err.provider(), "acme");
    }

    #[tokio::test]
    async fn a_token_is_replaced_before_it_expires_with_nobody_calling() {
        let (token_url, endpoint) = spawn_endpoint().await;
        let (broker, grants) = broker_with(&token_url);
        broker
            .install_grant("acme", due_grant())
            .await
            .expect("install");

        // No call, no operator: the sweep alone.
        let refreshed = broker.sweep().await;

        assert_eq!(refreshed, vec!["acme".to_string()]);
        assert_eq!(endpoint.exchanges.load(Ordering::SeqCst), 1);
        assert_eq!(
            broker.authorization_header("acme").await.expect("token"),
            "Bearer access-1",
            "upstreams must get the replacement, not the token that was about to die"
        );

        // The replacement is sealed too, so a restart does not undo the refresh.
        let sealed = grants.load("acme").expect("sealed grant");
        assert_eq!(sealed.access_token, "access-1");
        assert_ne!(sealed.access_token, ORIGINAL_ACCESS);
    }

    #[tokio::test]
    async fn a_live_token_is_left_alone_by_the_sweep() {
        let (token_url, endpoint) = spawn_endpoint().await;
        let (broker, _grants) = broker_with(&token_url);
        broker
            .install_grant("acme", live_grant())
            .await
            .expect("install");

        assert!(broker.sweep().await.is_empty());
        assert_eq!(
            endpoint.exchanges.load(Ordering::SeqCst),
            0,
            "refreshing a token with a day left burns the rotation for nothing"
        );
    }

    #[tokio::test]
    async fn neither_token_reaches_policy_the_policy_file_or_the_operator_surface() {
        let (token_url, _endpoint) = spawn_endpoint().await;
        let (broker, grants) = broker_with(&token_url);
        broker
            .install_grant("acme", live_grant())
            .await
            .expect("install");

        let mut policy = PolicyConfig {
            oauth_providers: providers(&token_url),
            ..Default::default()
        };
        let mut upstream = UpstreamConfig::new("brokered", "https://upstream.example");
        upstream.oauth_provider = Some("acme".into());
        upstream.tools_sha256 = Some("a".repeat(64));
        upstream.required_permission = Some(nmcp_policy::Permission::UpstreamCall);
        policy.upstreams.push(upstream);
        policy
            .validate_semantics()
            .expect("an upstream brokering from a configured provider is valid");

        // The policy an operator reads, and the file it is written to, are the same document,
        // so one check covers the policy read surface and a policy backup at once.
        let serialized = serde_json::to_string(&policy).expect("serialize policy");
        for token in [ORIGINAL_ACCESS, ORIGINAL_REFRESH] {
            assert!(
                !serialized.contains(token),
                "a token reached policy: {serialized}"
            );
        }
        // The provider's name is there, because naming is the whole posture; the grant is in
        // the broker's own store and nowhere else.
        assert!(serialized.contains("acme"));
        assert!(grants.load("acme").is_some());

        // The operator surface cannot even represent the grant's name, which is the
        // carve-out's invisibility enforced by type rather than by filter (SB-2, SB-R2).
        assert!(nmcp_secrets::SecretName::parse(&grant_secret_name("acme")).is_err());

        // And the console status view carries no material either.
        let statuses = serde_json::to_string(&broker.statuses().await).expect("serialize");
        assert!(!statuses.contains(ORIGINAL_ACCESS));
        assert!(!statuses.contains(ORIGINAL_REFRESH));
    }

    #[tokio::test]
    async fn a_revoked_refresh_token_is_a_named_failure_and_then_backs_off() {
        let (token_url, endpoint) = spawn_endpoint().await;
        let (broker, _grants) = broker_with(&token_url);
        broker
            .install_grant("acme", due_grant())
            .await
            .expect("install");
        endpoint.reject.store(true, Ordering::SeqCst);

        let err = broker
            .authorization_header("acme")
            .await
            .expect_err("a revoked grant cannot produce a token");

        let BrokerError::RefreshFailed { provider, reason } = &err else {
            panic!("a 400 from the token endpoint must be a refresh failure, got {err:?}");
        };
        assert_eq!(provider, "acme");
        // The provider's own words, because "refresh failed" alone sends an operator nowhere.
        assert!(reason.contains("invalid_grant"), "reason was {reason}");
        assert!(reason.contains("revoked"), "reason was {reason}");
        assert!(err.needs_operator());

        // The console can see it without anyone calling again.
        let status = broker
            .statuses()
            .await
            .into_iter()
            .find(|s| s.id == "acme")
            .expect("a configured provider has a status");
        assert_eq!(status.last_error.as_deref(), Some(reason.as_str()));
        assert!(
            status.authorized,
            "the grant is still held, it just does not work"
        );

        // A provider that just said no is not asked again on the next sweep. Without this, a
        // revoked grant is one request a minute at the provider for as long as the service
        // runs.
        let before = endpoint.exchanges.load(Ordering::SeqCst);
        assert!(broker.sweep().await.is_empty());
        assert_eq!(
            endpoint.exchanges.load(Ordering::SeqCst),
            before,
            "a failed provider must back off rather than retry every sweep"
        );
    }

    #[tokio::test]
    async fn a_provider_that_does_not_rotate_keeps_the_refresh_token_it_already_had() {
        let (token_url, endpoint) = spawn_endpoint().await;
        endpoint.withhold_refresh.store(true, Ordering::SeqCst);
        let (broker, grants) = broker_with(&token_url);
        broker
            .install_grant("acme", due_grant())
            .await
            .expect("install");

        assert_eq!(broker.sweep().await, vec!["acme".to_string()]);

        // Dropping the refresh token because the response did not repeat it would turn a
        // working grant into a dead one on the very first refresh.
        let stored = grants.load("acme").expect("sealed grant");
        assert_eq!(stored.refresh_token.as_deref(), Some(ORIGINAL_REFRESH));
        assert_eq!(stored.access_token, "access-1");
    }

    #[tokio::test]
    async fn a_provider_dropped_from_policy_stops_being_brokered() {
        let (token_url, _endpoint) = spawn_endpoint().await;
        let (broker, _grants) = broker_with(&token_url);
        broker
            .install_grant("acme", live_grant())
            .await
            .expect("install");
        assert!(broker.authorization_header("acme").await.is_ok());

        broker.reconfigure(BTreeMap::new());

        assert_eq!(
            broker.authorization_header("acme").await,
            Err(BrokerError::UnknownProvider("acme".into()))
        );
        assert!(broker.provider_ids().is_empty());
        assert!(!broker.knows("acme"));
    }

    #[tokio::test]
    async fn a_reload_that_keeps_a_provider_keeps_its_grant() {
        let (token_url, endpoint) = spawn_endpoint().await;
        let (broker, _grants) = broker_with(&token_url);
        broker
            .install_grant("acme", live_grant())
            .await
            .expect("install");

        // An unrelated part of policy changed. The grant is not part of policy and has no
        // business being disturbed by one, and re-authorizing six servers because a root rule
        // moved would be the kind of thing operators remember.
        let mut changed = providers(&token_url);
        changed.get_mut("acme").expect("acme").label = "Acme Corp".into();
        broker.reconfigure(changed);

        assert_eq!(
            broker.authorization_header("acme").await.expect("token"),
            format!("Bearer {ORIGINAL_ACCESS}")
        );
        assert_eq!(endpoint.exchanges.load(Ordering::SeqCst), 0);
        let status = broker
            .statuses()
            .await
            .into_iter()
            .find(|s| s.id == "acme")
            .expect("status");
        assert_eq!(status.label, "Acme Corp");
        assert!(status.authorized);
    }

    #[tokio::test]
    async fn forgetting_a_provider_clears_the_sealed_copy_as_well_as_the_live_one() {
        let (token_url, _endpoint) = spawn_endpoint().await;
        let (broker, grants) = broker_with(&token_url);
        broker
            .install_grant("acme", live_grant())
            .await
            .expect("install");
        assert!(grants.load("acme").is_some());

        assert!(broker.forget("acme").await.expect("forget"));

        assert!(
            grants.load("acme").is_none(),
            "a grant left on disk comes back at the next restart"
        );
        assert_eq!(
            broker.authorization_header("acme").await,
            Err(BrokerError::NotAuthorized {
                provider: "acme".into()
            })
        );
        assert!(!broker.forget("acme").await.expect("second forget"));
    }

    // ── The port's additions ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_sealed_grant_survives_the_broker_being_rebuilt_over_the_same_store() {
        // The restart story without a restart: a second broker over the same store restores
        // the authorization on reconfigure, and no endpoint round trip happens.
        let (token_url, endpoint) = spawn_endpoint().await;
        let grants = GrantStore::ephemeral();
        let first = Broker::with_default_client(grants.clone()).expect("broker builds");
        first.reconfigure(providers(&token_url));
        first
            .install_grant("acme", live_grant())
            .await
            .expect("install");
        drop(first);

        let second = Broker::with_default_client(grants).expect("broker builds");
        second.reconfigure(providers(&token_url));
        assert_eq!(
            second
                .authorization_header("acme")
                .await
                .expect("restored grant"),
            format!("Bearer {ORIGINAL_ACCESS}")
        );
        assert_eq!(endpoint.exchanges.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_sweep_and_the_backoff_run_on_the_injected_clock() {
        // The house pattern paying rent: expiry, the refresh skew and the failure backoff,
        // all crossed without one sleep. The base could not test the backoff expiring at all.
        let (token_url, endpoint) = spawn_endpoint().await;
        let start = 1_000_000_u64;
        let time = Arc::new(AtomicU64::new(start));
        let hand = Arc::clone(&time);
        let broker = Broker::with_clock(GrantStore::ephemeral(), test_client(), move || {
            hand.load(Ordering::SeqCst)
        });
        broker.reconfigure(providers(&token_url));
        broker
            .install_grant(
                "acme",
                Grant {
                    expires_at_unix: Some(start + 3_600),
                    ..live_grant()
                },
            )
            .await
            .expect("install");

        // The request count, distinct from `exchanges`: a rejected attempt is a request the
        // provider saw even though no exchange happened, and the backoff is about requests.
        let requests = || endpoint.bodies.lock().expect("bodies").len();

        // Not due yet: expiry minus the five-minute skew is still ahead.
        assert!(broker.sweep().await.is_empty());
        assert_eq!(requests(), 0);

        // Cross into the skew window and the sweep replaces the token.
        time.store(start + 3_300, Ordering::SeqCst);
        assert_eq!(broker.sweep().await, vec!["acme".to_string()]);
        assert_eq!(requests(), 1);

        // The replacement expires 3600 after the clock the refresh ran on. Advance to its
        // own due point with the endpoint now refusing: one failed attempt, then backoff.
        endpoint.reject.store(true, Ordering::SeqCst);
        time.store(start + 3_300 + 3_600 - 300, Ordering::SeqCst);
        assert!(broker.sweep().await.is_empty());
        assert_eq!(requests(), 2);

        // Inside the backoff window nothing is retried, however many sweeps run.
        assert!(broker.sweep().await.is_empty());
        assert_eq!(requests(), 2);

        // Past the backoff (one failure: 120 seconds) the sweep tries again.
        time.fetch_add(121, Ordering::SeqCst);
        assert!(broker.sweep().await.is_empty());
        assert_eq!(requests(), 3);
    }

    #[tokio::test]
    async fn the_device_flow_lands_a_grant_end_to_end() {
        let (token_url, endpoint) = spawn_endpoint().await;
        let (broker, grants) = broker_with(&token_url);

        let instruction = broker
            .begin_authorization("acme")
            .await
            .expect("device authorization begins");
        assert_eq!(instruction.user_code, "WDJB-MJHT");
        let shown = serde_json::to_string(&instruction).expect("serialize");
        assert!(
            !shown.contains("sentinel-device-code"),
            "the device code is a bearer credential and stays inside the broker"
        );

        // The console sees the pending authorization while the operator is away.
        let status = broker
            .statuses()
            .await
            .into_iter()
            .find(|s| s.id == "acme")
            .expect("status");
        assert!(!status.authorized);
        assert_eq!(
            status.pending.expect("pending instruction").user_code,
            "WDJB-MJHT"
        );

        // The operator finishes at the provider; the background poll picks it up.
        endpoint.approve_device.store(true, Ordering::SeqCst);
        let mut authorized = false;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if broker.authorization_header("acme").await.is_ok() {
                authorized = true;
                break;
            }
        }
        assert!(authorized, "the poll must land the grant");
        assert_eq!(
            broker.authorization_header("acme").await.expect("token"),
            "Bearer access-1"
        );
        assert!(grants.load("acme").is_some(), "the grant is sealed at rest");
        let status = broker
            .statuses()
            .await
            .into_iter()
            .find(|s| s.id == "acme")
            .expect("status");
        assert!(status.authorized);
        assert!(status.pending.is_none(), "nothing is pending once granted");
    }

    #[tokio::test]
    async fn a_configured_client_secret_with_no_lookup_refuses_by_name() {
        // The port's fail-closed divergence from the base, which silently sent the form
        // without the field: the refusal names the provider and the secret, carries no
        // value, and no request leaves the machine.
        let (token_url, endpoint) = spawn_endpoint().await;
        let (broker, _grants) = broker_with(&token_url);
        let mut configured = providers(&token_url);
        configured
            .get_mut("acme")
            .expect("acme")
            .client_secret_secret = Some("acme.client".into());
        broker.reconfigure(configured);
        broker
            .install_grant("acme", due_grant())
            .await
            .expect("install");

        let err = broker
            .authorization_header("acme")
            .await
            .expect_err("a missing client secret must refuse");

        let BrokerError::ClientSecretUnavailable {
            provider, secret, ..
        } = &err
        else {
            panic!("expected the client-secret refusal, got {err:?}");
        };
        assert_eq!(provider, "acme");
        assert_eq!(secret, "acme.client");
        assert!(err.needs_operator());
        assert_eq!(
            endpoint.exchanges.load(Ordering::SeqCst),
            0,
            "no request goes out without the credential the configuration promised"
        );
    }

    #[tokio::test]
    async fn a_wired_lookup_puts_the_client_secret_on_the_wire_and_nowhere_else() {
        let (token_url, endpoint) = spawn_endpoint().await;
        let lookup: ClientSecretLookup = Arc::new(|name: &str| {
            (name == "acme.client")
                .then(|| nmcp_secrets::Sealed::new(b"qf62wm-client-secret-value".to_vec()))
        });
        let broker = Broker::with_parts(
            GrantStore::ephemeral(),
            test_client(),
            now_unix,
            Some(lookup),
        );
        let mut configured = providers(&token_url);
        configured
            .get_mut("acme")
            .expect("acme")
            .client_secret_secret = Some("acme.client".into());
        broker.reconfigure(configured);
        broker
            .install_grant("acme", due_grant())
            .await
            .expect("install");

        assert_eq!(broker.sweep().await, vec!["acme".to_string()]);

        let bodies = endpoint.bodies.lock().expect("bodies").clone();
        assert!(
            bodies
                .iter()
                .any(|body| body.contains("client_secret=qf62wm-client-secret-value")),
            "the endpoint must receive the client secret"
        );
        // And the one place it went is the wire: not the status view, not an error.
        let statuses = serde_json::to_string(&broker.statuses().await).expect("serialize");
        assert!(!statuses.contains("qf62wm"));
    }

    #[tokio::test]
    async fn the_sweeper_stops_when_shutdown_is_signalled() {
        let (token_url, _endpoint) = spawn_endpoint().await;
        let (broker, _grants) = broker_with(&token_url);
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = broker.spawn_sweeper(rx);
        tx.send(true).expect("signal shutdown");
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("the sweeper must stop on shutdown")
            .expect("the sweeper task must not panic");
    }
}
