//! Inbound access token acceptance: the resource-server half of OAuth (G3-11, RS-9, RS-10,
//! RS-12).
//!
//! Part of the NativeMCP `core` workspace. The governance invariants in `docs/GOVERNANCE.md`
//! apply.
//!
//! # Not the crate that was already ported
//!
//! `nmcp-oauth` is the **outbound** device-code broker that obtains grants from upstream MCP
//! servers. This is the **inbound** direction: deciding whether a bearer token presented to
//! *this* server may be accepted. They share a protocol name and nothing else, and
//! NMCP-PLAN-002 finding F-1 records the trap: reading "OAuth is already ported" and skipping
//! this ships a server that cannot verify a token at all.
//!
//! # The clock is injected, and all six reads go through it (WG-4)
//!
//! The base's `accept` and `verify` already took `now: i64` so expiry was testable, while the
//! key cache read the wall clock at six places. Two were `Instant::now()`; the other four were
//! `.elapsed()` on a stored `Instant`, which is the same read wearing a different name.
//!
//! Injecting a clock at the two literal calls would have left four on the real clock and made
//! the trust ceiling untestable, which is the one property here worth a test. So `Instant` does
//! not appear in this crate. `fetched_at` and `last_attempt` hold milliseconds the injected
//! clock produced, and [`JwksCache::with_clock`] is what a test drives.
//!
//! This module decides whether a token that has already been *parsed* may be accepted, and who
//! the caller is if so. It does not verify a signature and does not fetch a key: those need a
//! crypto dependency and a network, and separating them is deliberate.
//!
//! Every project-specific requirement lives here, and every one of them is a rule an
//! implementation can pass a signature check and still get wrong: the algorithm allowlist, the
//! key-id discipline, the issuer check, expiry with bounded skew, audience binding, and the
//! subject mapping. A validator that only checks the signature accepts any token the same
//! authorization server ever issued, for any resource, for anyone. That is the failure this
//! file exists to make impossible to reach by accident.
//!
//! Signature verification wraps this rather than replacing it. Both must pass.

use std::collections::BTreeSet;

use nmcp_policy::{OAuthResourceConfig, OAuthSubject};
use serde_json::Value;

/// Why a token was not accepted.
///
/// Distinct variants rather than one opaque failure, because these are different problems with
/// different fixes and an operator reading a log needs to know which one they have. The variant
/// never reaches the caller: RS-8's response carries `invalid_token` and nothing more, because
/// telling an unauthenticated caller *why* their token failed is telling them how to fix it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenRejection {
    /// The token named an algorithm this server does not accept, including `none`.
    Algorithm(String),
    /// The token named no key, or a key this server has never seen.
    KeyId(Option<String>),
    /// A claim this server requires was absent.
    MissingClaim(&'static str),
    /// The issuer is not one this resource trusts.
    Issuer(String),
    /// Expired, allowing for configured skew.
    Expired,
    /// Not valid yet, allowing for configured skew.
    NotYetValid,
    /// The token was not issued for this resource (RS-10).
    Audience,
    /// Valid, correctly audienced, and belonging to nobody this policy knows (RS-12).
    UnmappedSubject(String),
    /// Not a JWT at all, or a header that could not be read.
    Malformed,
    /// The signature did not verify against the key `kid` named.
    Signature,
}

/// Render an attacker-supplied string safe to put in a log line.
///
/// The `kid` in a rejection comes from the token header, which is read before any signature is
/// checked, so an unauthenticated caller chooses it. Written raw into a plain-text log that is
/// two attacks rather than one: an embedded newline forges records in the file an operator
/// reads after an incident, and an unbounded length flushes the retention window. Control
/// characters are replaced and the value is capped.
fn loggable(value: &str) -> String {
    const MAX: usize = 96;
    let mut out: String = value
        .chars()
        .take(MAX)
        .map(|c| if c.is_control() { '.' } else { c })
        .collect();
    if value.chars().nth(MAX).is_some() {
        out.push_str("...(truncated)");
    }
    out
}

impl TokenRejection {
    /// The reason CLASS, from the closed set the audit specification defines (G3-13, AF-3).
    ///
    /// Coarser than [`TokenRejection::reason`] on purpose. That one goes to the service log,
    /// which an operator reads; this one goes into the audit chain, which is readable by
    /// anyone holding the log and is where a fine-grained reason would tell an attacker which
    /// of their guesses came closest.
    ///
    /// A `&'static str` rather than a formatted string, so no attacker-supplied byte can reach
    /// a record through this path at all.
    #[must_use]
    pub fn reason_class(&self) -> &'static str {
        match self {
            Self::Algorithm(_)
            | Self::KeyId(_)
            | Self::Malformed
            | Self::Signature
            | Self::MissingClaim(_) => "malformed",
            Self::Issuer(_) => "untrusted_issuer",
            Self::Expired | Self::NotYetValid => "expired",
            Self::Audience => "wrong_audience",
            Self::UnmappedSubject(_) => "unmapped_subject",
        }
    }

    /// A short reason for the service log. Never sent to the caller.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Algorithm(alg) => format!(
                "algorithm '{}' is not in the configured allowlist",
                loggable(alg)
            ),
            Self::KeyId(None) => "the token names no kid".to_string(),
            Self::KeyId(Some(kid)) => {
                format!("kid '{}' is not a key this server knows", loggable(kid))
            }
            Self::MissingClaim(claim) => format!("the token carries no '{claim}' claim"),
            Self::Issuer(iss) => format!(
                "issuer '{}' is not the authorization server whose key signed this token, or \
                 is not one this resource trusts",
                loggable(iss)
            ),
            Self::Expired => "the token has expired".to_string(),
            Self::NotYetValid => "the token is not valid yet".to_string(),
            Self::Audience => {
                "the token was not issued for this resource; its audience names something else"
                    .to_string()
            }
            Self::UnmappedSubject(sub) => format!(
                "subject '{}' is valid but is not mapped to an agent_id in policy for the \
                 issuer that signed it",
                loggable(sub)
            ),
            Self::Malformed => "the credential is not a readable JWT".to_string(),
            Self::Signature => {
                "the signature did not verify against the key the token named".to_string()
            }
        }
    }
}

/// The caller a token turns into once accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedToken {
    /// The identity the ring authorizes against, resolved from the subject binding.
    pub agent_id: String,
    /// The gateway profile this subject is pinned to, when the binding names one.
    pub profile: Option<String>,
    /// The `sub` claim the identity was resolved from, kept for the audit record.
    pub subject: String,
}

/// Decide whether to accept a parsed token.
///
/// `algorithm` and `key_id` come from the token's header, `claims` from its payload, and
/// `known_key_ids` from the keys actually held for the issuer. `now` is unix seconds, passed in
/// rather than read so the expiry rules are testable without waiting.
///
/// The order matters and is not arbitrary. The algorithm and key are checked before any claim,
/// because those are the checks that decide whether the signature meant anything, and a claim
/// read out of an unverifiable token is not evidence of anything. The subject mapping is last,
/// because it is the only rejection that means "this is a real token from a real person we do
/// not know", which is a different conversation from the rest.
///
/// `verifying_issuer` is the authorization server whose key actually verified the signature,
/// and it is what the `iss` claim must equal. Checking `iss` against the whole allowlist
/// instead would mean that with two issuers configured, either one's key could vouch for the
/// other one's identity: issuer A signs a token claiming `iss` of issuer B, both are trusted,
/// and the token is accepted as B's. The claim has to match the key that signed it, not merely
/// name somebody this resource has heard of.
///
/// # Errors
///
/// [`TokenRejection`], naming which rule refused it. The variant is for the service log only:
/// RS-8's response to the caller carries `invalid_token` and nothing more, because telling an
/// unauthenticated caller why their token failed is telling them how to fix it.
pub fn accept(
    oauth: &OAuthResourceConfig,
    verifying_issuer: &str,
    algorithm: &str,
    key_id: Option<&str>,
    known_key_ids: &BTreeSet<String>,
    claims: &Value,
    now: i64,
) -> Result<AcceptedToken, TokenRejection> {
    // RS-9. From the allowlist, never from the token. Case-insensitive because JWA names are
    // conventionally uppercase and an operator writing "rs256" meant RS256.
    if !oauth
        .algorithms
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(algorithm))
    {
        return Err(TokenRejection::Algorithm(algorithm.to_string()));
    }

    // RS-9. A kid this server does not hold is a refusal, not an invitation to try every key it
    // has. Trying them all turns an unknown key into an oracle and makes the kid meaningless.
    let Some(kid) = key_id else {
        return Err(TokenRejection::KeyId(None));
    };
    if !known_key_ids.contains(kid) {
        return Err(TokenRejection::KeyId(Some(kid.to_string())));
    }

    // Defence in depth: `verify` only ever passes an issuer it selected from this list, and a
    // direct caller of `accept` could pass anything.
    if !oauth
        .authorization_servers
        .iter()
        .any(|trusted| issuer_matches(trusted, verifying_issuer))
    {
        return Err(TokenRejection::Issuer(verifying_issuer.to_string()));
    }
    let issuer = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or(TokenRejection::MissingClaim("iss"))?;
    // The claim must name the authorization server whose key just verified it, not merely
    // somebody on the allowlist. See the doc comment: the allowlist form is cross-issuer
    // confusion whenever more than one issuer is configured.
    if !issuer_matches(verifying_issuer, issuer) {
        return Err(TokenRejection::Issuer(issuer.to_string()));
    }

    let skew = i64::try_from(oauth.clock_skew_secs).unwrap_or(i64::MAX);
    let expiry = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(TokenRejection::MissingClaim("exp"))?;
    if now > expiry.saturating_add(skew) {
        return Err(TokenRejection::Expired);
    }
    // nbf is optional; when present it is enforced.
    if let Some(not_before) = claims.get("nbf").and_then(Value::as_i64)
        && now < not_before.saturating_sub(skew)
    {
        return Err(TokenRejection::NotYetValid);
    }

    // RS-10. The requirement an implementation that checks only the signature will skip, and
    // skipping it accepts every token this authorization server issued for any other resource.
    if !audience_names(claims, &oauth.resource) {
        return Err(TokenRejection::Audience);
    }

    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or(TokenRejection::MissingClaim("sub"))?;
    // RS-12. Refused rather than given a default identity, for the same reason an undeclared
    // upstream is refused in G4-28: a default that silently grants is the failure mode the ring
    // exists to prevent.
    // RS-12, issuer-qualified. A `sub` is unique within one issuer and nowhere else, so a
    // binding written for one authorization server must not be satisfied by another's token
    // carrying the same subject string. Policy validation requires `issuer` on every binding
    // once more than one authorization server is configured, so `None` here means there is
    // exactly one issuer and the question cannot arise.
    let Some(OAuthSubject {
        agent_id,
        profile,
        issuer: bound_issuer,
    }) = oauth.subjects.get(subject)
    else {
        return Err(TokenRejection::UnmappedSubject(subject.to_string()));
    };
    if let Some(bound) = bound_issuer.as_deref()
        && !issuer_matches(bound, verifying_issuer)
    {
        return Err(TokenRejection::UnmappedSubject(subject.to_string()));
    }

    Ok(AcceptedToken {
        agent_id: agent_id.clone(),
        profile: profile.clone(),
        subject: subject.to_string(),
    })
}

/// Issuer comparison, tolerating only a trailing slash.
///
/// Nothing else is normalized. RFC 9207's rule for the `iss` parameter forbids scheme or host
/// case folding, default-port elision and percent-encoding normalization before comparison, and
/// there is no reason to be looser here than the specification is there. A trailing slash is
/// permitted because authorization servers disagree about it on the same issuer.
fn issuer_matches(trusted: &str, presented: &str) -> bool {
    trusted.trim_end_matches('/') == presented.trim_end_matches('/')
}

/// Whether the token's audience names this resource.
///
/// `aud` is a string or an array of strings in JWT, and both shapes have to be handled: an
/// implementation that reads only the string form silently accepts every multi-audience token,
/// because the check it thinks it is doing never runs.
fn audience_names(claims: &Value, resource: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(one)) => one == resource,
        Some(Value::Array(many)) => many
            .iter()
            .filter_map(Value::as_str)
            .any(|entry| entry == resource),
        _ => false,
    }
}

// ---------------------------------------------------------------------------------------------
// Signature verification and key material (RS-8, RS-9).
// ---------------------------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use parking_lot::RwLock;

/// How long a fetched key set is trusted before it is fetched again.
const JWKS_TTL: Duration = Duration::from_hours(1);

/// How long a key set may keep being trusted when refetching it is failing.
///
/// [`JWKS_TTL`] only decides when to TRY again. This decides when to stop trusting what we
/// have, which is a different question and the one that matters after a key compromise: an
/// authorization server that has retired a key and cannot be reached leaves this server
/// honouring the retired key for as long as the outage lasts. Trusting a key set forever
/// because the network is down converts an availability problem into an authentication one.
///
/// Twenty-four hours, so an ordinary outage costs nobody anything and an indefinite one fails
/// closed.
const JWKS_MAX_AGE: Duration = Duration::from_hours(24);

/// The floor between two fetch ATTEMPTS for the same issuer.
///
/// An unknown `kid` triggers one refetch, because that is what key rotation looks like from
/// here. Without a floor, a caller presenting a made-up `kid` in a loop would turn this server
/// into a request amplifier pointed at its own authorization server. The floor is keyed on the
/// attempt rather than on the success, because an authorization server that is erroring is
/// exactly when the amplification would otherwise run unthrottled, and sustained probing is
/// itself a way to provoke that state.
const JWKS_MIN_REFETCH: Duration = Duration::from_mins(1);

/// The type every cache timestamp in this file has, in milliseconds since the Unix epoch.
///
/// Not `Instant`, and that is WG-4's whole point. An `Instant` can only be compared against
/// `Instant::now()` or `.elapsed()`, both of which read the wall clock, so a struct holding one
/// cannot be driven by an injected clock however many parameters are threaded past it.
type Millis = u64;

/// The clock a cache reads. Milliseconds since the Unix epoch.
pub type Clock = Arc<dyn Fn() -> Millis + Send + Sync>;

/// The default clock: the system's.
///
/// # Panics
///
/// Never. A `SystemTime` before the epoch saturates to zero rather than failing, because a
/// misconfigured host clock must not take the token path down with it.
#[must_use]
pub fn system_clock() -> Clock {
    Arc::new(|| {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or_default(),
        )
        .unwrap_or(u64::MAX)
    })
}

/// How old a stamp is, saturating at zero.
///
/// Saturating rather than wrapping, and the direction is deliberate. A host clock that steps
/// backwards, from an NTP correction or a virtual machine resuming from a snapshot, would make a
/// wrapped subtraction enormous, and every cached key set would read as older than
/// [`JWKS_MAX_AGE`] at once. That is a self-inflicted outage on the token path. Reading a
/// backwards step as "no time has passed" fails the other way: keys stay trusted slightly
/// longer than they should, bounded by the size of the step, and the next forward tick corrects
/// it.
const fn age_ms(now: Millis, stamp: Millis) -> u128 {
    (now.saturating_sub(stamp)) as u128
}

struct CachedKeys {
    keys: JwkSet,
    fetched_at: Millis,
}

/// One issuer's cache line: the keys we hold, if any, and when we last tried to get them.
///
/// `last_attempt` exists separately from `CachedKeys::fetched_at` so that a failing fetch is
/// still throttled. Recording only successes leaves the throttle permanently open in the one
/// regime it was written for.
#[derive(Default)]
struct IssuerCache {
    cached: Option<CachedKeys>,
    last_attempt: Option<Millis>,
}

/// Key sets per issuer, fetched on demand and refetched on rotation.
#[derive(Clone)]
pub struct JwksCache {
    inner: Arc<RwLock<HashMap<String, IssuerCache>>>,
    client: reqwest::Client,
    /// WG-4's seam. See the crate doc: every age comparison below reads this and nothing else.
    clock: Clock,
}

impl JwksCache {
    /// A cache on the system clock.
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(system_clock())
    }

    /// A cache on the clock the caller supplies. WG-4's seam.
    ///
    /// The only way to assert the trust ceiling: a key set held past [`JWKS_MAX_AGE`] must be
    /// refused even when every refetch is failing, and reaching that state on the real clock
    /// would take a day.
    #[must_use]
    pub fn with_clock(clock: Clock) -> Self {
        Self {
            clock,
            inner: Arc::new(RwLock::new(HashMap::new())),
            // No system proxy, and a timeout that cannot be dropped, matching how mcp-gateway
            // builds its client. A hung authorization server must not hang a governed call.
            //
            // Redirects are refused rather than followed. The https check on a discovered
            // `jwks_uri` only binds the first hop, so a followed redirect would let an
            // authorization server, or anyone who can influence its metadata, aim this
            // LocalSystem process at an arbitrary host. A metadata or JWKS endpoint that
            // redirects is unusual enough that refusing it costs nothing and closes the
            // question entirely.
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// The key ids currently usable for an issuer, without fetching.
    ///
    /// A key set past [`JWKS_MAX_AGE`] is reported as holding nothing, so a token naming one of
    /// its keys is refused rather than accepted on evidence this server can no longer confirm.
    fn known_key_ids(&self, issuer: &str) -> BTreeSet<String> {
        let now = (self.clock)();
        self.inner
            .read()
            .get(issuer)
            .and_then(|entry| entry.usable(now))
            .map(|cached| {
                cached
                    .keys
                    .keys
                    .iter()
                    .filter_map(|key| key.common.key_id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn stale(&self, issuer: &str) -> bool {
        let now = (self.clock)();
        self.inner
            .read()
            .get(issuer)
            .and_then(|entry| entry.cached.as_ref())
            .is_none_or(|cached| age_ms(now, cached.fetched_at) >= JWKS_TTL.as_millis())
    }

    /// Whether another fetch ATTEMPT is permitted yet, successful or not.
    fn refetch_allowed(&self, issuer: &str) -> bool {
        let now = (self.clock)();
        self.inner
            .read()
            .get(issuer)
            .and_then(|entry| entry.last_attempt)
            .is_none_or(|attempted| age_ms(now, attempted) >= JWKS_MIN_REFETCH.as_millis())
    }

    /// Fetch and cache the key set for an issuer.
    ///
    /// The JWKS location comes from the authorization server's own metadata rather than from a
    /// path this server guesses. Both discovery documents are tried because the specification
    /// requires an authorization server to publish at least one of them and does not say which.
    async fn fetch(&self, issuer: &str) -> anyhow::Result<()> {
        let now = (self.clock)();
        // Stamped before the network call and kept whatever the outcome, so a failing
        // authorization server is throttled exactly like a working one.
        self.inner
            .write()
            .entry(issuer.to_string())
            .or_default()
            .last_attempt = Some(now);

        let base = issuer.trim_end_matches('/');
        let mut last_error = None;
        for suffix in [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        ] {
            match self.fetch_from(&format!("{base}{suffix}")).await {
                Ok(keys) => {
                    let mut guard = self.inner.write();
                    let entry = guard.entry(issuer.to_string()).or_default();
                    entry.cached = Some(CachedKeys {
                        keys,
                        fetched_at: now,
                    });
                    return Ok(());
                }
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error
            .unwrap_or_else(|| anyhow::anyhow!("no authorization server metadata for {issuer}")))
    }

    async fn fetch_from(&self, metadata_url: &str) -> anyhow::Result<JwkSet> {
        let metadata: Value = self
            .client
            .get(metadata_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let jwks_uri = metadata
            .get("jwks_uri")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{metadata_url} names no jwks_uri"))?;
        if !jwks_uri.starts_with("https://") {
            // RS-2 applies to every endpoint reached, not only the one an operator typed.
            anyhow::bail!("jwks_uri {jwks_uri} is not https");
        }
        Ok(self
            .client
            .get(jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    fn decoding_key(&self, issuer: &str, kid: &str) -> Option<DecodingKey> {
        let now = (self.clock)();
        let guard = self.inner.read();
        let cached = guard.get(issuer)?.usable(now)?;
        let jwk = cached.keys.find(kid)?;
        DecodingKey::from_jwk(jwk).ok()
    }
}

impl IssuerCache {
    /// The cached keys, if they are young enough to still stand for anything.
    fn usable(&self, now: Millis) -> Option<&CachedKeys> {
        self.cached
            .as_ref()
            .filter(|cached| age_ms(now, cached.fetched_at) < JWKS_MAX_AGE.as_millis())
    }
}

/// What this server currently holds for one issuer, for the posture check (RS-14).
///
/// Exists because [`JWKS_MAX_AGE`] can refuse every caller on an install where nothing is
/// misconfigured: the authorization server is simply unreachable and has been for a day. That
/// is the correct behaviour and an impossible one to diagnose from `invalid_token`, which is
/// all a caller is told. An operator has to be able to see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySetPosture {
    /// Never successfully fetched. Ordinary before the first token arrives.
    NeverFetched,
    /// Held and usable. Carries its age in seconds.
    Fresh {
        /// Seconds since this key set was fetched.
        age_secs: u64,
    },
    /// Held, past [`JWKS_TTL`], still inside [`JWKS_MAX_AGE`]. Refetching is being attempted.
    Stale {
        /// Seconds since this key set was fetched.
        age_secs: u64,
    },
    /// Held and past [`JWKS_MAX_AGE`], so no longer trusted. Every token is being refused.
    Expired {
        /// Seconds since this key set was fetched.
        age_secs: u64,
    },
}

impl JwksCache {
    /// The key set posture for each configured issuer, in configuration order.
    #[must_use]
    pub fn posture(&self, issuers: &[String]) -> Vec<(String, KeySetPosture)> {
        let now = (self.clock)();
        let guard = self.inner.read();
        issuers
            .iter()
            .map(|issuer| {
                let posture = match guard.get(issuer).and_then(|entry| entry.cached.as_ref()) {
                    None => KeySetPosture::NeverFetched,
                    Some(cached) => {
                        let elapsed = age_ms(now, cached.fetched_at);
                        let age_secs = u64::try_from(elapsed / 1_000).unwrap_or(u64::MAX);
                        if elapsed >= JWKS_MAX_AGE.as_millis() {
                            KeySetPosture::Expired { age_secs }
                        } else if elapsed >= JWKS_TTL.as_millis() {
                            KeySetPosture::Stale { age_secs }
                        } else {
                            KeySetPosture::Fresh { age_secs }
                        }
                    }
                };
                (issuer.clone(), posture)
            })
            .collect()
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a bearer token and turn it into a caller (RS-8).
///
/// Reads the header without trusting it, lets [`accept`] rule on the algorithm and key id,
/// verifies the signature with exactly the key `kid` named and exactly the algorithm the
/// allowlist matched, then lets [`accept`] rule on the claims.
///
/// `jsonwebtoken` is deliberately told to validate nothing else: no expiry, no audience, no
/// required claims. Those rules live in [`accept`] where they are tested exhaustively, and
/// splitting them between this call and a library's defaults is how a rule ends up enforced
/// twice in two different ways or not at all.
///
/// # Errors
///
/// [`TokenRejection`], from the signature check here or from [`accept`]'s claim rules. Both
/// must pass.
pub async fn verify(
    oauth: &OAuthResourceConfig,
    jwks: &JwksCache,
    token: &str,
    now: i64,
) -> Result<AcceptedToken, TokenRejection> {
    let header = decode_header(token).map_err(|_| TokenRejection::Malformed)?;
    let algorithm_name = format!("{:?}", header.alg);
    let Some(kid) = header.kid.clone() else {
        return Err(TokenRejection::KeyId(None));
    };

    // RS-9, before anything else. The algorithm comes from the allowlist, and a token naming one
    // outside it is refused before a key is fetched, so an unknown algorithm cannot even cause
    // network traffic.
    if !oauth
        .algorithms
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&algorithm_name))
    {
        return Err(TokenRejection::Algorithm(algorithm_name));
    }

    // Find the issuer holding this kid, fetching where the set is stale or the kid is new.
    // Deliberately NOT read from the token: doing that would mean parsing attacker-controlled
    // JSON before anything has been verified, and the kid alone is enough to find the key.
    let mut holder = None;
    for issuer in &oauth.authorization_servers {
        // A key set this old, or one that has never heard of this kid, is worth refetching.
        // `refetch_allowed` is the separate question of whether we may yet, and it is what
        // stops an unknown kid from becoming a request generator aimed at the authorization
        // server.
        let stale_for_this_kid = jwks.stale(issuer) || !jwks.known_key_ids(issuer).contains(&kid);
        if stale_for_this_kid && jwks.refetch_allowed(issuer) {
            let _ = jwks.fetch(issuer).await;
        }
        if jwks.known_key_ids(issuer).contains(&kid) {
            holder = Some(issuer.clone());
            break;
        }
    }
    let Some(issuer) = holder else {
        return Err(TokenRejection::KeyId(Some(kid)));
    };
    let known = jwks.known_key_ids(&issuer);
    let key = jwks
        .decoding_key(&issuer, &kid)
        .ok_or_else(|| TokenRejection::KeyId(Some(kid.clone())))?;

    // Exactly one algorithm, the one the allowlist matched, so the token cannot nominate another.
    let mut validation = Validation::new(header.alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims = std::collections::HashSet::new();

    let decoded =
        decode::<Value>(token, &key, &validation).map_err(|_| TokenRejection::Signature)?;

    // Every claim rule, on the payload that just verified, bound to the issuer whose key
    // verified it.
    accept(
        oauth,
        &issuer,
        &algorithm_name,
        Some(&kid),
        &known,
        &decoded.claims,
        now,
    )
}

#[cfg(test)]
mod tests {
    // Tests assert on shapes, verdicts and refusals, where unwrap/expect/indexing ARE the
    // assertion: a panic in a test is the failure signal, so the production rationale for the
    // workspace denies (availability plus an audit gap) does not apply. Scoped to the test
    // module, named in the PR.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    const NOW: i64 = 1_785_700_000;

    fn keys() -> BTreeSet<String> {
        BTreeSet::from(["key-1".to_string()])
    }

    /// The issuer whose key verified the signature, in every fixture below. Passed
    /// explicitly because binding the `iss` claim to THIS value rather than to the
    /// allowlist is what stops one configured issuer vouching for another.
    const ISSUER: &str = "https://login.example.com";

    fn oauth() -> OAuthResourceConfig {
        let mut subjects = BTreeMap::new();
        subjects.insert(
            "user@example.com".to_string(),
            OAuthSubject {
                agent_id: "chatgpt".into(),
                profile: None,
                issuer: None,
            },
        );
        OAuthResourceConfig {
            resource: "https://mcp.example.com/mcp".into(),
            authorization_servers: vec!["https://login.example.com".into()],
            subjects,
            algorithms: vec!["RS256".into()],
            clock_skew_secs: 60,
            scopes_supported: Vec::new(),
        }
    }

    fn claims() -> Value {
        json!({
            "iss": "https://login.example.com",
            "sub": "user@example.com",
            "aud": "https://mcp.example.com/mcp",
            "exp": NOW + 300,
        })
    }

    fn try_accept(
        oauth: &OAuthResourceConfig,
        claims: &Value,
    ) -> Result<AcceptedToken, TokenRejection> {
        accept(oauth, ISSUER, "RS256", Some("key-1"), &keys(), claims, NOW)
    }

    #[test]
    fn a_correct_token_becomes_the_caller_policy_named() {
        let accepted = try_accept(&oauth(), &claims()).expect("accepted");
        assert_eq!(accepted.agent_id, "chatgpt");
        assert_eq!(accepted.subject, "user@example.com");
        assert_eq!(accepted.profile, None);
    }

    /// RS-9. The oldest trick in this book: the token nominating its own verification.
    #[test]
    fn an_algorithm_outside_the_allowlist_is_refused_including_none() {
        for algorithm in ["none", "None", "HS256", "RS512"] {
            let rejection = accept(
                &oauth(),
                ISSUER,
                algorithm,
                Some("key-1"),
                &keys(),
                &claims(),
                NOW,
            )
            .expect_err(algorithm);
            assert!(
                matches!(rejection, TokenRejection::Algorithm(_)),
                "{algorithm}"
            );
        }
    }

    /// RS-9. An unknown kid is a refusal, not an invitation to try every key.
    #[test]
    fn an_unknown_or_absent_key_id_is_refused() {
        assert_eq!(
            accept(&oauth(), ISSUER, "RS256", None, &keys(), &claims(), NOW).unwrap_err(),
            TokenRejection::KeyId(None)
        );
        assert_eq!(
            accept(
                &oauth(),
                ISSUER,
                "RS256",
                Some("key-9"),
                &keys(),
                &claims(),
                NOW
            )
            .unwrap_err(),
            TokenRejection::KeyId(Some("key-9".into()))
        );
    }

    /// The finding this test exists for: `accept` used to check the `iss` claim against the
    /// WHOLE allowlist rather than against the issuer whose key verified the signature. With
    /// two issuers configured that let either one's key vouch for the other one's identity.
    #[test]
    fn one_trusted_issuers_key_cannot_vouch_for_another_trusted_issuers_identity() {
        let mut oauth = oauth();
        oauth
            .authorization_servers
            .push("https://partner.example.com".into());
        // Both bindings must now name an issuer, which is the other half of the fix.
        oauth.subjects.insert(
            "user@example.com".to_string(),
            OAuthSubject {
                agent_id: "chatgpt".into(),
                profile: None,
                issuer: Some("https://login.example.com".into()),
            },
        );

        // The partner's key signed it. The payload claims to be the primary issuer's.
        let mut forged = claims();
        forged["iss"] = json!("https://login.example.com");
        let rejection = accept(
            &oauth,
            "https://partner.example.com",
            "RS256",
            Some("key-1"),
            &keys(),
            &forged,
            NOW,
        )
        .expect_err("a key from one issuer must not vouch for another issuer's identity");
        assert!(
            matches!(rejection, TokenRejection::Issuer(_)),
            "{rejection:?}"
        );

        // The same claims, verified by the issuer that actually signs for them, are fine.
        accept(
            &oauth,
            "https://login.example.com",
            "RS256",
            Some("key-1"),
            &keys(),
            &forged,
            NOW,
        )
        .expect("the issuer whose key signed it is the issuer it claims");
    }

    /// A `sub` is unique within one issuer and nowhere else (RFC 7519 Section 4.1.2), so a
    /// binding written for one authorization server must not be satisfied by another's token
    /// carrying the same subject string.
    #[test]
    fn a_subject_binding_belongs_to_one_issuer_and_not_to_any_other() {
        let mut oauth = oauth();
        oauth
            .authorization_servers
            .push("https://partner.example.com".into());
        oauth.subjects.insert(
            "user@example.com".to_string(),
            OAuthSubject {
                agent_id: "chatgpt".into(),
                profile: None,
                issuer: Some("https://login.example.com".into()),
            },
        );

        // The partner's own token, honestly claiming the partner as issuer, for a subject
        // string the operator bound to the other issuer.
        let mut partner = claims();
        partner["iss"] = json!("https://partner.example.com");
        let rejection = accept(
            &oauth,
            "https://partner.example.com",
            "RS256",
            Some("key-1"),
            &keys(),
            &partner,
            NOW,
        )
        .expect_err("a subject bound to one issuer is not that subject at another");
        assert!(
            matches!(rejection, TokenRejection::UnmappedSubject(_)),
            "{rejection:?}"
        );
    }

    /// An unqualified binding still works, because policy validation only permits one when
    /// there is exactly one issuer for it to be unambiguous about.
    #[test]
    fn an_unqualified_binding_still_resolves_on_a_single_issuer_resource() {
        let accepted = try_accept(&oauth(), &claims()).expect("accepted");
        assert_eq!(accepted.agent_id, "chatgpt");
    }

    /// An unauthenticated caller chooses the `kid`, and it reaches the service log before any
    /// signature is checked. A newline in it would forge log records; length would flush the
    /// retention window.
    #[test]
    fn a_rejection_reason_cannot_be_used_to_forge_or_flood_the_log() {
        let forged = TokenRejection::KeyId(Some(
            "x\n2026-08-03T00:00:00Z INFO mcp_server: MCP: OAuth token accepted".to_string(),
        ));
        let reason = forged.reason();
        assert!(!reason.contains('\n'), "{reason}");
        assert!(
            reason.contains("token accepted"),
            "the text is kept, only made safe"
        );

        let flood = TokenRejection::KeyId(Some("A".repeat(10_000)));
        let reason = flood.reason();
        assert!(reason.len() < 200, "{}", reason.len());
        assert!(reason.contains("...(truncated)"), "{reason}");
    }

    #[test]
    fn an_issuer_this_resource_does_not_trust_is_refused() {
        let mut c = claims();
        c["iss"] = json!("https://elsewhere.example.com");
        assert!(matches!(
            try_accept(&oauth(), &c).unwrap_err(),
            TokenRejection::Issuer(_)
        ));
    }

    #[test]
    fn a_trailing_slash_on_the_issuer_is_the_only_thing_forgiven() {
        let mut c = claims();
        c["iss"] = json!("https://login.example.com/");
        assert!(try_accept(&oauth(), &c).is_ok());

        // Case folding is not forgiven, matching RFC 9207's rule for the iss parameter.
        c["iss"] = json!("https://LOGIN.example.com");
        assert!(matches!(
            try_accept(&oauth(), &c).unwrap_err(),
            TokenRejection::Issuer(_)
        ));
    }

    #[test]
    fn expiry_and_not_before_are_enforced_within_the_configured_skew() {
        let mut c = claims();
        c["exp"] = json!(NOW - 30);
        assert!(try_accept(&oauth(), &c).is_ok(), "inside the 60s skew");
        c["exp"] = json!(NOW - 90);
        assert_eq!(
            try_accept(&oauth(), &c).unwrap_err(),
            TokenRejection::Expired
        );

        let mut c = claims();
        c["nbf"] = json!(NOW + 30);
        assert!(try_accept(&oauth(), &c).is_ok(), "inside the 60s skew");
        c["nbf"] = json!(NOW + 90);
        assert_eq!(
            try_accept(&oauth(), &c).unwrap_err(),
            TokenRejection::NotYetValid
        );
    }

    /// RS-10. The one an implementation that checks only the signature will skip.
    #[test]
    fn a_token_issued_for_another_resource_is_refused() {
        let mut c = claims();
        c["aud"] = json!("https://someone-elses-api.example.com");
        assert_eq!(
            try_accept(&oauth(), &c).unwrap_err(),
            TokenRejection::Audience
        );

        // Absent audience is not "no restriction", it is a token that never named us.
        let mut c = claims();
        c.as_object_mut().unwrap().remove("aud");
        assert_eq!(
            try_accept(&oauth(), &c).unwrap_err(),
            TokenRejection::Audience
        );
    }

    /// The array form has to be handled, or a multi-audience token skips the check entirely.
    #[test]
    fn an_audience_array_is_read_as_carefully_as_a_string() {
        let mut c = claims();
        c["aud"] = json!(["https://other.example.com", "https://mcp.example.com/mcp"]);
        assert!(try_accept(&oauth(), &c).is_ok());

        c["aud"] = json!(["https://other.example.com", "https://another.example.com"]);
        assert_eq!(
            try_accept(&oauth(), &c).unwrap_err(),
            TokenRejection::Audience
        );

        c["aud"] = json!([]);
        assert_eq!(
            try_accept(&oauth(), &c).unwrap_err(),
            TokenRejection::Audience
        );
    }

    /// RS-12. A real token from a real person nobody mapped is refused, not defaulted.
    #[test]
    fn an_unmapped_subject_is_refused_rather_than_given_an_identity() {
        let mut c = claims();
        c["sub"] = json!("stranger@example.com");
        assert_eq!(
            try_accept(&oauth(), &c).unwrap_err(),
            TokenRejection::UnmappedSubject("stranger@example.com".into())
        );
    }

    #[test]
    fn a_subject_may_be_pinned_to_a_gateway_profile() {
        let mut oauth = oauth();
        oauth.subjects.insert(
            "user@example.com".into(),
            OAuthSubject {
                agent_id: "chatgpt".into(),
                profile: Some("reading".into()),
                issuer: None,
            },
        );
        let accepted = try_accept(&oauth, &claims()).expect("accepted");
        assert_eq!(accepted.profile.as_deref(), Some("reading"));
    }

    #[test]
    fn a_missing_required_claim_is_named() {
        for claim in ["iss", "exp", "sub"] {
            let mut c = claims();
            c.as_object_mut().unwrap().remove(claim);
            let rejection = try_accept(&oauth(), &c).unwrap_err();
            assert!(
                matches!(rejection, TokenRejection::MissingClaim(named) if named == claim)
                    || matches!(rejection, TokenRejection::Audience),
                "{claim}: {rejection:?}"
            );
        }
    }

    /// Every rejection says something an operator can act on, and none of them reach the caller.
    #[test]
    fn every_rejection_reason_names_what_was_wrong() {
        for rejection in [
            TokenRejection::Algorithm("none".into()),
            TokenRejection::KeyId(None),
            TokenRejection::KeyId(Some("key-9".into())),
            TokenRejection::MissingClaim("exp"),
            TokenRejection::Issuer("https://elsewhere".into()),
            TokenRejection::Expired,
            TokenRejection::NotYetValid,
            TokenRejection::Audience,
            TokenRejection::UnmappedSubject("stranger".into()),
        ] {
            let reason = rejection.reason();
            assert!(!reason.is_empty());
            assert!(
                reason.chars().next().is_some_and(char::is_lowercase),
                "reasons read as clause fragments in a log line: {reason}"
            );
        }
    }
}

// ── The trust ceiling, driven (WG-4, NMCP-PLAN-002 I-074 acceptance) ─────────────────────────

#[cfg(test)]
mod trust_ceiling_tests {
    // As the module above: a panic here is the assertion.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::{
        CachedKeys, Clock, IssuerCache, JWKS_MAX_AGE, JWKS_MIN_REFETCH, JWKS_TTL, JwksCache,
        KeySetPosture, Millis,
    };
    use jsonwebtoken::jwk::JwkSet;
    use parking_lot::Mutex;
    use serde_json::json;
    use std::sync::Arc;

    /// A clock a test moves by hand. The whole point of I-074's seam.
    #[derive(Clone)]
    struct TestClock(Arc<Mutex<Millis>>);

    impl TestClock {
        fn at(start: Millis) -> Self {
            Self(Arc::new(Mutex::new(start)))
        }
        fn advance(&self, by: std::time::Duration) {
            let mut guard = self.0.lock();
            *guard += u64::try_from(by.as_millis()).unwrap();
        }
        fn rewind(&self, by: std::time::Duration) {
            let mut guard = self.0.lock();
            *guard = guard.saturating_sub(u64::try_from(by.as_millis()).unwrap());
        }
        fn clock(&self) -> Clock {
            let inner = Arc::clone(&self.0);
            Arc::new(move || *inner.lock())
        }
    }

    /// One RSA key, enough that `find(kid)` has something to find. Never used to verify.
    fn key_set(kid: &str) -> JwkSet {
        serde_json::from_value(json!({
            "keys": [{
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": "sXchqfXm2ZQ1YlPl6JmZ6iMDNTGmVUZmVXUUdmM1FnZmVXcmVzaGtleQ",
                "e": "AQAB"
            }]
        }))
        .expect("a well formed key set")
    }

    /// Seed a cache as though a fetch had succeeded at `fetched_at`.
    fn cache_holding(clock: &TestClock, issuer: &str, kid: &str, fetched_at: Millis) -> JwksCache {
        let cache = JwksCache::with_clock(clock.clock());
        cache.inner.write().insert(
            issuer.to_string(),
            IssuerCache {
                cached: Some(CachedKeys {
                    keys: key_set(kid),
                    fetched_at,
                }),
                last_attempt: Some(fetched_at),
            },
        );
        cache
    }

    /// The acceptance criterion NMCP-PLAN-002 names for I-074.
    ///
    /// `JWKS_TTL` decides when to TRY to refetch. `JWKS_MAX_AGE` decides when to stop trusting
    /// what is held, and it is the one that matters after a key compromise: an authorization
    /// server that has retired a key and cannot be reached would otherwise leave this server
    /// honouring the retired key for as long as the outage lasts.
    ///
    /// No refetch succeeds anywhere in this test, which is the state being asserted about. On
    /// the real clock, reaching it would take a day, and that is why the clock is a parameter.
    #[test]
    fn a_key_set_past_the_trust_ceiling_stops_being_trusted_however_the_refetch_goes() {
        let clock = TestClock::at(1_000_000);
        let cache = cache_holding(&clock, "https://issuer.example", "kid-1", 1_000_000);

        assert!(
            cache
                .known_key_ids("https://issuer.example")
                .contains("kid-1"),
            "freshly fetched keys are usable"
        );
        assert!(matches!(
            cache.posture(&["https://issuer.example".to_string()])[0].1,
            KeySetPosture::Fresh { .. }
        ));

        // Past the refetch TTL, still inside the ceiling. Held, and refetching is attempted.
        clock.advance(JWKS_TTL + std::time::Duration::from_secs(1));
        assert!(
            cache.stale("https://issuer.example"),
            "past the TTL the cache wants a refetch"
        );
        assert!(
            cache
                .known_key_ids("https://issuer.example")
                .contains("kid-1"),
            "wanting a refetch is not the same as distrusting what is held, and conflating the \
             two would refuse every token during any outage longer than an hour"
        );
        assert!(matches!(
            cache.posture(&["https://issuer.example".to_string()])[0].1,
            KeySetPosture::Stale { .. }
        ));

        // Past the ceiling. Nothing is trusted, and no fetch has succeeded in between.
        clock.advance(JWKS_MAX_AGE);
        assert!(
            cache.known_key_ids("https://issuer.example").is_empty(),
            "past the ceiling the key set holds nothing, so a token naming one of its keys is \
             refused rather than accepted on evidence this server can no longer confirm"
        );
        assert!(
            cache
                .decoding_key("https://issuer.example", "kid-1")
                .is_none(),
            "and the verification path agrees with the report, or the posture surface would be \
             telling an operator something the token path does not act on"
        );
        let posture = &cache.posture(&["https://issuer.example".to_string()])[0].1;
        let KeySetPosture::Expired { age_secs } = posture else {
            panic!("expected Expired, got {posture:?}");
        };
        assert!(
            *age_secs >= JWKS_MAX_AGE.as_secs(),
            "the age reported is the real one: {age_secs}s"
        );
    }

    /// The amplification floor, which is keyed on the ATTEMPT rather than on the success.
    ///
    /// An unknown `kid` triggers one refetch, because that is what key rotation looks like from
    /// here. Without a floor, a caller presenting a made-up `kid` in a loop turns this server
    /// into a request amplifier pointed at its own authorization server, and an authorization
    /// server that is erroring is exactly when that would run unthrottled.
    #[test]
    fn the_refetch_floor_is_measured_from_the_attempt_and_not_from_the_success() {
        let clock = TestClock::at(500_000);
        let cache = cache_holding(&clock, "https://issuer.example", "kid-1", 500_000);

        assert!(
            !cache.refetch_allowed("https://issuer.example"),
            "an attempt was just recorded, so another is refused"
        );
        clock.advance(JWKS_MIN_REFETCH.saturating_sub(std::time::Duration::from_secs(1)));
        assert!(
            !cache.refetch_allowed("https://issuer.example"),
            "still inside the floor"
        );
        clock.advance(std::time::Duration::from_secs(2));
        assert!(
            cache.refetch_allowed("https://issuer.example"),
            "past the floor one attempt is allowed again"
        );
    }

    /// `age_ms` saturates, and the direction is a decision rather than an accident.
    ///
    /// A host clock that steps backwards, from an NTP correction or a virtual machine resuming
    /// from a snapshot, would make a wrapped subtraction enormous and every cached key set would
    /// read as past [`JWKS_MAX_AGE`] at once. That is a self-inflicted outage on the token path,
    /// triggered by something no attacker had to do. Reading a backwards step as "no time has
    /// passed" fails the other way, bounded by the size of the step.
    #[test]
    fn a_clock_that_steps_backwards_does_not_expire_every_key_set_at_once() {
        let clock = TestClock::at(10_000_000);
        let cache = cache_holding(&clock, "https://issuer.example", "kid-1", 10_000_000);

        clock.rewind(std::time::Duration::from_hours(1));
        assert!(
            cache
                .known_key_ids("https://issuer.example")
                .contains("kid-1"),
            "a backwards step must not read as an enormous age"
        );
        assert!(matches!(
            cache.posture(&["https://issuer.example".to_string()])[0].1,
            KeySetPosture::Fresh { age_secs: 0 }
        ));
    }
}

// ── The backend is actually present (I-082) ─────────────────────────────────────────────────

#[cfg(test)]
mod backend_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    use serde_json::{Value, json};

    /// A real RS256 verification, because nothing else in this crate performs one.
    ///
    /// Every other test drives `accept`, which decides claims, or the key cache, which decides
    /// ages. **None of them touches a signature.** So a build whose `jsonwebtoken` features
    /// leave no algorithm backend compiled in would pass this crate's whole suite and refuse
    /// every real token in production, which is a silent authentication outage rather than a
    /// failure anybody would see in CI.
    ///
    /// This asserts the backend exists by using it. The token is signed by a key this test does
    /// not hold, so verification must fail on the SIGNATURE rather than on "algorithm not
    /// supported": the distinction is the whole point.
    #[test]
    fn an_rs256_verification_reaches_the_signature_check_rather_than_an_unsupported_algorithm() {
        // A well-formed RSA public JWK. Verification against it must fail, and the reason
        // matters.
        let jwks: JwkSet = serde_json::from_value(json!({
            "keys": [{
                "kty": "RSA",
                "kid": "k1",
                "use": "sig",
                "alg": "RS256",
                "n": "sXchqfXm2ZQ1YlPl6JmZ6iMDNTGmVUZmVXUUdmM1FnZmVXcmVzaGtleQ",
                "e": "AQAB"
            }]
        }))
        .expect("a well formed key set");
        let jwk = jwks.find("k1").expect("the key is in the set");
        let key = DecodingKey::from_jwk(jwk).expect(
            "from_jwk must build an RSA decoding key; failing here means no RSA backend is \
             compiled in and every RS256 token would be refused in production",
        );

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        let forged =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.eyJzdWIiOiJhbGljZSJ9.bm90LWEtcmVhbC1zaWduYXR1cmU";

        let err = decode::<Value>(forged, &key, &validation)
            .expect_err("a token signed by nobody must not verify");
        assert!(
            !format!("{err:?}").to_lowercase().contains("unsupported"),
            "the algorithm must be supported and the SIGNATURE must be what fails. An \
             `unsupported` error means the crate was built with no backend for RS256, which \
             would refuse every real token while this crate's other tests all still pass. \
             Got: {err:?}"
        );
    }
}
