//! The admission surface: whether a caller may proceed, and as whom.
//!
//! Origin enforcement, the client identity, the gateway profile in force, the two credential
//! paths, and the throttled authenticate every lane goes through. The base keeps all of this at
//! its crate root and reaches it from the lane module through `use super::*`, so an inventory of
//! what the lanes import does not show it at all.
//!
//! # Why this is its own module and its own issue
//!
//! It is the part the three lanes agree on. NMCP-REF-001 enumerates thirty ways POST, SSE and
//! WebSocket diverge, and **not one of them is in here**: every lane calls
//! [`authenticate_and_record`] with the same arguments and reads the same answer. The
//! divergences begin after admission, in what a caller who has already been admitted is allowed
//! to ask for, which is I-075b.
//!
//! That is also why WD-24 is not this module's defect. `session_profile_from_headers` is
//! correct. The SSE lane simply never calls it, and the lane is where that is visible.
//!
//! # The order inside `authenticate_and_record` is load-bearing
//!
//! The throttle is checked **before** the credential is evaluated. That is the whole point of
//! it: a throttled source costs this process a map lookup rather than a signature verification
//! or a JWKS fetch against a remote issuer. Checking it after would leave the expensive work
//! reachable by exactly the caller the throttle exists to stop, and the endpoint would still
//! answer 401 either way, so nothing about the response shape would reveal the mistake.
//!
//! It is keyed on source alone and never on the credential, so one attacker cannot get a
//! legitimate client refused by guessing at its identity.

// Nothing routes here yet: the three lanes are I-075b and the composition root is I-078.
// `allow` rather than `expect` for the reason `diagnostics` gives: this module's own tests drive
// what they cover, so the lint fires in the lib target and not in the lib-test target, and an
// unfulfilled expectation in either is an error.
//
// Crate-visible rather than public throughout, which is what the base had. Widening these to
// `pub` to quiet the lint would publish an admission API that nothing outside this crate should
// be able to call.
#![allow(
    dead_code,
    reason = "the lanes are I-075b; the composition root is I-078"
)]

use crate::peer::PeerSource;
use crate::{AppState, constant_time_eq};
use axum::http::{HeaderMap, header};
use nmcp_policy::{McpClientCredential, PolicyConfig};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// The origin allowlist ────────────────────────────────────────────────────────────────────

pub(crate) fn enforce_mcp_origin(policy: &PolicyConfig, headers: &HeaderMap) -> anyhow::Result<()> {
    if let Some(origin) = headers.get("origin") {
        let value = origin.to_str().unwrap_or_default();
        if !origin_allowed(policy, value) {
            anyhow::bail!("origin rejected by MCP allowed-origin policy");
        }
    }
    Ok(())
}

/// Environment override for the MCP origin allowlist. NMCP-DEC-001 row B-12.
pub(crate) const ALLOWED_ORIGINS_ENV: &str = "NMCP_ALLOWED_ORIGINS";

/// Read the allowlist override.
///
/// # The compatibility machinery that was here, and why it could not come
///
/// The base carries a four-armed `OriginEnvSource` and two `Once`-gated deprecation warnings,
/// so that an operator upgrading from the pre-previous product does not silently lose an
/// allowlist. Silent loss is the right thing to protect against: it presents as intermittent
/// origin rejections rather than as an upgrade failure, so it is diagnosed late and by the
/// wrong person.
///
/// Shifting that machinery one rename forward, honouring the base's variable name as the
/// legacy one, is the obvious port and **INV-8 forbids it**: the base's name is a legacy brand
/// string, and the invariant is that no such string exists anywhere in this tree. The
/// pre-previous name is one too, from a product this one has never been.
///
/// So one arm survives, which makes it an `Option`, and the migration is an operator action
/// inside the cutover window. NMCP-DEC-001 already disposes of rows A-2 and A-11 that way:
/// the value is fixed here, the move is the operator's, and it happens once.
fn allowed_origins_from_env() -> Option<String> {
    std::env::var(ALLOWED_ORIGINS_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn origin_in_list(list: &str, origin: &str) -> bool {
    list.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .any(|allowed| allowed == origin)
}

fn origin_allowed(policy: &PolicyConfig, origin: &str) -> bool {
    if origin_has_loopback_host(origin) {
        return true;
    }
    if policy
        .mcp_allowed_origins
        .iter()
        .any(|allowed| allowed == origin)
    {
        return true;
    }
    allowed_origins_from_env().is_some_and(|list| origin_in_list(&list, origin))
}

fn origin_has_loopback_host(origin: &str) -> bool {
    let Some(after_scheme) = origin.split_once("://").map(|(_, rest)| rest) else {
        return false;
    };
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped
            .split_once(']')
            .map(|(inside, _)| inside)
            .unwrap_or_default()
    } else {
        authority
            .rsplit_once('@')
            .map_or(authority, |(_, host_port)| host_port)
            .split(':')
            .next()
            .unwrap_or_default()
    }
    .to_ascii_lowercase();

    matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1")
}

// Who is calling ──────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct McpClientIdentity {
    pub(crate) agent_id: String,
    /// Which credential path admitted this caller (G3-15, AF-7): `static` or `oauth`.
    ///
    /// Rides on the identity rather than being a separate parameter, because it is a fact
    /// about how this caller was established and travels wherever the identity does.
    pub(crate) credential_path: &'static str,
    /// The gateway profile this credential is pinned to, if any (G6-8).
    pub(crate) profile: Option<String>,
}

/// The header a client names a gateway profile in. NMCP-DEC-001 row B-9.
///
/// DEC-001 singles this row out as the one in its group whose migration must be verified rather
/// than assumed, and the reason is the failure shape: a request naming a profile this server
/// does not recognise is not refused, it is served **without** the profile, which is a silent
/// widening of what that caller can reach. INV-4's whole subject. Hence a constant rather than
/// a literal at the read site, and a test that asserts the pre-rename spelling no longer scopes
/// anything.
pub(crate) const PROFILE_HEADER: &str = "x-nmcp-profile";

/// The header the static credential path reads. NMCP-DEC-001 row B-8.
pub(crate) const CLIENT_TOKEN_HEADER: &str = "x-nmcp-token";

/// The gateway profile in force for one session.
///
/// Split from `authenticate_mcp_client` rather than folded into it so the two failures stay
/// distinguishable on the wire: a bad token and a profile a client may not have are different
/// problems with different fixes, and answering both with one error code would send an
/// operator to the wrong one.
pub(crate) fn session_profile_from_headers(
    policy: &PolicyConfig,
    identity: Option<&McpClientIdentity>,
    headers: &HeaderMap,
) -> Result<Option<String>, anyhow::Error> {
    policy
        .session_profile(
            identity.and_then(|identity| identity.profile.as_deref()),
            headers
                .get(PROFILE_HEADER)
                .and_then(|value| value.to_str().ok()),
        )
        .map_err(|err| anyhow::anyhow!(err))
}

fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    digest
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

// The two credential paths ────────────────────────────────────────────────────────────────

/// The `Authorization: Bearer` credential, and only that header.
///
/// Separate from [`mcp_client_token_from_headers`], which also accepts
/// [`CLIENT_TOKEN_HEADER`], because RS-13 splits the two paths by header rather than by
/// guessing at the credential's shape.
pub(crate) fn bearer_token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_credential)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

/// The credential from an `Authorization: Bearer` value, matching the scheme as HTTP defines it.
///
/// RFC 7235 Section 2.1 makes the auth-scheme token case-insensitive, so a conformant client
/// sending `authorization: bearer <jwt>` is sending a bearer token. A case-sensitive
/// `strip_prefix("Bearer ")` fails closed rather than open, but it fails on a correct client
/// and routes it to the wrong one of two authentication lanes, which is its own kind of wrong.
fn bearer_credential(value: &str) -> Option<&str> {
    let (scheme, credential) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("Bearer").then_some(credential)
}

pub(crate) fn mcp_client_token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(CLIENT_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| bearer_token_from_headers(headers))
}

/// `sha256_hex` for the lane tests, which build a credential the same way policy does.
///
/// A named seam rather than widening `sha256_hex` itself: the hash belongs to the static
/// credential path and nothing outside this module should be reaching for it in production.
#[cfg(test)]
pub(crate) fn sha256_hex_for_tests(input: &str) -> String {
    sha256_hex(input)
}

// Refusal, at the resolution an audit record may carry ────────────────────────────────────

/// Why an authentication attempt failed, at the resolution an audit record may carry.
///
/// A closed set of `&'static str` rather than a formatted string, and that is the point: an
/// audit record is readable by anyone holding the log, and the fine-grained reason is exactly
/// what tells an attacker which of their guesses came closest (G3-13, AF-3). Making the class
/// a compile-time constant means attacker-supplied bytes cannot reach a record by accident,
/// rather than being trusted not to (AF-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthRejection {
    /// Which credential path was attempted: `static` or `oauth`.
    pub(crate) credential_path: &'static str,
    /// The reason class, from the specification's closed set.
    pub(crate) reason: &'static str,
    /// What the caller is told. Never more specific than the class.
    pub(crate) message: &'static str,
}

impl AuthRejection {
    const fn new(
        credential_path: &'static str,
        reason: &'static str,
        message: &'static str,
    ) -> Self {
        Self {
            credential_path,
            reason,
            message,
        }
    }
}

impl std::fmt::Display for AuthRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for AuthRejection {}

// Admission ───────────────────────────────────────────────────────────────────────────────

/// Authenticate, and record a failure into the coalescing ledger (G3-13, AF-1).
///
/// Every lane goes through this rather than calling `authenticate_mcp_client` directly, so a
/// lane added later cannot forget to record. The record itself is coalesced, so most calls to
/// this function append nothing at all: see `auth_attempts` for why one record per attempt
/// would be a write primitive against the audit log.
///
/// An audit write that fails does not turn a refusal into an acceptance (AF-11). The record is
/// best effort in the direction of availability and never in the direction of access.
pub(crate) async fn authenticate_and_record(
    state: &AppState,
    peer: Option<std::net::SocketAddr>,
    headers: &HeaderMap,
) -> Result<Option<McpClientIdentity>, AuthRejection> {
    let source = peer.map(PeerSource::from);

    // G3-14 AF-8. Checked BEFORE the credential is evaluated, which is the point: a throttled
    // source costs this process a map lookup rather than a signature verification or a JWKS
    // fetch. Keyed on source alone, so one attacker cannot get a legitimate client refused.
    let throttle = state.policy().auth_throttle.clone();
    if throttle.enabled
        && state.auth_attempts.should_throttle(
            source.as_ref(),
            throttle.threshold,
            Duration::from_secs(throttle.window_secs),
            Instant::now(),
        )
    {
        // AF-9. Marked once on the open window rather than appended per refused request, so
        // the throttle that exists to bound attacker-driven work does not become
        // attacker-driven work.
        state
            .auth_attempts
            .mark_throttled(source.as_ref(), Instant::now());
        return Err(AuthRejection::new(
            "throttled",
            "throttled",
            "too many failed authentication attempts",
        ));
    }

    let outcome = authenticate_mcp_client(state, headers).await;
    let Err(rejection) = outcome else {
        return outcome;
    };
    if let Some(record) = state.auth_attempts.record(
        source.as_ref(),
        rejection.credential_path,
        rejection.reason,
        Instant::now(),
    ) && let Err(err) = state.audit.append(&record)
    {
        tracing::warn!(
            error = %err,
            "MCP: could not write a coalesced authentication-attempt record"
        );
    }
    Err(rejection)
}

/// Establish who is calling, by whichever credential path applies (RS-13).
///
/// The two paths are separated by header rather than by guessing at a credential's shape.
/// [`CLIENT_TOKEN_HEADER`] is the static path the desktop connector uses.
/// `Authorization: Bearer` becomes the OAuth path when `oauth_resource` is configured, and
/// continues to feed the static path exactly as before when it is not, so an install that never
/// opted in sees no change.
///
/// Before this split, a bearer JWT was SHA-256 hashed and compared against configured static
/// credentials, which fails in a way that explains nothing to anybody.
async fn authenticate_mcp_client(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<McpClientIdentity>, AuthRejection> {
    let policy = state.policy();
    if let Some(oauth) = policy.oauth_resource.as_ref()
        && let Some(bearer) = bearer_token_from_headers(headers)
    {
        // A clock this process cannot read is a reason to refuse tokens, not a reason to
        // treat every one of them as current. Defaulting to 0 here would make `now > exp`
        // false for every token ever issued.
        let Ok(elapsed) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            tracing::error!(
                "MCP: refusing OAuth tokens because the system clock is before the Unix epoch \
                 and expiry cannot be evaluated"
            );
            return Err(AuthRejection::new("oauth", "malformed", "invalid_token"));
        };
        // The same decision as above, applied to the second clock read rather than only the
        // first. A `u64` past `i64::MAX` wraps negative, and a negative `now` makes `now > exp`
        // false for every token ever issued, which is the accept-everything outcome the block
        // above exists to prevent. Unreachable on a real clock; written this way because the
        // function has already said what an unreadable clock means and this read was not
        // obeying it.
        let Ok(now) = i64::try_from(elapsed.as_secs()) else {
            tracing::error!(
                "MCP: refusing OAuth tokens because the system clock is past the representable \
                 range and expiry cannot be evaluated"
            );
            return Err(AuthRejection::new("oauth", "malformed", "invalid_token"));
        };
        return match nmcp_authn::verify(oauth, state.jwks(), &bearer, now).await {
            Ok(accepted) => {
                tracing::info!(
                    subject = %accepted.subject,
                    agent_id = %accepted.agent_id,
                    "MCP: OAuth token accepted"
                );
                Ok(Some(McpClientIdentity {
                    credential_path: "oauth",
                    agent_id: accepted.agent_id,
                    profile: accepted.profile,
                }))
            }
            Err(rejection) => {
                // The reason goes to the log and never to the caller: telling an
                // unauthenticated caller why their token failed is telling them how to fix it.
                tracing::warn!("MCP: OAuth token refused: {}", rejection.reason());
                Err(AuthRejection::new(
                    "oauth",
                    rejection.reason_class(),
                    "invalid_token",
                ))
            }
        };
    }
    if policy.mcp_clients.is_empty() {
        if policy.mcp_require_client_auth {
            return Err(AuthRejection::new(
                "static",
                "absent",
                "MCP client authentication is required but no mcp_clients are configured",
            ));
        }
        // G3-11 RS-6 and RS-8. A server that published protected resource metadata does not
        // also answer anonymously. Without this, configuring oauth_resource on an install
        // that has no mcp_clients would advertise a challenge nothing ever enforces, which
        // is the exact shape section 5 of the specification refuses to ship.
        if policy.oauth_resource.is_some() {
            return Err(AuthRejection::new(
                "oauth",
                "absent",
                "MCP client authentication required",
            ));
        }
        return Ok(None);
    }
    let Some(token) = mcp_client_token_from_headers(headers) else {
        return Err(AuthRejection::new(
            "static",
            "absent",
            "MCP client authentication required",
        ));
    };
    let token_hash = sha256_hex(&token);
    for McpClientCredential {
        agent_id,
        token_sha256,
        profile,
    } in &policy.mcp_clients
    {
        if constant_time_eq(&token_hash, &token_sha256.to_ascii_lowercase()) {
            return Ok(Some(McpClientIdentity {
                credential_path: "static",
                agent_id: agent_id.clone(),
                profile: profile.clone(),
            }));
        }
    }
    Err(AuthRejection::new(
        "static",
        "unknown_credential",
        "invalid MCP client token",
    ))
}
// Tests ─────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "a test that cannot fail loudly is a test that reports nothing"
    )]

    use super::*;
    use nmcp_policy::{AuthThrottleConfig, GatewayProfile, McpClientCredential};
    use std::collections::BTreeMap;
    use std::net::SocketAddr;

    fn client_policy(token: &str) -> PolicyConfig {
        PolicyConfig {
            mcp_clients: vec![McpClientCredential {
                agent_id: "agent-alpha".into(),
                token_sha256: sha256_hex(token),
                profile: None,
            }],
            ..PolicyConfig::default()
        }
    }

    fn header_map(name: &str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).expect("a legal header name"),
            value.parse().expect("a legal header value"),
        );
        headers
    }

    fn peer(port: u16) -> SocketAddr {
        format!("203.0.113.{}:{port}", port % 250 + 1)
            .parse()
            .expect("a legal socket address")
    }

    // ── The origin allowlist, ported ─────────────────────────────────────────────────────

    #[test]
    fn an_absent_loopback_or_configured_origin_is_allowed_and_null_is_not() {
        let policy = PolicyConfig {
            mcp_allowed_origins: vec!["https://chatgpt.example".into()],
            ..PolicyConfig::default()
        };
        assert!(!origin_allowed(&policy, "null"));
        assert!(origin_allowed(&policy, "http://localhost:3000"));
        assert!(origin_allowed(&policy, "http://127.0.0.1:18769"));
        assert!(origin_allowed(&policy, "https://chatgpt.example"));
        assert!(origin_allowed(&policy, "http://[::1]:18770"));
    }

    #[test]
    fn an_unconfigured_public_origin_is_refused() {
        assert!(!origin_allowed(
            &PolicyConfig::default(),
            "https://not-allowed.example"
        ));
    }

    #[test]
    fn a_loopback_name_appearing_anywhere_but_the_host_does_not_make_an_origin_loopback() {
        // Each of these reads as loopback to a `contains` and is not one. The host is parsed
        // out of the authority rather than searched for, which is why they all fail.
        let policy = PolicyConfig::default();
        assert!(!origin_allowed(&policy, "https://localhost.evil.example"));
        assert!(!origin_allowed(&policy, "https://127.0.0.1.evil.example"));
        assert!(!origin_allowed(
            &policy,
            "https://evil.example/path?next=http://localhost"
        ));
        // Userinfo is the sharpest of them: everything before `@` is a credential, not a host.
        assert!(!origin_allowed(&policy, "https://localhost@evil.example"));
    }

    #[test]
    fn the_allowlist_matches_whole_entries_and_not_substrings() {
        let list = "https://a.example, https://b.example";
        assert!(origin_in_list(list, "https://a.example"));
        assert!(origin_in_list(list, "https://b.example"));
        assert!(!origin_in_list(list, "https://a.example.evil"));
        assert!(!origin_in_list(list, "https://evil.a.example"));
        assert!(!origin_in_list(list, ""));
        assert!(!origin_in_list(", ,", ""));
    }

    #[test]
    fn a_request_carrying_no_origin_at_all_is_not_refused() {
        // A non-browser client sends no `Origin`. Refusing an absent header would break every
        // one of them while stopping no browser, because a browser always sends it.
        assert!(enforce_mcp_origin(&PolicyConfig::default(), &HeaderMap::new()).is_ok());
        assert!(
            enforce_mcp_origin(
                &PolicyConfig::default(),
                &header_map("origin", "https://not-allowed.example")
            )
            .is_err()
        );
    }

    // ── NMCP-DEC-001, and the row that has to be verified rather than assumed ────────────

    #[test]
    fn the_profile_header_is_the_renamed_one_and_the_pre_rename_spelling_scopes_nothing() {
        // DEC-001 row B-9. The retired spelling is assembled from fragments here for the same
        // reason CI's INV-8 gate assembles its own pattern that way: a test that asserts a name
        // is gone must not be the thing that puts it back in the tree.
        let retired = format!("x-{}{}-profile", "signal", "desk");
        let policy = PolicyConfig {
            gateway_profiles: BTreeMap::from([("reading".to_string(), GatewayProfile::default())]),
            ..PolicyConfig::default()
        };

        assert_eq!(PROFILE_HEADER, "x-nmcp-profile");
        assert_eq!(
            session_profile_from_headers(&policy, None, &header_map(PROFILE_HEADER, "reading"))
                .expect("a configured profile resolves"),
            Some("reading".to_string())
        );

        // The failure this guards is not a refusal, which is why it needs its own test. A
        // request naming a profile under the retired header is served **unscoped**, reaching
        // every upstream rather than the profile's subset. INV-4's subject exactly: the widening
        // is silent, so nothing about the response says the header was ignored.
        assert_eq!(
            session_profile_from_headers(&policy, None, &header_map(&retired, "reading"))
                .expect("an unrecognised header is not an error"),
            None,
            "the retired profile header still scoped a session, which is a silent widening \
             rather than a visible break"
        );
    }

    #[test]
    fn the_static_credential_header_is_the_renamed_one() {
        // DEC-001 row B-8.
        assert_eq!(CLIENT_TOKEN_HEADER, "x-nmcp-token");
        assert_eq!(
            mcp_client_token_from_headers(&header_map(CLIENT_TOKEN_HEADER, "alpha")),
            Some("alpha".to_string())
        );
        // The bearer fallback is deliberate and is what RS-13 splits by header: this reader
        // accepts either, and `bearer_token_from_headers` accepts only the one.
        assert_eq!(
            mcp_client_token_from_headers(&header_map("authorization", "Bearer alpha")),
            Some("alpha".to_string())
        );
        assert_eq!(
            bearer_token_from_headers(&header_map(CLIENT_TOKEN_HEADER, "alpha")),
            None
        );
    }

    #[test]
    fn the_bearer_scheme_is_matched_the_way_http_defines_it() {
        // RFC 7235 Section 2.1 makes the scheme token case-insensitive. A case-sensitive
        // `strip_prefix` fails closed, which sounds safe and is not: it routes a conformant
        // client to the static credential path, where its JWT is hashed and compared against
        // configured tokens, and the refusal explains nothing to anybody.
        assert_eq!(
            bearer_token_from_headers(&header_map("authorization", "bearer alpha")),
            Some("alpha".to_string())
        );
        assert_eq!(
            bearer_token_from_headers(&header_map("authorization", "BEARER alpha")),
            Some("alpha".to_string())
        );
        assert_eq!(
            bearer_token_from_headers(&header_map("authorization", "Basic alpha")),
            None
        );
        assert_eq!(
            bearer_token_from_headers(&header_map("authorization", "Bearer    ")),
            None
        );
    }

    #[test]
    fn the_environment_override_reads_one_name_and_there_is_no_second() {
        // The base carries a four-armed source and two deprecation warnings so an upgrade does
        // not silently lose an allowlist. Both legacy names are legacy brand strings, so INV-8
        // forbids either from existing here and the machinery has one arm left. This pins the
        // name DEC-001 row B-12 settled; the migration is an operator action in the cutover
        // window, exactly as DEC-001 disposes of rows A-2 and A-11.
        assert_eq!(ALLOWED_ORIGINS_ENV, "NMCP_ALLOWED_ORIGINS");
    }

    // ── The two credential paths ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_configured_static_credential_is_accepted_under_the_renamed_header() {
        let state = AppState::new(client_policy("alpha")).expect("state");
        let identity = authenticate_mcp_client(&state, &header_map(CLIENT_TOKEN_HEADER, "alpha"))
            .await
            .expect("auth ok")
            .expect("identity");
        assert_eq!(identity.agent_id, "agent-alpha");
        assert_eq!(identity.credential_path, "static");
    }

    #[tokio::test]
    async fn a_missing_or_wrong_static_credential_is_refused_and_the_two_differ() {
        let state = AppState::new(client_policy("alpha")).expect("state");

        let absent = authenticate_mcp_client(&state, &HeaderMap::new())
            .await
            .expect_err("no credential is a refusal");
        assert_eq!(absent.reason, "absent");

        let wrong = authenticate_mcp_client(&state, &header_map(CLIENT_TOKEN_HEADER, "beta"))
            .await
            .expect_err("a wrong credential is a refusal");
        assert_eq!(wrong.reason, "unknown_credential");

        assert_eq!(absent.credential_path, wrong.credential_path);

        // The messages for absent and wrong differ, and that is not a leak: the caller already
        // knows which of the two it did. I asserted they were identical when writing this and
        // the test said otherwise, which is worth keeping as the reason the weaker assertion is
        // not the one here.
        //
        // The property that does matter is that no message varies with the credential. A message
        // that changed between two wrong guesses would be an oracle, telling an attacker which
        // guess came closer, and it would be invisible from any single request.
        let other_wrong =
            authenticate_mcp_client(&state, &header_map(CLIENT_TOKEN_HEADER, "gamma"))
                .await
                .expect_err("a different wrong credential is also a refusal");
        assert_eq!(wrong.message, other_wrong.message);
        assert_eq!(wrong.reason, other_wrong.reason);
        for refusal in [absent, wrong, other_wrong] {
            assert!(
                !refusal.message.contains("beta") && !refusal.message.contains("gamma"),
                "a refusal message quoted the credential back: {}",
                refusal.message
            );
        }
    }

    #[tokio::test]
    async fn an_install_with_no_clients_configured_answers_anonymously_unless_it_said_otherwise() {
        let open = AppState::new(PolicyConfig::default()).expect("state");
        assert!(
            authenticate_mcp_client(&open, &HeaderMap::new())
                .await
                .expect("an install with no clients admits anonymously")
                .is_none()
        );

        let required = AppState::new(PolicyConfig {
            mcp_require_client_auth: true,
            ..PolicyConfig::default()
        })
        .expect("state");
        assert_eq!(
            authenticate_mcp_client(&required, &HeaderMap::new())
                .await
                .expect_err("required auth with nothing configured is a refusal")
                .reason,
            "absent"
        );
    }

    // ── The order inside `authenticate_and_record` ───────────────────────────────────────

    #[tokio::test]
    async fn the_throttle_is_evaluated_before_the_credential_is() {
        // The acceptance criterion, and it is asserted the only way that admits no other
        // explanation: the attempt that must be refused carries the **correct** credential.
        //
        // If the credential were evaluated first it would be accepted, and the endpoint would
        // answer 200. Refusing it proves the throttle short-circuited ahead of any signature
        // work, which is the property that keeps an attacker from making this process do a JWKS
        // fetch per guess. Counting refusals would not prove it: a wrong credential is refused
        // either way and the response shape is identical.
        let policy = PolicyConfig {
            auth_throttle: AuthThrottleConfig {
                enabled: true,
                threshold: 3,
                window_secs: 60,
            },
            ..client_policy("alpha")
        };
        let state = AppState::new(policy).expect("state");
        let attacker = peer(9000);

        for attempt in 0..3 {
            let refusal = authenticate_and_record(
                &state,
                Some(attacker),
                &header_map(CLIENT_TOKEN_HEADER, "wrong"),
            )
            .await
            .expect_err("a wrong credential is refused");
            assert_eq!(
                refusal.credential_path, "static",
                "attempt {attempt} should still be reaching the credential"
            );
        }

        let refusal = authenticate_and_record(
            &state,
            Some(attacker),
            &header_map(CLIENT_TOKEN_HEADER, "alpha"),
        )
        .await
        .expect_err("a throttled source is refused whatever it presents");
        assert_eq!(
            refusal.credential_path, "throttled",
            "the correct credential was accepted from a throttled source, so the credential is \
             being evaluated before the throttle and every guess costs this process real work"
        );
    }

    #[tokio::test]
    async fn one_source_tripping_the_throttle_does_not_refuse_another() {
        // The other half of the same requirement (G3-14, AF-8). The key is the source and never
        // the credential, so an attacker cannot lock out a client by guessing at its identity.
        let policy = PolicyConfig {
            auth_throttle: AuthThrottleConfig {
                enabled: true,
                threshold: 2,
                window_secs: 60,
            },
            ..client_policy("alpha")
        };
        let state = AppState::new(policy).expect("state");
        let attacker = peer(9100);
        let legitimate = peer(9200);

        for _ in 0..2 {
            let _ = authenticate_and_record(
                &state,
                Some(attacker),
                &header_map(CLIENT_TOKEN_HEADER, "wrong"),
            )
            .await;
        }
        assert_eq!(
            authenticate_and_record(
                &state,
                Some(attacker),
                &header_map(CLIENT_TOKEN_HEADER, "alpha")
            )
            .await
            .expect_err("the attacker is throttled")
            .credential_path,
            "throttled"
        );

        let identity = authenticate_and_record(
            &state,
            Some(legitimate),
            &header_map(CLIENT_TOKEN_HEADER, "alpha"),
        )
        .await
        .expect("a different source is unaffected")
        .expect("identity");
        assert_eq!(identity.agent_id, "agent-alpha");
    }

    #[tokio::test]
    async fn a_disabled_throttle_never_refuses_however_many_attempts_arrive() {
        let policy = PolicyConfig {
            auth_throttle: AuthThrottleConfig {
                enabled: false,
                threshold: 1,
                window_secs: 60,
            },
            ..client_policy("alpha")
        };
        let state = AppState::new(policy).expect("state");
        let source = peer(9300);
        for _ in 0..5 {
            let _ = authenticate_and_record(
                &state,
                Some(source),
                &header_map(CLIENT_TOKEN_HEADER, "wrong"),
            )
            .await;
        }
        assert!(
            authenticate_and_record(
                &state,
                Some(source),
                &header_map(CLIENT_TOKEN_HEADER, "alpha")
            )
            .await
            .expect("a disabled throttle refuses nothing")
            .is_some()
        );
    }

    // ── Two failures a caller must be able to tell apart ─────────────────────────────────

    #[tokio::test]
    async fn a_bad_credential_and_an_unavailable_profile_stay_distinguishable() {
        // Why they are separate calls rather than one. Both refuse a request, and the fixes are
        // unrelated: one is "your token is wrong", the other is "this server has no such
        // profile". Folding them into a single error would send an operator to the wrong one,
        // and the wrong one is the one that looks like a security event.
        let policy = PolicyConfig {
            gateway_profiles: BTreeMap::from([("reading".to_string(), GatewayProfile::default())]),
            ..client_policy("alpha")
        };
        let state = AppState::new(policy.clone()).expect("state");

        let identity = authenticate_mcp_client(&state, &header_map(CLIENT_TOKEN_HEADER, "alpha"))
            .await
            .expect("the credential is good")
            .expect("identity");

        // Authentication succeeded. Profile resolution is where this request fails, separately.
        let failure = session_profile_from_headers(
            &policy,
            Some(&identity),
            &header_map(PROFILE_HEADER, "no-such-profile"),
        )
        .expect_err("an unconfigured profile is refused");
        assert!(
            failure.to_string().contains("no-such-profile"),
            "the profile failure must name the profile, because the fix is to configure it: {failure}"
        );

        // And a credential pinned to a profile cannot be talked out of it by a header.
        let pinned = PolicyConfig {
            mcp_clients: vec![McpClientCredential {
                agent_id: "agent-alpha".into(),
                token_sha256: sha256_hex("alpha"),
                profile: Some("reading".into()),
            }],
            ..policy
        };
        let pinned_identity = McpClientIdentity {
            agent_id: "agent-alpha".into(),
            credential_path: "static",
            profile: Some("reading".into()),
        };
        assert!(
            session_profile_from_headers(
                &pinned,
                Some(&pinned_identity),
                &header_map(PROFILE_HEADER, "reading")
            )
            .is_ok()
        );
        assert!(
            session_profile_from_headers(
                &pinned,
                Some(&pinned_identity),
                &header_map(PROFILE_HEADER, "something-else")
            )
            .is_err(),
            "a header talked a pinned credential out of its profile, which makes the pin a \
             suggestion rather than a boundary"
        );
    }
}
