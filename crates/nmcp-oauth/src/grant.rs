//! What a broker holds on behalf of a provider, and the name it holds it under.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// The namespace the broker owns (SB-2), re-exported from the one definition in `nmcp-schema`.
///
/// Grant names live under this label plus a separator, and names under it belong to the broker
/// rather than to an operator. The operator surface cannot write them: a [`SecretName`]
/// (`nmcp-secrets`) refuses the namespace at parse, so `SealedStore::set` cannot be called
/// with one. Not because a pasted access token would be rejected by the provider, but because
/// it would be silently replaced by the next refresh, and a credential that works until it
/// mysteriously stops is worse than one that never worked.
///
/// One definition on purpose: the reserving parser in `nmcp-schema` and the broker that owns
/// the namespace must agree about what is reserved, and a copy of the label here would be the
/// two-copies drift SB-2 records the base already paying for. The base's `GRANT_PREFIX`
/// constant becomes this re-export plus [`grant_secret_name`], which is the one place a full
/// grant name is assembled.
///
/// [`SecretName`]: nmcp_secrets::SecretName
pub use nmcp_schema::OAUTH_GRANT_NAMESPACE as GRANT_NAMESPACE;

/// The storage name a provider's grant is held under: the reserved namespace, the separator,
/// and the provider id.
#[must_use]
pub fn grant_secret_name(provider: &str) -> String {
    format!("{GRANT_NAMESPACE}/{provider}")
}

/// How long before true expiry a token counts as due for refresh.
///
/// Five minutes rather than the ninety seconds the base's vendor-specific broker used, because
/// that one refreshed lazily on the calling path where a small buffer is enough, and this one
/// refreshes ahead of the call on a sweep with an interval of its own. The buffer has to cover
/// a sweep it missed.
pub const REFRESH_SKEW_SECS: u64 = 300;

/// The token half of an authorization: everything a request needs and nothing policy may hold.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    /// The bearer token a request carries. Material (SB-1): it reaches the authorization
    /// header of an outbound request and nowhere else.
    pub access_token: String,
    /// What a refresh presents. Material, and longer-lived than the access token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Absent for a token the provider issued without an expiry, which is never due.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    /// The scopes the provider actually granted, when it said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The authorization scheme, `Bearer` unless the provider says otherwise.
    #[serde(default = "default_token_type")]
    pub token_type: String,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

/// Redacted by construction.
///
/// A derived `Debug` would put both tokens into any log line, panic message or trace span that
/// ever formatted a grant. There is no way to use one of those safely, so there is no derive.
/// This is the pattern NMCP-SPEC-002 SB-1 cites from the base and `Sealed<T>` follows.
impl fmt::Debug for Grant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Grant")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at_unix", &self.expires_at_unix)
            .field("scope", &self.scope)
            .field("token_type", &self.token_type)
            .finish()
    }
}

impl Grant {
    /// The value for the authorization header, scheme included.
    #[must_use]
    pub fn authorization_header(&self) -> String {
        format!("{} {}", self.token_type.trim(), self.access_token.trim())
    }

    /// Whether this token should be replaced before it is next used.
    #[must_use]
    pub fn is_due(&self, now_unix: u64) -> bool {
        match self.expires_at_unix {
            Some(expiry) => now_unix.saturating_add(REFRESH_SKEW_SECS) >= expiry,
            None => false,
        }
    }

    /// Seconds until this token is due, saturating at zero.
    #[must_use]
    pub fn seconds_until_due(&self, now_unix: u64) -> u64 {
        match self.expires_at_unix {
            Some(expiry) => expiry
                .saturating_sub(REFRESH_SKEW_SECS)
                .saturating_sub(now_unix),
            None => u64::MAX,
        }
    }
}

/// Wall clock seconds, and the default clock a broker is built with.
///
/// Wall clock rather than a monotonic instant because an expiry has to survive the process
/// restarting, and a monotonic instant does not mean anything after that. The broker takes the
/// clock as an injected lookup ([`crate::Broker::with_clock`]), following the house pattern the
/// sealed store set, so the sweep, the skew and the backoff are all testable without a test
/// ever sleeping; this function is what the zero-parameter constructors inject.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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

    const ACCESS: &str = "sentinel-access-value";
    const REFRESH: &str = "sentinel-refresh-value";

    fn grant(expires_at_unix: Option<u64>) -> Grant {
        Grant {
            access_token: ACCESS.into(),
            refresh_token: Some(REFRESH.into()),
            expires_at_unix,
            scope: None,
            token_type: "Bearer".into(),
        }
    }

    #[test]
    fn a_grant_is_due_before_it_actually_expires() {
        let g = grant(Some(1_000));
        assert!(!g.is_due(1_000 - REFRESH_SKEW_SECS - 1));
        assert!(g.is_due(1_000 - REFRESH_SKEW_SECS));
        assert!(g.is_due(1_001));
    }

    #[test]
    fn a_grant_without_an_expiry_is_never_due() {
        assert!(!grant(None).is_due(u64::MAX - 1));
        assert_eq!(grant(None).seconds_until_due(u64::MAX - 1), u64::MAX);
    }

    #[test]
    fn neither_token_survives_being_formatted() {
        let rendered = format!("{:?}", grant(Some(1)));
        assert!(!rendered.contains(ACCESS), "access token in {rendered}");
        assert!(!rendered.contains(REFRESH), "refresh token in {rendered}");
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn a_grant_round_trips_through_the_shape_the_store_seals() {
        let before = grant(Some(42));
        let text = serde_json::to_string(&before).expect("serialize");
        let after: Grant = serde_json::from_str(&text).expect("deserialize");
        assert_eq!(before, after);
        assert_eq!(after.authorization_header(), format!("Bearer {ACCESS}"));
    }

    #[test]
    fn a_grant_is_held_under_a_name_an_operator_cannot_reach_by_accident() {
        assert_eq!(grant_secret_name("acme"), "oauth/acme");
        assert!(grant_secret_name("acme").starts_with(GRANT_NAMESPACE));
        // The enforcement, asserted where the name is minted: the operator surface's name
        // type refuses every name this function can produce, so no store method the operator
        // surface exposes can ever be called with one (SB-2, SB-13).
        assert!(nmcp_secrets::SecretName::parse(&grant_secret_name("acme")).is_err());
    }

    #[test]
    fn the_namespace_is_the_schema_definition_and_not_a_second_copy() {
        // The drift lock: this crate re-exports the label, so the reserving parser and the
        // broker cannot disagree about what is reserved.
        assert_eq!(GRANT_NAMESPACE, nmcp_schema::OAUTH_GRANT_NAMESPACE);
        assert!(
            nmcp_schema::RESERVED_SECRET_NAMESPACES.contains(&GRANT_NAMESPACE),
            "the namespace this broker owns must be the one the reference grammar reserves"
        );
    }
}
