//! RFC 8628 device authorization, which is the only flow this broker runs.
//!
//! ## Why not authorization code with PKCE
//!
//! PKCE is the flow more providers support, so this is a real cost and worth stating. It needs
//! a redirect URI, which for a service with no browser means a loopback listener, which here
//! means a route on the admin plane that accepts a request nobody has authenticated yet. That
//! plane is authenticated end to end, and a `state` parameter would become the only thing
//! standing between a local process and a grant.
//!
//! Device code needs no inbound route at all. The operator carries the code to the provider in
//! a browser they already trust, and the daemon polls outbound. For a governed runtime whose
//! whole posture is that the admin listener is small and fully authenticated, giving up some
//! provider coverage to add no inbound surface is the right side of that trade. A provider that
//! cannot do device code fails by name here rather than silently, and PKCE can be its own item
//! if one turns up that matters.

use crate::grant::Grant;
use serde_json::Value;
use std::fmt;

/// The `grant_type` value for a device-code exchange (RFC 8628 section 3.4). Wire constant.
pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// The interval to poll at when a provider does not name one (RFC 8628 section 3.2).
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
/// What a `slow_down` adds to the interval (RFC 8628 section 3.5).
pub const SLOW_DOWN_INCREMENT_SECS: u64 = 5;
/// The ceiling on a provider-supplied interval, so a hostile or broken value cannot park the
/// poll past the point the device code itself expires.
pub const MAX_POLL_INTERVAL_SECS: u64 = 60;

/// A device authorization in progress.
///
/// `device_code` is a bearer credential for the pending grant: whoever holds it can complete
/// the exchange. It stays inside the broker and never reaches an API response, which is why
/// [`DeviceInstruction`] exists separately.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceAuthorization {
    /// The credential half, presented on every poll. Never leaves the broker.
    pub device_code: String,
    /// The short code the operator types at the provider.
    pub user_code: String,
    /// Where the operator goes to type it.
    pub verification_uri: String,
    /// A URI with the code already embedded, when the provider offers one.
    pub verification_uri_complete: Option<String>,
    /// When the device code stops being exchangeable.
    pub expires_at_unix: u64,
    /// How often to poll the token endpoint.
    pub interval_secs: u64,
}

impl fmt::Debug for DeviceAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAuthorization")
            .field("device_code", &"<redacted>")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("interval_secs", &self.interval_secs)
            .finish_non_exhaustive()
    }
}

impl DeviceAuthorization {
    /// The part an operator needs, which is the part that is safe to hand out.
    #[must_use]
    pub fn instruction(&self) -> DeviceInstruction {
        DeviceInstruction {
            user_code: self.user_code.clone(),
            verification_uri: self.verification_uri.clone(),
            verification_uri_complete: self.verification_uri_complete.clone(),
            expires_at_unix: self.expires_at_unix,
        }
    }

    /// Whether the device code has aged out unused.
    #[must_use]
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at_unix
    }
}

/// What the console shows an operator, carrying nothing that could complete the exchange.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DeviceInstruction {
    /// The short code the operator types at the provider.
    pub user_code: String,
    /// Where the operator goes to type it.
    pub verification_uri: String,
    /// A URI with the code already embedded, when the provider offers one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    /// When the offer stops being usable.
    pub expires_at_unix: u64,
}

/// What one poll of the token endpoint meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// The operator has not finished at the provider yet. Keep waiting.
    Pending,
    /// Keep waiting, and add [`SLOW_DOWN_INCREMENT_SECS`] to the interval first.
    SlowDown,
    /// The operator finished, and this is the grant.
    Granted(Box<Grant>),
    /// Terminal. The reason is safe to show an operator.
    Failed(String),
}

/// Read a device authorization response.
///
/// # Errors
///
/// A reason safe to show an operator, when the response carries no device code, no user code
/// or no verification URI. Nothing from the body beyond the missing field's name.
pub fn parse_device_authorization(
    body: &Value,
    now_unix: u64,
) -> Result<DeviceAuthorization, String> {
    let device_code = required_str(body, "device_code")?;
    let user_code = required_str(body, "user_code")?;
    // `verification_uri` is the RFC spelling. One of the largest providers shipped
    // `verification_url` before the RFC settled and still returns it, so accepting both is not
    // indulgence, it is the difference between working with that provider and not. Both are
    // wire constants and are not renamed by any scrub.
    let verification_uri = str_field(body, "verification_uri")
        .or_else(|| str_field(body, "verification_url"))
        .ok_or_else(|| "device authorization response has no verification_uri".to_string())?;
    let expires_in = body
        .get("expires_in")
        .and_then(Value::as_u64)
        .unwrap_or(900);
    let interval_secs = body
        .get("interval")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_POLL_INTERVAL_SECS)
        .clamp(1, MAX_POLL_INTERVAL_SECS);
    Ok(DeviceAuthorization {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete: str_field(body, "verification_uri_complete")
            .or_else(|| str_field(body, "verification_url_complete")),
        expires_at_unix: now_unix.saturating_add(expires_in),
        interval_secs,
    })
}

/// Read a successful token response into a grant.
///
/// # Errors
///
/// A reason safe to show an operator, when the response carries no access token.
pub fn parse_token_response(body: &Value, now_unix: u64) -> Result<Grant, String> {
    let access_token = required_str(body, "access_token")?;
    Ok(Grant {
        access_token,
        refresh_token: str_field(body, "refresh_token"),
        // No `expires_in` means a token the provider does not expire. Recorded as absent rather
        // than as some default lifetime, because inventing an expiry would make the sweep throw
        // away a working token on a schedule of this crate's own invention.
        expires_at_unix: body
            .get("expires_in")
            .and_then(Value::as_u64)
            .map(|secs| now_unix.saturating_add(secs)),
        scope: str_field(body, "scope"),
        token_type: str_field(body, "token_type").unwrap_or_else(|| "Bearer".to_string()),
    })
}

/// Classify a token endpoint response during a device poll.
#[must_use]
pub fn classify_poll(body: &Value, now_unix: u64) -> PollOutcome {
    match body.get("error").and_then(Value::as_str) {
        Some("authorization_pending") => PollOutcome::Pending,
        Some("slow_down") => PollOutcome::SlowDown,
        Some(other) => PollOutcome::Failed(format!("{other}{}", described(body))),
        None => match parse_token_response(body, now_unix) {
            Ok(grant) => PollOutcome::Granted(Box::new(grant)),
            Err(why) => PollOutcome::Failed(why),
        },
    }
}

/// The next interval after an outcome, respecting `slow_down`.
#[must_use]
pub fn next_interval(current: u64, outcome: &PollOutcome) -> u64 {
    match outcome {
        PollOutcome::SlowDown => current
            .saturating_add(SLOW_DOWN_INCREMENT_SECS)
            .min(MAX_POLL_INTERVAL_SECS),
        _ => current,
    }
}

/// The human half of an OAuth error, when there is one.
#[must_use]
pub fn described(body: &Value) -> String {
    match str_field(body, "error_description") {
        Some(text) => format!(": {text}"),
        None => String::new(),
    }
}

/// The reason an authorization or refresh failed, from a response body, safe to show.
///
/// A token endpoint answers a bad refresh token with a 400 and a JSON error, so the status code
/// alone tells an operator nothing. This reads the body the provider actually sent.
#[must_use]
pub fn error_reason(body: &Value, status: u16) -> String {
    match body.get("error").and_then(Value::as_str) {
        Some(code) => format!("{code}{}", described(body)),
        None => format!("token endpoint returned HTTP {status}"),
    }
}

fn str_field(body: &Value, key: &str) -> Option<String> {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn required_str(body: &Value, key: &str) -> Result<String, String> {
    str_field(body, key).ok_or_else(|| format!("response has no {key}"))
}

/// The form body for a device authorization request.
#[must_use]
pub fn device_authorization_form<'a>(
    client_id: &'a str,
    scope: &'a str,
) -> Vec<(&'a str, &'a str)> {
    let mut form = vec![("client_id", client_id)];
    if !scope.is_empty() {
        form.push(("scope", scope));
    }
    form
}

/// The form body for exchanging a device code.
#[must_use]
pub fn device_token_form<'a>(client_id: &'a str, device_code: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("grant_type", DEVICE_CODE_GRANT_TYPE),
        ("client_id", client_id),
        ("device_code", device_code),
    ]
}

/// The form body for a refresh.
#[must_use]
pub fn refresh_form<'a>(
    client_id: &'a str,
    refresh_token: &'a str,
    scope: &'a str,
) -> Vec<(&'a str, &'a str)> {
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
    ];
    if !scope.is_empty() {
        form.push(("scope", scope));
    }
    form
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
    use serde_json::json;

    #[test]
    fn a_device_authorization_reads_the_rfc_spelling() {
        let body = json!({
            "device_code": "dc", "user_code": "WDJB-MJHT",
            "verification_uri": "https://example.test/device",
            "expires_in": 1800, "interval": 5
        });
        let auth = parse_device_authorization(&body, 1_000).expect("parse");
        assert_eq!(auth.user_code, "WDJB-MJHT");
        assert_eq!(auth.expires_at_unix, 2_800);
        assert_eq!(auth.interval_secs, 5);
    }

    #[test]
    fn a_device_authorization_also_reads_the_pre_rfc_spelling() {
        let body = json!({
            "device_code": "dc", "user_code": "ABC",
            "verification_url": "https://example.test/device"
        });
        let auth = parse_device_authorization(&body, 0).expect("parse");
        assert_eq!(auth.verification_uri, "https://example.test/device");
        // No interval named, so the RFC default rather than zero, which would be a hot loop.
        assert_eq!(auth.interval_secs, DEFAULT_POLL_INTERVAL_SECS);
    }

    #[test]
    fn a_hostile_interval_cannot_park_the_poll() {
        let body = json!({
            "device_code": "dc", "user_code": "ABC",
            "verification_uri": "https://example.test/device",
            "interval": 86_400
        });
        let auth = parse_device_authorization(&body, 0).expect("parse");
        assert_eq!(auth.interval_secs, MAX_POLL_INTERVAL_SECS);
    }

    #[test]
    fn the_device_code_never_reaches_the_operator_facing_half() {
        let body = json!({
            "device_code": "sentinel-device-code", "user_code": "ABC",
            "verification_uri": "https://example.test/device"
        });
        let auth = parse_device_authorization(&body, 0).expect("parse");
        let shown = serde_json::to_string(&auth.instruction()).expect("serialize");
        assert!(!shown.contains("sentinel-device-code"), "leaked in {shown}");
        assert!(!format!("{auth:?}").contains("sentinel-device-code"));
    }

    #[test]
    fn a_pending_poll_is_not_a_failure() {
        let body = json!({"error": "authorization_pending"});
        assert_eq!(classify_poll(&body, 0), PollOutcome::Pending);
    }

    #[test]
    fn a_slow_down_widens_the_interval_and_stops_at_the_ceiling() {
        let outcome = classify_poll(&json!({"error": "slow_down"}), 0);
        assert_eq!(outcome, PollOutcome::SlowDown);
        assert_eq!(next_interval(5, &outcome), 10);
        assert_eq!(
            next_interval(MAX_POLL_INTERVAL_SECS, &outcome),
            MAX_POLL_INTERVAL_SECS
        );
        assert_eq!(next_interval(5, &PollOutcome::Pending), 5);
    }

    #[test]
    fn a_denial_is_terminal_and_says_why() {
        let body = json!({"error": "access_denied", "error_description": "the operator said no"});
        let PollOutcome::Failed(reason) = classify_poll(&body, 0) else {
            panic!("access_denied must be terminal");
        };
        assert!(reason.contains("access_denied"));
        assert!(reason.contains("the operator said no"));
    }

    #[test]
    fn a_granted_poll_carries_the_expiry_forward() {
        let body = json!({
            "access_token": "at", "refresh_token": "rt",
            "token_type": "Bearer", "expires_in": 3600
        });
        let PollOutcome::Granted(grant) = classify_poll(&body, 1_000) else {
            panic!("a token response must be a grant");
        };
        assert_eq!(grant.expires_at_unix, Some(4_600));
        assert_eq!(grant.refresh_token.as_deref(), Some("rt"));
    }

    #[test]
    fn a_token_without_an_expiry_is_stored_without_one() {
        let grant = parse_token_response(&json!({"access_token": "at"}), 1_000).expect("parse");
        assert_eq!(grant.expires_at_unix, None);
        assert_eq!(grant.token_type, "Bearer");
        assert!(!grant.is_due(u64::MAX - 1));
    }

    #[test]
    fn a_response_with_no_token_and_no_error_is_a_failure_not_a_grant() {
        let PollOutcome::Failed(reason) = classify_poll(&json!({"scope": "read"}), 0) else {
            panic!("a body with no access_token cannot be a grant");
        };
        assert!(reason.contains("access_token"));
    }

    #[test]
    fn a_refresh_failure_reads_the_body_rather_than_the_status_code() {
        let body = json!({"error": "invalid_grant", "error_description": "token revoked"});
        let reason = error_reason(&body, 400);
        assert!(reason.contains("invalid_grant"));
        assert!(reason.contains("token revoked"));
        assert_eq!(
            error_reason(&json!({}), 503),
            "token endpoint returned HTTP 503"
        );
    }

    #[test]
    fn scope_is_left_out_of_a_form_rather_than_sent_empty() {
        assert_eq!(
            device_authorization_form("cid", ""),
            vec![("client_id", "cid")]
        );
        assert_eq!(
            device_authorization_form("cid", "repo"),
            vec![("client_id", "cid"), ("scope", "repo")]
        );
        assert_eq!(refresh_form("cid", "rt", "").len(), 3);
        assert_eq!(refresh_form("cid", "rt", "repo").len(), 4);
    }
}
