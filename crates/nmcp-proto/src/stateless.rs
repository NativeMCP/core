//! The MCP 2026-07-28 stateless core (G5-2, G5-4).
//!
//! SEP-2575 removes the `initialize` handshake. Protocol version, client identity and client
//! capabilities travel on every request inside `_meta`, and SEP-2243 mirrors the method and the
//! named target into HTTP headers so an intermediary can route without parsing a body.
//!
//! ## The header is an integrity check, never an input
//!
//! SEP-2243 is explicit that header values MUST NOT be treated as trusted input for
//! security-sensitive decisions. So nothing here ever *reads* a value out of a header and uses
//! it: the body stays the only input to authorization, and a header that disagrees with the
//! body is refused rather than reconciled. Refusing rather than preferring the body matters
//! too, because a request whose header and body disagree is one where the intermediary that
//! routed it and the server that executed it saw different requests, and that is worth a 400
//! whichever of the two is wrong.
//!
//! Everything in this module is a pure function over the parsed request, so the rules are
//! testable without a socket and the transport is left to decide status codes.

use serde_json::Value;

/// `_meta` key naming the protocol revision. REQUIRED (SEP-2575).
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
/// `_meta` key carrying the client's self-reported identity. REQUIRED.
pub const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
/// `_meta` key carrying the client's capabilities object. REQUIRED.
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
/// `_meta` key requesting a log level. The one OPTIONAL key.
pub const META_LOG_LEVEL: &str = "io.modelcontextprotocol/logLevel";

/// SEP-2243 method header, lowercase because that is how `HeaderMap` keys compare.
pub const HEADER_MCP_METHOD: &str = "mcp-method";
/// SEP-2243 named-target header, same casing rule as [`HEADER_MCP_METHOD`].
pub const HEADER_MCP_NAME: &str = "mcp-name";

/// JSON-RPC `INVALID_PARAMS`, which SEP-2575 names for a request missing a required `_meta`
/// field.
pub const INVALID_PARAMS: i64 = -32602;

/// SEP-2243 `HeaderMismatch`, reassigned from `-32001` by modelcontextprotocol PR #2907.
pub const HEADER_MISMATCH: i64 = -32020;

/// The methods that carry a named target, and are therefore the only ones `Mcp-Name` is
/// required on.
///
/// The first pass of the scoping note left it open whether `Mcp-Name` was required on requests
/// with no named target. It is not, and requiring it everywhere would refuse a compliant
/// `tools/list`.
pub const NAMED_TARGET_METHODS: [&str; 3] = ["tools/call", "resources/read", "prompts/get"];

/// Methods SEP-2575 removed outright, which this server must not answer on 2026-07-28.
///
/// Answering them anyway would be the same dishonesty as advertising a revision whose
/// behaviour does not exist: a client that gets a result from `initialize` on this revision
/// learns something false about the server. They keep working on 2025-11-25, which is the
/// revision they belong to.
pub const REMOVED_IN_2026_07_28: [&str; 8] = [
    "initialize",
    "notifications/initialized",
    "logging/setLevel",
    "roots/list",
    "notifications/roots/list_changed",
    "resources/subscribe",
    "resources/unsubscribe",
    "ping",
];

/// Who the client says it is. Self-reported and never an authorization input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInfo {
    /// Client product name, verbatim from `_meta`.
    pub name: String,
    /// Client version string, verbatim from `_meta`.
    pub version: String,
}

impl ClientInfo {
    /// A single-line rendering, for a log or an audit field.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{}/{}", self.name, self.version)
    }
}

/// The per-request `_meta` block that replaces the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMeta {
    /// The revision the body claims, compared against the header later.
    pub protocol_version: String,
    /// Who the client says it is. Never an authorization input.
    pub client_info: ClientInfo,
    /// Taken verbatim. An empty object means the client supports no optional capabilities, and
    /// SEP-2575 forbids inferring any from a previous request, which is the whole point of
    /// carrying them per request.
    pub client_capabilities: Value,
    /// Requested log level, when the optional key was present.
    pub log_level: Option<String>,
}

/// Why a request's `_meta` is not usable. Every variant names the field, because the client
/// author reading the error is looking for which key they left out.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetaError {
    /// The request carried no `params` at all.
    #[error("request has no params, so it carries no _meta")]
    NoParams,
    /// `params` exists but has no `_meta` member.
    #[error("request params carry no _meta")]
    NoMeta,
    /// A REQUIRED `_meta` key is absent.
    #[error("_meta is missing the required field '{0}'")]
    MissingField(&'static str),
    /// A `_meta` key is present with the wrong shape.
    #[error("_meta field '{field}' is not {expected}")]
    WrongType {
        /// The offending `_meta` key.
        field: &'static str,
        /// What the key was required to be.
        expected: &'static str,
    },
    /// Header and `_meta` name different revisions; the request is refused.
    #[error("MCP-Protocol-Version header says '{header}' but _meta says '{meta}'; they must agree")]
    VersionDisagreement {
        /// Revision named by the HTTP header.
        header: String,
        /// Revision named inside `_meta`.
        meta: String,
    },
}

/// Read the `_meta` block from a request's params.
///
/// Every required field missing is [`INVALID_PARAMS`] and, for HTTP, a 400. That is stricter
/// than tolerating a partial block, and deliberately so: capabilities do not carry over between
/// requests under this revision, so a request that omits them is not a request whose
/// capabilities are unchanged, it is a request whose capabilities are unknown.
///
/// # Errors
///
/// Returns a [`MetaError`] naming the missing or malformed field; the
/// transport maps it to [`INVALID_PARAMS`] and, on HTTP, a 400.
pub fn parse_request_meta(params: Option<&Value>) -> Result<RequestMeta, MetaError> {
    let params = params.ok_or(MetaError::NoParams)?;
    let meta = params.get("_meta").ok_or(MetaError::NoMeta)?;

    let protocol_version = required_str(meta, META_PROTOCOL_VERSION)?;
    let client_info_value = meta
        .get(META_CLIENT_INFO)
        .ok_or(MetaError::MissingField(META_CLIENT_INFO))?;
    let client_info = ClientInfo {
        name: required_str_in(client_info_value, "name", META_CLIENT_INFO)?,
        version: required_str_in(client_info_value, "version", META_CLIENT_INFO)?,
    };
    let client_capabilities = meta
        .get(META_CLIENT_CAPABILITIES)
        .ok_or(MetaError::MissingField(META_CLIENT_CAPABILITIES))?;
    if !client_capabilities.is_object() {
        return Err(MetaError::WrongType {
            field: META_CLIENT_CAPABILITIES,
            expected: "an object",
        });
    }

    Ok(RequestMeta {
        protocol_version,
        client_info,
        client_capabilities: client_capabilities.clone(),
        log_level: meta
            .get(META_LOG_LEVEL)
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

/// Check that the negotiated revision and the one inside `_meta` are the same.
///
/// Separate from parsing because the header is the transport's business and `_meta` is the
/// body's, and only the caller holding both can compare them.
///
/// # Errors
///
/// Returns [`MetaError::VersionDisagreement`] when the two name different
/// revisions.
pub fn check_version_agreement(header: &str, meta: &RequestMeta) -> Result<(), MetaError> {
    if header.trim() == meta.protocol_version.trim() {
        return Ok(());
    }
    Err(MetaError::VersionDisagreement {
        header: header.to_string(),
        meta: meta.protocol_version.clone(),
    })
}

/// Whether `Mcp-Name` is required for this method.
#[must_use]
pub fn requires_name(method: &str) -> bool {
    NAMED_TARGET_METHODS.contains(&method)
}

/// Whether this method was removed by 2026-07-28.
#[must_use]
pub fn removed_in_2026_07_28(method: &str) -> bool {
    REMOVED_IN_2026_07_28.contains(&method)
}

/// The named target the `Mcp-Name` header must carry, read from the body.
///
/// `resources/read` names its target with `uri`; the other two use `name`.
#[must_use]
pub fn named_target(method: &str, params: Option<&Value>) -> Option<String> {
    if !requires_name(method) {
        return None;
    }
    let key = if method == "resources/read" {
        "uri"
    } else {
        "name"
    };
    params?.get(key).and_then(Value::as_str).map(str::to_string)
}

/// Why a request's SEP-2243 headers do not match its body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    /// The method header is absent or blank.
    #[error("Mcp-Method is required on every request under 2026-07-28")]
    MethodMissing,
    /// The method header and the body's method disagree.
    #[error("Mcp-Method says '{header}' but the body's method is '{body}'")]
    MethodMismatch {
        /// Method named by the header.
        header: String,
        /// Method named by the body.
        body: String,
    },
    /// The name header is required for this method and absent.
    #[error("Mcp-Name is required on '{0}'")]
    NameMissing(String),
    /// The name header and the body's named target disagree.
    #[error("Mcp-Name says '{header}' but the body names '{body}'")]
    NameMismatch {
        /// Target named by the header.
        header: String,
        /// Target named by the body.
        body: String,
    },
    /// The method requires a named target and the body carries none.
    #[error("'{method}' requires a named target and the body does not carry one")]
    BodyHasNoName {
        /// The method whose body was incomplete.
        method: String,
    },
}

/// Verify the SEP-2243 headers against the body.
///
/// Nothing here is copied out of a header into the request. The body already said what it is;
/// this only refuses the case where the two disagree, which means the intermediary that routed
/// the request and the server about to execute it are looking at different requests.
///
/// # Errors
///
/// Returns a [`HeaderError`] naming the missing or disagreeing header; the
/// transport maps it to [`HEADER_MISMATCH`].
pub fn check_headers(
    method: &str,
    params: Option<&Value>,
    mcp_method: Option<&str>,
    mcp_name: Option<&str>,
) -> Result<(), HeaderError> {
    let declared = mcp_method
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(HeaderError::MethodMissing)?;
    if declared != method {
        return Err(HeaderError::MethodMismatch {
            header: declared.to_string(),
            body: method.to_string(),
        });
    }

    if !requires_name(method) {
        // A stray Mcp-Name on a method with no named target is not a mismatch, because there is
        // nothing for it to disagree with. Refusing it would refuse a client that sends the
        // header uniformly, which the spec does not forbid.
        return Ok(());
    }

    let declared_name = mcp_name
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| HeaderError::NameMissing(method.to_string()))?;
    let body_name = named_target(method, params).ok_or_else(|| HeaderError::BodyHasNoName {
        method: method.to_string(),
    })?;
    if declared_name != body_name {
        return Err(HeaderError::NameMismatch {
            header: declared_name.to_string(),
            body: body_name,
        });
    }
    Ok(())
}

fn required_str(meta: &Value, key: &'static str) -> Result<String, MetaError> {
    match meta.get(key) {
        None => Err(MetaError::MissingField(key)),
        Some(value) => value
            .as_str()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
            .ok_or(MetaError::WrongType {
                field: key,
                expected: "a non-empty string",
            }),
    }
}

fn required_str_in(parent: &Value, key: &str, field: &'static str) -> Result<String, MetaError> {
    parent
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .ok_or(MetaError::WrongType {
            field,
            expected: "an object with a non-empty name and version",
        })
}

#[cfg(test)]
mod tests {
    // Tests assert on JSON shape, where indexing and unwrap/expect ARE the
    // assertion: a panic in a test is the failure signal, so the production
    // rationale for the workspace denies does not apply. Scoped here.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;
    use serde_json::json;

    fn full_meta() -> Value {
        json!({
            "name": "read_file_window_report",
            "_meta": {
                META_PROTOCOL_VERSION: "2026-07-28",
                META_CLIENT_INFO: {"name": "claude-desktop", "version": "1.4.2"},
                META_CLIENT_CAPABILITIES: {},
            }
        })
    }

    #[test]
    fn a_complete_meta_block_reads_every_field() {
        let meta = parse_request_meta(Some(&full_meta())).expect("parse");
        assert_eq!(meta.protocol_version, "2026-07-28");
        assert_eq!(meta.client_info.name, "claude-desktop");
        assert_eq!(meta.client_info.label(), "claude-desktop/1.4.2");
        assert_eq!(meta.client_capabilities, json!({}));
        assert_eq!(meta.log_level, None);
    }

    #[test]
    fn an_empty_capabilities_object_is_a_declaration_and_not_an_omission() {
        // SEP-2575: an empty object means no optional capabilities, and a server must not infer
        // any from a previous request. So it has to parse, and it has to be distinguishable
        // from the field being absent, which is an error.
        let meta = parse_request_meta(Some(&full_meta())).expect("parse");
        assert_eq!(meta.client_capabilities, json!({}));

        let mut without = full_meta();
        without["_meta"]
            .as_object_mut()
            .expect("meta object")
            .remove(META_CLIENT_CAPABILITIES);
        assert_eq!(
            parse_request_meta(Some(&without)),
            Err(MetaError::MissingField(META_CLIENT_CAPABILITIES))
        );
    }

    #[test]
    fn every_required_field_is_actually_required() {
        for key in [
            META_PROTOCOL_VERSION,
            META_CLIENT_INFO,
            META_CLIENT_CAPABILITIES,
        ] {
            let mut params = full_meta();
            params["_meta"]
                .as_object_mut()
                .expect("meta object")
                .remove(key);
            let err = parse_request_meta(Some(&params)).expect_err("missing field must be refused");
            assert!(
                matches!(err, MetaError::MissingField(missing) if missing == key),
                "removing {key} gave {err:?}"
            );
        }
    }

    #[test]
    fn client_info_without_a_version_is_not_client_info() {
        let mut params = full_meta();
        params["_meta"][META_CLIENT_INFO] = json!({"name": "claude-desktop"});
        assert!(matches!(
            parse_request_meta(Some(&params)),
            Err(MetaError::WrongType { field, .. }) if field == META_CLIENT_INFO
        ));
    }

    #[test]
    fn a_request_with_no_params_and_one_with_no_meta_are_told_apart() {
        assert_eq!(parse_request_meta(None), Err(MetaError::NoParams));
        assert_eq!(
            parse_request_meta(Some(&json!({"name": "x"}))),
            Err(MetaError::NoMeta)
        );
    }

    #[test]
    fn the_log_level_is_optional_and_read_when_present() {
        let mut params = full_meta();
        params["_meta"][META_LOG_LEVEL] = json!("debug");
        let meta = parse_request_meta(Some(&params)).expect("parse");
        assert_eq!(meta.log_level.as_deref(), Some("debug"));
    }

    #[test]
    fn the_header_and_the_meta_block_must_name_the_same_revision() {
        let meta = parse_request_meta(Some(&full_meta())).expect("parse");
        assert!(check_version_agreement("2026-07-28", &meta).is_ok());
        // Whitespace is not a disagreement.
        assert!(check_version_agreement(" 2026-07-28 ", &meta).is_ok());
        assert!(matches!(
            check_version_agreement("2025-11-25", &meta),
            Err(MetaError::VersionDisagreement { .. })
        ));
    }

    #[test]
    fn mcp_method_is_required_and_must_match_the_body() {
        assert_eq!(
            check_headers("tools/list", None, None, None),
            Err(HeaderError::MethodMissing)
        );
        assert_eq!(
            check_headers("tools/list", None, Some("   "), None),
            Err(HeaderError::MethodMissing),
            "a blank header is not a header"
        );
        assert!(check_headers("tools/list", None, Some("tools/list"), None).is_ok());
        assert_eq!(
            check_headers("tools/list", None, Some("tools/call"), None),
            Err(HeaderError::MethodMismatch {
                header: "tools/call".into(),
                body: "tools/list".into()
            })
        );
    }

    #[test]
    fn mcp_name_is_required_only_where_there_is_a_name() {
        // No named target, so no header needed, and a stray one is not a mismatch.
        assert!(check_headers("tools/list", None, Some("tools/list"), None).is_ok());
        assert!(check_headers("tools/list", None, Some("tools/list"), Some("anything")).is_ok());

        let params = full_meta();
        assert_eq!(
            check_headers("tools/call", Some(&params), Some("tools/call"), None),
            Err(HeaderError::NameMissing("tools/call".into()))
        );
        assert!(
            check_headers(
                "tools/call",
                Some(&params),
                Some("tools/call"),
                Some("read_file_window_report")
            )
            .is_ok()
        );
        assert_eq!(
            check_headers(
                "tools/call",
                Some(&params),
                Some("tools/call"),
                Some("write_text_file")
            ),
            Err(HeaderError::NameMismatch {
                header: "write_text_file".into(),
                body: "read_file_window_report".into()
            }),
            "the body is authoritative and the header only has to agree with it"
        );
    }

    #[test]
    fn resources_read_names_its_target_with_uri_rather_than_name() {
        let params = json!({"uri": "file:///x"});
        assert_eq!(
            named_target("resources/read", Some(&params)).as_deref(),
            Some("file:///x")
        );
        assert!(
            check_headers(
                "resources/read",
                Some(&params),
                Some("resources/read"),
                Some("file:///x")
            )
            .is_ok()
        );
        assert_eq!(named_target("tools/list", Some(&params)), None);
    }

    #[test]
    fn a_named_method_whose_body_carries_no_name_is_refused_before_dispatch() {
        assert_eq!(
            check_headers(
                "tools/call",
                Some(&json!({})),
                Some("tools/call"),
                Some("x")
            ),
            Err(HeaderError::BodyHasNoName {
                method: "tools/call".into()
            })
        );
    }

    #[test]
    fn the_removed_rpcs_are_the_ones_sep_2575_removed() {
        for removed in [
            "initialize",
            "notifications/initialized",
            "ping",
            "roots/list",
        ] {
            assert!(removed_in_2026_07_28(removed), "{removed}");
        }
        for kept in ["tools/list", "tools/call", "server/discover"] {
            assert!(!removed_in_2026_07_28(kept), "{kept}");
        }
    }
}
