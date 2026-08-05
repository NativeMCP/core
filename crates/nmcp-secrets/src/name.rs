//! The operator secret name and the version counter.
//!
//! NMCP-SPEC-002 SB-2 and SB-10, RATIFIED v1.0.
//!
//! [`SecretName`] is the only name type the store's surface admits, and its parser is where
//! the reserved-namespace rule lives: a name inside `oauth/` is not a `SecretName`, so it is
//! not a name [`SealedStore::set`](crate::SealedStore::set) can be called with and not a name
//! [`SealedStore::names`](crate::SealedStore::names) can report. The broker that owns that
//! namespace, and the storage lifecycle SB-10 carves out for it, arrive with the OAuth port in
//! the W2 tail; this crate reserves the namespace at its surface and deliberately ships no
//! read or write path into it, because a removal path with no owner in the tree is the kind of
//! surface that gets found by the wrong caller first.

use std::fmt;

use nmcp_schema::{SECRET_REF_PREFIX, SecretRef, SecretRefError};
use serde::{Deserialize, Serialize};

/// A name the operator surface may write and a reference may address.
///
/// The grammar is SB-2's, and it is not re-implemented here. Parsing prefixes the reference
/// scheme and delegates to [`SecretRef::parse`], which I-032 landed in `nmcp-schema`, so there
/// is exactly one implementation of the grammar in the workspace and a name that parses here
/// is a name a reference can address by construction. Two parsers for one grammar is two
/// parsers that drift, and SB-2 already records that three of them exist in the base.
///
/// A reserved name cannot be one of these. That is inherited rather than added: the delegated
/// parse refuses `nmcp_schema::RESERVED_SECRET_NAMESPACES`, so `oauth/anything` and the bare
/// `oauth` label are refused with the namespace named, and the store's whole surface is typed
/// on this rather than on a check at the top of each method that somebody has to remember to
/// write.
///
/// Serialization round-trips through the parse. `Deserialize` goes through `try_from`, so a
/// store document read off disk cannot smuggle in a name the grammar refuses: a document
/// carrying one fails to load, and the store isolates that document rather than serving it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretName(String);

impl SecretName {
    /// Parse `text` as an operator secret name.
    ///
    /// # Errors
    ///
    /// [`SecretNameError`] when the name is empty, too long, in a reserved namespace, or
    /// outside the SB-2 character class.
    pub fn parse(text: &str) -> Result<Self, SecretNameError> {
        // The grammar lives in the reference parser, so the name is checked by asking whether
        // a reference to it would parse. `NotASecretReference` is unreachable through this
        // path because the prefix is added here, and it is mapped rather than dismissed: a
        // parser that changed its mind about the prefix should surface as a refusal and not as
        // a silently accepted name.
        match SecretRef::parse(&format!("{SECRET_REF_PREFIX}{text}")) {
            Ok(reference) => Ok(Self(reference.name().to_string())),
            Err(source) => Err(SecretNameError { source }),
        }
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for SecretName {
    type Error = SecretNameError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<SecretName> for String {
    fn from(name: SecretName) -> Self {
        name.0
    }
}

impl From<&SecretRef> for SecretName {
    /// A reference already carries a name the grammar admits, so this cannot fail. The
    /// conversion I-034's resolution wiring uses to go from a caller's reference to the name a
    /// store method takes, defined here so it exists in exactly one place.
    fn from(reference: &SecretRef) -> Self {
        Self(reference.name().to_string())
    }
}

/// Why a string is not an operator secret name.
///
/// A thin wrapper rather than a second enumeration of the same refusals. The grammar is
/// `nmcp-schema`'s and so are its refusals; restating them here would be a second list to keep
/// in step with the first. The wrapper exists so this crate's callers get an error whose
/// `Display` talks about a name rather than about a reference they did not write.
///
/// Carries no material. The wrapped error carries the name once the length has been bounded,
/// which SB-R2 permits because a name is not a value, and never the caller's raw input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a usable secret name: {source}")]
pub struct SecretNameError {
    /// What the SB-2 grammar objected to.
    #[from]
    pub source: SecretRefError,
}

/// A monotonic version counter for one secret's values.
///
/// SB-10 makes values versioned and SB-14 gives versions distinct lifecycle states, so a
/// version is the unit the state machine acts on rather than a label on a value. Starts at
/// one: version zero would be a value that never existed, and every audit record naming a
/// version would have to say which convention it meant.
///
/// `Deserialize` goes through [`Version::from_number`], so a stored document cannot carry
/// version zero into a running store; a document claiming one fails to load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Version(u32);

impl Version {
    /// The first version of any secret.
    #[must_use]
    pub const fn first() -> Self {
        Self(1)
    }

    /// The next version after this one.
    ///
    /// Saturating rather than wrapping. Wrapping would hand version four billion and something
    /// a number that already names a stored value, and a rotation that silently overwrites a
    /// version is the one outcome INV-1 exists to prevent. Saturation makes `next` return the
    /// same version, which [`SealedStore::rotate`](crate::SealedStore::rotate) detects and
    /// refuses as exhaustion.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// The version as a number, for encoding.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Build a version from a stored number.
    ///
    /// # Errors
    ///
    /// [`VersionError::Zero`] for zero, which no secret has.
    pub const fn from_number(number: u32) -> Result<Self, VersionError> {
        if number == 0 {
            return Err(VersionError::Zero);
        }
        Ok(Self(number))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<u32> for Version {
    type Error = VersionError;

    fn try_from(number: u32) -> Result<Self, Self::Error> {
        Self::from_number(number)
    }
}

impl From<Version> for u32 {
    fn from(version: Version) -> Self {
        version.0
    }
}

/// Why a number is not a version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VersionError {
    /// Zero, which is a value that never existed.
    #[error("version zero names a value that never existed; versions start at one")]
    Zero,
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
    use nmcp_schema::{SecretRef, SecretRefError};

    use super::{SecretName, SecretNameError, Version, VersionError};

    #[test]
    fn a_name_the_grammar_admits_parses_and_reads_back() {
        let name = SecretName::parse("api.token-1_v2").unwrap();
        assert_eq!(name.as_str(), "api.token-1_v2");
        assert_eq!(name.to_string(), "api.token-1_v2");
    }

    /// SB-2's reserved namespace, refused here so no store method can ever be called with one.
    /// This is the store-surface half of SB-R2's filter: `oauth/` names are unrepresentable as
    /// operator names, so `set` refuses them by type and `names` cannot report one.
    #[test]
    fn a_reserved_name_is_not_a_secret_name() {
        for reserved in ["oauth", "oauth/provider", "oauth/a.b-c"] {
            let refused = SecretName::parse(reserved).unwrap_err();
            assert!(
                matches!(
                    &refused.source,
                    SecretRefError::ReservedNamespace { namespace, .. } if *namespace == "oauth"
                ),
                "{reserved:?} must be refused as reserved, got {refused:?}"
            );
            let message = refused.to_string();
            assert!(message.contains("reserved"), "{message}");
        }
        // The refusal does not widen past the namespace it names.
        assert!(SecretName::parse("oauth_provider").is_ok());
        assert!(SecretName::parse("oauthority").is_ok());
    }

    #[test]
    fn the_grammar_is_the_reference_grammar_and_not_a_second_copy() {
        // One grammar: whatever the reference parser refuses, this refuses, for the same
        // reason. Sampled across the refusal classes rather than restated.
        for (name, expect_ok) in [
            ("a", true),
            ("z9._-", true),
            ("", false),
            ("API_TOKEN", false),
            ("with space", false),
            (&"a".repeat(65), false),
        ] {
            assert_eq!(SecretName::parse(name).is_ok(), expect_ok, "{name:?}");
        }
    }

    #[test]
    fn a_reference_converts_to_the_name_it_carries() {
        let reference = SecretRef::parse("nmcp://secret/db.password").unwrap();
        let name = SecretName::from(&reference);
        assert_eq!(name.as_str(), "db.password");
        assert_eq!(name, SecretName::parse("db.password").unwrap());
    }

    #[test]
    fn serde_round_trips_and_deserialization_runs_the_parse() {
        let name = SecretName::parse("github.token").unwrap();
        let text = serde_json::to_string(&name).unwrap();
        assert_eq!(text, "\"github.token\"");
        let back: SecretName = serde_json::from_str(&text).unwrap();
        assert_eq!(back, name);
        // A document cannot smuggle in what the parser refuses.
        assert!(serde_json::from_str::<SecretName>("\"oauth/provider\"").is_err());
        assert!(serde_json::from_str::<SecretName>("\"NOT_LOWER\"").is_err());
    }

    #[test]
    fn versions_start_at_one_and_advance_by_one() {
        assert_eq!(Version::first().get(), 1);
        assert_eq!(Version::first().next().get(), 2);
        assert_eq!(Version::first().to_string(), "1");
        assert_eq!(Version::from_number(7).unwrap().get(), 7);
        assert_eq!(Version::from_number(0), Err(VersionError::Zero));
    }

    #[test]
    fn the_version_counter_saturates_rather_than_wrapping() {
        let last = Version::from_number(u32::MAX).unwrap();
        assert_eq!(
            last.next(),
            last,
            "saturation, which rotate detects and refuses"
        );
    }

    #[test]
    fn version_serde_round_trips_and_refuses_zero() {
        let version = Version::from_number(3).unwrap();
        let text = serde_json::to_string(&version).unwrap();
        assert_eq!(text, "3");
        assert_eq!(serde_json::from_str::<Version>("3").unwrap(), version);
        assert!(serde_json::from_str::<Version>("0").is_err());
    }

    #[test]
    fn the_name_error_wraps_the_grammar_refusal_rather_than_restating_it() {
        let refused: SecretNameError = SecretName::parse("A").unwrap_err();
        assert!(matches!(
            refused.source,
            SecretRefError::IllegalCharacter { .. }
        ));
        let message = refused.to_string();
        assert!(
            message.starts_with("not a usable secret name:"),
            "{message}"
        );
    }
}
