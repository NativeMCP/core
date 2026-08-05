//! The sealer abstraction: what it means to seal, and what a blob is bound to.
//!
//! NMCP-SPEC-002 SB-11, RATIFIED v1.0. The [`Sealer`] signature is frozen at ratification and
//! implemented as written. [`SealContext`], [`SealError`] and [`SealerId`] are named by SB-11
//! and defined here.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::Sealed;
use crate::name::Version;

/// The entropy label every blob this crate seals is bound to.
///
/// SB-11 fixes the value and NDEC-6 fixes the naming. It is a label rather than a secret: it
/// separates one purpose from another so a blob sealed for the secret store cannot be replayed
/// into some other consumer of the same key, and it separates one generation from the next so a
/// migration can tell them apart.
///
/// A previous generation's label is **not** compiled in anywhere. SB-12's migration unseals
/// under the old label and reseals under this one, and it takes the old value as a parameter
/// ([`crate::FileSealer::open_with_purpose`]) rather than as a constant, because INV-8 forbids
/// the retired name this repository would otherwise have to carry to name it.
pub const SECRET_ENTROPY: &str = "NativeMCP.secrets.v2";

/// Which sealer, of which generation, on which deployment, sealed a blob.
///
/// Recorded on every stored blob (SB-10) so a migration can tell what it is looking at. Three
/// things have to be distinguishable for [`crate::SealedStore::migrate`] to be able to do
/// anything useful, and the identifier carries all three: the kind of sealer, so a DPAPI blob
/// is not fed to a file sealer; the entropy generation, so SB-12's v1 blobs are separable from
/// v2 ones; and the deployment, so a store carried to a machine whose key file is a different
/// key file reports that rather than reporting a corrupt blob.
///
/// It carries nothing derived from key material. The deployment component is an identifier
/// generated beside the key and independent of it, not a digest of it: a digest of a key
/// written into a file an attacker may read is a distinguisher handed over for nothing, and the
/// identifier travels into [`crate::MigrationReport`] where an operator reads it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SealerId(String);

impl SealerId {
    /// Build an identifier from its three components.
    ///
    /// `kind` names the implementation (`file`, `memory`, and in the platform repositories
    /// `dpapi`, `keychain`, `secret-service`). `purpose` is the entropy label. `deployment`
    /// identifies the key this sealer holds without describing it.
    #[must_use]
    pub fn new(
        kind: impl fmt::Display,
        purpose: impl fmt::Display,
        deployment: impl fmt::Display,
    ) -> Self {
        Self(format!("{kind}/{purpose}/{deployment}"))
    }

    /// The identifier as text, which is how it is stored and compared.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SealerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a blob is bound to, beyond the key.
///
/// Passed to both halves of [`Sealer`] and carried into the cipher as associated data, so a
/// blob unseals only in the slot it was sealed for. That is worth having because the store is a
/// file: an attacker who can write it cannot make a copy of the value from one key resolve as
/// another key, and cannot roll a rotated key back by moving an old blob into the current
/// version's slot. Both are edits that succeed against a store whose blobs are bound to nothing
/// but the key.
///
/// The context is not secret and carries no material. It is a name, a version and a purpose
/// label, all three of which SB-R2 already permits the agent to see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealContext {
    purpose: String,
    name: String,
    version: Version,
}

impl SealContext {
    /// The context for `name` at `version`, under this crate's current entropy label.
    #[must_use]
    pub fn new(name: impl Into<String>, version: Version) -> Self {
        Self {
            purpose: SECRET_ENTROPY.to_string(),
            name: name.into(),
            version,
        }
    }

    /// The context for `name` at `version` under a caller-supplied entropy label.
    ///
    /// SB-12's migration path: a blob sealed by an earlier generation is bound to that
    /// generation's label, and unsealing it needs the label back. It is a parameter rather than
    /// a constant for the reason [`SECRET_ENTROPY`] gives.
    #[must_use]
    pub fn with_purpose(
        purpose: impl Into<String>,
        name: impl Into<String>,
        version: Version,
    ) -> Self {
        Self {
            purpose: purpose.into(),
            name: name.into(),
            version,
        }
    }

    /// The entropy label.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// The secret name this blob belongs to.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The version this blob belongs to.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// The canonical byte encoding a sealer binds a blob to.
    ///
    /// Length-prefixed rather than delimited. A delimiter would make the encodings of
    /// `("a/b", "c")` and `("a", "b/c")` the same bytes, and the whole value of binding is that
    /// two different slots produce two different bindings. The name grammar happens to exclude
    /// the separator today, which is exactly the kind of fact that stops being true in a
    /// migration, so the encoding does not rely on it.
    #[must_use]
    pub fn associated_data(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for field in [self.purpose.as_bytes(), self.name.as_bytes()] {
            out.extend_from_slice(&u32::try_from(field.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(field);
        }
        out.extend_from_slice(&self.version.get().to_be_bytes());
        out
    }
}

/// Sealing and unsealing, whoever provides it.
///
/// The trait NMCP-SPEC-001 R-4 places outside this repository: DPAPI in WinMCP, Keychain in
/// MacMCP, secret-service in LinuxMCP, and enterprise backends in the private layer. This crate
/// ships a real implementation of it ([`crate::FileSealer`]) rather than a mock, so headless
/// Linux and CI have a complete one (SB-A7).
///
/// `Send + Sync` because [`crate::SealedStore`] holds one behind a lock and the server is
/// multi-threaded.
pub trait Sealer: Send + Sync {
    /// Seal `plain` for the slot `context` names.
    ///
    /// # Errors
    ///
    /// [`SealError`], carrying no material and nothing derived from it (SB-1). In particular
    /// not a length: a ciphertext length is a plaintext length plus a constant.
    fn seal(&self, plain: &[u8], context: &SealContext) -> Result<Vec<u8>, SealError>;

    /// Unseal `blob` for the slot `context` names.
    ///
    /// An implementation that copies plaintext out of a buffer it allocated must zero that
    /// buffer before releasing it. SB-11 requires it and T12 records why: the base's DPAPI
    /// unseal releases a plaintext buffer without zeroing, so the value persists in freed heap
    /// that [`Sealed`] never touches and cannot erase.
    ///
    /// # Errors
    ///
    /// [`SealError`]. A blob that fails authentication is [`SealError::Unsealable`], and the
    /// variant deliberately cannot say why: distinguishing a wrong key from a wrong context
    /// from a corrupted tag is an oracle, and an operator's remedy is the same in all three.
    fn unseal(&self, blob: &[u8], context: &SealContext) -> Result<Sealed<Vec<u8>>, SealError>;

    /// Which sealer, of which generation, on which deployment.
    fn id(&self) -> SealerId;
}

/// Why a seal or an unseal did not happen.
///
/// No variant carries material or any value derived from material, including a length or a
/// digest (SB-1). That is the reason the variants look thin: an operator diagnosing an
/// unreadable store gets the kind of failure and the path of the file, and the bytes stay where
/// they are. SB-8's fail-closed posture means the request carrying the reference is refused
/// either way, so the missing detail costs a diagnosis rather than a decision.
///
/// Exhaustive rather than `#[non_exhaustive]`. This enum is owned by NMCP-SPEC-002 rather than
/// frozen by a ratified contract another crate matches on, and a new way for sealing to fail
/// arrives with the specification revision that invents it, at which point every `match` on it
/// should break loudly.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// The sealer's key file is not where it should be, or cannot be read.
    #[error("sealer key file {path} could not be read: {reason}")]
    KeyFileUnreadable {
        /// Where the sealer looked.
        path: String,
        /// The operating system's description of the failure, which describes the file rather
        /// than its contents.
        reason: String,
    },

    /// The key file is present and is not a key file this sealer understands.
    #[error("sealer key file {path} is not in the format this sealer writes")]
    KeyFileMalformed {
        /// Where the sealer looked.
        path: String,
    },

    /// The key file or its directory is readable by somebody other than the owner.
    ///
    /// A refusal rather than a repair. SB-11 decides that this sealer's entire guarantee
    /// against a local attacker is the filesystem's, so a key file the filesystem is not
    /// protecting is a sealer with no guarantee at all, and silently tightening the mode would
    /// hide the window during which it was open.
    #[error(
        "sealer key file {path} is mode {mode:o} and this sealer requires {required:o}, since filesystem permissions are the whole of its guarantee"
    )]
    KeyFileExposed {
        /// The offending path.
        path: String,
        /// The mode found.
        mode: u32,
        /// The mode required.
        required: u32,
    },

    /// The key file could not be created.
    #[error("sealer key file {path} could not be created: {reason}")]
    KeyFileNotCreated {
        /// Where the sealer tried.
        path: String,
        /// The operating system's description of the failure.
        reason: String,
    },

    /// The operating system's random source did not answer.
    ///
    /// Fails closed. A sealer that generates a key or a nonce from a fallback when the system
    /// generator is unavailable is a sealer whose output an attacker can predict.
    #[error("the system random source is unavailable, and this sealer has no fallback")]
    NoEntropy,

    /// The cipher refused the plaintext.
    #[error("sealing failed")]
    NotSealable,

    /// The blob did not authenticate under this key and this context.
    ///
    /// One variant for every cause on purpose. A wrong key, a wrong entropy generation, a
    /// blob moved from another slot and a corrupted tag are indistinguishable here, because
    /// telling them apart is an oracle for an attacker holding the file and an operator's
    /// remedy is the same in all four.
    #[error("blob did not authenticate under this sealer and this context")]
    Unsealable,
}

impl From<crate::perms::PermsError> for SealError {
    /// A restriction failure on the key file, in this crate's sealer vocabulary.
    fn from(error: crate::perms::PermsError) -> Self {
        match error {
            crate::perms::PermsError::Exposed {
                path,
                mode,
                required,
            } => Self::KeyFileExposed {
                path,
                mode,
                required,
            },
            crate::perms::PermsError::Failed { path, reason } => {
                Self::KeyFileNotCreated { path, reason }
            }
        }
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
    use super::{SealContext, SealerId, Version};

    #[test]
    fn a_sealer_id_names_kind_generation_and_deployment() {
        let id = SealerId::new("file", "NativeMCP.secrets.v2", "0a1b2c3d");
        assert_eq!(id.as_str(), "file/NativeMCP.secrets.v2/0a1b2c3d");
        assert_eq!(id.to_string(), id.as_str());
    }

    #[test]
    fn two_deployments_of_the_same_sealer_are_different_ids() {
        // The property migration depends on: a store carried to another machine reports a
        // sealer it does not have rather than reporting corruption.
        let here = SealerId::new("file", "NativeMCP.secrets.v2", "aaaaaaaa");
        let there = SealerId::new("file", "NativeMCP.secrets.v2", "bbbbbbbb");
        assert_ne!(here, there);
        let older = SealerId::new("file", "NativeMCP.secrets.v1", "aaaaaaaa");
        assert_ne!(here, older, "a generation bump is a different sealer");
    }

    /// Length prefixing is the property that makes binding mean anything, so it is tested
    /// against the collision a delimiter would produce rather than asserted from the code.
    #[test]
    fn associated_data_does_not_collide_across_field_boundaries() {
        let left = SealContext::with_purpose("a", "bc", Version::first());
        let right = SealContext::with_purpose("ab", "c", Version::first());
        assert_ne!(left.associated_data(), right.associated_data());
    }

    #[test]
    fn associated_data_separates_name_version_and_purpose() {
        let base = SealContext::new("github.token", Version::first());
        assert_ne!(
            base.associated_data(),
            SealContext::new("gitlab.token", Version::first()).associated_data()
        );
        assert_ne!(
            base.associated_data(),
            SealContext::new("github.token", Version::first().next()).associated_data()
        );
        assert_ne!(
            base.associated_data(),
            SealContext::with_purpose("other.purpose", "github.token", Version::first())
                .associated_data()
        );
        // Equal inputs give equal bindings, so unsealing what was sealed works at all.
        assert_eq!(
            base.associated_data(),
            SealContext::new("github.token", Version::first()).associated_data()
        );
    }

    #[test]
    fn the_context_reads_back_what_it_was_given() {
        let context = SealContext::new("db.password", Version::first().next());
        assert_eq!(context.purpose(), super::SECRET_ENTROPY);
        assert_eq!(context.name(), "db.password");
        assert_eq!(context.version(), Version::first().next());
    }
}
