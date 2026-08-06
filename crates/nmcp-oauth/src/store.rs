//! The broker's own sealed storage: the `oauth/` carve-out, implemented as its own store.
//!
//! NMCP-SPEC-002 SB-10 reserves the `oauth/` namespace to this broker "with its own
//! lifecycle, exempt from the SB-14 FSM and from the never-deleted rule, and its entries are
//! invisible to `secrets_list`". This module is that lifecycle. The base's broker wrote and
//! hard-deleted grants inside the operator secret store; core's [`SealedStore`](nmcp_secrets::SealedStore) deliberately
//! has no delete method and its [`SecretName`](nmcp_secrets::SecretName) refuses reserved names at parse, so the port
//! cannot retarget those calls, and the spec says it must not: a broker door on the operator
//! store is exactly what the carve-out exists to avoid (SB-13). The broker therefore owns a
//! small sealed store of its own.
//!
//! ## The two stores do not share a directory, and that is the isolation
//!
//! The operator store's invisibility rule is enforced by type: an `oauth/` name cannot be a
//! [`SecretName`](nmcp_secrets::SecretName), so no [`SealedStore`](nmcp_secrets::SealedStore) method can be called with one and
//! `SealedStore::names` has nothing to filter. This store completes the separation in the
//! other direction: grants live in a directory of their own, sealed under a
//! [`Sealer`] of their own, and never inside the operator store's `secrets/` directory at
//! all. There is no shared layout to keep filtered; a hand-planted grant file in the operator
//! store's directory is isolated by that store as a name outside its grammar, which its own
//! suite proves. Invisibility by absence rather than by filter, which is the enforcement
//! shape SB-10 asks for.
//!
//! ## One document, deliberately
//!
//! The operator store keeps one file per secret because an operator secret is irreplaceable:
//! isolation exists so a damaged neighbour cannot take out a credential nobody can retype.
//! A grant is the opposite kind of thing, re-obtainable by signing in again, and a provider
//! id is policy text that should never become a filesystem path, which is the whole class of
//! file-naming questions a per-provider layout would import. So this store is one sealed
//! document, the same shape the base's store actually had, replaced atomically through the
//! fixed-temporary-name-then-rename discipline the operator store uses, at the same `0700`
//! and `0600` modes, applied and verified by the same `nmcp-secrets` code rather than by a
//! copy of it.
//!
//! ## Revocation destroys material without a delete primitive
//!
//! INV-1's scanner refuses destructive filesystem primitives in production code and is not
//! namespace-aware, so revocation-by-deletion is off the table even though SB-10 exempts
//! this namespace from never-deleted. The safe shape, used here: [`GrantStore::revoke`]
//! tombstones the entry, the way the operator store's quarantine does, **and** replaces the
//! sealed blob with a fresh sealing of the empty value under the next version. The document
//! is rewritten in place through the rename path, so after a revocation the directory holds
//! no ciphertext of either token: the file remains, the entry remains and says `revoked`,
//! and the material is unrecoverable even by the holder of the sealer key. The tests measure
//! exactly that, byte-window over the whole directory, plus an unseal of what the tombstone
//! actually holds.
//!
//! ## Rollback, honestly bounded
//!
//! Every blob is sealed bound to its name and a per-entry version counter, so an edit that
//! copies one provider's blob onto another provider's entry, or an old blob onto a newer
//! version number, does not authenticate. What the counter does not prevent, here exactly as
//! in the operator store, is an attacker with write access replacing the whole document with
//! an older whole document; the counter and the version live together in the file. Stated
//! rather than implied, because a revoked grant restored that way still fails at the
//! provider, which revoked it too, and that is the real backstop.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nmcp_secrets::{
    RESTRICTED_DIR_MODE, RESTRICTED_FILE_MODE, SealContext, SealError, Sealed, Sealer, SealerId,
    Version, create_restricted_dir, verify_restricted, write_restricted,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tracing::warn;
use zeroize::Zeroizing;

use crate::grant::{Grant, grant_secret_name};

/// The document this store lives in, inside the store directory.
pub const GRANTS_FILE: &str = "grants.json";

/// The document's schema version, so a later format is recognised rather than misread.
pub const GRANT_STORE_SCHEMA_VERSION: u32 = 1;

/// The suffix the document is written under before being renamed into place.
///
/// Fixed rather than unique, for the operator store's reason: a failed rename leaves one file
/// that the next write overwrites, and no cleanup path calling a destructive primitive needs
/// to exist.
const WRITE_EXTENSION: &str = "json.writing";

/// One provider's entry, as it sits in the document.
///
/// `deny_unknown_fields` for the reason the operator store gives: an unknown field means a
/// foreign document, and a foreign document is refused rather than half-read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantEntry {
    state: GrantState,
    /// The per-entry write counter the blob is sealed against. Monotonic across the entry's
    /// whole life, revocations included, so no two writes ever share a binding.
    version: Version,
    /// Which sealer sealed the blob, so a store carried to another machine is reported as
    /// sealed by a different deployment rather than as corrupt.
    sealed_by: SealerId,
    /// The sealed grant, or the sealed empty value on a revoked entry.
    blob_hex: String,
}

/// Where one provider's entry is in its lifecycle. The whole carve-out FSM: two states, and
/// the only transitions are grant, refresh (which stays `Granted`) and revoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GrantState {
    /// A grant is sealed here.
    Granted,
    /// The tombstone: the entry remains, the blob holds the sealed empty value, and the
    /// material this entry once held is gone from the directory.
    Revoked,
}

/// The document, the unit of atomic replacement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantsDocument {
    schema: u32,
    entries: BTreeMap<String, GrantEntry>,
}

impl GrantsDocument {
    fn empty() -> Self {
        Self {
            schema: GRANT_STORE_SCHEMA_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

/// The mutable half, behind one lock.
struct State {
    document: GrantsDocument,
    /// The store directory, or `None` for an ephemeral store.
    dir: Option<PathBuf>,
}

/// The broker's grants, sealed at rest, in a directory of their own.
///
/// Clonable and cheap to clone, the way the base's store was: the broker holds one and a test
/// or a console holds the same store through another handle. All handles share one lock.
#[derive(Clone)]
pub struct GrantStore {
    sealer: Arc<dyn Sealer>,
    state: Arc<Mutex<State>>,
}

impl std::fmt::Debug for GrantStore {
    /// Hand-written, printing the sealer identity and nothing about the entries, for the
    /// operator store's reason: the set of providers a machine holds grants for is the shape
    /// of its attack surface, and a `Debug` is what lands in a trace span.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantStore")
            .field("sealer", &self.sealer.id())
            .finish_non_exhaustive()
    }
}

impl GrantStore {
    /// Open the store in `dir`, sealing with `sealer`.
    ///
    /// An absent directory or document is an empty store. `dir` must be the broker's own
    /// directory, never the operator store's, and the sealer's key must live in a directory
    /// of its own ([`nmcp_secrets::default_key_dir`] picks a sibling), so a backup that
    /// captures one does not necessarily capture the other.
    ///
    /// # Errors
    ///
    /// [`GrantStoreError`] when the directory cannot be created or read, the document does
    /// not parse or declares a schema this build does not know, or, on Unix, the directory or
    /// document is readable by somebody other than its owner. A document that does not parse
    /// refuses the open rather than being treated as empty and later overwritten: the
    /// operator moves it aside first, so the destruction of whatever it still holds is a
    /// human action, not a side effect of starting the service.
    pub fn open(dir: &Path, sealer: Box<dyn Sealer>) -> Result<Self, GrantStoreError> {
        create_restricted_dir(dir)?;
        verify_restricted(dir, RESTRICTED_DIR_MODE)?;
        let path = dir.join(GRANTS_FILE);
        let document = match fs::read_to_string(&path) {
            Ok(text) => {
                verify_restricted(&path, RESTRICTED_FILE_MODE)?;
                let document: GrantsDocument =
                    serde_json::from_str(&text).map_err(|_| GrantStoreError::Unreadable {
                        path: path.display().to_string(),
                    })?;
                if document.schema != GRANT_STORE_SCHEMA_VERSION {
                    return Err(GrantStoreError::UnknownSchema {
                        path: path.display().to_string(),
                        found: document.schema,
                        known: GRANT_STORE_SCHEMA_VERSION,
                    });
                }
                document
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => GrantsDocument::empty(),
            Err(err) => {
                return Err(GrantStoreError::Io {
                    path: path.display().to_string(),
                    reason: err.kind().to_string(),
                });
            }
        };
        Ok(Self {
            sealer: Arc::from(sealer),
            state: Arc::new(Mutex::new(State {
                document,
                dir: Some(dir.to_path_buf()),
            })),
        })
    }

    /// An in-memory store, for callers that have no directory.
    ///
    /// It still seals, with a key generated for this process and written nowhere, so an
    /// ephemeral store exercises the same sealing path as a persistent one. When the system
    /// random source is unavailable the store gets a sealer that refuses every operation
    /// (SB-8's posture, exactly as `SealedStore::ephemeral` handles the same case): grants
    /// then live only in broker memory and every persistence attempt fails closed and loudly.
    #[must_use]
    pub fn ephemeral() -> Self {
        let sealer: Arc<dyn Sealer> = match nmcp_secrets::MemorySealer::new() {
            Ok(sealer) => Arc::new(sealer),
            Err(_) => Arc::new(NoEntropySealer),
        };
        Self {
            sealer,
            state: Arc::new(Mutex::new(State {
                document: GrantsDocument::empty(),
                dir: None,
            })),
        }
    }

    /// The sealed grant for `provider`, if one is held and opens.
    ///
    /// `None` covers absent, revoked, unsealable and unparseable at once, deliberately, the
    /// way the base's read did: the broker does the same thing in every case, which is to
    /// treat the provider as not authorized, and the distinction is worth a log line rather
    /// than a branch every caller must carry. The log line is written here, without material.
    #[must_use]
    pub fn load(&self, provider: &str) -> Option<Grant> {
        let state = self.state.lock();
        let entry = state.document.entries.get(provider)?;
        if entry.state != GrantState::Granted {
            return None;
        }
        let Ok(blob) = hex::decode(&entry.blob_hex) else {
            warn!(
                provider,
                "oauth: sealed grant is not hex; treating as absent"
            );
            return None;
        };
        let context = SealContext::new(grant_secret_name(provider), entry.version);
        let Ok(sealed) = self.sealer.unseal(&blob, &context) else {
            // The identifier comparison is diagnosis, not access control: a blob from
            // another deployment fails to authenticate either way.
            if entry.sealed_by == self.sealer.id() {
                warn!(
                    provider,
                    "oauth: sealed grant did not open; treating as absent"
                );
            } else {
                warn!(
                    provider,
                    sealed_by = %entry.sealed_by,
                    "oauth: grant was sealed by a different deployment; treating as absent"
                );
            }
            return None;
        };
        // The unsealed JSON is material in another spelling; parse inside the scoped
        // exposure and let the buffer zeroize on the way out (SB-1, T12).
        let parsed = sealed.with_exposed(|bytes| {
            serde_json::from_slice::<Grant>(bytes).map_err(|err| err.classify())
        });
        match parsed {
            Ok(grant) => Some(grant),
            Err(class) => {
                warn!(
                    provider,
                    kind = ?class,
                    "oauth: sealed grant does not parse; treating as absent"
                );
                None
            }
        }
    }

    /// Seal and persist `grant` for `provider`, replacing whatever the entry held.
    ///
    /// A refresh, a fresh authorization and a re-authorization after revocation all land
    /// here; the entry's counter advances every time, so no two writes share a sealing
    /// context.
    ///
    /// # Errors
    ///
    /// [`GrantStoreError`] when the grant cannot be encoded or sealed, the entry's write
    /// counter is exhausted, or the document cannot be written. The caller decides whether
    /// that is fatal; the broker keeps serving the in-memory grant and warns, exactly as the
    /// base did.
    pub fn store(&self, provider: &str, grant: &Grant) -> Result<(), GrantStoreError> {
        let mut state = self.state.lock();
        let version = next_version(&state.document, provider)?;
        let plain = Zeroizing::new(serde_json::to_vec(grant).map_err(|_| {
            GrantStoreError::NotEncodable {
                provider: provider.to_string(),
            }
        })?);
        let context = SealContext::new(grant_secret_name(provider), version);
        let blob = self
            .sealer
            .seal(&plain, &context)
            .map_err(|source| GrantStoreError::Seal {
                provider: provider.to_string(),
                source,
            })?;
        let entry = GrantEntry {
            state: GrantState::Granted,
            version,
            sealed_by: self.sealer.id(),
            blob_hex: hex::encode(blob),
        };
        state.document.entries.insert(provider.to_string(), entry);
        persist(&state)
    }

    /// Tombstone `provider`'s entry and destroy the sealed material (the SB-10 carve-out).
    ///
    /// Returns whether a grant was actually held. The entry is not removed: its state becomes
    /// `revoked` and its blob becomes a fresh sealing of the empty value under the next
    /// counter, so the rewritten document carries no ciphertext of either token and the
    /// directory holds nothing the sealer key could give back. No file is deleted; the
    /// material is gone even though the file is not.
    ///
    /// # Errors
    ///
    /// [`GrantStoreError`] when the tombstone cannot be sealed or the document cannot be
    /// written. On an error nothing was replaced; a caller that must guarantee destruction
    /// surfaces this rather than logging it, which is what [`crate::Broker::forget`] does.
    pub fn revoke(&self, provider: &str) -> Result<bool, GrantStoreError> {
        let mut state = self.state.lock();
        let Some(existing) = state.document.entries.get(provider) else {
            return Ok(false);
        };
        let had = existing.state == GrantState::Granted;
        let version = next_version(&state.document, provider)?;
        let context = SealContext::new(grant_secret_name(provider), version);
        let blob = self
            .sealer
            .seal(&[], &context)
            .map_err(|source| GrantStoreError::Seal {
                provider: provider.to_string(),
                source,
            })?;
        let entry = GrantEntry {
            state: GrantState::Revoked,
            version,
            sealed_by: self.sealer.id(),
            blob_hex: hex::encode(blob),
        };
        state.document.entries.insert(provider.to_string(), entry);
        persist(&state)?;
        Ok(had)
    }
}

/// The next write counter for `provider`'s entry, starting at one for a new entry.
fn next_version(document: &GrantsDocument, provider: &str) -> Result<Version, GrantStoreError> {
    match document.entries.get(provider) {
        None => Ok(Version::first()),
        Some(entry) => {
            let next = entry.version.next();
            if next == entry.version {
                // Saturation. Refused rather than reused, because a reused counter is two
                // writes under one sealing context, which is the binding not meaning anything.
                return Err(GrantStoreError::CounterExhausted {
                    provider: provider.to_string(),
                });
            }
            Ok(next)
        }
    }
}

/// Write the document to disk, atomically, at the restricted mode. A no-op when ephemeral.
fn persist(state: &State) -> Result<(), GrantStoreError> {
    let Some(dir) = &state.dir else {
        return Ok(());
    };
    let path = dir.join(GRANTS_FILE);
    let body =
        serde_json::to_vec_pretty(&state.document).map_err(|_| GrantStoreError::NotEncodable {
            provider: String::new(),
        })?;
    let temporary = dir.join(format!("{GRANTS_FILE}.{WRITE_EXTENSION}"));
    write_restricted(&temporary, &body, RESTRICTED_FILE_MODE)?;
    fs::rename(&temporary, &path).map_err(|err| GrantStoreError::Io {
        path: path.display().to_string(),
        reason: err.kind().to_string(),
    })
}

/// A sealer that refuses everything, for an ephemeral store on a machine whose random source
/// is unavailable. The same fail-closed shape `SealedStore::ephemeral` uses for the same case.
struct NoEntropySealer;

impl Sealer for NoEntropySealer {
    fn seal(&self, _plain: &[u8], _context: &SealContext) -> Result<Vec<u8>, SealError> {
        Err(SealError::NoEntropy)
    }

    fn unseal(&self, _blob: &[u8], _context: &SealContext) -> Result<Sealed<Vec<u8>>, SealError> {
        Err(SealError::NoEntropy)
    }

    fn id(&self) -> SealerId {
        SealerId::new("unavailable", nmcp_secrets::SECRET_ENTROPY, "no-entropy")
    }
}

/// Why a grant store operation did not happen.
///
/// No variant carries material or any value derived from material, including a length or a
/// digest (SB-1). Paths describe containers; provider ids are policy text.
#[derive(Debug, thiserror::Error)]
pub enum GrantStoreError {
    /// The store directory or document is missing a required property of its container:
    /// unreadable, uncreatable, or, on Unix, readable by somebody other than its owner.
    #[error("grant store refused: {0}")]
    Storage(#[from] nmcp_secrets::PermsError),

    /// The document could not be read or replaced.
    #[error("grant store {path} could not be read or written: {reason}")]
    Io {
        /// The file involved.
        path: String,
        /// The operating system's description, which describes the file rather than its
        /// contents.
        reason: String,
    },

    /// The document does not parse as a grants document. It is refused, not overwritten.
    #[error("grant store {path} does not parse as a grants document; move it aside to start empty")]
    Unreadable {
        /// The file involved.
        path: String,
    },

    /// The document declares a schema this build does not know. Written by a newer build;
    /// guessing at fields you do not know is how a migration corrupts a store.
    #[error("grant store {path} declares schema {found} and this build knows schema {known}")]
    UnknownSchema {
        /// The file involved.
        path: String,
        /// The schema the document declares.
        found: u32,
        /// The schema this build writes.
        known: u32,
    },

    /// The grant could not be encoded for sealing.
    #[error("grant for provider '{provider}' could not be encoded")]
    NotEncodable {
        /// The provider whose grant was being written.
        provider: String,
    },

    /// The sealer refused.
    #[error("grant for provider '{provider}' could not be sealed: {source}")]
    Seal {
        /// The provider whose grant was being written.
        provider: String,
        /// What the sealer said.
        source: SealError,
    },

    /// The entry's write counter is exhausted.
    #[error("provider '{provider}' has exhausted its grant write counter; revoke and re-add it")]
    CounterExhausted {
        /// The provider whose entry can no longer advance.
        provider: String,
    },
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

    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use nmcp_secrets::{FileSealer, SealContext, Sealed, SealedStore, Sealer, SecretName, Version};

    use super::{GRANTS_FILE, GrantStore, GrantStoreError};
    use crate::grant::{Grant, grant_secret_name};

    /// Distinctive material with no English substring, so byte-window assertions cannot
    /// collide with legitimate prose.
    const ACCESS: &str = "qz84vw-a11xr-t63np-k97dh";
    const REFRESH: &str = "mv27jk-b55um-c40sw-e81yl";

    /// Distinguishes directories within one process; the process id distinguishes runs.
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A directory under the system temporary root that removes itself on drop.
    ///
    /// Test-only by construction: this module is `#[cfg(test)]`, so the removal in `Drop` is
    /// compiled out of the release binary and sits outside INV-1's scope, following the
    /// pattern every crate in this workspace with filesystem tests uses.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "nmcp-oauth-{label}-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("test temp dir is creatable");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn grant() -> Grant {
        Grant {
            access_token: ACCESS.into(),
            refresh_token: Some(REFRESH.into()),
            expires_at_unix: Some(4_000_000_000),
            scope: Some("read write".into()),
            token_type: "Bearer".into(),
        }
    }

    fn open(dir: &TempDir) -> GrantStore {
        let sealer = FileSealer::open(&dir.path().join("grants-sealer")).expect("sealer opens");
        GrantStore::open(&dir.path().join("grants"), Box::new(sealer)).expect("store opens")
    }

    /// Every byte of every file under `dir`, concatenated, for windowed-absence assertions.
    fn all_bytes_under(dir: &Path) -> Vec<u8> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(next) = stack.pop() {
            for entry in std::fs::read_dir(&next).expect("dir reads") {
                let path = entry.expect("entry reads").path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.extend(std::fs::read(&path).expect("file reads"));
                }
            }
        }
        out
    }

    fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn a_grant_round_trips_and_survives_a_reopen() {
        let dir = TempDir::new("roundtrip");
        let store = open(&dir);
        store.store("acme", &grant()).expect("store");
        assert_eq!(store.load("acme").expect("loads"), grant());
        // A second handle and a reopened store both see it: persistence, not cache.
        drop(store);
        let reopened = open(&dir);
        assert_eq!(reopened.load("acme").expect("loads"), grant());
        assert_eq!(reopened.load("other"), None);
    }

    #[test]
    fn material_never_touches_the_directory_in_the_clear() {
        // SB-1's measurement discipline over the carve-out store: the tokens are on disk
        // only as ciphertext, from the first write.
        let dir = TempDir::new("sealed-at-rest");
        let store = open(&dir);
        store.store("acme", &grant()).expect("store");
        let bytes = all_bytes_under(dir.path());
        assert!(!contains_window(&bytes, ACCESS.as_bytes()));
        assert!(!contains_window(&bytes, REFRESH.as_bytes()));
    }

    #[test]
    fn revocation_leaves_no_material_recoverable_from_the_directory() {
        // The carve-out's destruction property (SB-10), measured three ways: the old
        // ciphertext is gone from the document, no byte window of either token exists
        // anywhere under the directory, and what the tombstone holds unseals to empty even
        // for the holder of the sealer key.
        let dir = TempDir::new("revoke");
        let store = open(&dir);
        store.store("acme", &grant()).expect("store");
        let document_path = dir.path().join("grants").join(GRANTS_FILE);
        let before: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&document_path).expect("read")).expect("parse");
        let old_blob = before["entries"]["acme"]["blob_hex"]
            .as_str()
            .expect("blob")
            .to_string();

        assert!(store.revoke("acme").expect("revoke"));
        assert_eq!(store.load("acme"), None, "a revoked grant does not load");

        let bytes = all_bytes_under(dir.path());
        assert!(
            !contains_window(&bytes, old_blob.as_bytes()),
            "the old ciphertext must be gone, not merely disowned"
        );
        assert!(!contains_window(&bytes, ACCESS.as_bytes()));
        assert!(!contains_window(&bytes, REFRESH.as_bytes()));

        // The strongest form: with the sealer key in hand, the entry gives back nothing.
        let after: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&document_path).expect("read")).expect("parse");
        let entry = &after["entries"]["acme"];
        assert_eq!(entry["state"], "revoked", "the tombstone remains");
        let blob = hex::decode(entry["blob_hex"].as_str().expect("blob")).expect("hex");
        let version = Version::from_number(
            u32::try_from(entry["version"].as_u64().expect("version")).expect("fits"),
        )
        .expect("version");
        let sealer = FileSealer::open(&dir.path().join("grants-sealer")).expect("sealer");
        let plain = sealer
            .unseal(&blob, &SealContext::new(grant_secret_name("acme"), version))
            .expect("the tombstone blob authenticates");
        assert_eq!(plain.with_exposed(Vec::len), 0, "the sealed value is empty");

        // And the file itself was never deleted: the tombstone is the record.
        assert!(document_path.exists());
    }

    #[test]
    fn revoking_what_is_absent_or_already_revoked_reports_no_grant() {
        let dir = TempDir::new("revoke-absent");
        let store = open(&dir);
        assert!(!store.revoke("acme").expect("revoke absent"));
        store.store("acme", &grant()).expect("store");
        assert!(store.revoke("acme").expect("revoke"));
        assert!(!store.revoke("acme").expect("second revoke"));
    }

    #[test]
    fn a_reauthorization_after_revocation_advances_the_counter_and_works() {
        let dir = TempDir::new("regrant");
        let store = open(&dir);
        store.store("acme", &grant()).expect("first");
        store.revoke("acme").expect("revoke");
        let second = Grant {
            access_token: "second-access".into(),
            ..grant()
        };
        store.store("acme", &second).expect("second");
        assert_eq!(store.load("acme").expect("loads"), second);
        let document: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("grants").join(GRANTS_FILE)).expect("read"),
        )
        .expect("parse");
        assert_eq!(
            document["entries"]["acme"]["version"], 3,
            "grant, tombstone, grant: three writes, three counters"
        );
    }

    #[test]
    fn a_blob_moved_between_providers_does_not_open() {
        // The binding at work in this store's own layout: an edit that copies one
        // provider's ciphertext onto another provider's entry reads back as absent, not as
        // the other provider's grant.
        let dir = TempDir::new("swap");
        let store = open(&dir);
        store.store("acme", &grant()).expect("acme");
        store.store("umbrella", &grant()).expect("umbrella");
        let path = dir.path().join("grants").join(GRANTS_FILE);
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
        let acme_blob = document["entries"]["acme"]["blob_hex"].clone();
        document["entries"]["umbrella"]["blob_hex"] = acme_blob;
        std::fs::write(&path, serde_json::to_vec(&document).expect("encode")).expect("write");
        drop(store);
        let reopened = open(&dir);
        assert_eq!(reopened.load("umbrella"), None);
        assert!(reopened.load("acme").is_some());
    }

    #[test]
    fn the_operator_store_and_the_grant_store_share_nothing() {
        // The invisibility assertion made from the oauth side, against the deployment
        // layout the two stores would actually share: sibling directories under one root.
        // The operator's list never reports a grant because there is nothing to filter;
        // the grant lives in a different store entirely, and the operator store's own name
        // type could not represent it anyway.
        let dir = TempDir::new("two-stores");
        let operator_sealer = FileSealer::open(&dir.path().join("secrets-sealer")).expect("sealer");
        let operator = SealedStore::open(&dir.path().join("secrets"), Box::new(operator_sealer))
            .expect("operator store");
        let grants = open(&dir);

        let name = SecretName::parse("api.token").expect("name");
        operator
            .set(&name, Sealed::new(b"operator-held-value".to_vec()))
            .expect("set");
        grants.store("acme", &grant()).expect("grant");

        let names = operator.names();
        assert_eq!(names.len(), 1, "one operator secret, no grants");
        assert_eq!(names[0].name.as_str(), "api.token");
        assert!(operator.unreadable().is_empty(), "nothing to set aside");

        // The reserved name is unrepresentable on the operator surface, so there is no
        // call that could ever have listed it.
        assert!(SecretName::parse(&grant_secret_name("acme")).is_err());

        // And the layouts are disjoint: nothing of the grant store sits under the operator
        // store's directory or vice versa.
        assert!(!dir.path().join("secrets").join(GRANTS_FILE).exists());
        assert!(!dir.path().join("grants").join("secrets").exists());
    }

    #[test]
    fn a_document_that_does_not_parse_refuses_the_open() {
        let dir = TempDir::new("damaged");
        let store = open(&dir);
        store.store("acme", &grant()).expect("store");
        drop(store);
        let path = dir.path().join("grants").join(GRANTS_FILE);
        std::fs::write(&path, b"{ not a grants document").expect("damage");
        let sealer = FileSealer::open(&dir.path().join("grants-sealer")).expect("sealer");
        match GrantStore::open(&dir.path().join("grants"), Box::new(sealer)) {
            Err(GrantStoreError::Unreadable { path: reported }) => {
                assert!(reported.ends_with(GRANTS_FILE));
            }
            other => panic!("a damaged document must refuse the open, got {other:?}"),
        }
        // Refused, not repaired: the damaged bytes are still there for the operator.
        assert!(std::fs::read(&path).expect("read").starts_with(b"{ not"));
    }

    #[test]
    fn a_newer_schema_refuses_the_open_rather_than_guessing() {
        let dir = TempDir::new("newer");
        let store = open(&dir);
        store.store("acme", &grant()).expect("store");
        drop(store);
        let path = dir.path().join("grants").join(GRANTS_FILE);
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
        document["schema"] = serde_json::json!(99);
        std::fs::write(&path, serde_json::to_vec(&document).expect("encode")).expect("write");
        let sealer = FileSealer::open(&dir.path().join("grants-sealer")).expect("sealer");
        assert!(matches!(
            GrantStore::open(&dir.path().join("grants"), Box::new(sealer)),
            Err(GrantStoreError::UnknownSchema {
                found: 99,
                known: 1,
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn an_exposed_directory_or_document_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("exposed");
        let store = open(&dir);
        store.store("acme", &grant()).expect("store");
        drop(store);
        let grants_dir = dir.path().join("grants");
        std::fs::set_permissions(&grants_dir, std::fs::Permissions::from_mode(0o755))
            .expect("widen");
        let sealer = FileSealer::open(&dir.path().join("grants-sealer")).expect("sealer");
        assert!(matches!(
            GrantStore::open(&grants_dir, Box::new(sealer)),
            Err(GrantStoreError::Storage(_))
        ));
        std::fs::set_permissions(&grants_dir, std::fs::Permissions::from_mode(0o700))
            .expect("restore");
        std::fs::set_permissions(
            grants_dir.join(GRANTS_FILE),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("widen file");
        let sealer = FileSealer::open(&dir.path().join("grants-sealer")).expect("sealer");
        assert!(matches!(
            GrantStore::open(&grants_dir, Box::new(sealer)),
            Err(GrantStoreError::Storage(_))
        ));
    }

    #[test]
    fn an_ephemeral_store_seals_and_forgets_on_drop() {
        let store = GrantStore::ephemeral();
        store.store("acme", &grant()).expect("store");
        assert_eq!(store.load("acme").expect("loads"), grant());
        assert!(store.revoke("acme").expect("revoke"));
        assert_eq!(store.load("acme"), None);
        // A second ephemeral store shares nothing with the first.
        assert_eq!(GrantStore::ephemeral().load("acme"), None);
    }

    #[test]
    fn errors_render_without_material() {
        let dir = TempDir::new("errors");
        let store = open(&dir);
        store.store("acme", &grant()).expect("store");
        let rendered = format!("{store:?}");
        assert!(!rendered.contains(ACCESS) && !rendered.contains("acme"));
        let err = GrantStoreError::CounterExhausted {
            provider: "acme".into(),
        };
        assert!(err.to_string().contains("acme"));
        assert!(!err.to_string().contains(ACCESS));
    }
}
