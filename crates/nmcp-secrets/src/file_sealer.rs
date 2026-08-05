//! The core file sealer, and the honest statement of what it protects against.
//!
//! NMCP-SPEC-002 SB-11 and SB-A7, RATIFIED v1.0.
//!
//! # What this sealer guarantees, said plainly
//!
//! **Against another local user, its guarantee is filesystem permissions and nothing more.**
//! The key sits in a file on the same machine as the store it seals. Anyone who can read that
//! file can read every secret in the store. There is no passphrase, no hardware, and no
//! operating system keyring involved, and the encryption buys nothing against an attacker who
//! has the key file.
//!
//! That is a decision rather than an oversight, and SB-11 made it deliberately. The two
//! available answers for a headless daemon have opposite properties: an operator-supplied
//! passphrase means the service cannot start unattended, which is the deployment model this
//! project has; a key file beside the store means the cryptography is a costume over the file
//! permissions. The second was chosen, and section 7's G-6 repeats it so a reader scanning gaps
//! finds it. What the encryption does buy is real but narrow: a store file copied off the
//! machine on its own, a backup that captured the store directory and not the key directory,
//! and an edit to the store file, are all defeated. A local attacker with read access to the
//! key file is not.
//!
//! **A deployment that needs more uses a platform sealer.** That is why DPAPI, Keychain and
//! secret-service exist and why the platform repositories ship them at W3 and W4. This crate
//! ships a real implementation rather than a mock so that headless Linux and CI have a complete
//! one (SB-A7, INV-6).
//!
//! # Where the restriction is applied, and where it is not
//!
//! On Unix the sealer creates its key directory at `0700` and its key file at `0600`, and it
//! **verifies both on every open**, refusing rather than repairing. A key file the filesystem
//! is not protecting is a sealer with no guarantee at all, and silently tightening the mode
//! would hide the window during which it was open.
//!
//! On other platforms this sealer applies no restriction of its own and the key file inherits
//! whatever the parent directory grants. That is stated rather than papered over, and it is
//! queryable: [`FileSealer::key_protection`] returns [`KeyProtection::PlatformDefault`] there,
//! so a caller can tell the difference between a restriction that was applied and one that was
//! not. A Windows deployment uses the DPAPI sealer, which is what the machine-scope DACL the
//! base already writes is for.

use std::fs;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::perms::{
    RESTRICTED_DIR_MODE, RESTRICTED_FILE_MODE, create_restricted_dir, verify_restricted,
    write_restricted,
};
use crate::sealed::Sealed;
use crate::sealer::{SECRET_ENTROPY, SealContext, SealError, Sealer, SealerId};

/// The file the sealer's key lives in, inside the key directory.
pub const KEY_FILE: &str = "sealer-key.json";

/// The mode a key file must have on Unix, and the mode this sealer creates one with.
pub const KEY_FILE_MODE: u32 = RESTRICTED_FILE_MODE;

/// The mode a key directory must have on Unix, and the mode this sealer creates one with.
pub const KEY_DIR_MODE: u32 = RESTRICTED_DIR_MODE;

/// The key length, in bytes. Fixed by the cipher.
const KEY_BYTES: usize = 32;

/// The nonce length, in bytes. Fixed by the cipher.
const NONCE_BYTES: usize = 12;

/// The schema version of the key file, so a later format is recognised rather than misread.
const KEY_FILE_SCHEMA: u32 = 1;

/// Whether the sealer applied a restriction to its key file, or inherited one.
///
/// Exists so the answer is a value a caller can read rather than a sentence in documentation
/// a caller does not read. The whole of this sealer's guarantee is the filesystem's, so whether
/// the filesystem was actually asked to provide it is the single most important fact about a
/// running deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProtection {
    /// The sealer created and verified the key file at this mode.
    UnixMode {
        /// The mode required of the key file.
        file: u32,
        /// The mode required of the key directory.
        directory: u32,
    },
    /// The sealer applied no restriction; the key file inherits the parent's access control.
    ///
    /// A deployment on such a platform should use the platform sealer its own repository ships.
    PlatformDefault,
}

/// The key file's contents.
///
/// The key identifier is generated beside the key and derived from nothing. A digest of the key
/// would be simpler and is refused for the reason [`SealerId`] gives: it travels into a
/// migration report an operator reads and into blob headers an attacker may read, and a
/// distinguisher for the key is not a thing to hand over for free.
#[derive(Serialize, Deserialize)]
struct KeyFile {
    schema: u32,
    key_id: String,
    key_hex: String,
}

impl Drop for KeyFile {
    /// `key_hex` is the key in another spelling, so this struct is an intermediate buffer in
    /// SB-11's sense and is zeroed before release, exactly as T12 requires of every sealer's
    /// own copies. The identifier and the schema number are not material and are left alone.
    fn drop(&mut self) {
        self.key_hex.zeroize();
    }
}

/// A sealer whose key is a file on the same machine as the store.
///
/// Read the module documentation before deploying this. Its guarantee against a local attacker
/// is filesystem permissions and nothing more.
pub struct FileSealer {
    key: SealingKey,
    id: SealerId,
    protection: KeyProtection,
}

impl std::fmt::Debug for FileSealer {
    /// Hand-written: the identifier and the protection, never the key. There is no derived
    /// `Debug` to get wrong, because the key field's type does not implement it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSealer")
            .field("id", &self.id)
            .field("protection", &self.protection)
            .finish_non_exhaustive()
    }
}

/// The key material, wrapped so that dropping the sealer erases it.
///
/// A separate type rather than a `Sealed<Vec<u8>>` field because the cipher wants a fixed-size
/// key and because the sealer needs to build a cipher from it on every call, which is a read
/// path and would otherwise be a `with_exposed` around the whole of `seal` and `unseal`. It
/// zeroizes on drop for the same reason `Sealed` does.
struct SealingKey([u8; KEY_BYTES]);

impl Drop for SealingKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl FileSealer {
    /// Open the sealer whose key lives in `key_dir`, creating the key on first use.
    ///
    /// `key_dir` must not be the store directory. SB-11 puts the key in a separate directory so
    /// that a backup, an archive or a copy that captured one does not necessarily capture the
    /// other, which is the one attacker this design does defeat.
    ///
    /// # Errors
    ///
    /// [`SealError`] when the directory cannot be created, the key file cannot be read or
    /// written, the key file is malformed, or the key file or its directory is readable by
    /// somebody other than its owner.
    pub fn open(key_dir: &Path) -> Result<Self, SealError> {
        Self::open_with_purpose(key_dir, SECRET_ENTROPY)
    }

    /// Open the sealer under a caller-supplied entropy label.
    ///
    /// SB-12's migration path. A blob sealed by an earlier generation is bound to that
    /// generation's label, so unsealing it needs a sealer holding that label, and the label
    /// arrives as a parameter rather than as a constant compiled into this repository: INV-8
    /// forbids the retired product name a previous generation's label contains, so naming it
    /// here would fail the brand gate. The operator running
    /// [`SealedStore::migrate`](crate::SealedStore::migrate) supplies the old value.
    ///
    /// # Errors
    ///
    /// As [`FileSealer::open`].
    pub fn open_with_purpose(key_dir: &Path, purpose: &str) -> Result<Self, SealError> {
        create_restricted_dir(key_dir)?;
        let path = key_dir.join(KEY_FILE);
        let file = match fs::read_to_string(&path) {
            // The raw text holds the key in hex, so it is erased when this arm ends rather
            // than left for the allocator (SB-11, T12).
            Ok(text) => parse_key_file(&Zeroizing::new(text), &path)?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => create_key_file(&path)?,
            Err(err) => {
                return Err(SealError::KeyFileUnreadable {
                    path: path.display().to_string(),
                    reason: err.kind().to_string(),
                });
            }
        };
        // The mode is verified after the file is known to exist and on every open, not only on
        // the run that created it. A key file whose mode was widened between two boots is
        // exactly the case worth catching, and it is the only case a create-time check misses.
        verify_restricted(&path, KEY_FILE_MODE)?;
        verify_restricted(key_dir, KEY_DIR_MODE)?;
        let mut raw = hex::decode(&file.key_hex).map_err(|_| SealError::KeyFileMalformed {
            path: path.display().to_string(),
        })?;
        let key =
            <[u8; KEY_BYTES]>::try_from(raw.as_slice()).map_err(|_| SealError::KeyFileMalformed {
                path: path.display().to_string(),
            });
        // The decoded buffer is zeroed whether or not it was the right length, before the
        // error leaves this function. SB-11 puts this obligation on every sealer and T12
        // records the base's DPAPI unseal releasing a plaintext buffer without it.
        raw.zeroize();
        Ok(Self {
            key: SealingKey(key?),
            id: SealerId::new("file", purpose, &file.key_id),
            protection: key_protection(),
        })
    }

    /// Whether this sealer applied a restriction to its key file, or inherited one.
    #[must_use]
    pub const fn key_protection(&self) -> KeyProtection {
        self.protection
    }
}

/// A sealer whose key is generated at construction and never written anywhere.
///
/// What [`SealedStore::ephemeral`](crate::SealedStore::ephemeral) uses, since that constructor
/// is frozen at no parameters and so cannot be handed one.
///
/// Its cryptographic guarantee is nil and saying otherwise would be dishonest: the key and the
/// blobs it seals are in the same process memory, so anything that can read one can read the
/// other. It exists so that an ephemeral store is the same code path as a persistent one. A
/// store that held plaintext when it had no directory would be a store whose test coverage ran
/// past the sealing path, and the sealing path is the one worth covering.
pub struct MemorySealer {
    key: SealingKey,
    id: SealerId,
}

impl std::fmt::Debug for MemorySealer {
    /// Hand-written for the reason [`FileSealer`]'s is.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemorySealer")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl MemorySealer {
    /// Generate a key and an identifier for this process.
    ///
    /// # Errors
    ///
    /// [`SealError::NoEntropy`] when the system random source is unavailable. Fails closed
    /// rather than falling back: a sealer whose key an attacker can predict is worse than one
    /// that does not start.
    pub fn new() -> Result<Self, SealError> {
        let mut key = [0_u8; KEY_BYTES];
        fill_random(&mut key)?;
        let mut id_bytes = [0_u8; 8];
        fill_random(&mut id_bytes)?;
        Ok(Self {
            key: SealingKey(key),
            id: SealerId::new("memory", SECRET_ENTROPY, hex::encode(id_bytes)),
        })
    }
}

impl Sealer for FileSealer {
    fn seal(&self, plain: &[u8], context: &SealContext) -> Result<Vec<u8>, SealError> {
        seal_with(&self.key, plain, context)
    }

    fn unseal(&self, blob: &[u8], context: &SealContext) -> Result<Sealed<Vec<u8>>, SealError> {
        unseal_with(&self.key, blob, context)
    }

    fn id(&self) -> SealerId {
        self.id.clone()
    }
}

impl Sealer for MemorySealer {
    fn seal(&self, plain: &[u8], context: &SealContext) -> Result<Vec<u8>, SealError> {
        seal_with(&self.key, plain, context)
    }

    fn unseal(&self, blob: &[u8], context: &SealContext) -> Result<Sealed<Vec<u8>>, SealError> {
        unseal_with(&self.key, blob, context)
    }

    fn id(&self) -> SealerId {
        self.id.clone()
    }
}

/// Seal `plain` under `key`, bound to `context`.
///
/// The blob is the nonce followed by the ciphertext and its tag. The nonce is fresh from the
/// system generator on every call, including a reseal of the same value, because a repeated
/// nonce under one key is the failure mode this cipher has no defence against.
///
/// The context travels as associated data rather than being stored beside the blob, so a blob
/// moved into another key's slot or another version's slot does not authenticate. The store is
/// a file an attacker may be able to write, and without that binding an edit could roll a
/// rotated key back to a superseded value or copy one key's value onto another key's name.
fn seal_with(key: &SealingKey, plain: &[u8], context: &SealContext) -> Result<Vec<u8>, SealError> {
    let cipher = ChaCha20Poly1305::new(&Key::from(key.0));
    let mut nonce = [0_u8; NONCE_BYTES];
    fill_random(&mut nonce)?;
    let sealed = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plain,
                aad: &context.associated_data(),
            },
        )
        .map_err(|_| SealError::NotSealable)?;
    let mut blob = Vec::with_capacity(NONCE_BYTES + sealed.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// Unseal `blob` under `key`, bound to `context`.
fn unseal_with(
    key: &SealingKey,
    blob: &[u8],
    context: &SealContext,
) -> Result<Sealed<Vec<u8>>, SealError> {
    let (nonce, body) = blob
        .split_at_checked(NONCE_BYTES)
        .ok_or(SealError::Unsealable)?;
    let nonce = <[u8; NONCE_BYTES]>::try_from(nonce).map_err(|_| SealError::Unsealable)?;
    let cipher = ChaCha20Poly1305::new(&Key::from(key.0));
    let plain = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: body,
                aad: &context.associated_data(),
            },
        )
        .map_err(|_| SealError::Unsealable)?;
    // The cipher's output buffer is the only intermediate copy, and it is moved into `Sealed`
    // rather than copied out of, so there is no second allocation to zero. SB-11's obligation
    // is met by not making the copy in the first place.
    Ok(Sealed::new(plain))
}

/// Fill `buffer` from the system random source.
fn fill_random(buffer: &mut [u8]) -> Result<(), SealError> {
    getrandom::fill(buffer).map_err(|_| SealError::NoEntropy)
}

/// Read a key file, refusing one this sealer did not write.
fn parse_key_file(text: &str, path: &Path) -> Result<KeyFile, SealError> {
    let file: KeyFile = serde_json::from_str(text).map_err(|_| SealError::KeyFileMalformed {
        path: path.display().to_string(),
    })?;
    if file.schema != KEY_FILE_SCHEMA {
        return Err(SealError::KeyFileMalformed {
            path: path.display().to_string(),
        });
    }
    Ok(file)
}

/// Generate a key file at `path`, restricted before anything is written into it.
fn create_key_file(path: &Path) -> Result<KeyFile, SealError> {
    let mut key = [0_u8; KEY_BYTES];
    fill_random(&mut key)?;
    let mut id_bytes = [0_u8; 8];
    fill_random(&mut id_bytes)?;
    let file = KeyFile {
        schema: KEY_FILE_SCHEMA,
        key_id: hex::encode(id_bytes),
        key_hex: hex::encode(key),
    };
    key.zeroize();
    let mut body = serde_json::to_string(&file).map_err(|_| SealError::KeyFileNotCreated {
        path: path.display().to_string(),
        reason: "the key file could not be encoded".to_string(),
    })?;
    let written = write_restricted(path, body.as_bytes(), KEY_FILE_MODE);
    // The encoded document holds the key, so it is erased whether or not the write succeeded.
    body.zeroize();
    written?;
    Ok(file)
}

/// What this build applies to its key file.
#[cfg(unix)]
const fn key_protection() -> KeyProtection {
    KeyProtection::UnixMode {
        file: KEY_FILE_MODE,
        directory: KEY_DIR_MODE,
    }
}

/// What this build applies to its key file.
#[cfg(not(unix))]
const fn key_protection() -> KeyProtection {
    KeyProtection::PlatformDefault
}

/// The default key directory beside a store directory.
///
/// SB-11 requires the key to live in a directory of its own. This picks the sibling rather than
/// a child, so a backup of the store directory does not carry the key with it, and a caller
/// that wants them further apart passes its own path to [`FileSealer::open`].
#[must_use]
pub fn default_key_dir(store_dir: &Path) -> PathBuf {
    let mut name = store_dir.file_name().map_or_else(
        || "nmcp".to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    name.push_str("-sealer");
    store_dir.parent().unwrap_or(Path::new(".")).join(name)
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
    use super::{
        FileSealer, KEY_FILE, KeyProtection, MemorySealer, SealContext, SealError, Sealer,
        default_key_dir,
    };
    use crate::Version;
    use crate::testdir::TempDir;

    fn context() -> SealContext {
        SealContext::new("github.token", Version::first())
    }

    /// The single most important fact about a running deployment (the module doc's words) is
    /// asserted on every platform this crate builds for, in the platform's own terms: a Unix
    /// build applied and verified the modes, and any other build applied nothing and says so
    /// rather than claiming a restriction it never made. This is also what keeps
    /// [`KeyProtection`] exercised by the test build on every platform, so a platform where
    /// the mode checks compile away cannot quietly lose the reporting seam too.
    #[test]
    fn key_protection_reports_what_this_build_applies() {
        let dir = TempDir::new("sealer-protection");
        let sealer = FileSealer::open(dir.path()).unwrap();
        #[cfg(unix)]
        assert_eq!(
            sealer.key_protection(),
            KeyProtection::UnixMode {
                file: super::KEY_FILE_MODE,
                directory: super::KEY_DIR_MODE,
            }
        );
        #[cfg(not(unix))]
        assert_eq!(sealer.key_protection(), KeyProtection::PlatformDefault);
    }

    #[test]
    fn a_sealed_value_round_trips() {
        let dir = TempDir::new("sealer-roundtrip");
        let sealer = FileSealer::open(dir.path()).unwrap();
        let blob = sealer.seal(b"ghp_not-a-real-token", &context()).unwrap();
        assert!(
            !blob.windows(4).any(|w| w == b"ghp_"),
            "the blob is not the plaintext"
        );
        let plain = sealer.unseal(&blob, &context()).unwrap();
        assert_eq!(
            plain.with_exposed(Vec::clone),
            b"ghp_not-a-real-token".to_vec()
        );
    }

    #[test]
    fn two_seals_of_one_value_differ() {
        // A repeated nonce under one key is the failure this cipher has no defence against, so
        // the fresh nonce is asserted rather than assumed from the code.
        let dir = TempDir::new("sealer-nonce");
        let sealer = FileSealer::open(dir.path()).unwrap();
        let first = sealer.seal(b"same value", &context()).unwrap();
        let second = sealer.seal(b"same value", &context()).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn a_blob_does_not_open_in_another_slot() {
        // The property that makes an edit to the store file detectable: a value copied onto
        // another name, or rolled back onto another version, does not authenticate.
        let dir = TempDir::new("sealer-binding");
        let sealer = FileSealer::open(dir.path()).unwrap();
        let blob = sealer.seal(b"value for one slot", &context()).unwrap();
        let other_name = SealContext::new("gitlab.token", Version::first());
        assert!(matches!(
            sealer.unseal(&blob, &other_name),
            Err(SealError::Unsealable)
        ));
        let other_version = SealContext::new("github.token", Version::first().next());
        assert!(matches!(
            sealer.unseal(&blob, &other_version),
            Err(SealError::Unsealable)
        ));
        let other_purpose =
            SealContext::with_purpose("some.other.v9", "github.token", Version::first());
        assert!(matches!(
            sealer.unseal(&blob, &other_purpose),
            Err(SealError::Unsealable)
        ));
    }

    #[test]
    fn a_blob_does_not_open_under_another_key() {
        // The one attacker this design does defeat: a store copied without its key directory.
        let here = TempDir::new("sealer-key-a");
        let there = TempDir::new("sealer-key-b");
        let mine = FileSealer::open(here.path()).unwrap();
        let theirs = FileSealer::open(there.path()).unwrap();
        assert_ne!(mine.id(), theirs.id(), "two deployments, two identifiers");
        let blob = mine.seal(b"value", &context()).unwrap();
        assert!(matches!(
            theirs.unseal(&blob, &context()),
            Err(SealError::Unsealable)
        ));
    }

    #[test]
    fn a_corrupted_blob_is_refused_rather_than_returned() {
        let dir = TempDir::new("sealer-corrupt");
        let sealer = FileSealer::open(dir.path()).unwrap();
        let mut blob = sealer.seal(b"value", &context()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(
            sealer.unseal(&blob, &context()),
            Err(SealError::Unsealable)
        ));
        // And a blob too short to carry a nonce is refused rather than indexed into.
        assert!(matches!(
            sealer.unseal(&[0_u8; 4], &context()),
            Err(SealError::Unsealable)
        ));
        assert!(matches!(
            sealer.unseal(&[], &context()),
            Err(SealError::Unsealable)
        ));
    }

    #[test]
    fn the_identifier_is_stable_across_opens_and_moves_with_the_purpose() {
        let dir = TempDir::new("sealer-id");
        let first = FileSealer::open(dir.path()).unwrap().id();
        let second = FileSealer::open(dir.path()).unwrap().id();
        assert_eq!(first, second, "the same key file is the same deployment");
        let legacy = FileSealer::open_with_purpose(dir.path(), "Example.secrets.v1")
            .unwrap()
            .id();
        assert_ne!(first, legacy, "a generation bump is a different sealer");
        assert!(first.as_str().starts_with("file/NativeMCP.secrets.v2/"));
    }

    #[test]
    fn an_earlier_generation_reads_only_what_it_sealed() {
        // SB-12's migration shape, without naming any retired constant: the old label is a
        // parameter, and blobs sealed under it do not open under the current one.
        let dir = TempDir::new("sealer-generation");
        let legacy = FileSealer::open_with_purpose(dir.path(), "Example.secrets.v1").unwrap();
        let current = FileSealer::open(dir.path()).unwrap();
        let legacy_context =
            SealContext::with_purpose("Example.secrets.v1", "github.token", Version::first());
        let blob = legacy.seal(b"old value", &legacy_context).unwrap();
        assert!(matches!(
            current.unseal(&blob, &context()),
            Err(SealError::Unsealable)
        ));
        assert_eq!(
            legacy
                .unseal(&blob, &legacy_context)
                .unwrap()
                .with_exposed(Vec::clone),
            b"old value".to_vec()
        );
    }

    #[test]
    fn a_malformed_key_file_is_refused_rather_than_replaced() {
        let dir = TempDir::new("sealer-malformed");
        std::fs::write(dir.path().join(KEY_FILE), "{\"schema\":99}").unwrap();
        crate::perms::set_mode(&dir.path().join(KEY_FILE), super::KEY_FILE_MODE).unwrap();
        assert!(matches!(
            FileSealer::open(dir.path()),
            Err(SealError::KeyFileMalformed { .. })
        ));
        // The refusal is the point: overwriting it would destroy the key every existing blob
        // in the store was sealed under.
        assert!(dir.path().join(KEY_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn an_exposed_key_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("sealer-exposed");
        let sealer = FileSealer::open(dir.path()).unwrap();
        assert_eq!(
            sealer.key_protection(),
            KeyProtection::UnixMode {
                file: super::KEY_FILE_MODE,
                directory: super::KEY_DIR_MODE,
            }
        );
        let key_path = dir.path().join(KEY_FILE);
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        match FileSealer::open(dir.path()) {
            Err(SealError::KeyFileExposed { mode, required, .. }) => {
                assert_eq!(mode, 0o644);
                assert_eq!(required, super::KEY_FILE_MODE);
            }
            other => panic!("a world-readable key file must be refused, got {other:?}"),
        }
        // A tighter mode is accepted: this sealer needs to read the key, not to write it.
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(FileSealer::open(dir.path()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn an_exposed_key_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("sealer-exposed-dir");
        FileSealer::open(dir.path()).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            FileSealer::open(dir.path()),
            Err(SealError::KeyFileExposed { .. })
        ));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_created_key_file_is_restricted_without_being_asked_twice() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("sealer-modes");
        FileSealer::open(dir.path()).unwrap();
        let file_mode = std::fs::metadata(dir.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, super::KEY_FILE_MODE);
        let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, super::KEY_DIR_MODE);
    }

    #[test]
    fn the_memory_sealer_is_a_real_sealer() {
        let sealer = MemorySealer::new().unwrap();
        let blob = sealer.seal(b"in-process value", &context()).unwrap();
        assert!(!blob.windows(2).any(|w| w == b"in"));
        assert_eq!(
            sealer
                .unseal(&blob, &context())
                .unwrap()
                .with_exposed(Vec::clone),
            b"in-process value".to_vec()
        );
        assert!(sealer.id().as_str().starts_with("memory/"));
        // Two of them are two keys, which is what makes an ephemeral store ephemeral.
        let other = MemorySealer::new().unwrap();
        assert_ne!(sealer.id(), other.id());
        assert!(matches!(
            other.unseal(&blob, &context()),
            Err(SealError::Unsealable)
        ));
    }

    #[test]
    fn the_default_key_directory_is_a_sibling_of_the_store() {
        let key_dir = default_key_dir(std::path::Path::new("/var/lib/nmcp/secrets"));
        assert_eq!(
            key_dir,
            std::path::PathBuf::from("/var/lib/nmcp/secrets-sealer")
        );
        assert!(
            !key_dir.starts_with("/var/lib/nmcp/secrets/"),
            "the key must not sit inside the directory a backup of the store would capture"
        );
    }

    #[test]
    fn an_empty_value_seals_and_a_large_one_does_too() {
        let dir = TempDir::new("sealer-sizes");
        let sealer = FileSealer::open(dir.path()).unwrap();
        for size in [0_usize, 1, 4096] {
            let plain = vec![0x5A_u8; size];
            let blob = sealer.seal(&plain, &context()).unwrap();
            assert_eq!(
                sealer
                    .unseal(&blob, &context())
                    .unwrap()
                    .with_exposed(Vec::len),
                size
            );
        }
    }
}
