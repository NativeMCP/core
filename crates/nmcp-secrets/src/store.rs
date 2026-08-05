//! The sealed store: per-secret blob files, versions, tombstones, and the operator write
//! surface.
//!
//! NMCP-SPEC-002 SB-10, SB-13 and SB-14, RATIFIED v1.0. The [`SealedStore`] surface quoted in
//! SB-14 is frozen at ratification and implemented as written; the methods beyond it are
//! additions, each named on its own documentation with what it is for.
//!
//! ## The files
//!
//! One JSON document **per secret**, under `secrets/` inside the store directory, plus an
//! optional `store.json` holding store-level configuration. Every document carries the schema
//! version (SB-10), and every sealed blob inside one records the [`SealerId`] that sealed it.
//!
//! From I-036 a document may also carry the key's binding block: the operator-written terms
//! of use, their own schema version, and the use budget's spend state (SB-6 at v1.1, which
//! rules that bindings are per-key store metadata and the crate that owns the store owns
//! their evaluation). [`SealedStore::bind`] writes it, [`SealedStore::evaluate`] consumes it
//! and mints the [`BindingGrant`] resolution costs; the model, the evaluation order and the
//! budget decisions live in [`crate::binding`]'s documentation. A document without the block
//! is every store written before bindings existed, and its keys refuse evaluation until
//! bound, which is deny by default rather than a compatibility break.
//!
//! Per-secret files are the isolation SB-10 asks for, taken literally: a document that will
//! not parse, or a blob that will not authenticate, takes out one key. The other keys load,
//! list and resolve, the damaged file is reported by [`SealedStore::unreadable`] rather than
//! silently skipped, and nothing will overwrite it: [`SealedStore::set`] refuses a name whose
//! file exists but could not be read, because writing over a damaged document is destroying
//! whatever it still holds, which is the one thing INV-1 forbids.
//!
//! The bound on isolation, stated so the claim is not larger than the mechanism: a document
//! that parses but declares a schema this build does not know fails the whole open. That is
//! not corruption, it is a store written by a newer build, and guessing at fields you do not
//! know is how a migration corrupts a store; the same rule `accepts_contract_version` applies
//! to a newer contract applies here.
//!
//! ## What is never deleted
//!
//! Nothing removes a secret. Quarantine writes a tombstone: every version's state moves to
//! [`KeyState::Quarantined`] in the secret's own document, the file stays, the blobs stay,
//! and [`SealedStore::restore`] reverses it. Rotation retains every prior version. Migration
//! writes new blobs **alongside** the old ones, so a store migrated to a new sealer still
//! opens under the old one. There is no removal operation anywhere in this crate, and writes
//! go through a fixed temporary name in the same directory followed by a rename, so a crash
//! mid-write leaves the previous document intact; the temporary name is fixed rather than
//! unique so a failed rename leaves one file that the next write overwrites, and no cleanup
//! path calling a destructive primitive needs to exist.
//!
//! ## Modes
//!
//! On Unix the store directory and `secrets/` are created at `0700`, documents at `0600`, and
//! all of them are verified on every open, refusing rather than repairing, exactly as the
//! sealer treats its key file (SB-11). On Windows this crate applies no restriction and files
//! inherit the parent's default ACLs; the crate documentation records why that is the spec's
//! position and not a gap: the Windows answer is the DPAPI sealer at W3.
//!
//! ## Time
//!
//! The rotation overlap window (SB-14) is measured against an injected clock, following the
//! same injected-lookup shape as `MirrorConfig::from_lookup` in `nmcp-audit`: the
//! zero-parameter constructors inject the system clock, and
//! [`SealedStore::open_with_clock`] and [`SealedStore::ephemeral_with_clock`] take the
//! lookup, so the window is testable at zero, within and after without a test ever sleeping.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::binding::{
    BINDING_SCHEMA_VERSION, BindingDenial, BindingRecord, BindingRequest, KeyBinding,
};
use crate::file_sealer::MemorySealer;
use crate::grant::{BindingGrant, BindingRuleId};
use crate::lifecycle::{IllegalTransition, KeyLifecycle, KeyState};
use crate::name::{SecretName, Version};
use crate::perms::{
    PermsError, RESTRICTED_DIR_MODE, RESTRICTED_FILE_MODE, create_restricted_dir,
    verify_restricted, write_restricted,
};
use crate::sealed::Sealed;
use crate::sealer::{SealContext, SealError, Sealer, SealerId};

/// The store-level configuration document, inside the store directory.
///
/// Holds the rotation overlap window. Written only when
/// [`SealedStore::set_overlap_window`] is called: an absent file means the defaults, so a
/// deployment that never chose a window follows a later default rather than a frozen copy of
/// an old one.
pub const STORE_CONFIG_FILE: &str = "store.json";

/// The directory per-secret documents live in, inside the store directory.
pub const SECRETS_DIR: &str = "secrets";

/// The store format's schema version (SB-10), carried in every document.
///
/// A document declaring a schema this build does not know refuses the open rather than being
/// guessed at.
pub const STORE_SCHEMA_VERSION: u32 = 1;

/// The default rotation overlap window, in seconds.
///
/// Operator decision 3 in NMCP-SPEC-002 section 8, and the reasoning matters more than the
/// value. Rotation is not revocation: a compromised value is quarantined, which is immediate
/// and has no window, and the overlap exists only for the benign case where an operator
/// rotates on schedule and should not cause a burst of failures in calls already in flight or
/// in durable jobs that resume. Five minutes drains any interactive call and most short jobs.
/// Zero is permitted and gives the hard cutover.
pub const DEFAULT_OVERLAP_WINDOW_SECS: u64 = 300;

/// The suffix a document is written under before being renamed into place.
const WRITE_EXTENSION: &str = "json.writing";

/// What [`SealedStore::names`] reports about one version of one secret.
///
/// A state, a version number and two timestamps. No value, no digest of one, and no length of
/// one (SB-R2): the way to keep that true of the agent-facing list I-034 builds is to keep it
/// true of the type the list is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMeta {
    /// The version.
    pub version: Version,
    /// Its lifecycle state.
    pub state: KeyState,
    /// When it was stored, in milliseconds since the Unix epoch.
    pub created_at_unix_ms: u64,
    /// When it was superseded by a rotation, if it has been; what the overlap window is
    /// measured from.
    pub superseded_at_unix_ms: Option<u64>,
}

/// What [`SealedStore::names`] reports about one secret.
///
/// Carries every version's state, not only the current one, so a caller writing SB-7's audit
/// records at I-034 can capture the prior state of a key before a write and the outcome after
/// it, which the write-before-effect ordering INV-3 requires it to be doing anyway. There is
/// no `SecretMeta` for a reserved-namespace entry, and that is the enforcement rather than a
/// filter: building one needs a [`SecretName`], whose parser refuses every reserved name, so
/// an `oauth/` entry has no representation here to be accidentally included (SB-R2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMeta {
    /// The secret's name.
    pub name: SecretName,
    /// The version a fresh resolution would use, if any version is in service.
    pub current_version: Option<Version>,
    /// The state of the current version, or of the highest version when none is in service,
    /// so a quarantined key reports that it is quarantined rather than reporting nothing.
    pub state: KeyState,
    /// When the secret was first stored, in milliseconds since the Unix epoch.
    pub created_at_unix_ms: u64,
    /// Every version, in ascending order, with its state.
    pub versions: Vec<VersionMeta>,
}

/// One file the store found and could not read, and why.
///
/// Reported by [`SealedStore::unreadable`]. Isolation without visibility is silent data loss:
/// a store that skipped a damaged document and said nothing would list one key fewer and let
/// nobody notice until the missing credential failed a call that pointed at the wrong thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableEntry {
    /// The file, as a displayable path.
    pub file: String,
    /// Why it could not be read.
    pub reason: UnreadableReason,
}

/// Why a file in the store's secrets directory was set aside rather than loaded.
///
/// A closed classification rather than a pass-through of parser text. The variants describe
/// the container; none of them can carry file contents, so nothing here can echo a foreign
/// document into a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreadableReason {
    /// The file does not parse as a secret document.
    NotASecretDocument,
    /// The file's name is outside the SB-2 grammar or inside a reserved namespace, so no
    /// operator secret can sit under it; this is where a hand-planted `oauth/` entry lands.
    NameOutsideGrammar,
    /// The document's recorded name is not the name the file sits under, which is what a
    /// document copied onto another name looks like.
    NameMismatch,
    /// The document holds no versions, which no writer of this format produces.
    NoVersions,
    /// A version carries no sealed blob at all, so it names a value that is not there.
    VersionWithoutBlobs,
    /// More than one version claims to be in service, or would return to service on restore,
    /// which breaks the invariant resolution depends on.
    AmbiguousActiveVersion,
}

impl UnreadableReason {
    /// The reason's stable name, for an operator message.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotASecretDocument => "does not parse as a secret document",
            Self::NameOutsideGrammar => "file name is outside the secret name grammar",
            Self::NameMismatch => "document names a different secret than its file",
            Self::NoVersions => "document holds no versions",
            Self::VersionWithoutBlobs => "a version carries no sealed blob",
            Self::AmbiguousActiveVersion => "more than one version claims to be in service",
        }
    }
}

impl std::fmt::Display for UnreadableReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One version [`SealedStore::migrate`] resealed, or could not reseal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationEntry {
    /// The secret's name.
    pub name: SecretName,
    /// The version.
    pub version: Version,
}

/// One version a migration left alone, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedEntry {
    /// The secret's name.
    pub name: SecretName,
    /// The version.
    pub version: Version,
    /// Every sealer holding a blob for this version. Identifiers, not key material.
    pub sealed_by: Vec<SealerId>,
    /// Whether it already holds a blob sealed by the migration's target.
    pub already_at_target: bool,
}

/// What [`SealedStore::migrate`] did.
///
/// Names, versions and sealer identifiers. No material and nothing derived from it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// Versions that gained a blob under the target sealer, with every prior blob retained.
    pub migrated: Vec<MigrationEntry>,
    /// Versions left alone, with the reason.
    pub skipped: Vec<SkippedEntry>,
    /// Versions whose source blob could not be opened or resealed, left exactly as they were.
    pub failed: Vec<MigrationEntry>,
}

/// One sealed blob, as it sits in a document.
///
/// Each blob records the [`SealerId`] that sealed it (SB-10), which is what lets a migration
/// tell what it is looking at and lets a store carried to another machine report which sealer
/// its blobs want rather than reporting corruption.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobRecord {
    sealed_by: SealerId,
    blob_hex: String,
    sealed_at_unix_ms: u64,
}

/// One version of one secret, as it sits in a document.
///
/// `deny_unknown_fields` on this and its siblings for the reason NMCP-SPEC-002 G-3 argues
/// about configuration generally: a key that is tolerated and unread is a key somebody
/// believes does something. An unknown field means a foreign document, and a foreign document
/// is isolated rather than half-read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionRecord {
    lifecycle: KeyLifecycle,
    created_at_unix_ms: u64,
    /// When this version was superseded, which is what the overlap window is measured from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    superseded_at_unix_ms: Option<u64>,
    /// The state this version was in when it was quarantined, so a restore returns it there
    /// rather than returning every version of a key to `Active`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quarantined_from: Option<KeyState>,
    /// Every sealing of this version's value. Migration appends; nothing removes.
    blobs: Vec<BlobRecord>,
}

/// One secret's document, the unit of isolation and of atomic replacement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretDocument {
    schema: u32,
    name: SecretName,
    created_at_unix_ms: u64,
    /// The key's binding, when the operator has written one (SB-6, v1.1). Absent means no
    /// use: [`SealedStore::evaluate`] refuses an unbound key with the rule named, which is
    /// deny by default made visible rather than a parse-time default. Absent is also what
    /// every pre-binding document is, so stores written before this field exists open
    /// unchanged and their keys refuse evaluation until bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<BindingRecord>,
    versions: BTreeMap<Version, VersionRecord>,
}

/// The store-level configuration document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreConfig {
    schema: u32,
    overlap_window_secs: u64,
}

/// The mutable half, behind one lock.
struct State {
    secrets: BTreeMap<SecretName, SecretDocument>,
    unreadable: Vec<UnreadableEntry>,
    overlap_window_secs: u64,
    /// The store directory, or `None` for an ephemeral store.
    dir: Option<PathBuf>,
}

/// Named secrets, sealed at rest, versioned, and tombstoned rather than deleted.
///
/// A `Mutex` rather than an `RwLock` because every path takes the write side: resolution and
/// listing sweep elapsed overlap windows before they answer, so the read paths mutate too,
/// and an `RwLock` whose read half always upgrades is a `Mutex` that looks like something
/// else.
pub struct SealedStore {
    sealer: Box<dyn Sealer>,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    state: Mutex<State>,
}

impl std::fmt::Debug for SealedStore {
    /// Hand-written, and it prints no name and no count.
    ///
    /// Names are not material and SB-R2 lists them to the agent, so printing them would not
    /// breach SB-1. It still prints none: a `Debug` on the store is what ends up in a panic
    /// message or a trace span, and the set of credentials a machine holds is the shape of
    /// its attack surface. There is a method for asking, and it is [`SealedStore::names`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedStore")
            .field("sealer", &self.sealer.id())
            .finish_non_exhaustive()
    }
}

impl SealedStore {
    /// Open the store in `dir`, sealing with `sealer`.
    ///
    /// An empty or absent directory is an empty store. A document that will not parse is set
    /// aside and reported by [`SealedStore::unreadable`] rather than taking the store down
    /// with it; a document declaring a schema this build does not know refuses the open.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the directories cannot be created or read, a document declares an
    /// unknown schema, or, on Unix, anything here is readable by somebody other than its
    /// owner.
    pub fn open(dir: &Path, sealer: Box<dyn Sealer>) -> Result<Self, StoreError> {
        Self::open_with_clock(dir, sealer, system_now_ms)
    }

    /// [`SealedStore::open`] with the clock injected, so the rotation overlap window is
    /// testable without sleeping (the house pattern: `MirrorConfig::from_lookup` in
    /// `nmcp-audit` injects the environment read for the same reason).
    ///
    /// `clock` returns milliseconds since the Unix epoch. It is consulted under the store's
    /// lock and must not call back into the store.
    ///
    /// # Errors
    ///
    /// As [`SealedStore::open`].
    pub fn open_with_clock(
        dir: &Path,
        sealer: Box<dyn Sealer>,
        clock: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Result<Self, StoreError> {
        create_restricted_dir(dir)?;
        verify_restricted(dir, RESTRICTED_DIR_MODE)?;
        let secrets_dir = dir.join(SECRETS_DIR);
        create_restricted_dir(&secrets_dir)?;
        verify_restricted(&secrets_dir, RESTRICTED_DIR_MODE)?;
        let overlap_window_secs = load_config(dir)?;
        let (secrets, unreadable) = load_secrets(&secrets_dir)?;
        Ok(Self {
            sealer,
            clock: Box::new(clock),
            state: Mutex::new(State {
                secrets,
                unreadable,
                overlap_window_secs,
                dir: Some(dir.to_path_buf()),
            }),
        })
    }

    /// An in-memory store, for callers that have no directory.
    ///
    /// It still seals, with a key generated for this process and written nowhere. The
    /// cryptographic guarantee is nil, because the key and the blobs share one address space,
    /// and it is not there for one: it is there so that an ephemeral store is the same code
    /// path as a persistent one, rather than a second path whose coverage runs past the
    /// sealing code.
    ///
    /// The signature is frozen at no parameters and no `Result`, and the system random source
    /// can fail. When it does, the store gets a sealer that holds no key and refuses every
    /// seal and every unseal with [`SealError::NoEntropy`]. That is SB-8's posture rather
    /// than a fallback: there is no fixed key and no plaintext mode, and every operation
    /// fails closed.
    #[must_use]
    pub fn ephemeral() -> Self {
        Self::ephemeral_with_clock(system_now_ms)
    }

    /// [`SealedStore::ephemeral`] with the clock injected; see
    /// [`SealedStore::open_with_clock`] for what the seam is for.
    #[must_use]
    pub fn ephemeral_with_clock(clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        let sealer: Box<dyn Sealer> = match MemorySealer::new() {
            Ok(sealer) => Box::new(sealer),
            Err(_) => Box::new(NoEntropySealer),
        };
        Self {
            sealer,
            clock: Box::new(clock),
            state: Mutex::new(State {
                secrets: BTreeMap::new(),
                unreadable: Vec::new(),
                overlap_window_secs: DEFAULT_OVERLAP_WINDOW_SECS,
                dir: None,
            }),
        }
    }

    /// Every operator secret the store holds, with no values (SB-R2).
    ///
    /// Reserved-namespace entries are absent, and absent by construction: [`SecretMeta`]
    /// carries a [`SecretName`], and no reserved name is one. Damaged documents are absent
    /// too and reported by [`SealedStore::unreadable`] instead, because their contents,
    /// including their states, cannot be trusted enough to list.
    #[must_use]
    pub fn names(&self) -> Vec<SecretMeta> {
        let mut state = self.state.lock();
        sweep(&mut state, (self.clock)());
        state
            .secrets
            .values()
            .map(|document| {
                let current = current_version(document);
                let state_now = current
                    .and_then(|version| document.versions.get(&version))
                    .or_else(|| document.versions.values().next_back())
                    .map_or(KeyState::Created, |record| record.lifecycle.state());
                SecretMeta {
                    name: document.name.clone(),
                    current_version: current,
                    state: state_now,
                    created_at_unix_ms: document.created_at_unix_ms,
                    versions: document
                        .versions
                        .iter()
                        .map(|(version, record)| VersionMeta {
                            version: *version,
                            state: record.lifecycle.state(),
                            created_at_unix_ms: record.created_at_unix_ms,
                            superseded_at_unix_ms: record.superseded_at_unix_ms,
                        })
                        .collect(),
                }
            })
            .collect()
    }

    /// Every file the store found and could not read.
    ///
    /// The visibility half of SB-10's isolation: a damaged document costs one key, and this
    /// is where an operator learns which one, instead of learning it from a call that failed
    /// pointing at the wrong thing. Recomputed at open; empty for an ephemeral store.
    #[must_use]
    pub fn unreadable(&self) -> Vec<UnreadableEntry> {
        self.state.lock().unreadable.clone()
    }

    /// Resolve the key `grant` authorizes, once.
    ///
    /// Takes the grant by value (SB-15), so one grant resolves one key one time, and takes no
    /// separate reference, so a grant issued for one key has no way to name another.
    ///
    /// # Errors
    ///
    /// [`ResolveError`], naming the governing rule (SB-8). The request carrying the reference
    /// is refused pre-effect; there is no degraded mode.
    pub fn resolve(&self, grant: BindingGrant) -> Result<Sealed<Vec<u8>>, ResolveError> {
        let (name, version, rule) = grant.into_parts();
        let mut state = self.state.lock();
        sweep(&mut state, (self.clock)());
        if is_damaged(&state, &name) {
            return Err(ResolveError::DamagedEntry {
                name: name.to_string(),
                rule,
            });
        }
        let Some(document) = state.secrets.get(&name) else {
            return Err(ResolveError::UnknownSecret {
                name: name.to_string(),
                rule,
            });
        };
        let Some(record) = document.versions.get(&version) else {
            return Err(ResolveError::UnknownVersion {
                name: name.to_string(),
                version,
                rule,
            });
        };
        if !record.lifecycle.resolves() {
            return Err(ResolveError::NotResolvable {
                name: name.to_string(),
                version,
                state: record.lifecycle.state(),
                rule,
            });
        }
        let mine = self.sealer.id();
        let Some(blob) = record
            .blobs
            .iter()
            .rev()
            .find(|blob| blob.sealed_by == mine)
        else {
            return Err(ResolveError::SealedElsewhere {
                name: name.to_string(),
                version,
                sealed_by: record
                    .blobs
                    .last()
                    .map_or_else(|| mine.clone(), |blob| blob.sealed_by.clone()),
                sealer: mine,
                rule,
            });
        };
        let context = SealContext::new(name.as_str(), version);
        let unsealable = |source: SealError| ResolveError::Unsealable {
            name: name.to_string(),
            version,
            sealed_by: blob.sealed_by.clone(),
            rule: rule.clone(),
            source: Box::new(source),
        };
        let bytes = hex::decode(&blob.blob_hex).map_err(|_| unsealable(SealError::Unsealable))?;
        self.sealer.unseal(&bytes, &context).map_err(unsealable)
    }

    /// Evaluate `name`'s binding against `request` and mint the grant one resolution costs.
    ///
    /// The binding evaluator NMCP-SPEC-002 v1.1 places in this crate (SB-6, section 9), and
    /// the only production path that constructs a [`BindingGrant`]: the constructor never
    /// crosses a crate boundary, which is what makes the grant unforgeable (SB-15). The host
    /// calls this at ring stage 5b with the request context and hands the grant to
    /// [`SealedStore::resolve`]; the gates, their order, the use budget's home and the
    /// decision that the budget decrements here rather than at resolution are all argued in
    /// the binding module's documentation, `src/binding.rs`.
    ///
    /// Evaluation decides authorization and service state; it does not pre-flight the
    /// cryptography. A grant can still be refused by `resolve` when the key was quarantined
    /// between the two or the blob does not open under this store's sealer, and a budgeted
    /// use spent on such a grant stays spent, which is the decrement-at-mint ruling.
    ///
    /// # Errors
    ///
    /// [`BindingDenial`], naming the one governing rule (SB-8): the first refusing gate in
    /// the documented order. A key with no binding refuses with the rule named, which is
    /// deny by default made visible, and a key with no version in service refuses here, at
    /// the earliest point that knows, rather than minting a grant resolution would refuse.
    pub fn evaluate(
        &self,
        name: &SecretName,
        request: &BindingRequest,
    ) -> Result<BindingGrant, BindingDenial> {
        let mut state = self.state.lock();
        let now = (self.clock)();
        sweep(&mut state, now);
        if is_damaged(&state, name) {
            return Err(BindingDenial::DamagedEntry {
                name: name.to_string(),
            });
        }
        let Some(document) = state.secrets.get(name) else {
            return Err(BindingDenial::UnknownSecret {
                name: name.to_string(),
            });
        };
        let Some(record) = document.binding.as_ref() else {
            return Err(BindingDenial::NoBinding {
                name: name.to_string(),
            });
        };
        crate::binding::admit(&record.terms, request, name, now)?;
        let Some(version) = current_version(document) else {
            // The current version's state, or the highest version's when nothing is in
            // service, exactly as [`SealedStore::names`] reports it: a quarantined key says
            // it is quarantined rather than saying nothing.
            let state_now = document
                .versions
                .values()
                .next_back()
                .map_or(KeyState::Created, |record| record.lifecycle.state());
            return Err(BindingDenial::NotInService {
                name: name.to_string(),
                state: state_now,
            });
        };
        if let Some(budget) = record.terms.budget {
            // The one gate that writes, reached only by a request every other gate
            // admitted, and persisted before the grant exists: decrement at mint, argued in
            // the binding module's documentation.
            let spent = crate::binding::spend(budget, record.spent, name, now)?;
            let mut updated = document.clone();
            if let Some(updated_record) = updated.binding.as_mut() {
                updated_record.spent = Some(spent);
            }
            persist_and_commit(&mut state, name, updated).map_err(|source| {
                BindingDenial::UseNotRecorded {
                    name: name.to_string(),
                    source: Box::new(source),
                }
            })?;
        }
        Ok(BindingGrant::issue(
            name.clone(),
            version,
            crate::binding::rule_for(name),
        ))
    }

    /// Store the first version of `name`.
    ///
    /// Refuses a name that already exists, and names [`SealedStore::rotate`] in the refusal:
    /// the base's store replaced a value in place, which is the hard cutover SB-14 removed
    /// from rotation. Refuses a name whose file exists but could not be read, because
    /// overwriting a damaged document destroys whatever it still holds (INV-1). A reserved
    /// name cannot arrive here at all: no [`SecretName`] holds one (SB-2, SB-R2).
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the name exists or is damaged on disk, the value cannot be sealed,
    /// or the document cannot be written.
    pub fn set(&self, name: &SecretName, value: Sealed<Vec<u8>>) -> Result<Version, StoreError> {
        let mut state = self.state.lock();
        let now = (self.clock)();
        sweep(&mut state, now);
        ensure_not_damaged(&state, name)?;
        if state.secrets.contains_key(name) {
            return Err(StoreError::AlreadyExists {
                name: name.to_string(),
            });
        }
        let version = Version::first();
        let record = self.seal_version(name, version, value, now)?;
        let document = SecretDocument {
            schema: STORE_SCHEMA_VERSION,
            name: name.clone(),
            created_at_unix_ms: now,
            // Deny by default (SB-6): a fresh secret has no binding, so nothing may use it
            // until the operator binds it.
            binding: None,
            versions: BTreeMap::from([(version, record)]),
        };
        persist_and_commit(&mut state, name, document)?;
        Ok(version)
    }

    /// Store a new version of `name`, leaving the previous one resolvable for the overlap
    /// window.
    ///
    /// The new version is [`KeyState::Active`] and the previous becomes
    /// [`KeyState::Superseded`], which resolves until [`SealedStore::overlap_window`] has
    /// elapsed and then becomes [`KeyState::Retained`]. At a window of zero the retirement
    /// happens inside this call, so the hard cutover is the general rule evaluated at its
    /// boundary rather than a special case beside it.
    ///
    /// Refuses a key with nothing in service: rotating a quarantined key would silently
    /// return it to service, which is the opposite of what the operator asked for when they
    /// revoked it.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the key is absent or damaged, has no version in service, has
    /// exhausted the version counter, or cannot be sealed or written.
    pub fn rotate(&self, name: &SecretName, value: Sealed<Vec<u8>>) -> Result<Version, StoreError> {
        let mut state = self.state.lock();
        let now = (self.clock)();
        sweep(&mut state, now);
        ensure_not_damaged(&state, name)?;
        let window_ms = state.overlap_window_secs.saturating_mul(1_000);
        let Some(document) = state.secrets.get(name) else {
            return Err(StoreError::UnknownSecret {
                name: name.to_string(),
            });
        };
        let Some(current) = current_version(document) else {
            return Err(StoreError::NotInService {
                name: name.to_string(),
            });
        };
        let highest = document
            .versions
            .keys()
            .next_back()
            .copied()
            .unwrap_or(current);
        let next = highest.next();
        if next == highest {
            return Err(StoreError::VersionsExhausted {
                name: name.to_string(),
                highest,
            });
        }
        let fresh = self.seal_version(name, next, value, now)?;
        let mut updated = document.clone();
        let Some(prior) = updated.versions.get_mut(&current) else {
            // `current` was found in this same document one lookup ago, so this arm is belt
            // and braces; if it ever fired, its message would still be the truth.
            return Err(StoreError::NotInService {
                name: name.to_string(),
            });
        };
        prior.lifecycle = prior
            .lifecycle
            .advance(KeyState::Superseded)
            .map_err(|source| StoreError::illegal(name, current, source))?;
        prior.superseded_at_unix_ms = Some(now);
        updated.versions.insert(next, fresh);
        // Swept again with the same instant, so a window of zero retires the version this
        // call superseded before the call returns.
        sweep_document(&mut updated, window_ms, now);
        persist_and_commit(&mut state, name, updated)?;
        Ok(next)
    }

    /// Revoke `name`: every version stops resolving immediately, and nothing is deleted.
    ///
    /// The tombstone INV-1 asks for, written into the secret's own document. Each version
    /// records the state it was in so [`SealedStore::restore`] can put it back rather than
    /// promoting every version of the key to [`KeyState::Active`]. Immediate and without a
    /// window, which is what distinguishes revocation from rotation: an in-flight call
    /// holding the previous version fails closed, and that is the point of revoking (T8).
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the key is absent or damaged, is already wholly quarantined, or a
    /// version is in a state the lifecycle does not permit quarantining, which halts with
    /// nothing written and the transition named (INV-5).
    pub fn quarantine(&self, name: &SecretName) -> Result<(), StoreError> {
        let mut state = self.state.lock();
        sweep(&mut state, (self.clock)());
        ensure_not_damaged(&state, name)?;
        let Some(document) = state.secrets.get(name) else {
            return Err(StoreError::UnknownSecret {
                name: name.to_string(),
            });
        };
        let mut updated = document.clone();
        let mut moved = 0_usize;
        for (version, record) in &mut updated.versions {
            let from = record.lifecycle.state();
            // `Quarantined` is already there; `Created` resolves nothing and was never in
            // service, so there is nothing revocation would stop. Both are left alone rather
            // than walked through an edge SB-14 does not declare.
            if matches!(from, KeyState::Quarantined | KeyState::Created) {
                continue;
            }
            record.lifecycle = record
                .lifecycle
                .advance(KeyState::Quarantined)
                .map_err(|source| StoreError::illegal(name, *version, source))?;
            record.quarantined_from = Some(from);
            moved += 1;
        }
        if moved == 0 {
            return Err(StoreError::NothingToQuarantine {
                name: name.to_string(),
            });
        }
        persist_and_commit(&mut state, name, updated)?;
        Ok(())
    }

    /// Return `name` to service, reversing a quarantine.
    ///
    /// Two steps, both operator-only and both edges the lifecycle declares. Every quarantined
    /// version goes back to the state it was quarantined from, so a version that was
    /// superseded when the operator revoked comes back superseded rather than active, and a
    /// superseded version whose window elapsed while it sat in quarantine retires on the next
    /// sweep, exactly as it would have outside. Then, if no version returned to service, the
    /// highest [`KeyState::Retained`] version is promoted, which is SB-14's "restorable by
    /// operator" for a key whose every version had already drained; nothing this crate's own
    /// writers produce reaches that shape today, but a document written by another generation
    /// or edited by an operator can hold it, and the store reads those.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the key is absent or damaged, has nothing to restore, or a version
    /// is in a state the lifecycle does not permit restoring, which halts with nothing
    /// written and the transition named (INV-5).
    pub fn restore(&self, name: &SecretName) -> Result<(), StoreError> {
        let mut state = self.state.lock();
        sweep(&mut state, (self.clock)());
        ensure_not_damaged(&state, name)?;
        let Some(document) = state.secrets.get(name) else {
            return Err(StoreError::UnknownSecret {
                name: name.to_string(),
            });
        };
        let mut updated = document.clone();
        let mut moved = 0_usize;
        for (version, record) in &mut updated.versions {
            if record.lifecycle.state() != KeyState::Quarantined {
                continue;
            }
            let back = record.quarantined_from.unwrap_or(KeyState::Active);
            record.lifecycle = record
                .lifecycle
                .advance(back)
                .map_err(|source| StoreError::illegal(name, *version, source))?;
            record.quarantined_from = None;
            moved += 1;
        }
        if current_version(&updated).is_none()
            && let Some((version, record)) = updated
                .versions
                .iter_mut()
                .rev()
                .find(|(_, record)| record.lifecycle.state() == KeyState::Retained)
        {
            record.lifecycle = record
                .lifecycle
                .advance(KeyState::Active)
                .map_err(|source| StoreError::illegal(name, *version, source))?;
            record.superseded_at_unix_ms = None;
            moved += 1;
        }
        if moved == 0 {
            return Err(StoreError::NothingToRestore {
                name: name.to_string(),
            });
        }
        persist_and_commit(&mut state, name, updated)?;
        Ok(())
    }

    /// Write `name`'s binding: what may use the key, per SB-6, replacing any prior binding.
    ///
    /// The fifth operator write (SB-13's "bind"), and like the other four it exists only on
    /// the operator surface and is audited by its caller (SB-7 at I-034, `nmcpctl` at
    /// I-038); no agent-reachable path leads here. Until a key is bound, nothing may use it:
    /// [`SealedStore::evaluate`] refuses an unbound key with the rule named, so `bind` is
    /// the grant of use, not a refinement of one.
    ///
    /// Replacement is whole and it resets the budget's spend state, deliberately: a new
    /// binding is a new regime, and the operator writing it is the authority the budget
    /// constrains callers against, not a caller the budget constrains (INV-4 bounds what a
    /// caller supplies; an operator rewriting terms is the policy changing). A quarantined
    /// or suspended key can be bound, because a binding is authorization metadata that takes
    /// effect when the key returns to service, and refusing would order two operator steps
    /// for no safety gain: evaluation still refuses the key on state either way. There is no
    /// unbind and none is needed: an operator withdrawing use binds empty allowlists, which
    /// admit nothing and stay visible, or quarantines the key; values are untouched either
    /// way (INV-1).
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the key is absent or damaged on disk, or the document cannot be
    /// written.
    pub fn bind(&self, name: &SecretName, binding: KeyBinding) -> Result<(), StoreError> {
        let mut state = self.state.lock();
        sweep(&mut state, (self.clock)());
        ensure_not_damaged(&state, name)?;
        let Some(document) = state.secrets.get(name) else {
            return Err(StoreError::UnknownSecret {
                name: name.to_string(),
            });
        };
        let mut updated = document.clone();
        updated.binding = Some(BindingRecord {
            schema: BINDING_SCHEMA_VERSION,
            terms: binding,
            spent: None,
        });
        persist_and_commit(&mut state, name, updated)?;
        Ok(())
    }

    /// Reseal every blob `from` holds under `to`, alongside what is already there.
    ///
    /// SB-12's migration, and an offline one. `to` is borrowed rather than owned, so this
    /// store cannot adopt it: after a successful migration the next process opens the store
    /// with `to` in place of `from`, which is exactly the shape of an operator-run, one-way,
    /// audited migration. The old blobs are retained beside the new ones (INV-1), so the
    /// store still opens under the old sealer and a migration interrupted anywhere leaves
    /// every key readable somewhere.
    ///
    /// Idempotent: a version already holding a blob under the target is skipped, so a second
    /// run does nothing. A version holding no blob under `from` is refused individually,
    /// skipped and reported with the sealers that do hold it, rather than resealed on a
    /// guess. A blob the source sealer cannot open is reported as failed and left exactly as
    /// it was: one unreadable blob costs one version, not the run (SB-10).
    ///
    /// # Errors
    ///
    /// [`StoreError::MigrationSourceMismatch`] when this store's sealer is not `from`, which
    /// would otherwise fail every unseal one blob at a time and report corruption that is
    /// not; and [`StoreError`] when a document cannot be written, which stops the run with
    /// everything already persisted kept.
    pub fn migrate(&self, from: SealerId, to: &dyn Sealer) -> Result<MigrationReport, StoreError> {
        let mine = self.sealer.id();
        if mine != from {
            return Err(StoreError::MigrationSourceMismatch { from, sealer: mine });
        }
        let mut state = self.state.lock();
        let now = (self.clock)();
        sweep(&mut state, now);
        let mut report = MigrationReport::default();
        let names: Vec<SecretName> = state.secrets.keys().cloned().collect();
        for name in names {
            let Some(document) = state.secrets.get(&name) else {
                continue;
            };
            let mut updated = document.clone();
            let mut touched = false;
            for (version, record) in &mut updated.versions {
                let context = SealContext::new(name.as_str(), *version);
                let outcome = reseal_version(self.sealer.as_ref(), to, &context, record, now);
                let entry = MigrationEntry {
                    name: name.clone(),
                    version: *version,
                };
                match outcome {
                    ResealOutcome::Migrated => {
                        touched = true;
                        report.migrated.push(entry);
                    }
                    ResealOutcome::AlreadyAtTarget => report.skipped.push(SkippedEntry {
                        name: entry.name,
                        version: entry.version,
                        sealed_by: blob_sealers(record),
                        already_at_target: true,
                    }),
                    ResealOutcome::HeldElsewhere => report.skipped.push(SkippedEntry {
                        name: entry.name,
                        version: entry.version,
                        sealed_by: blob_sealers(record),
                        already_at_target: false,
                    }),
                    ResealOutcome::Failed => report.failed.push(entry),
                }
            }
            if touched {
                persist_and_commit(&mut state, &name, updated)?;
            }
        }
        Ok(report)
    }

    /// How long a superseded version keeps resolving after a rotation (SB-14).
    #[must_use]
    pub fn overlap_window(&self) -> Duration {
        Duration::from_secs(self.state.lock().overlap_window_secs)
    }

    /// Set the rotation overlap window, and persist it.
    ///
    /// Persisted in [`STORE_CONFIG_FILE`] rather than passed to [`SealedStore::open`], whose
    /// signature is frozen at two parameters, and persisted rather than defaulted so a
    /// restart does not silently return a deployment to five minutes. Zero is permitted and
    /// means the hard cutover. Sub-second resolution is discarded: the window is a drain time
    /// an operator reasons about in seconds, and a stored duration that does not round-trip
    /// is a setting that reads back as something else.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the configuration document cannot be written.
    pub fn set_overlap_window(&self, window: Duration) -> Result<(), StoreError> {
        let mut state = self.state.lock();
        persist_config(state.dir.as_deref(), window.as_secs())?;
        state.overlap_window_secs = window.as_secs();
        sweep(&mut state, (self.clock)());
        Ok(())
    }

    /// The sealer every blob written from now on is sealed by.
    ///
    /// What an operator passes to [`SealedStore::migrate`] as the source when moving away
    /// from this sealer.
    #[must_use]
    pub fn sealer_id(&self) -> SealerId {
        self.sealer.id()
    }

    /// Seal one value into a fresh version record, walked `Created -> Active` in memory.
    ///
    /// `Created` is a real state and this is where it lives: between sealing and service
    /// there is a record that exists and does not resolve, and the walk into `Active` is a
    /// checked lifecycle transition rather than a field assignment, so the one-active-version
    /// invariant has no unguarded writer.
    ///
    /// Consumes the value: once the blob exists, the store owns nothing in plaintext, and
    /// [`Sealed`]'s drop erases the one copy it was handed before this returns.
    fn seal_version(
        &self,
        name: &SecretName,
        version: Version,
        value: Sealed<Vec<u8>>,
        now: u64,
    ) -> Result<VersionRecord, StoreError> {
        let context = SealContext::new(name.as_str(), version);
        let blob = value
            .with_exposed(|plain| self.sealer.seal(plain, &context))
            .map_err(|source| StoreError::Seal {
                name: name.to_string(),
                source,
            })?;
        // The explicit drop is the point of taking the value: the plaintext's one owned copy
        // is zeroized here, before any document is written, and the store holds only the
        // blob from this line on.
        drop(value);
        let lifecycle = KeyLifecycle::created()
            .advance(KeyState::Active)
            .map_err(|source| StoreError::illegal(name, version, source))?;
        Ok(VersionRecord {
            lifecycle,
            created_at_unix_ms: now,
            superseded_at_unix_ms: None,
            quarantined_from: None,
            blobs: vec![BlobRecord {
                sealed_by: self.sealer.id(),
                blob_hex: hex::encode(blob),
                sealed_at_unix_ms: now,
            }],
        })
    }
}

/// How one version fared under [`SealedStore::migrate`].
enum ResealOutcome {
    /// A blob under the target was appended alongside the existing ones.
    Migrated,
    /// A blob under the target already exists; nothing to do.
    AlreadyAtTarget,
    /// No blob under the migration's source; refused individually and reported.
    HeldElsewhere,
    /// The source blob would not decode, unseal or reseal; left exactly as it was.
    Failed,
}

/// Reseal one version's value under `target`, appending rather than replacing.
fn reseal_version(
    source: &dyn Sealer,
    target: &dyn Sealer,
    context: &SealContext,
    record: &mut VersionRecord,
    now: u64,
) -> ResealOutcome {
    let target_id = target.id();
    if record.blobs.iter().any(|blob| blob.sealed_by == target_id) {
        return ResealOutcome::AlreadyAtTarget;
    }
    let source_id = source.id();
    let Some(held) = record
        .blobs
        .iter()
        .rev()
        .find(|blob| blob.sealed_by == source_id)
    else {
        return ResealOutcome::HeldElsewhere;
    };
    let Ok(bytes) = hex::decode(&held.blob_hex) else {
        return ResealOutcome::Failed;
    };
    let Ok(plain) = source.unseal(&bytes, context) else {
        return ResealOutcome::Failed;
    };
    let Ok(resealed) = plain.with_exposed(|bytes| target.seal(bytes, context)) else {
        return ResealOutcome::Failed;
    };
    record.blobs.push(BlobRecord {
        sealed_by: target_id,
        blob_hex: hex::encode(resealed),
        sealed_at_unix_ms: now,
    });
    ResealOutcome::Migrated
}

/// Every sealer holding a blob for `record`, for a migration report.
fn blob_sealers(record: &VersionRecord) -> Vec<SealerId> {
    record
        .blobs
        .iter()
        .map(|blob| blob.sealed_by.clone())
        .collect()
}

/// Refuse an operator write on a name whose file exists and could not be read.
///
/// Writing over a damaged document is destroying whatever it still holds, which is the one
/// thing INV-1 forbids; the operator moves the file aside by hand, outside this server,
/// exactly as INV-1's quarantine model has it.
fn ensure_not_damaged(state: &State, name: &SecretName) -> Result<(), StoreError> {
    if let Some(entry) = damaged_entry(state, name) {
        return Err(StoreError::DamagedEntry {
            name: name.to_string(),
            file: entry.file.clone(),
        });
    }
    Ok(())
}

/// Whether `name`'s file was set aside at open.
fn is_damaged(state: &State, name: &SecretName) -> bool {
    damaged_entry(state, name).is_some()
}

/// The unreadable entry sitting where `name`'s file would go, if any.
fn damaged_entry<'state>(
    state: &'state State,
    name: &SecretName,
) -> Option<&'state UnreadableEntry> {
    let file_name = format!("{name}.json");
    state.unreadable.iter().find(|entry| {
        Path::new(&entry.file)
            .file_name()
            .and_then(|found| found.to_str())
            == Some(file_name.as_str())
    })
}

/// Write `document` then commit it to memory, in that order.
///
/// The write happens before the in-memory map changes, so a failed write leaves the store
/// exactly as it was: the caller's mutation lived only in a clone.
fn persist_and_commit(
    state: &mut State,
    name: &SecretName,
    document: SecretDocument,
) -> Result<(), StoreError> {
    persist_secret(state.dir.as_deref(), &document)?;
    state.secrets.insert(name.clone(), document);
    Ok(())
}

/// Retire every superseded version whose overlap window has closed.
fn sweep(state: &mut State, now: u64) {
    let window_ms = state.overlap_window_secs.saturating_mul(1_000);
    for document in state.secrets.values_mut() {
        sweep_document(document, window_ms, now);
    }
}

/// [`sweep`] for one document.
///
/// The window is measured from `superseded_at_unix_ms`, which is the datum; the state is
/// derived from it here and then held as data (INV-5), re-derived identically by the next
/// process from the same timestamp. The comparison is `elapsed >= window`, so a window of
/// zero retires a version the instant it is superseded, and a superseded record missing its
/// timestamp, which no writer of this format produces, retires immediately rather than
/// resolving forever: the fail-closed direction.
fn sweep_document(document: &mut SecretDocument, window_ms: u64, now: u64) {
    for record in document.versions.values_mut() {
        if record.lifecycle.state() != KeyState::Superseded {
            continue;
        }
        let elapsed = record
            .superseded_at_unix_ms
            .map_or(u64::MAX, |at| now.saturating_sub(at));
        if elapsed >= window_ms
            && let Ok(retained) = record.lifecycle.advance(KeyState::Retained)
        {
            record.lifecycle = retained;
        }
    }
}

/// The version a fresh resolution would use, which is the one in [`KeyState::Active`].
///
/// At most one version is ever active, which load-time validation refuses documents that
/// break and the checked lifecycle walk preserves; that is what makes this a lookup rather
/// than a choice. A superseded version resolves and is deliberately not returned here: the
/// overlap window exists to let calls that already named it finish, not to hand it to new
/// ones.
fn current_version(document: &SecretDocument) -> Option<Version> {
    document
        .versions
        .iter()
        .find(|(_, record)| record.lifecycle.state() == KeyState::Active)
        .map(|(version, _)| *version)
}

/// Milliseconds since the Unix epoch, from the system clock.
///
/// A clock before the epoch saturates at zero rather than aborting. The consequence is that
/// an overlap window measured against it closes immediately, which is the fail-closed
/// direction.
fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Read the store-level configuration, or the defaults when none was ever written.
fn load_config(dir: &Path) -> Result<u64, StoreError> {
    let path = dir.join(STORE_CONFIG_FILE);
    match fs::read_to_string(&path) {
        Ok(text) => {
            verify_restricted(&path, RESTRICTED_FILE_MODE)?;
            let value: serde_json::Value =
                serde_json::from_str(&text).map_err(|err| StoreError::Unparsable {
                    path: path.display().to_string(),
                    reason: err.to_string(),
                })?;
            check_schema(&value, &path)?;
            let config: StoreConfig =
                serde_json::from_value(value).map_err(|err| StoreError::Unparsable {
                    path: path.display().to_string(),
                    reason: err.to_string(),
                })?;
            Ok(config.overlap_window_secs)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(DEFAULT_OVERLAP_WINDOW_SECS),
        Err(err) => Err(StoreError::Unreadable {
            path: path.display().to_string(),
            reason: err.kind().to_string(),
        }),
    }
}

/// Load every per-secret document, isolating the ones that cannot be read.
fn load_secrets(
    secrets_dir: &Path,
) -> Result<(BTreeMap<SecretName, SecretDocument>, Vec<UnreadableEntry>), StoreError> {
    let mut secrets = BTreeMap::new();
    let mut unreadable = Vec::new();
    for path in secret_files(secrets_dir)? {
        verify_restricted(&path, RESTRICTED_FILE_MODE)?;
        let file = path.display().to_string();
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            unreadable.push(UnreadableEntry {
                file,
                reason: UnreadableReason::NameOutsideGrammar,
            });
            continue;
        };
        let Ok(name) = SecretName::parse(stem) else {
            unreadable.push(UnreadableEntry {
                file,
                reason: UnreadableReason::NameOutsideGrammar,
            });
            continue;
        };
        let text = fs::read_to_string(&path).map_err(|err| StoreError::Unreadable {
            path: file.clone(),
            reason: err.kind().to_string(),
        })?;
        match read_document(&text, &name, &path)? {
            Ok(document) => {
                secrets.insert(name, document);
            }
            Err(reason) => unreadable.push(UnreadableEntry { file, reason }),
        }
    }
    Ok((secrets, unreadable))
}

/// Every candidate document in the secrets directory, in name order.
///
/// Files without the `.json` extension are not documents and are ignored; the one thing that
/// produces such a file here is a write interrupted between temporary and rename, and the
/// next write to that name replaces it.
fn secret_files(secrets_dir: &Path) -> Result<Vec<PathBuf>, StoreError> {
    let entries = fs::read_dir(secrets_dir).map_err(|err| StoreError::Unreadable {
        path: secrets_dir.display().to_string(),
        reason: err.kind().to_string(),
    })?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| StoreError::Unreadable {
            path: secrets_dir.display().to_string(),
            reason: err.kind().to_string(),
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// Parse and validate one document.
///
/// The outer `Result` is the store-level refusal: a document that parses and declares a
/// schema this build does not know fails the open, because it is not corruption, it is a
/// newer format. The inner `Result` is the isolation: everything else that is wrong with a
/// file costs that file alone.
fn read_document(
    text: &str,
    name: &SecretName,
    path: &Path,
) -> Result<Result<SecretDocument, UnreadableReason>, StoreError> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Ok(Err(UnreadableReason::NotASecretDocument));
    };
    if value
        .get("schema")
        .and_then(serde_json::Value::as_u64)
        .is_some()
    {
        check_schema(&value, path)?;
    }
    check_binding_schema(&value, path)?;
    let Ok(document) = serde_json::from_value::<SecretDocument>(value) else {
        return Ok(Err(UnreadableReason::NotASecretDocument));
    };
    if document.name != *name {
        return Ok(Err(UnreadableReason::NameMismatch));
    }
    if document.versions.is_empty() {
        return Ok(Err(UnreadableReason::NoVersions));
    }
    if document
        .versions
        .values()
        .any(|record| record.blobs.is_empty())
    {
        return Ok(Err(UnreadableReason::VersionWithoutBlobs));
    }
    let in_service = document
        .versions
        .values()
        .filter(|record| {
            record.lifecycle.state() == KeyState::Active
                || (record.lifecycle.state() == KeyState::Quarantined
                    && record.quarantined_from == Some(KeyState::Active))
        })
        .count();
    if in_service > 1 {
        return Ok(Err(UnreadableReason::AmbiguousActiveVersion));
    }
    Ok(Ok(document))
}

/// Refuse a schema this build does not know.
fn check_schema(value: &serde_json::Value, path: &Path) -> Result<(), StoreError> {
    let found = value.get("schema").and_then(serde_json::Value::as_u64);
    match found {
        Some(found) if found == u64::from(STORE_SCHEMA_VERSION) => Ok(()),
        Some(found) => Err(StoreError::UnknownSchema {
            path: path.display().to_string(),
            found,
            known: STORE_SCHEMA_VERSION,
        }),
        None => Err(StoreError::Unparsable {
            path: path.display().to_string(),
            reason: "the document declares no schema".to_string(),
        }),
    }
}

/// Refuse a binding block written to a schema this build does not know.
///
/// The same rule [`check_schema`] applies to the document, at the binding block's own
/// version: a block declaring a newer schema is a store written by a newer build, refused
/// rather than guessed at, and the check runs against the raw value because the newer
/// block's unknown fields would otherwise fail the typed parse first and report the wrong
/// thing, a foreign document instead of a newer store. A block with no numeric schema at all
/// is left to the typed parse, which refuses it and isolates that one document: malformation
/// costs a key, a newer format refuses the open.
fn check_binding_schema(value: &serde_json::Value, path: &Path) -> Result<(), StoreError> {
    let Some(found) = value
        .get("binding")
        .and_then(|block| block.get("schema"))
        .and_then(serde_json::Value::as_u64)
    else {
        return Ok(());
    };
    if found == u64::from(BINDING_SCHEMA_VERSION) {
        Ok(())
    } else {
        Err(StoreError::UnknownBindingSchema {
            path: path.display().to_string(),
            found,
            known: BINDING_SCHEMA_VERSION,
        })
    }
}

/// Write one secret's document, or do nothing for an ephemeral store.
fn persist_secret(dir: Option<&Path>, document: &SecretDocument) -> Result<(), StoreError> {
    let Some(dir) = dir else {
        return Ok(());
    };
    let path = secret_path(dir, &document.name);
    let body = serde_json::to_vec_pretty(document).map_err(|err| StoreError::Unwritable {
        path: path.display().to_string(),
        reason: err.to_string(),
    })?;
    write_via_rename(&path, &body)
}

/// Write the store-level configuration, or do nothing for an ephemeral store.
fn persist_config(dir: Option<&Path>, overlap_window_secs: u64) -> Result<(), StoreError> {
    let Some(dir) = dir else {
        return Ok(());
    };
    let path = dir.join(STORE_CONFIG_FILE);
    let config = StoreConfig {
        schema: STORE_SCHEMA_VERSION,
        overlap_window_secs,
    };
    let body = serde_json::to_vec_pretty(&config).map_err(|err| StoreError::Unwritable {
        path: path.display().to_string(),
        reason: err.to_string(),
    })?;
    write_via_rename(&path, &body)
}

/// The file `name`'s document lives in.
fn secret_path(dir: &Path, name: &SecretName) -> PathBuf {
    dir.join(SECRETS_DIR).join(format!("{name}.json"))
}

/// Write through a fixed temporary name in the same directory, then rename into place.
///
/// The rename is atomic on the platforms this serves, so a crash mid-write leaves the
/// previous document intact rather than a truncated one. This is the write-temp-then-rename
/// shape INV-1's gate permits; no destructive primitive is involved.
fn write_via_rename(path: &Path, body: &[u8]) -> Result<(), StoreError> {
    let temporary = path.with_extension(WRITE_EXTENSION);
    write_restricted(&temporary, body, RESTRICTED_FILE_MODE)?;
    fs::rename(&temporary, path).map_err(|err| StoreError::Unwritable {
        path: path.display().to_string(),
        reason: err.kind().to_string(),
    })
}

/// A sealer with no key, for the one failure [`SealedStore::ephemeral`] cannot report.
///
/// Not a mock and not a placeholder: it is the fail-closed behaviour SB-8 requires when the
/// sealer is unavailable, expressed as a sealer rather than as an `Option` every call site
/// would have to check. Every operation refuses, so a store holding one stores nothing and
/// resolves nothing.
struct NoEntropySealer;

impl Sealer for NoEntropySealer {
    fn seal(&self, _plain: &[u8], _context: &SealContext) -> Result<Vec<u8>, SealError> {
        Err(SealError::NoEntropy)
    }

    fn unseal(&self, _blob: &[u8], _context: &SealContext) -> Result<Sealed<Vec<u8>>, SealError> {
        Err(SealError::NoEntropy)
    }

    fn id(&self) -> SealerId {
        SealerId::new("unavailable", crate::sealer::SECRET_ENTROPY, "no-entropy")
    }
}

/// Why a store operation did not happen.
///
/// No variant carries material or any value derived from material, including a length or a
/// digest (SB-1). Names, versions, states, sealer identifiers and paths are all carried, and
/// none of them is material: SB-R2 lists names and states to the agent, and a path describes
/// a container rather than its contents.
///
/// Exhaustive rather than `#[non_exhaustive]`, for the reason `SecretSlotError` gives in
/// `nmcp-schema`: this enum is owned by NMCP-SPEC-002 rather than frozen by a ratified
/// contract another crate matches on, so a new way for a store operation to fail should break
/// every `match` on it loudly.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The store directory or a document is readable by somebody other than its owner.
    ///
    /// A refusal rather than a repair, for the reason [`SealError::KeyFileExposed`] gives:
    /// on a core-sealer deployment the filesystem is the whole of the guarantee (T6, G-6).
    #[error("{path} is mode {mode:o} and a secret store requires {required:o}")]
    Exposed {
        /// The offending path.
        path: String,
        /// The mode found.
        mode: u32,
        /// The mode required.
        required: u32,
    },

    /// A directory or document could not be read.
    #[error("secret store path {path} could not be read: {reason}")]
    Unreadable {
        /// The path involved.
        path: String,
        /// The operating system's description of the failure, which describes the file
        /// rather than its contents.
        reason: String,
    },

    /// The store-level configuration is present and will not parse, or a document carries a
    /// malformed schema declaration.
    #[error("secret store document {path} will not parse and will not be replaced: {reason}")]
    Unparsable {
        /// The path involved.
        path: String,
        /// What the parser objected to. Structural: sealed values appear to the parser only
        /// as hexadecimal text, and configuration holds no values at all.
        reason: String,
    },

    /// A document is written to a schema this build does not know.
    #[error(
        "secret store document {path} is schema {found} and this build knows schema {known}; a newer store is refused rather than guessed at"
    )]
    UnknownSchema {
        /// The path involved.
        path: String,
        /// The schema the document declares.
        found: u64,
        /// The schema this build writes.
        known: u32,
    },

    /// A document's binding block is written to a schema this build does not know.
    ///
    /// Refused for the reason [`StoreError::UnknownSchema`] refuses a newer document: it is
    /// a store written by a newer build, and guessing at binding fields you do not know is
    /// guessing at authorization, which is worse than guessing at layout.
    #[error(
        "secret store document {path} carries a binding at schema {found} and this build knows binding schema {known}; a newer store is refused rather than guessed at"
    )]
    UnknownBindingSchema {
        /// The path involved.
        path: String,
        /// The binding schema the document declares.
        found: u64,
        /// The binding schema this build writes.
        known: u32,
    },

    /// A document could not be written.
    #[error("secret store document {path} could not be written: {reason}")]
    Unwritable {
        /// The path involved.
        path: String,
        /// The operating system's description of the failure.
        reason: String,
    },

    /// The value could not be sealed.
    #[error("the value for {name} could not be sealed")]
    Seal {
        /// The name whose value was being sealed.
        name: String,
        /// What the sealer objected to, which carries no material either.
        #[source]
        source: SealError,
    },

    /// The name already exists, and a store never overwrites a value in place.
    #[error(
        "secret {name} already exists; storing a second value for it is a rotation, which keeps the previous version resolvable for the overlap window"
    )]
    AlreadyExists {
        /// The name that exists.
        name: String,
    },

    /// The name's file exists and could not be read, so no write will touch it.
    #[error(
        "secret {name} cannot be written: a document this build could not read sits at {file}, and overwriting it would destroy whatever it still holds; move it aside by hand and reopen the store"
    )]
    DamagedEntry {
        /// The name that was asked for.
        name: String,
        /// The file that is in the way.
        file: String,
    },

    /// The name does not exist.
    #[error("no secret named {name}")]
    UnknownSecret {
        /// The name that was asked for.
        name: String,
    },

    /// The key has no version in service.
    #[error(
        "secret {name} has no version in service; a quarantined key is restored before it is rotated, so that rotating one does not silently return it to service"
    )]
    NotInService {
        /// The name.
        name: String,
    },

    /// No version of the key is in a state revocation applies to.
    #[error(
        "no version of {name} is in a state revocation applies to: each is already quarantined or was never in service"
    )]
    NothingToQuarantine {
        /// The name.
        name: String,
    },

    /// The key has nothing a restore would change.
    #[error("secret {name} has nothing to restore: no version is quarantined or waiting retained")]
    NothingToRestore {
        /// The name.
        name: String,
    },

    /// The version counter cannot advance.
    ///
    /// Rotation stops rather than wrapping onto a version number that already names a stored
    /// value, which would be the one overwrite INV-1 exists to prevent.
    #[error("secret {name} has reached version {highest} and cannot be rotated further")]
    VersionsExhausted {
        /// The name.
        name: String,
        /// The highest version stored.
        highest: Version,
    },

    /// A version is in a state the attempted transition is not legal from (INV-5).
    ///
    /// Halts: nothing is written, and the message names the transition so an audit record
    /// can carry it. Emitting that record is I-034's, which is the first code with an audit
    /// sink in scope; this crate holds none, and adding one would put a second chain writer
    /// beside `nmcp-audit`'s.
    #[error("secret {name} version {version}: {source}")]
    IllegalTransition {
        /// The name.
        name: String,
        /// The version whose state would have moved.
        version: Version,
        /// The transition that was refused.
        #[source]
        source: IllegalTransition,
    },

    /// The migration's source sealer is not the one this store holds.
    ///
    /// Refused once and clearly rather than one failed unseal per blob, which is the same
    /// outcome reported as corruption.
    #[error(
        "migration names {from} as the source and this store seals with {sealer}; open the store with the source sealer to migrate away from it"
    )]
    MigrationSourceMismatch {
        /// The sealer the migration was told to migrate from.
        from: SealerId,
        /// The sealer this store actually holds.
        sealer: SealerId,
    },
}

impl StoreError {
    /// Attach a name and a version to a refused transition.
    fn illegal(name: &SecretName, version: Version, source: IllegalTransition) -> Self {
        Self::IllegalTransition {
            name: name.to_string(),
            version,
            source,
        }
    }
}

impl From<PermsError> for StoreError {
    fn from(error: PermsError) -> Self {
        match error {
            PermsError::Exposed {
                path,
                mode,
                required,
            } => Self::Exposed {
                path,
                mode,
                required,
            },
            PermsError::Failed { path, reason } => Self::Unwritable { path, reason },
        }
    }
}

/// Why a resolution was refused.
///
/// Every variant names the governing rule, which is SB-8's requirement rather than a
/// convenience: a refusal at ring stage 5b rejects the request carrying the reference
/// pre-effect, and the record of that refusal has to say what refused it. There is no
/// degraded mode and no variant meaning "resolved something else instead".
///
/// No variant carries material or any value derived from material, including a length or a
/// digest (SB-1).
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// No secret of that name.
    #[error("no secret named {name} (rule {rule})")]
    UnknownSecret {
        /// The name the grant carried.
        name: String,
        /// The governing rule.
        rule: BindingRuleId,
    },

    /// The secret exists and the version the grant names does not.
    #[error("secret {name} has no version {version} (rule {rule})")]
    UnknownVersion {
        /// The name the grant carried.
        name: String,
        /// The version the grant carried.
        version: Version,
        /// The governing rule.
        rule: BindingRuleId,
    },

    /// The version exists and its state does not resolve.
    #[error("secret {name} version {version} is {state} and does not resolve (rule {rule})")]
    NotResolvable {
        /// The name.
        name: String,
        /// The version.
        version: Version,
        /// The state that refused.
        state: KeyState,
        /// The governing rule.
        rule: BindingRuleId,
    },

    /// The name's file exists and could not be read.
    #[error(
        "secret {name} sits in a document this build could not read and does not resolve (rule {rule})"
    )]
    DamagedEntry {
        /// The name.
        name: String,
        /// The governing rule.
        rule: BindingRuleId,
    },

    /// The version holds no blob sealed by this store's sealer.
    ///
    /// The half-migrated and carried-to-another-machine shape, told apart from corruption
    /// because the remedy is different: open the store with the sealer the blob names.
    #[error(
        "secret {name} version {version} holds no blob sealed by {sealer}; its newest blob is sealed by {sealed_by} (rule {rule})"
    )]
    SealedElsewhere {
        /// The name.
        name: String,
        /// The version.
        version: Version,
        /// The sealer of the version's newest blob.
        sealed_by: SealerId,
        /// The sealer this store holds.
        sealer: SealerId,
        /// The governing rule.
        rule: BindingRuleId,
    },

    /// The blob did not open.
    ///
    /// Which of the causes it was is deliberately absent, for the reason
    /// [`SealError::Unsealable`] gives: distinguishing them is an oracle, and the remedy is
    /// the same. `sealed_by` is an identifier rather than anything derived from a key. The
    /// source is boxed to keep the refusal type small on every `Result` this crate returns.
    #[error("secret {name} version {version} did not open under {sealed_by} (rule {rule})")]
    Unsealable {
        /// The name.
        name: String,
        /// The version.
        version: Version,
        /// The sealer the blob records.
        sealed_by: SealerId,
        /// The governing rule.
        rule: BindingRuleId,
        /// What the sealer objected to, which carries no material either.
        #[source]
        source: Box<SealError>,
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
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use super::{
        DEFAULT_OVERLAP_WINDOW_SECS, ResolveError, STORE_SCHEMA_VERSION, SealedStore, StoreError,
        UnreadableReason,
    };
    use crate::file_sealer::FileSealer;
    use crate::grant::{BindingGrant, BindingRuleId};
    use crate::lifecycle::KeyState;
    use crate::name::{SecretName, Version};
    use crate::sealed::Sealed;
    use crate::sealer::{SealContext, SealError, Sealer, SealerId};
    use crate::testdir::TempDir;

    // - Fixtures -

    /// Distinctive material with no English substring, so the leak assertions below cannot
    /// collide with legitimate error prose such as the word "secret".
    const MATERIAL: &[u8] = b"vq7zx9kw3-jf8ur2-pq5mn1-hty6";

    fn name(text: &str) -> SecretName {
        SecretName::parse(text).unwrap()
    }

    fn sealed(bytes: &[u8]) -> Sealed<Vec<u8>> {
        Sealed::new(bytes.to_vec())
    }

    fn grant(for_name: &SecretName, version: Version) -> BindingGrant {
        BindingGrant::issue(for_name.clone(), version, BindingRuleId::new("test.rule"))
    }

    fn file_sealer(dir: &TempDir, label: &str) -> Box<dyn Sealer> {
        Box::new(FileSealer::open(&dir.path().join(label)).unwrap())
    }

    fn open(dir: &TempDir) -> SealedStore {
        SealedStore::open(&dir.path().join("store"), file_sealer(dir, "keys")).unwrap()
    }

    /// A store whose clock is a shared counter, so the overlap window is walked rather than
    /// slept through.
    fn open_with_clock(dir: &TempDir) -> (SealedStore, Arc<AtomicU64>) {
        let time = Arc::new(AtomicU64::new(1_000_000));
        let handle = Arc::clone(&time);
        let store = SealedStore::open_with_clock(
            &dir.path().join("store"),
            file_sealer(dir, "keys"),
            move || handle.load(Ordering::SeqCst),
        )
        .unwrap();
        (store, time)
    }

    fn exposed(value: &Sealed<Vec<u8>>) -> Vec<u8> {
        value.with_exposed(Vec::clone)
    }

    /// No byte window of `material` four bytes or longer appears in `rendered` (SB-1: not
    /// the value, and nothing derived from it that could reconstruct part of it).
    fn assert_material_absent(rendered: &str, material: &[u8]) {
        let bytes = rendered.as_bytes();
        for width in 4..=material.len() {
            for window in material.windows(width) {
                assert!(
                    !bytes.windows(width).any(|candidate| candidate == window),
                    "a {width}-byte window of the material appears in: {rendered}"
                );
            }
        }
    }

    /// A sealer that refuses everything, for driving material through error paths.
    struct RefusingSealer;

    impl Sealer for RefusingSealer {
        fn seal(&self, _plain: &[u8], _context: &SealContext) -> Result<Vec<u8>, SealError> {
            Err(SealError::NotSealable)
        }

        fn unseal(
            &self,
            _blob: &[u8],
            _context: &SealContext,
        ) -> Result<Sealed<Vec<u8>>, SealError> {
            Err(SealError::Unsealable)
        }

        fn id(&self) -> SealerId {
            SealerId::new("test", "refuses-everything", "0")
        }
    }

    /// Rewrite one field inside a stored document, keeping it valid JSON.
    fn tamper(store_dir: &Path, file: &str, edit: impl FnOnce(&mut serde_json::Value)) {
        let path = store_dir.join("secrets").join(file);
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        edit(&mut value);
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    // - SB-10: storage, round trips and persistence -

    #[test]
    fn a_stored_value_round_trips_and_survives_reopen() {
        let dir = TempDir::new("store-roundtrip");
        let key = name("github.token");
        {
            let store = open(&dir);
            let version = store.set(&key, sealed(MATERIAL)).unwrap();
            assert_eq!(version, Version::first());
            let resolved = store.resolve(grant(&key, version)).unwrap();
            assert_eq!(exposed(&resolved), MATERIAL.to_vec());
        }
        // A second process: same directory, same key directory, nothing carried in memory.
        let store = open(&dir);
        let resolved = store.resolve(grant(&key, Version::first())).unwrap();
        assert_eq!(exposed(&resolved), MATERIAL.to_vec());
        assert!(
            dir.path()
                .join("store")
                .join("secrets")
                .join("github.token.json")
                .is_file(),
            "one document per secret"
        );
    }

    #[test]
    fn names_reports_metadata_and_never_values() {
        let dir = TempDir::new("store-names");
        let store = open(&dir);
        store.set(&name("alpha"), sealed(MATERIAL)).unwrap();
        store
            .set(&name("beta"), sealed(b"btq2-zzv8-xkc4-pp0d"))
            .unwrap();
        store
            .rotate(&name("alpha"), sealed(b"c8r3-wwy7-qqm5-nn1e"))
            .unwrap();

        let metas = store.names();
        assert_eq!(metas.len(), 2);
        let alpha = &metas[0];
        assert_eq!(alpha.name.as_str(), "alpha");
        assert_eq!(alpha.current_version, Some(Version::first().next()));
        assert_eq!(alpha.state, KeyState::Active);
        assert_eq!(alpha.versions.len(), 2);
        assert_eq!(alpha.versions[0].state, KeyState::Superseded);
        assert!(alpha.versions[0].superseded_at_unix_ms.is_some());
        assert_eq!(alpha.versions[1].state, KeyState::Active);
        assert_eq!(metas[1].name.as_str(), "beta");

        // The whole rendered metadata carries nothing derived from any value.
        let rendered = format!("{metas:?}");
        assert_material_absent(&rendered, MATERIAL);
        assert_material_absent(&rendered, b"btq2-zzv8-xkc4-pp0d");
        assert_material_absent(&rendered, b"c8r3-wwy7-qqm5-nn1e");
    }

    #[test]
    fn set_refuses_a_second_value_and_names_rotate() {
        let dir = TempDir::new("store-set-twice");
        let store = open(&dir);
        let key = name("db.password");
        store.set(&key, sealed(b"first-value-zz91")).unwrap();
        let refused = store.set(&key, sealed(b"second-value-zz92")).unwrap_err();
        assert!(matches!(&refused, StoreError::AlreadyExists { name } if name == "db.password"));
        assert!(refused.to_string().contains("rotation"), "{refused}");
    }

    /// SB-2 and SB-R2 at the store surface: a reserved name cannot reach `set`, because no
    /// [`SecretName`] holds one. The type-level refusal is exercised through the parse, which
    /// is the only door.
    #[test]
    fn a_reserved_name_cannot_reach_the_store() {
        for reserved in ["oauth", "oauth/provider"] {
            let refused = SecretName::parse(reserved).unwrap_err();
            assert!(refused.to_string().contains("reserved"), "{refused}");
        }
    }

    /// SB-R2's filter, exercised against a store whose directory really contains an
    /// `oauth`-named document: it is not listed, not resolvable, and reported as set aside.
    #[test]
    fn a_planted_reserved_namespace_file_is_invisible_and_reported() {
        let dir = TempDir::new("store-planted");
        {
            let store = open(&dir);
            store
                .set(&name("legit"), sealed(b"legit-value-aa17"))
                .unwrap();
        }
        // A file named for the reserved namespace, planted beside the real documents.
        let planted = dir.path().join("store").join("secrets").join("oauth.json");
        std::fs::write(&planted, "{\"schema\":1,\"whatever\":true}").unwrap();
        crate::perms::set_mode(&planted, 0o600).unwrap();

        let store = open(&dir);
        let listed: Vec<String> = store
            .names()
            .into_iter()
            .map(|meta| meta.name.as_str().to_string())
            .collect();
        assert_eq!(
            listed,
            vec!["legit".to_string()],
            "the planted file is not listed"
        );
        let unreadable = store.unreadable();
        assert_eq!(unreadable.len(), 1);
        assert!(unreadable[0].file.ends_with("oauth.json"));
        assert_eq!(unreadable[0].reason, UnreadableReason::NameOutsideGrammar);
        // And the untouched key still resolves: the plant cost nothing.
        assert!(
            store
                .resolve(grant(&name("legit"), Version::first()))
                .is_ok()
        );
    }

    // - SB-14: the overlap window, walked with an injected clock, never slept -

    #[test]
    fn a_superseded_version_resolves_within_the_overlap_window() {
        let dir = TempDir::new("store-window-within");
        let (store, time) = open_with_clock(&dir);
        let key = name("api.key");
        let first = store.set(&key, sealed(b"first-value-qq01")).unwrap();
        let second = store.rotate(&key, sealed(b"second-value-qq02")).unwrap();
        assert_eq!(second, first.next());

        // One millisecond before the default window closes: the prior version still answers,
        // which is the drain SB-14 bought.
        time.fetch_add(DEFAULT_OVERLAP_WINDOW_SECS * 1_000 - 1, Ordering::SeqCst);
        let old = store.resolve(grant(&key, first)).unwrap();
        assert_eq!(exposed(&old), b"first-value-qq01".to_vec());
        let new = store.resolve(grant(&key, second)).unwrap();
        assert_eq!(exposed(&new), b"second-value-qq02".to_vec());
        assert_eq!(
            store.names()[0].versions[0].state,
            KeyState::Superseded,
            "still inside the window"
        );
    }

    #[test]
    fn the_prior_version_retires_at_exactly_the_window_and_after_it() {
        let dir = TempDir::new("store-window-after");
        let (store, time) = open_with_clock(&dir);
        let key = name("api.key");
        let first = store.set(&key, sealed(b"first-value-rr01")).unwrap();
        store.rotate(&key, sealed(b"second-value-rr02")).unwrap();

        // At exactly the window: elapsed >= window, so the version is retired. The boundary
        // belongs to the closed side because the window is a drain allowance, not a lease.
        time.fetch_add(DEFAULT_OVERLAP_WINDOW_SECS * 1_000, Ordering::SeqCst);
        let refused = store.resolve(grant(&key, first)).unwrap_err();
        match &refused {
            ResolveError::NotResolvable { state, version, .. } => {
                assert_eq!(*state, KeyState::Retained);
                assert_eq!(*version, first);
            }
            other => panic!("expected NotResolvable, got {other:?}"),
        }
        assert!(refused.to_string().contains("retained"), "{refused}");
        assert!(
            refused.to_string().contains("test.rule"),
            "the rule is named: {refused}"
        );

        // Well after: still retired, and the metadata says so.
        time.fetch_add(3_600_000, Ordering::SeqCst);
        assert_eq!(store.names()[0].versions[0].state, KeyState::Retained);
    }

    #[test]
    fn a_zero_window_is_a_hard_cutover() {
        let dir = TempDir::new("store-window-zero");
        let (store, _time) = open_with_clock(&dir);
        store.set_overlap_window(Duration::ZERO).unwrap();
        let key = name("api.key");
        let first = store.set(&key, sealed(b"first-value-ss01")).unwrap();
        let second = store.rotate(&key, sealed(b"second-value-ss02")).unwrap();

        // The clock never moved: the retirement happened inside `rotate` itself.
        let refused = store.resolve(grant(&key, first)).unwrap_err();
        assert!(
            matches!(
                &refused,
                ResolveError::NotResolvable {
                    state: KeyState::Retained,
                    ..
                }
            ),
            "zero window means retired before rotate returns, got {refused:?}"
        );
        assert!(store.resolve(grant(&key, second)).is_ok());
    }

    #[test]
    fn the_overlap_window_setting_persists_across_reopen() {
        let dir = TempDir::new("store-window-persist");
        {
            let store = open(&dir);
            assert_eq!(
                store.overlap_window(),
                Duration::from_secs(DEFAULT_OVERLAP_WINDOW_SECS)
            );
            store.set_overlap_window(Duration::from_secs(7)).unwrap();
        }
        let store = open(&dir);
        assert_eq!(store.overlap_window(), Duration::from_secs(7));
        assert!(dir.path().join("store").join("store.json").is_file());
    }

    // - SB-14 and INV-1: revocation, tombstones and restores -

    #[test]
    fn quarantine_refuses_immediately_with_no_window() {
        let dir = TempDir::new("store-quarantine");
        let (store, _time) = open_with_clock(&dir);
        let key = name("live.key");
        let first = store.set(&key, sealed(b"value-one-tt01")).unwrap();
        let second = store.rotate(&key, sealed(b"value-two-tt02")).unwrap();

        store.quarantine(&key).unwrap();
        // The clock did not move: both the superseded version, which was mid-window, and the
        // active one refuse instantly. Revocation is a cliff, not a drain (T8).
        for version in [first, second] {
            let refused = store.resolve(grant(&key, version)).unwrap_err();
            assert!(
                matches!(
                    &refused,
                    ResolveError::NotResolvable {
                        state: KeyState::Quarantined,
                        ..
                    }
                ),
                "version {version} must refuse as quarantined, got {refused:?}"
            );
        }
        let meta = &store.names()[0];
        assert_eq!(meta.state, KeyState::Quarantined);
        assert_eq!(meta.current_version, None);
    }

    #[test]
    fn quarantine_is_a_persisted_tombstone_and_deletes_nothing() {
        let dir = TempDir::new("store-tombstone");
        let key = name("revoked.key");
        {
            let store = open(&dir);
            store.set(&key, sealed(b"revoked-value-uu01")).unwrap();
            store.quarantine(&key).unwrap();
        }
        let file = dir
            .path()
            .join("store")
            .join("secrets")
            .join("revoked.key.json");
        assert!(
            file.is_file(),
            "the tombstone is the document, still present"
        );
        // A later process reads the tombstone back: still quarantined, still refusing.
        let store = open(&dir);
        assert_eq!(store.names()[0].state, KeyState::Quarantined);
        assert!(matches!(
            store.resolve(grant(&key, Version::first())).unwrap_err(),
            ResolveError::NotResolvable {
                state: KeyState::Quarantined,
                ..
            }
        ));
        // And nothing rotates a revoked key back into service by accident.
        let refused = store.rotate(&key, sealed(b"new-value-uu02")).unwrap_err();
        assert!(
            matches!(&refused, StoreError::NotInService { .. }),
            "{refused:?}"
        );
        assert!(refused.to_string().contains("restored"), "{refused}");
    }

    #[test]
    fn restore_returns_each_version_to_the_state_it_was_quarantined_from() {
        let dir = TempDir::new("store-restore");
        let (store, _time) = open_with_clock(&dir);
        let key = name("cycled.key");
        let first = store.set(&key, sealed(b"value-one-vv01")).unwrap();
        let second = store.rotate(&key, sealed(b"value-two-vv02")).unwrap();
        // first is Superseded and mid-window; second is Active.
        store.quarantine(&key).unwrap();
        store.restore(&key).unwrap();

        let meta = &store.names()[0];
        assert_eq!(meta.current_version, Some(second));
        assert_eq!(
            meta.versions[0].state,
            KeyState::Superseded,
            "back where it was, not active"
        );
        assert_eq!(meta.versions[1].state, KeyState::Active);
        // Both resolve again: the superseded one because its window has still not elapsed on
        // the injected clock.
        assert!(store.resolve(grant(&key, first)).is_ok());
        assert!(store.resolve(grant(&key, second)).is_ok());
    }

    /// SB-14's "restorable by operator" for a key whose every version had drained. This shape
    /// is not produced by this crate's own writers, so it arrives the way it would in the
    /// field: in a document some other generation wrote.
    #[test]
    fn restore_promotes_the_highest_retained_version_when_nothing_returns_to_service() {
        let dir = TempDir::new("store-promote");
        let key = name("drained.key");
        {
            let store = open(&dir);
            store.set(&key, sealed(b"old-value-ww01")).unwrap();
            store.rotate(&key, sealed(b"new-value-ww02")).unwrap();
        }
        // Rewrite the document so both versions are Retained: a drained key.
        tamper(&dir.path().join("store"), "drained.key.json", |value| {
            for record in value["versions"].as_object_mut().unwrap().values_mut() {
                record["lifecycle"] = serde_json::json!("retained");
                record
                    .as_object_mut()
                    .unwrap()
                    .remove("superseded_at_unix_ms");
            }
        });
        let store = open(&dir);
        assert_eq!(store.names()[0].current_version, None);
        store.restore(&key).unwrap();
        let meta = &store.names()[0];
        assert_eq!(
            meta.current_version,
            Some(Version::first().next()),
            "the highest is promoted"
        );
        let restored = store.resolve(grant(&key, Version::first().next())).unwrap();
        assert_eq!(exposed(&restored), b"new-value-ww02".to_vec());
        // The older retained version stays retained: promotion is one version, not a flood.
        assert_eq!(meta.versions[0].state, KeyState::Retained);
    }

    #[test]
    fn the_write_surface_refuses_what_the_lifecycle_refuses() {
        let dir = TempDir::new("store-refusals");
        let store = open(&dir);
        let key = name("k");
        assert!(matches!(
            store.rotate(&key, sealed(b"v")).unwrap_err(),
            StoreError::UnknownSecret { .. }
        ));
        assert!(matches!(
            store.quarantine(&key).unwrap_err(),
            StoreError::UnknownSecret { .. }
        ));
        store.set(&key, sealed(b"v-xx01")).unwrap();
        assert!(matches!(
            store.restore(&key).unwrap_err(),
            StoreError::NothingToRestore { .. }
        ));
        store.quarantine(&key).unwrap();
        let twice = store.quarantine(&key).unwrap_err();
        assert!(
            matches!(&twice, StoreError::NothingToQuarantine { .. }),
            "{twice:?}"
        );
        assert!(twice.to_string().contains("already quarantined"), "{twice}");
    }

    // - SB-10: corruption isolates one key -

    #[test]
    fn a_corrupted_blob_isolates_one_key() {
        let dir = TempDir::new("store-corrupt-blob");
        let good = name("good.key");
        let bad = name("bad.key");
        {
            let store = open(&dir);
            store.set(&good, sealed(b"good-value-yy01")).unwrap();
            store.set(&bad, sealed(MATERIAL)).unwrap();
        }
        // Corrupt one hex character of the bad key's only blob; the document stays valid
        // JSON, so this is blob corruption rather than document corruption.
        tamper(&dir.path().join("store"), "bad.key.json", |value| {
            let blob = &mut value["versions"]["1"]["blobs"][0]["blob_hex"];
            let mut text = blob.as_str().unwrap().to_string();
            let flipped = if text.starts_with('0') { "f" } else { "0" };
            text.replace_range(0..1, flipped);
            *blob = serde_json::Value::String(text);
        });
        let store = open(&dir);
        // The corrupted key refuses, names the sealer that should have opened it, and leaks
        // nothing about what it held.
        let refused = store.resolve(grant(&bad, Version::first())).unwrap_err();
        assert!(
            matches!(&refused, ResolveError::Unsealable { .. }),
            "{refused:?}"
        );
        assert_material_absent(&refused.to_string(), MATERIAL);
        assert_material_absent(&format!("{refused:?}"), MATERIAL);
        // The other key never noticed.
        let resolved = store.resolve(grant(&good, Version::first())).unwrap();
        assert_eq!(exposed(&resolved), b"good-value-yy01".to_vec());
    }

    #[test]
    fn a_corrupt_document_isolates_one_key_and_is_reported() {
        let dir = TempDir::new("store-corrupt-doc");
        let good = name("good.key");
        let bad = name("bad.key");
        {
            let store = open(&dir);
            store.set(&good, sealed(b"good-value-zz01")).unwrap();
            store.set(&bad, sealed(b"bad-value-zz02")).unwrap();
        }
        let bad_file = dir
            .path()
            .join("store")
            .join("secrets")
            .join("bad.key.json");
        std::fs::write(&bad_file, b"not json at all \x7f\x03").unwrap();

        let store = open(&dir);
        assert_eq!(store.names().len(), 1, "one key loads, one is set aside");
        let unreadable = store.unreadable();
        assert_eq!(unreadable.len(), 1);
        assert_eq!(unreadable[0].reason, UnreadableReason::NotASecretDocument);
        assert!(store.resolve(grant(&good, Version::first())).is_ok());
        // The damaged key fails closed with the damage named, not as "unknown".
        let refused = store.resolve(grant(&bad, Version::first())).unwrap_err();
        assert!(
            matches!(&refused, ResolveError::DamagedEntry { .. }),
            "{refused:?}"
        );
        // And no write will touch the damaged file (INV-1).
        let set_refused = store.set(&bad, sealed(b"replacement-zz03")).unwrap_err();
        assert!(
            matches!(&set_refused, StoreError::DamagedEntry { .. }),
            "{set_refused:?}"
        );
        assert_eq!(
            std::fs::read(&bad_file).unwrap(),
            b"not json at all \x7f\x03".to_vec(),
            "the damaged file is byte-identical after every refusal"
        );
    }

    #[test]
    fn a_document_copied_onto_another_name_is_refused() {
        let dir = TempDir::new("store-name-mismatch");
        {
            let store = open(&dir);
            store
                .set(&name("original"), sealed(b"original-value-ab12"))
                .unwrap();
        }
        let secrets = dir.path().join("store").join("secrets");
        std::fs::copy(secrets.join("original.json"), secrets.join("copied.json")).unwrap();
        crate::perms::set_mode(&secrets.join("copied.json"), 0o600).unwrap();

        let store = open(&dir);
        let listed: Vec<String> = store
            .names()
            .into_iter()
            .map(|meta| meta.name.as_str().to_string())
            .collect();
        assert_eq!(listed, vec!["original".to_string()]);
        let unreadable = store.unreadable();
        assert_eq!(unreadable.len(), 1);
        assert_eq!(unreadable[0].reason, UnreadableReason::NameMismatch);
    }

    #[test]
    fn foreign_document_shapes_are_isolated_by_their_defect() {
        let dir = TempDir::new("store-foreign");
        {
            let store = open(&dir);
            store
                .set(&name("anchor"), sealed(b"anchor-value-cd34"))
                .unwrap();
        }
        let secrets = dir.path().join("store").join("secrets");
        // No versions at all.
        std::fs::write(
            secrets.join("empty.json"),
            serde_json::json!({
                "schema": 1, "name": "empty", "created_at_unix_ms": 0, "versions": {}
            })
            .to_string(),
        )
        .unwrap();
        // Version zero, which no secret has.
        std::fs::write(
            secrets.join("zeroed.json"),
            serde_json::json!({
                "schema": 1, "name": "zeroed", "created_at_unix_ms": 0,
                "versions": { "0": {
                    "lifecycle": "active", "created_at_unix_ms": 0,
                    "blobs": [{ "sealed_by": "x", "blob_hex": "00", "sealed_at_unix_ms": 0 }]
                } }
            })
            .to_string(),
        )
        .unwrap();
        // Two versions both claiming to be in service.
        let active = serde_json::json!({
            "lifecycle": "active", "created_at_unix_ms": 0,
            "blobs": [{ "sealed_by": "x", "blob_hex": "00", "sealed_at_unix_ms": 0 }]
        });
        std::fs::write(
            secrets.join("doubled.json"),
            serde_json::json!({
                "schema": 1, "name": "doubled", "created_at_unix_ms": 0,
                "versions": { "1": active.clone(), "2": active }
            })
            .to_string(),
        )
        .unwrap();
        // A version with no blob: it names a value that is not there.
        std::fs::write(
            secrets.join("blobless.json"),
            serde_json::json!({
                "schema": 1, "name": "blobless", "created_at_unix_ms": 0,
                "versions": { "1": {
                    "lifecycle": "active", "created_at_unix_ms": 0, "blobs": []
                } }
            })
            .to_string(),
        )
        .unwrap();
        for file in ["empty.json", "zeroed.json", "doubled.json", "blobless.json"] {
            crate::perms::set_mode(&secrets.join(file), 0o600).unwrap();
        }

        let store = open(&dir);
        assert_eq!(store.names().len(), 1);
        let mut reasons: Vec<(String, UnreadableReason)> = store
            .unreadable()
            .into_iter()
            .map(|entry| {
                let file = Path::new(&entry.file)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                (file, entry.reason)
            })
            .collect();
        reasons.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(
            reasons,
            vec![
                (
                    "blobless.json".to_string(),
                    UnreadableReason::VersionWithoutBlobs
                ),
                (
                    "doubled.json".to_string(),
                    UnreadableReason::AmbiguousActiveVersion
                ),
                ("empty.json".to_string(), UnreadableReason::NoVersions),
                (
                    "zeroed.json".to_string(),
                    UnreadableReason::NotASecretDocument
                ),
            ]
        );
    }

    /// `Suspended` is a state nothing in this crate enters at I-033 (the tripwire that
    /// suspends is I-035), and the store still reads documents that hold it. Revoking such a
    /// key and restoring it must round-trip back to `Suspended`, not fail and not widen to
    /// `Active`: a quarantine that no restore can reverse is a trap on a legal operator
    /// sequence, and a restore that returns a suspended version to service hands
    /// revoke-plus-restore more authority than the operator had.
    #[test]
    fn a_suspended_version_survives_quarantine_and_restore_as_suspended() {
        let dir = TempDir::new("store-suspended");
        let key = name("paused.key");
        {
            let store = open(&dir);
            store.set(&key, sealed(b"paused-value-gk21")).unwrap();
        }
        tamper(&dir.path().join("store"), "paused.key.json", |value| {
            value["versions"]["1"]["lifecycle"] = serde_json::json!("suspended");
        });
        let store = open(&dir);
        assert_eq!(store.names()[0].state, KeyState::Suspended);
        // Suspended does not resolve.
        assert!(matches!(
            store.resolve(grant(&key, Version::first())).unwrap_err(),
            ResolveError::NotResolvable {
                state: KeyState::Suspended,
                ..
            }
        ));
        store.quarantine(&key).unwrap();
        assert_eq!(store.names()[0].state, KeyState::Quarantined);
        store.restore(&key).unwrap();
        assert_eq!(
            store.names()[0].state,
            KeyState::Suspended,
            "back where it was: not active, not stuck"
        );
    }

    #[test]
    fn a_future_schema_is_refused_rather_than_guessed_at() {
        let dir = TempDir::new("store-future-schema");
        {
            let store = open(&dir);
            store.set(&name("k"), sealed(b"v-ef56")).unwrap();
        }
        tamper(&dir.path().join("store"), "k.json", |value| {
            value["schema"] = serde_json::json!(STORE_SCHEMA_VERSION + 1);
        });
        let refused =
            SealedStore::open(&dir.path().join("store"), file_sealer(&dir, "keys")).unwrap_err();
        match &refused {
            StoreError::UnknownSchema { found, known, .. } => {
                assert_eq!(*found, u64::from(STORE_SCHEMA_VERSION + 1));
                assert_eq!(*known, STORE_SCHEMA_VERSION);
            }
            other => panic!("expected UnknownSchema, got {other:?}"),
        }
        assert!(
            refused.to_string().contains("refused rather than guessed"),
            "{refused}"
        );
    }

    // - SB-15: the grant, bound to its subject -

    #[test]
    fn a_grant_for_one_key_resolves_that_key_and_not_another() {
        let dir = TempDir::new("store-grant-subject");
        let store = open(&dir);
        let alpha = name("alpha");
        let beta = name("beta");
        store.set(&alpha, sealed(b"alpha-value-gh78")).unwrap();
        store.set(&beta, sealed(b"beta-value-ij90")).unwrap();

        // `resolve` takes the grant and nothing else, so the only key a grant can yield is
        // the one on its face; asserted on the material itself.
        let resolved = store.resolve(grant(&alpha, Version::first())).unwrap();
        assert_eq!(exposed(&resolved), b"alpha-value-gh78".to_vec());
        assert_ne!(
            exposed(&store.resolve(grant(&beta, Version::first())).unwrap()),
            b"alpha-value-gh78".to_vec()
        );
    }

    #[test]
    fn a_grant_for_what_does_not_exist_is_refused_naming_the_rule() {
        let dir = TempDir::new("store-grant-missing");
        let store = open(&dir);
        store
            .set(&name("real"), sealed(b"real-value-kl12"))
            .unwrap();

        let unknown = store
            .resolve(grant(&name("ghost"), Version::first()))
            .unwrap_err();
        assert!(
            matches!(&unknown, ResolveError::UnknownSecret { .. }),
            "{unknown:?}"
        );
        assert!(unknown.to_string().contains("test.rule"), "{unknown}");

        let missing_version = store
            .resolve(grant(&name("real"), Version::from_number(9).unwrap()))
            .unwrap_err();
        assert!(
            matches!(&missing_version, ResolveError::UnknownVersion { .. }),
            "{missing_version:?}"
        );
        assert!(
            missing_version.to_string().contains("test.rule"),
            "{missing_version}"
        );
    }

    // - SB-12 shape: migration between sealers -

    #[test]
    fn migrate_reseals_alongside_and_round_trips_between_sealers() {
        let dir = TempDir::new("store-migrate");
        let store_dir = dir.path().join("store");
        let key = name("moving.key");
        let second_value: &[u8] = b"second-value-mn34";
        {
            let store = SealedStore::open(&store_dir, file_sealer(&dir, "keys-a")).unwrap();
            store.set(&key, sealed(b"first-value-mn33")).unwrap();
            store.rotate(&key, sealed(second_value)).unwrap();

            let target = FileSealer::open(&dir.path().join("keys-b")).unwrap();
            let report = store.migrate(store.sealer_id(), &target).unwrap();
            assert_eq!(report.migrated.len(), 2, "both versions reseal");
            assert!(report.skipped.is_empty());
            assert!(report.failed.is_empty());

            // Idempotent: a second run finds everything already at the target.
            let again = store.migrate(store.sealer_id(), &target).unwrap();
            assert!(again.migrated.is_empty());
            assert_eq!(again.skipped.len(), 2);
            assert!(again.skipped.iter().all(|entry| entry.already_at_target));
        }
        // The next process opens with the target sealer and everything resolves.
        {
            let store = SealedStore::open(&store_dir, file_sealer(&dir, "keys-b")).unwrap();
            let resolved = store.resolve(grant(&key, Version::first().next())).unwrap();
            assert_eq!(exposed(&resolved), second_value.to_vec());
        }
        // And the old blobs were retained alongside (INV-1): the old sealer still works too,
        // which is what makes an interrupted migration recoverable.
        {
            let store = SealedStore::open(&store_dir, file_sealer(&dir, "keys-a")).unwrap();
            let resolved = store.resolve(grant(&key, Version::first().next())).unwrap();
            assert_eq!(exposed(&resolved), second_value.to_vec());
        }
    }

    #[test]
    fn migrate_refuses_a_source_that_is_not_the_stores_sealer() {
        let dir = TempDir::new("store-migrate-mismatch");
        let store = open(&dir);
        store.set(&name("k"), sealed(b"v-op56")).unwrap();
        let stranger = FileSealer::open(&dir.path().join("keys-stranger")).unwrap();
        let refused = store.migrate(stranger.id(), &stranger).unwrap_err();
        match &refused {
            StoreError::MigrationSourceMismatch { from, sealer } => {
                assert_eq!(*from, stranger.id());
                assert_eq!(*sealer, store.sealer_id());
            }
            other => panic!("expected MigrationSourceMismatch, got {other:?}"),
        }
        assert!(
            refused
                .to_string()
                .contains("open the store with the source sealer"),
            "{refused}"
        );
    }

    #[test]
    fn migrate_skips_and_reports_a_version_whose_blobs_from_does_not_match() {
        let dir = TempDir::new("store-migrate-skip");
        let store_dir = dir.path().join("store");
        let stranded = name("stranded.key");
        let native = name("native.key");
        // `stranded` is written under sealer A; `native` under sealer B.
        {
            let store = SealedStore::open(&store_dir, file_sealer(&dir, "keys-a")).unwrap();
            store
                .set(&stranded, sealed(b"stranded-value-qr78"))
                .unwrap();
        }
        let store = SealedStore::open(&store_dir, file_sealer(&dir, "keys-b")).unwrap();
        store.set(&native, sealed(b"native-value-st90")).unwrap();

        // Migrating from B: the A-sealed version holds no blob `from` matches, so it is
        // refused individually, skipped, and reported with the sealer that does hold it.
        let target = FileSealer::open(&dir.path().join("keys-c")).unwrap();
        let report = store.migrate(store.sealer_id(), &target).unwrap();
        assert_eq!(report.migrated.len(), 1);
        assert_eq!(report.migrated[0].name, native);
        assert_eq!(report.skipped.len(), 1);
        let skipped = &report.skipped[0];
        assert_eq!(skipped.name, stranded);
        assert!(!skipped.already_at_target);
        let sealer_a = FileSealer::open(&dir.path().join("keys-a")).unwrap();
        assert_eq!(skipped.sealed_by, vec![sealer_a.id()]);

        // Resolving the stranded key under B names the sealer it wants, told apart from
        // corruption because the remedy is different.
        let refused = store
            .resolve(grant(&stranded, Version::first()))
            .unwrap_err();
        match &refused {
            ResolveError::SealedElsewhere {
                sealed_by, sealer, ..
            } => {
                assert_eq!(*sealed_by, sealer_a.id());
                assert_eq!(*sealer, store.sealer_id());
            }
            other => panic!("expected SealedElsewhere, got {other:?}"),
        }
    }

    // - SB-1 and SB-8: the error discipline, measured -

    /// Every error constructed from an operation that touched sealed material renders, in
    /// both `Display` and `Debug`, with no byte subsequence of that material. This is SB-1's
    /// "no error type carries material or any value derived from it" as a measurement rather
    /// than a review comment.
    #[test]
    fn no_error_reachable_from_material_describes_it() {
        let mut rendered: Vec<String> = Vec::new();

        // A sealer that refuses to seal: the material was in hand when the error was built.
        let refusing = SealedStore::open(
            &TempDir::new("store-leak-refusing").path().join("store"),
            Box::new(RefusingSealer),
        )
        .unwrap();
        let seal_refused = refusing.set(&name("k"), sealed(MATERIAL)).unwrap_err();
        rendered.push(seal_refused.to_string());
        rendered.push(format!("{seal_refused:?}"));

        // A store that sealed the material and then finds the blob corrupted.
        let dir = TempDir::new("store-leak-corrupt");
        {
            let store = open(&dir);
            store.set(&name("k"), sealed(MATERIAL)).unwrap();
        }
        tamper(&dir.path().join("store"), "k.json", |value| {
            value["versions"]["1"]["blobs"][0]["blob_hex"] = serde_json::json!("00ff00ff");
        });
        let store = open(&dir);
        let unsealable = store
            .resolve(grant(&name("k"), Version::first()))
            .unwrap_err();
        rendered.push(unsealable.to_string());
        rendered.push(format!("{unsealable:?}"));

        // The refusals that never had the material still get measured: they carry the name,
        // the version, the state and the rule, and must carry nothing else.
        let dir2 = TempDir::new("store-leak-states");
        let store2 = open(&dir2);
        store2.set(&name("k"), sealed(MATERIAL)).unwrap();
        rendered.push(
            store2
                .set(&name("k"), sealed(MATERIAL))
                .unwrap_err()
                .to_string(),
        );
        store2.quarantine(&name("k")).unwrap();
        let quarantined = store2
            .resolve(grant(&name("k"), Version::first()))
            .unwrap_err();
        rendered.push(quarantined.to_string());
        rendered.push(format!("{quarantined:?}"));

        for text in &rendered {
            assert_material_absent(text, MATERIAL);
        }
    }

    // - The rest of the surface -

    #[test]
    fn an_ephemeral_store_is_the_same_surface_with_nothing_on_disk() {
        let store = SealedStore::ephemeral();
        let key = name("mem.key");
        let first = store.set(&key, sealed(b"mem-value-uv12")).unwrap();
        let second = store.rotate(&key, sealed(b"mem-value-uv13")).unwrap();
        assert_eq!(
            exposed(&store.resolve(grant(&key, second)).unwrap()),
            b"mem-value-uv13"
        );
        store.quarantine(&key).unwrap();
        assert!(store.resolve(grant(&key, first)).is_err());
        store.restore(&key).unwrap();
        assert!(store.resolve(grant(&key, second)).is_ok());
        assert!(store.unreadable().is_empty());
        assert_eq!(store.names().len(), 1);
    }

    #[test]
    fn the_ephemeral_clock_seam_walks_the_window_too() {
        let time = Arc::new(AtomicU64::new(500_000));
        let handle = Arc::clone(&time);
        let store = SealedStore::ephemeral_with_clock(move || handle.load(Ordering::SeqCst));
        let key = name("mem.key");
        let first = store.set(&key, sealed(b"one-wx34")).unwrap();
        store.rotate(&key, sealed(b"two-wx35")).unwrap();
        assert!(
            store.resolve(grant(&key, first)).is_ok(),
            "within the window"
        );
        time.fetch_add(DEFAULT_OVERLAP_WINDOW_SECS * 1_000, Ordering::SeqCst);
        assert!(
            matches!(
                store.resolve(grant(&key, first)).unwrap_err(),
                ResolveError::NotResolvable {
                    state: KeyState::Retained,
                    ..
                }
            ),
            "after the window"
        );
    }

    #[test]
    fn the_store_debug_form_names_no_secret() {
        let dir = TempDir::new("store-debug");
        let store = open(&dir);
        store
            .set(&name("hidden.name"), sealed(b"hidden-value-yz56"))
            .unwrap();
        let rendered = format!("{store:?}");
        assert!(!rendered.contains("hidden.name"), "{rendered}");
        assert!(rendered.contains("SealedStore"), "{rendered}");
    }

    #[test]
    fn version_saturation_refuses_rotation_rather_than_wrapping() {
        let dir = TempDir::new("store-saturate");
        let key = name("maxed.key");
        {
            let store = open(&dir);
            store.set(&key, sealed(b"maxed-value-za78")).unwrap();
        }
        // Push the stored version number to the counter's ceiling by hand; walking there
        // through four billion rotations is not a test.
        tamper(&dir.path().join("store"), "maxed.key.json", |value| {
            let versions = value["versions"].as_object_mut().unwrap();
            let record = versions.remove("1").unwrap();
            versions.insert(u32::MAX.to_string(), record);
        });
        let store = open(&dir);
        let refused = store.rotate(&key, sealed(b"next-value-za79")).unwrap_err();
        match &refused {
            StoreError::VersionsExhausted { highest, .. } => {
                assert_eq!(highest.get(), u32::MAX);
            }
            other => panic!("expected VersionsExhausted, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_store_its_directories_and_documents_are_restricted() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("store-modes");
        let store_dir = dir.path().join("store");
        {
            let store = open(&dir);
            store.set(&name("k"), sealed(b"v-ab90")).unwrap();
        }
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&store_dir), 0o700);
        assert_eq!(mode(&store_dir.join("secrets")), 0o700);
        assert_eq!(mode(&store_dir.join("secrets").join("k.json")), 0o600);

        // A widened document refuses the open: on this deployment the mode is the guarantee.
        std::fs::set_permissions(
            store_dir.join("secrets").join("k.json"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let refused = SealedStore::open(&store_dir, file_sealer(&dir, "keys")).unwrap_err();
        assert!(
            matches!(&refused, StoreError::Exposed { mode: 0o644, .. }),
            "{refused:?}"
        );
        std::fs::set_permissions(
            store_dir.join("secrets").join("k.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(SealedStore::open(&store_dir, file_sealer(&dir, "keys")).is_ok());
    }

    /// INV-1, measured on the filesystem: a full workflow only ever adds files.
    #[test]
    fn nothing_on_the_operator_surface_ever_deletes_a_file() {
        let dir = TempDir::new("store-no-delete");
        let store_dir = dir.path().join("store");
        let list = |dir: &Path| -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(dir.join("secrets"))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        let store = SealedStore::open(&store_dir, file_sealer(&dir, "keys")).unwrap();
        let key = name("kept.key");
        store.set(&key, sealed(b"v1-cd12")).unwrap();
        let after_set = list(&store_dir);
        store.rotate(&key, sealed(b"v2-cd13")).unwrap();
        store.quarantine(&key).unwrap();
        store.restore(&key).unwrap();
        let target = FileSealer::open(&dir.path().join("keys-next")).unwrap();
        store.migrate(store.sealer_id(), &target).unwrap();
        store.set_overlap_window(Duration::from_secs(1)).unwrap();
        let after_everything = list(&store_dir);
        assert_eq!(
            after_set, after_everything,
            "the same files, every one still present"
        );
        // And the versions only accumulated: two versions, each with its original blob, the
        // migrated one alongside.
        let meta = &store.names()[0];
        assert_eq!(meta.versions.len(), 2);
    }

    #[test]
    fn the_store_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SealedStore>();
    }
}
