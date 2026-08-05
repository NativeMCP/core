//! `nmcp-secrets`
//!
//! Part of the NativeMCP `core` workspace. The governance invariants in
//! `docs/GOVERNANCE.md` are normative for every item in this crate.
//!
//! ## What this crate is
//!
//! NMCP-SPEC-002, RATIFIED v1.1, section 3 names this as a **new** crate, created under
//! NMCP-SPEC-001 R-4 placement: the sealed store, the [`Sealer`] abstraction, the core file
//! sealer, [`Sealed<T>`](Sealed), the key lifecycle state machine, the binding grant, and,
//! from I-036 under the v1.1 revision, the [`KeyBinding`] model and its evaluator. It is the
//! half of the secret broker that owns material at rest and decides what a resolution is.
//! Every type here is real, wired and tested, and none of it is a mock (SB-A7, INV-6).
//!
//! ## What this crate is not, which is the I-033/I-036 boundary
//!
//! Nothing here is reachable from a tool call, and that is the scope rather than a gap with no
//! owner. Resolution wiring at ring stage 5b and the audit records for every store operation
//! are I-034, which is the first code with both a dispatch path and an `AuditSink` in scope;
//! it is where [`SealedStore::evaluate`] and [`SealedStore::resolve`] get their production
//! caller. The exfiltration tripwire is I-035. The operator command surface, `nmcpctl`, is
//! I-037 and I-038, and until it lands the write half below has no production caller, exactly
//! as NMCP-SPEC-002 SB-13 sequences it.
//!
//! ## Dependency discipline
//!
//! This crate depends on `nmcp-schema` and nothing else in the workspace, so that SB-2's name
//! grammar has exactly one implementation: [`SecretName`] parses by asking whether a reference
//! to the name would parse, and the reference parser is I-032's, in `nmcp-schema`. Two copies
//! of one grammar is how list and call come to disagree, which NMCP-SPEC-002 SB-2 records
//! having already happened three times in the base. The edge is acyclic under NMCP-SPEC-003
//! RC-D1: `nmcp-secrets -> nmcp-schema -> nmcp-policy -> nmcp-identity`, and nothing depends
//! on this crate today.
//!
//! ## Where binding evaluation lives, ruled at v1.1 (I-036)
//!
//! NMCP-SPEC-002 v1.0's section 3 placed "`KeyBinding` evaluation (SB-6)" in `nmcp-policy`,
//! and SB-15 makes [`BindingGrant`] constructible only by the binding evaluator. I-033 proved
//! those two placements cannot both hold: a constructor callable from `nmcp-policy` means
//! `nmcp-policy -> nmcp-secrets`, and with this crate's `nmcp-secrets -> nmcp-schema` edge and
//! RC-1's `nmcp-schema -> nmcp-policy` edge that is a dependency cycle, the exact shape RC-D1
//! exists to prevent, confirmed with cargo tree. The v1.1 revision rules on it, following
//! SB-13's own text: bindings are written only through the operator surface, per key, so they
//! are per-key store metadata, and the crate that owns the store owns the evaluator.
//! Unforgeability then costs nothing, because the grant constructor never crosses a crate
//! boundary. [`SealedStore::evaluate`] is that evaluator and the only production path that
//! mints a grant; `nmcp-policy` retains no binding role, and INV-4 stays as the evaluation
//! model rather than a location. The host wires the two at ring stage 5b (I-034): it reads
//! nothing secret, holds the store handle, and passes the request context in. The model, the
//! evaluation order, the use budget's home (G-2) and the decrement-at-mint ruling are argued
//! in the binding module's documentation, `src/binding.rs`.
//!
//! ## The platform position on at-rest protection
//!
//! On Unix the store directory and the sealer's key directory are created at mode `0700`,
//! their files at `0600`, and both are verified on every open, refusing rather than repairing
//! (SB-11). On Windows this crate applies no restriction of its own and files inherit the
//! parent directory's default ACLs; that is NMCP-SPEC-002's stated position, not an oversight
//! in this crate: the Windows answer is the DPAPI sealer, which ships in the platform
//! repository at W3 with machine-scope sealing and the DACL the base already writes.
//! [`FileSealer::key_protection`] reports which of the two a running deployment actually has.
//!
//! ## Error discipline
//!
//! SB-1 and SB-8, applied to every error type here: each refusal names the governing rule, and
//! no variant carries material or any value derived from material, including a length or a
//! digest. The store's tests drive material through every reachable failure path and assert
//! that no rendered error contains any byte subsequence of it.

mod binding;
mod file_sealer;
mod grant;
mod lifecycle;
mod name;
mod perms;
mod sealed;
mod sealer;
mod store;

pub use binding::{BINDING_SCHEMA_VERSION, BindingDenial, BindingRequest, KeyBinding, UseBudget};
pub use file_sealer::{
    FileSealer, KEY_DIR_MODE, KEY_FILE, KEY_FILE_MODE, KeyProtection, MemorySealer, default_key_dir,
};
pub use grant::{BindingGrant, BindingRuleId};
pub use lifecycle::{IllegalTransition, KeyLifecycle, KeyState};
pub use name::{SecretName, SecretNameError, Version, VersionError};
pub use sealed::Sealed;
pub use sealer::{SECRET_ENTROPY, SealContext, SealError, Sealer, SealerId};
pub use store::{
    DEFAULT_OVERLAP_WINDOW_SECS, MigrationEntry, MigrationReport, ResolveError, SECRETS_DIR,
    STORE_CONFIG_FILE, STORE_SCHEMA_VERSION, SealedStore, SecretMeta, SkippedEntry, StoreError,
    UnreadableEntry, UnreadableReason, VersionMeta,
};

/// Semantic version of this crate, taken from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate identity as it appears in audit records and capability manifests.
pub const COMPONENT: &str = "nmcp-secrets";

#[cfg(test)]
mod testdir {
    //! Unique, self-cleaning temporary directories for this crate's tests.
    //!
    //! Test-only by construction: the module is `#[cfg(test)]`, so the removal in `Drop` is
    //! compiled out of the release binary and sits outside INV-1's scope, which covers
    //! dependency paths reachable from a tool handler. Production code in this crate calls no
    //! destructive filesystem primitive at all.

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

    /// Distinguishes directories within one process; the process id distinguishes runs.
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A directory under the system temporary root that removes itself on drop.
    pub(crate) struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        /// Create a fresh directory whose name carries `label` for post-mortem readability.
        pub(crate) fn new(label: &str) -> Self {
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "nmcp-secrets-{label}-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("test temp dir is creatable");
            // Restricted like everything else in this crate, so a test may hand the
            // directory itself to a sealer or a store, both of which refuse a wide mode.
            crate::perms::set_mode(&path, 0o700).expect("test temp dir mode is settable");
            Self { path }
        }

        /// The directory's path.
        pub(crate) fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
