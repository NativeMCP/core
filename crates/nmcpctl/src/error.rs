//! The command surface's error type, and the three exit classes it maps to.
//!
//! NMCP-SPEC-002 SB-8's posture applied to a CLI: a refusal prints the refusing library's own
//! `Display`, because those errors name their governing rules by design, and inventing a
//! paraphrase here would be a second copy of the rule that drifts. Exit codes are distinct per
//! class so a script can tell a rule that refused from a disk that failed from a command line
//! that never parsed:
//!
//! - [`EXIT_REFUSAL`] (1): a governing rule refused the operation. The store, the sealer, the
//!   name grammar, the policy loader and this crate's own confirmations all land here.
//! - [`EXIT_USAGE`] (2): the invocation itself is wrong, which is also the code `clap` exits
//!   with for a command line it cannot parse.
//! - [`EXIT_IO`] (3): this crate's own reads and writes failed: a binding file that cannot be
//!   read, a stream that cannot be written. The store's `Unreadable`/`Unwritable` variants
//!   stay in the refusal class deliberately, because they are refusals with named rules and
//!   remedies, not anonymous stream failures.
//!
//! No variant carries secret material or anything derived from it (SB-1): every wrapped error
//! already holds that property, and this crate's own variants carry names, paths and prose.

use nmcp_secrets::{SealError, SecretNameError, StoreError};

/// Exit code for an operation a governing rule refused.
pub const EXIT_REFUSAL: u8 = 1;

/// Exit code for an invocation that is itself wrong; `clap` uses the same code.
pub const EXIT_USAGE: u8 = 2;

/// Exit code for a read or write this crate could not perform.
pub const EXIT_IO: u8 = 3;

/// Which exit code an error maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClass {
    /// A governing rule refused the operation.
    Refusal,
    /// The invocation is wrong.
    Usage,
    /// A read or write failed.
    Io,
}

impl ExitClass {
    /// The process exit code for this class.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Refusal => EXIT_REFUSAL,
            Self::Usage => EXIT_USAGE,
            Self::Io => EXIT_IO,
        }
    }
}

/// Why a command did not complete.
///
/// Wrapped library errors are `#[error(transparent)]`: what prints is the library's own
/// `Display`, verbatim, because SB-8 requires the governing rule named and those messages are
/// where the rules live.
#[derive(Debug, thiserror::Error)]
pub enum CtlError {
    /// The sealed store refused the operation; the message names the governing rule.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// The sealer refused; the message names the file or the missing capability.
    #[error(transparent)]
    Seal(#[from] SealError),

    /// The name is not one the operator surface may write (SB-2), including every reserved
    /// namespace; the message is the grammar's own refusal.
    #[error(transparent)]
    Name(#[from] SecretNameError),

    /// The policy loader refused the document; the message is the loader's own.
    #[error(transparent)]
    Policy(#[from] nmcp_policy::PolicyError),

    /// This crate refused, for a reason of its own: a missing confirmation, an empty value,
    /// a path that already exists, a verification that reported tampering.
    #[error("{reason}")]
    Refusal {
        /// What refused, with the remedy where one exists.
        reason: String,
    },

    /// The invocation cannot be acted on as given.
    #[error("{reason}")]
    Usage {
        /// What is wrong with the invocation.
        reason: String,
    },

    /// A read or write this crate performs itself failed.
    #[error("{context}: {reason}")]
    Io {
        /// What was being read or written.
        context: String,
        /// The operating system's description of the failure.
        reason: String,
    },
}

impl CtlError {
    /// The exit class this error belongs to.
    #[must_use]
    pub const fn class(&self) -> ExitClass {
        match self {
            Self::Store(_)
            | Self::Seal(_)
            | Self::Name(_)
            | Self::Policy(_)
            | Self::Refusal { .. } => ExitClass::Refusal,
            Self::Usage { .. } => ExitClass::Usage,
            Self::Io { .. } => ExitClass::Io,
        }
    }

    /// A refusal with a stated reason.
    pub(crate) fn refusal(reason: impl Into<String>) -> Self {
        Self::Refusal {
            reason: reason.into(),
        }
    }

    /// An I/O failure with the operation named.
    pub(crate) fn io(context: impl Into<String>, error: &std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            reason: error.to_string(),
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
    use super::{CtlError, EXIT_IO, EXIT_REFUSAL, EXIT_USAGE, ExitClass};
    use nmcp_secrets::StoreError;

    #[test]
    fn the_three_classes_have_three_distinct_codes() {
        let codes = [
            ExitClass::Refusal.code(),
            ExitClass::Usage.code(),
            ExitClass::Io.code(),
        ];
        assert_eq!(codes, [EXIT_REFUSAL, EXIT_USAGE, EXIT_IO]);
        assert_eq!(codes[0], 1);
        assert_eq!(codes[1], 2, "usage matches the code clap exits with");
        assert_eq!(codes[2], 3);
    }

    #[test]
    fn a_store_error_is_a_refusal_and_prints_the_store_text_verbatim() {
        let refused = CtlError::from(StoreError::UnknownSecret {
            name: "api.token".to_string(),
        });
        assert_eq!(refused.class(), ExitClass::Refusal);
        assert_eq!(refused.to_string(), "no secret named api.token");
    }

    #[test]
    fn own_variants_map_to_their_classes() {
        assert_eq!(CtlError::refusal("declined").class(), ExitClass::Refusal);
        assert_eq!(
            CtlError::Usage {
                reason: "bad".to_string()
            }
            .class(),
            ExitClass::Usage
        );
        let io = CtlError::io(
            "reading x",
            &std::io::Error::new(std::io::ErrorKind::NotFound, "gone"),
        );
        assert_eq!(io.class(), ExitClass::Io);
        assert_eq!(io.to_string(), "reading x: gone");
    }
}
