//! Where the store and its sealer key live when the operator does not say.
//!
//! One rule, no configuration file: the `--store` flag wins, and its absence means the
//! platform's conventional per-machine or per-user data location, stated in the flag's own
//! help text so the default is documented where the operator reads it. The sealer's key
//! directory defaults to the store's sibling through
//! [`nmcp_secrets::default_key_dir`], which is SB-11's separate-directory rule: a backup that
//! captures the store does not necessarily capture the key.
//!
//! The environment variables read here (`ProgramData`, `XDG_DATA_HOME`, `HOME`) are location
//! discovery, not value input: SB-R1's rule that secret values never arrive through the
//! environment is untouched, and the structural test in this crate's suite asserts that no
//! argument of any command reads an environment variable at all.

use std::path::{Path, PathBuf};

use crate::error::CtlError;

/// The help text documenting the per-platform default, verbatim on the `--store` flag.
pub(crate) const STORE_HELP: &str = "Store directory. Default: %ProgramData%\\NativeMCP\\secrets \
on Windows, ~/Library/Application Support/NativeMCP/secrets on macOS, $XDG_DATA_HOME/nmcp/secrets \
(else ~/.local/share/nmcp/secrets) on other Unix";

/// The store directory: the flag when given, the platform default otherwise.
///
/// # Errors
///
/// [`CtlError::Usage`] when no flag was given and the platform default cannot be resolved
/// because the environment carries no home location; the remedy is `--store`.
pub(crate) fn resolve_store_dir(flag: Option<PathBuf>) -> Result<PathBuf, CtlError> {
    match flag {
        Some(dir) => Ok(dir),
        None => default_store_dir(),
    }
}

/// The sealer key directory: the flag when given, the store's sibling otherwise (SB-11).
pub(crate) fn resolve_key_dir(flag: Option<PathBuf>, store_dir: &Path) -> PathBuf {
    flag.unwrap_or_else(|| nmcp_secrets::default_key_dir(store_dir))
}

/// The platform's conventional location, exactly as [`STORE_HELP`] documents it.
///
/// Infallible on this platform, because `%ProgramData%` has a documented fallback. The other
/// two arms fail when the environment names no home, and [`resolve_store_dir`] is
/// `cfg`-agnostic, so the signature is shared across the three rather than narrowed here.
#[cfg(target_os = "windows")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "shared signature with the two fallible arms; the caller is cfg-agnostic"
)]
fn default_store_dir() -> Result<PathBuf, CtlError> {
    let base = std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    Ok(base.join("NativeMCP").join("secrets"))
}

/// The platform's conventional location, exactly as [`STORE_HELP`] documents it.
#[cfg(target_os = "macos")]
fn default_store_dir() -> Result<PathBuf, CtlError> {
    let home = std::env::var_os("HOME").ok_or_else(no_home)?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("NativeMCP")
        .join("secrets"))
}

/// The platform's conventional location, exactly as [`STORE_HELP`] documents it.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn default_store_dir() -> Result<PathBuf, CtlError> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        let base = PathBuf::from(&xdg);
        // The XDG specification says a relative value is invalid and must be ignored.
        if base.is_absolute() {
            return Ok(base.join("nmcp").join("secrets"));
        }
    }
    let home = std::env::var_os("HOME").ok_or_else(no_home)?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("nmcp")
        .join("secrets"))
}

/// The refusal when the environment names no home to derive a default from.
#[cfg(not(target_os = "windows"))]
fn no_home() -> CtlError {
    CtlError::Usage {
        reason: "no default store location: the environment sets neither HOME nor an absolute \
                 XDG_DATA_HOME; pass --store <dir>"
            .to_string(),
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
    use std::path::{Path, PathBuf};

    use super::{resolve_key_dir, resolve_store_dir};

    #[test]
    fn an_explicit_store_flag_wins_and_needs_no_environment() {
        let dir = resolve_store_dir(Some(PathBuf::from("/tmp/elsewhere"))).unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/elsewhere"));
    }

    #[test]
    fn the_key_dir_defaults_to_the_stores_sibling_and_the_flag_overrides() {
        let store = Path::new("/data/nmcp/secrets");
        assert_eq!(
            resolve_key_dir(None, store),
            PathBuf::from("/data/nmcp/secrets-sealer"),
            "SB-11: the key lives beside the store, not inside it"
        );
        assert_eq!(
            resolve_key_dir(Some(PathBuf::from("/keys")), store),
            PathBuf::from("/keys")
        );
    }
}
