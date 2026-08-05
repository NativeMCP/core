//! Filesystem restriction, applied and verified in one place.
//!
//! NMCP-SPEC-002 SB-11 puts the same mode restriction on the sealer's key file as on the store,
//! and section 4's T6 records that on a core-sealer deployment the filesystem is the whole of
//! the guarantee. Two callers applying "the same" restriction from two copies of the code is
//! how they stop being the same, so both call this.
//!
//! Enforced on Unix, not enforced elsewhere, and the difference is reported rather than assumed
//! either way: see [`crate::KeyProtection`].

use std::fs;
use std::path::Path;

/// The mode a file holding key material or sealed blobs must have on Unix.
pub(crate) const RESTRICTED_FILE_MODE: u32 = 0o600;

/// The mode a directory holding either must have on Unix.
pub(crate) const RESTRICTED_DIR_MODE: u32 = 0o700;

/// Why a path is not usable for material.
///
/// Carries a path, a mode and an error kind. No material and nothing derived from material: a
/// mode is a property of the container, not of what is in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PermsError {
    /// The path is readable by somebody other than its owner.
    ///
    /// Constructed only by the Unix [`verify_restricted`]: mode bits do not exist in `std`
    /// off Unix, the wide-mode refusal is a Unix check, and the platform answer for at-rest
    /// protection there is the DPAPI sealer at W3 (SB-11, T6, G-6). The variant is retained
    /// on every platform rather than `cfg`-ed out, so this enum, and the public
    /// [`SealError::KeyFileExposed`](crate::SealError::KeyFileExposed) and
    /// [`StoreError::Exposed`](crate::StoreError::Exposed) variants built from it, have one
    /// shape everywhere and code matching on them compiles everywhere; the `allow` below is
    /// scoped to exactly this variant on exactly the platforms whose builds never construct
    /// it, which is the fact it states.
    #[cfg_attr(not(unix), allow(dead_code))]
    Exposed {
        /// The offending path.
        path: String,
        /// The mode found.
        mode: u32,
        /// The mode required.
        required: u32,
    },
    /// The path could not be created, read or restricted.
    Failed {
        /// The path involved.
        path: String,
        /// The operating system's description, which describes the file rather than its
        /// contents.
        reason: String,
    },
}

impl PermsError {
    /// Build a failure from an I/O error, keeping the kind and dropping everything else.
    fn failed(path: &Path, err: &std::io::Error) -> Self {
        Self::Failed {
            path: path.display().to_string(),
            reason: err.kind().to_string(),
        }
    }
}

/// Create `dir` and every parent, restricting `dir` itself where the platform allows it.
pub(crate) fn create_restricted_dir(dir: &Path) -> Result<(), PermsError> {
    if !dir.exists() {
        fs::create_dir_all(dir).map_err(|err| PermsError::failed(dir, &err))?;
        set_mode(dir, RESTRICTED_DIR_MODE)?;
    }
    Ok(())
}

/// Write `body` to `path` and restrict it where the platform allows it.
///
/// The mode is applied after the write rather than at creation, which leaves a window on the
/// order of one system call during which a freshly created file carries the process umask.
/// Named rather than hidden: closing it needs `OpenOptions::mode`, which is a Unix-only
/// extension, and the directory these files sit in is already `0700`, so an attacker who can
/// exploit the window can already read the directory.
pub(crate) fn write_restricted(path: &Path, body: &[u8], mode: u32) -> Result<(), PermsError> {
    fs::write(path, body).map_err(|err| PermsError::failed(path, &err))?;
    set_mode(path, mode)
}

/// Apply `mode` on Unix.
#[cfg(unix)]
pub(crate) fn set_mode(path: &Path, mode: u32) -> Result<(), PermsError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|err| PermsError::failed(path, &err))
}

/// Apply `mode`. Not enforced off Unix; see [`crate::KeyProtection::PlatformDefault`].
#[cfg(not(unix))]
pub(crate) fn set_mode(_path: &Path, _mode: u32) -> Result<(), PermsError> {
    Ok(())
}

/// Refuse a path the filesystem is not protecting.
///
/// Compares the permission bits against the required mode and refuses anything wider. Narrower
/// is accepted: an operator who tightened a key directory to `0500` has not weakened anything,
/// and refusing them would be this code insisting on write access it does not need.
#[cfg(unix)]
pub(crate) fn verify_restricted(path: &Path, required: u32) -> Result<(), PermsError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|err| PermsError::failed(path, &err))?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & !required != 0 {
        return Err(PermsError::Exposed {
            path: path.display().to_string(),
            mode,
            required,
        });
    }
    Ok(())
}

/// Refuse a path the filesystem is not protecting. Not enforced off Unix; see
/// [`crate::KeyProtection::PlatformDefault`].
#[cfg(not(unix))]
pub(crate) fn verify_restricted(_path: &Path, _required: u32) -> Result<(), PermsError> {
    Ok(())
}
