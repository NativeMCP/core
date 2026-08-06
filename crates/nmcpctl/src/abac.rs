//! ABAC key management ported from the base ctl: rotating the manifest verification key.
//!
//! CLI only, never an MCP tool: the base's own rule (its ADR-012), kept because handing an
//! agent the ability to swap the key that signatures are checked against would let it bless
//! its own manifests. The surface this operates on exists in core: `nmcp-abac` verifies
//! manifest signatures against an operator-held public key file, and this command is how
//! that file is replaced.
//!
//! Two deviations from the base, deliberate:
//!
//! - The prior key is retained under a timestamped name instead of being overwritten. The
//!   INV-1 posture applied to this tool's own writes: rotation replaces what is in force,
//!   and destroys nothing.
//! - The completion note is platform-neutral. The base told the operator to restart its
//!   daemon by name; the process consuming this key in a deployment belongs to the platform
//!   repositories, so the note says what must happen rather than naming who does it.

use std::io::Write;
use std::path::Path;

use crate::error::CtlError;

/// `nmcpctl abac rotate-signing-key`: put a new public verification key in place.
///
/// The new key file must be 32 raw bytes or 64 hex characters (a raw Ed25519 public key or
/// its hex spelling), which is the same validation the base applied: enough to catch a
/// wrong file, while leaving cryptographic judgement to the verifier that consumes it.
pub(crate) fn rotate_signing_key(
    new_key: &Path,
    key_path: &Path,
    out: &mut dyn Write,
) -> Result<(), CtlError> {
    let raw = std::fs::read(new_key)
        .map_err(|error| CtlError::io(format!("reading {}", new_key.display()), &error))?;
    if raw.len() != 32 && raw.len() != 64 {
        return Err(CtlError::refusal(format!(
            "the key file must be 32 raw bytes or 64 hex characters, got {} bytes; nothing was \
             rotated",
            raw.len()
        )));
    }
    if let Some(parent) = key_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| CtlError::io(format!("creating {}", parent.display()), &error))?;
    }
    let retired = retire_existing(key_path)?;
    std::fs::copy(new_key, key_path).map_err(|error| {
        CtlError::io(
            format!("copying {} to {}", new_key.display(), key_path.display()),
            &error,
        )
    })?;
    writeln!(
        out,
        "rotated the ABAC verification key: {} -> {}",
        new_key.display(),
        key_path.display()
    )
    .map_err(|error| CtlError::io("writing output", &error))?;
    if let Some(retired) = retired {
        writeln!(
            out,
            "  prior key retained at {retired} (nothing is overwritten)"
        )
        .map_err(|error| CtlError::io("writing output", &error))?;
    }
    writeln!(
        out,
        "  the consuming process reads the key at start; restart it to verify under the new key"
    )
    .map_err(|error| CtlError::io("writing output", &error))
}

/// Move an existing key aside under a timestamped name, and say where it went.
fn retire_existing(key_path: &Path) -> Result<Option<String>, CtlError> {
    if key_path.symlink_metadata().is_err() {
        return Ok(None);
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis());
    let mut retired = key_path.as_os_str().to_owned();
    retired.push(format!(".retired-{stamp}"));
    let retired_path = std::path::PathBuf::from(retired);
    if retired_path.symlink_metadata().is_ok() {
        return Err(CtlError::refusal(format!(
            "refusing to rotate: the retirement name {} is already taken",
            retired_path.display()
        )));
    }
    std::fs::rename(key_path, &retired_path).map_err(|error| {
        CtlError::io(
            format!(
                "retiring {} to {}",
                key_path.display(),
                retired_path.display()
            ),
            &error,
        )
    })?;
    Ok(Some(retired_path.display().to_string()))
}
