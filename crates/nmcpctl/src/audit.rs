//! Audit log tools ported from the base ctl: chain verification.
//!
//! One deviation, deliberate: `--path` is required where the base defaulted to its daemon's
//! deployed log location, a path the base defines and this workspace does not. The verifier
//! itself is `nmcp-audit`'s, unchanged: a broken chain is a report, not an I/O error, and
//! this surface turns `ok: false` into a refusal so a pipeline stops on tampering.

use std::io::Write;
use std::path::Path;

use crate::error::CtlError;

/// Write one line of command output.
fn put(out: &mut dyn Write, line: std::fmt::Arguments<'_>) -> Result<(), CtlError> {
    writeln!(out, "{line}").map_err(|error| CtlError::io("writing output", &error))
}

/// `nmcpctl audit verify`: re-walk the log and verify the tamper-evident hash chain.
pub(crate) fn verify(
    path: &Path,
    from_sequence: Option<u64>,
    out: &mut dyn Write,
) -> Result<(), CtlError> {
    let report =
        nmcp_audit::verify_chain_from(path, from_sequence).map_err(|error| CtlError::Io {
            context: format!("reading the audit log {}", path.display()),
            reason: error.to_string(),
        })?;
    let rendered = serde_json::to_string_pretty(&report)
        .map_err(|error| CtlError::refusal(format!("the report could not be encoded: {error}")))?;
    put(out, format_args!("{rendered}"))?;
    if !report.ok {
        return Err(CtlError::refusal(format!(
            "audit chain verification FAILED: {}",
            report.reason.unwrap_or_default()
        )));
    }
    Ok(())
}
