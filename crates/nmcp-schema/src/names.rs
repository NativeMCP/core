//! Derivation and validation of the public tool name.
//!
//! NMCP-SPEC-003 RC-D6. Both functions moved here verbatim from `nmcp-router`, which
//! re-exports them so nothing that used them broke. They live here because the registry
//! that owns the local-to-public mapping will live here, and a name derived in two places
//! is the shape of the defect section 1 of that spec measures.
//!
//! Validation applies to the **derived public name**, never to `ToolContract.name`: local
//! names legitimately contain dots (`mem.write`, `win.eventlog_query`) and the validator
//! rejects dots, so applying it to the local name would refuse the existing first-party
//! catalogue.

/// The public tool name a provider's local name is advertised and dispatched under.
///
/// Sanitizes separator runs and truncates at 64 characters, because MCP clients constrain
/// the name character set more tightly than this workspace's local names do. Truncation
/// means two distinct local names can collide into one public name; that is a duplicate
/// like any other and the registry refuses it by naming both contributors.
#[must_use]
pub fn public_tool_name(provider_id: &str, local_name: &str) -> String {
    let canonical = if provider_id.is_empty() {
        local_name.to_string()
    } else {
        format!("{provider_id}_{local_name}")
    };
    let mut safe = String::with_capacity(canonical.len().min(64));
    let mut previous_was_separator = false;
    for ch in canonical.chars() {
        let mapped = if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            ch
        } else {
            '_'
        };
        if mapped == '_' {
            if previous_was_separator {
                continue;
            }
            previous_was_separator = true;
        } else {
            previous_was_separator = false;
        }
        safe.push(mapped);
        if safe.len() >= 64 {
            break;
        }
    }
    safe.trim_matches('_').to_string()
}

/// Whether `name` is a public tool name an MCP client will accept.
#[must_use]
pub fn is_valid_public_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

/// Tool names INV-1 forbids outright, whatever a provider says about them.
///
/// Kernel-owned and not delegable (RC-D4): a provider that declares itself non-destructive is
/// a provider grading its own homework, so the list is compared against rather than consulted
/// for advice. It moved here from `nmcp-router` for the same reason
/// [`public_tool_name`] did at I-047a and no other: the registry refuses a delete-denied name
/// at registration (`RegistrationError::DeleteDeniedName`) and the registry does not live in
/// the crate that dispatches. `nmcp-router` imports it privately, so the dispatch-time guard
/// and the registration-time refusal compare against one table rather than two that can drift.
///
/// This is the one exception RC-11 names to "the kernel names no tool": a guarantee cannot
/// enumerate what it refuses without saying the names.
pub const DELETE_DENIED_NAMES: &[&str] = &[
    "delete",
    "delete_file",
    "remove",
    "remove_root",
    "uninstall",
    "drop",
    "drop_table",
    "destroy",
    "purge",
    "wipe",
    "truncate",
    "rm",
];

/// Whether `tool_name` is one of the names INV-1 refuses.
///
/// Equality against [`DELETE_DENIED_NAMES`] after lowercasing, which is the base's rule and
/// stays the rule: a substring test would refuse `list_directory` for containing `rm` in
/// `format`, and a prefix test would refuse nothing useful that equality does not.
#[must_use]
pub fn contains_delete_intent(tool_name: &str) -> bool {
    let lower = tool_name.to_ascii_lowercase();
    DELETE_DENIED_NAMES.iter().any(|denied| lower == *denied)
}
