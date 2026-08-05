//! `nmcp-identity`
//!
//! Platform-neutral filesystem identity for the NativeMCP server family: the
//! product name, the per-platform data root, and the standard directories and
//! file paths derived from it. The governance invariants in
//! `docs/GOVERNANCE.md` are normative for every item in this crate.
//!
//! Windows service and executable identity (service name, daemon/tray/ctl exe
//! names) is deliberately NOT here: it is platform-specific and belongs to the
//! platform daemon that installs it. It is held for WinMCP at
//! `_hold/w3-winmcp-identity.rs` (NMCP-SPEC-001 W3).

use std::path::PathBuf;

/// The product name, as it appears in the data-root directory and logs.
pub const PRODUCT_NAME: &str = "NativeMCP";

/// The directory name under the platform data root that holds all product
/// state.
pub const DATA_DIR_NAME: &str = "NativeMCP";

/// The audit chain filename under [`audit_dir`].
pub const AUDIT_FILE: &str = "nmcp.audit.jsonl";

/// The product data root: `%ProgramData%\NativeMCP` on Windows, a temp-dir
/// subtree elsewhere until the platform daemons define their own (W4).
///
/// The `cfg` split selects a std path per platform and pulls in no
/// platform crate, which is the distinction INV-1's supply-chain posture and
/// the core `deny.toml` draw: conditionals over std are fine in core, a
/// Windows crate dependency is not.
#[must_use]
pub fn program_data_root() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join(DATA_DIR_NAME)
    }
    #[cfg(not(windows))]
    {
        std::env::temp_dir().join(DATA_DIR_NAME)
    }
}

/// Installed-binaries directory under the data root.
#[must_use]
pub fn bin_dir() -> PathBuf {
    program_data_root().join("bin")
}

/// Configuration directory under the data root.
#[must_use]
pub fn config_dir() -> PathBuf {
    program_data_root().join("config")
}

/// Log directory under the data root.
#[must_use]
pub fn logs_dir() -> PathBuf {
    program_data_root().join("logs")
}

/// Audit directory under the data root.
#[must_use]
pub fn audit_dir() -> PathBuf {
    program_data_root().join("audit")
}

/// Working-state directory under the data root.
#[must_use]
pub fn work_dir() -> PathBuf {
    program_data_root().join("work")
}

/// Agent-memory directory under the data root.
///
/// Not a configured MCP root and not reachable by fs tools, on any platform.
#[must_use]
pub fn default_memory_dir() -> PathBuf {
    program_data_root().join("memory")
}

/// Full path to the agent-memory database.
#[must_use]
pub fn default_memory_db_path() -> PathBuf {
    default_memory_dir().join("memory.db")
}

/// Default policy file path.
#[must_use]
pub fn default_config_path() -> PathBuf {
    config_dir().join("policy.json")
}

/// Default audit chain path.
#[must_use]
pub fn default_audit_path() -> PathBuf {
    audit_dir().join(AUDIT_FILE)
}

/// Default durable-execution state directory.
#[must_use]
pub fn default_exec_state_dir() -> PathBuf {
    work_dir().join("exec-jobs")
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;

    #[test]
    fn identity_constants_are_rebranded_and_consistent() {
        assert_eq!(PRODUCT_NAME, "NativeMCP");
        assert_eq!(DATA_DIR_NAME, "NativeMCP");
        assert!(program_data_root().ends_with(DATA_DIR_NAME));
    }

    #[test]
    fn memory_path_is_under_the_data_root_and_not_a_configured_root() {
        let mem_dir = default_memory_dir();
        let mem_db = default_memory_db_path();
        assert!(mem_dir.ends_with("memory"));
        assert!(mem_db.ends_with("memory.db"));
        assert!(mem_db.starts_with(program_data_root()));
    }

    #[test]
    fn the_standard_paths_hang_off_the_data_root() {
        let root = program_data_root();
        for p in [bin_dir(), config_dir(), logs_dir(), audit_dir(), work_dir()] {
            assert!(p.starts_with(&root), "{p:?} must be under {root:?}");
        }
        assert!(default_audit_path().ends_with(AUDIT_FILE));
        assert!(default_exec_state_dir().ends_with("exec-jobs"));
    }
}
