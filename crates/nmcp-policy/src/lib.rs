//! `nmcp-policy`
//!
//! The governance policy engine for the NativeMCP server family: hierarchical
//! instruction authority (INV-4), root and permission resolution (INV-2),
//! deny-by-default evaluation, attribute rules, the change-plan differ, and
//! fleet-policy tightening that can only narrow. The invariants in
//! `docs/GOVERNANCE.md` are normative for every item in this crate.
//!
//! Platform note (NMCP-SPEC-001 R-3): the fleet-policy SOURCE is a platform
//! concern and lives behind [`machine::MachinePolicySource`]. Core ships
//! [`machine::NoFleetPolicy`]; WinMCP injects a Windows Group Policy reader at
//! W3. That is what keeps this crate free of any platform crate dependency.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub mod diff;
pub mod machine;

/// Expand Windows-style `%VARIABLE%` tokens in a string using the process environment.
/// Unrecognised tokens are left as-is. On non-Windows platforms the function is still
/// defined so policy files are portable at the type level, but no system env lookup occurs
/// beyond what `std::env::var` provides.
#[must_use]
pub fn expand_env_vars(s: &str) -> String {
    expand_env_vars_with(s, |name| std::env::var(name).ok())
}

/// [`expand_env_vars`] with the environment read injected, so the expansion
/// rules are testable without mutating process env (unsafe in edition 2024,
/// forbidden workspace-wide).
#[must_use]
pub fn expand_env_vars_with(s: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    let mut result = String::with_capacity(s.len());
    let mut cursor = 0;
    while cursor < s.len() {
        let Some(start_rel) = s[cursor..].find('%') else {
            result.push_str(&s[cursor..]);
            break;
        };
        let start = cursor + start_rel;
        result.push_str(&s[cursor..start]);
        let after_start = start + '%'.len_utf8();
        let Some(end_rel) = s[after_start..].find('%') else {
            result.push_str(&s[start..]);
            break;
        };
        let end = after_start + end_rel;
        let var_name = &s[after_start..end];
        if !var_name.is_empty()
            && let Some(value) = lookup(var_name)
        {
            result.push_str(&value);
        } else {
            result.push('%');
            result.push_str(var_name);
            result.push('%');
        }
        cursor = end + '%'.len_utf8();
    }
    result
}

/// Expand env vars in a `Path` and return the result as a `PathBuf`.
#[must_use]
pub fn expand_path_env(path: &Path) -> PathBuf {
    PathBuf::from(expand_env_vars(&path.to_string_lossy()))
}

/// Why a policy operation was refused.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("operation is permanently unavailable: {0}")]
    /// An operation this server will never offer.
    PermanentlyUnavailable(&'static str),
    #[error("path is outside configured roots: {0}")]
    /// A path resolved outside every granted root.
    OutsideRoots(String),
    #[error("permission denied: {permission} for {path}")]
    /// The permission is not granted on the matching root.
    PermissionDenied {
        /// The capability this concerns.
        permission: Permission,
        /// Filesystem path.
        path: String,
    },
    #[error("root path must be absolute in service mode: {0}")]
    /// A service root was configured as a relative path.
    RelativeServiceRoot(String),
    #[error("root path does not exist: {0}")]
    /// A configured root does not exist.
    MissingRoot(String),
    #[error("invalid policy: {0}")]
    /// The policy is structurally valid but semantically illegal.
    SemanticValidation(String),
    #[error("policy JSON could not be parsed: {0}")]
    /// The policy file is not valid JSON.
    MalformedJson(String),
}

/// A capability a tool call may require.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Enumerate a directory.
    List,
    /// Read file contents.
    Read,
    /// Search within files.
    Search,
    /// Create a file.
    Create,
    /// Write file contents.
    Write,
    /// Modify a file in place.
    Modify,
    /// Rename a file.
    Rename,
    /// Move a file to another directory.
    Move,
    /// Back a file up (rename, never destroy).
    Backup,
    /// Run a program.
    Execute,
    /// Scan a repository.
    Scan,
    /// Produce a report.
    Report,
    #[serde(rename = "memory.read")]
    /// Read agent memory.
    MemoryRead,
    #[serde(rename = "memory.write")]
    /// Write agent memory.
    MemoryWrite,
    #[serde(rename = "win.api")]
    /// Read via a Windows API surface.
    WindowsApi,
    #[serde(rename = "git.publish")]
    /// Publish to a git remote.
    GitPublish,
    #[serde(rename = "m365")]
    /// Reach Microsoft 365.
    M365,
    #[serde(rename = "win.api.write")]
    /// Write via a Windows API surface.
    WindowsApiWrite,
    /// The right to call a gateway upstream at all (G4-28).
    ///
    /// No default root grants this, which is the point. An upstream that declares it is
    /// refused until an operator adds it deliberately. Reusing `Execute` would have
    /// conflated "this box may run local programs" with "this box may proxy to a server
    /// whose tools this policy cannot see", and the shipped default already grants
    /// `Execute`, so the gate would have been open on delivery.
    #[serde(rename = "upstream.call")]
    UpstreamCall,
}

impl Permission {
    /// The name this permission serializes to.
    ///
    /// Written out rather than round-tripped through serde so it is available without
    /// allocating and without a `Result`, and so the pairing is one exhaustive match a reader
    /// can check against the attributes above. `permission_names_match_what_serde_writes`
    /// asserts the two agree for every variant, and this match has no wildcard, so adding a
    /// permission stops this crate compiling until somebody names it here.
    ///
    /// M4-1 needs it: the audit record carries this string, and the Event Log mirror derives
    /// its Event ID class from it, so a SIEM can separate a read from a change from an
    /// execution from an egress without parsing a message body.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Read => "read",
            Self::Search => "search",
            Self::Create => "create",
            Self::Write => "write",
            Self::Modify => "modify",
            Self::Rename => "rename",
            Self::Move => "move",
            Self::Backup => "backup",
            Self::Execute => "execute",
            Self::Scan => "scan",
            Self::Report => "report",
            Self::MemoryRead => "memory.read",
            Self::MemoryWrite => "memory.write",
            Self::WindowsApi => "win.api",
            Self::GitPublish => "git.publish",
            Self::M365 => "m365",
            Self::WindowsApiWrite => "win.api.write",
            Self::UpstreamCall => "upstream.call",
        }
    }
}

impl Permission {
    /// Every permission, in declaration order.
    ///
    /// Exhaustive by construction: `assert_permission_all_is_exhaustive` below matches on the
    /// enum, so adding a variant without adding it here fails to compile rather than quietly
    /// producing a policy diff that omits it.
    pub const ALL: [Permission; 19] = [
        Permission::List,
        Permission::Read,
        Permission::Search,
        Permission::Create,
        Permission::Write,
        Permission::Modify,
        Permission::Rename,
        Permission::Move,
        Permission::Backup,
        Permission::Execute,
        Permission::Scan,
        Permission::Report,
        Permission::MemoryRead,
        Permission::MemoryWrite,
        Permission::WindowsApi,
        Permission::GitPublish,
        Permission::M365,
        Permission::WindowsApiWrite,
        Permission::UpstreamCall,
    ];
}

/// Not called. It exists so the compiler refuses a new `Permission` variant that
/// [`Permission::ALL`] does not list, which is the only way a const array stays exhaustive.
#[allow(dead_code)]
fn assert_permission_all_is_exhaustive(permission: Permission) -> usize {
    let index = match permission {
        Permission::List => 0,
        Permission::Read => 1,
        Permission::Search => 2,
        Permission::Create => 3,
        Permission::Write => 4,
        Permission::Modify => 5,
        Permission::Rename => 6,
        Permission::Move => 7,
        Permission::Backup => 8,
        Permission::Execute => 9,
        Permission::Scan => 10,
        Permission::Report => 11,
        Permission::MemoryRead => 12,
        Permission::MemoryWrite => 13,
        Permission::WindowsApi => 14,
        Permission::GitPublish => 15,
        Permission::M365 => 16,
        Permission::WindowsApiWrite => 17,
        Permission::UpstreamCall => 18,
    };
    debug_assert_eq!(Permission::ALL.get(index), Some(&permission));
    index
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Permission::List => "list",
                Permission::Read => "read",
                Permission::Search => "search",
                Permission::Create => "create",
                Permission::Write => "write",
                Permission::Modify => "modify",
                Permission::Rename => "rename",
                Permission::Move => "move",
                Permission::Backup => "backup",
                Permission::Execute => "execute",
                Permission::Scan => "scan",
                Permission::Report => "report",
                Permission::MemoryRead => "memory.read",
                Permission::MemoryWrite => "memory.write",
                Permission::WindowsApi => "win.api",
                Permission::GitPublish => "git.publish",
                Permission::M365 => "m365",
                Permission::WindowsApiWrite => "win.api.write",
                Permission::UpstreamCall => "upstream.call",
            }
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// One configured root: a path and the permissions granted on it.
pub struct RootRule {
    /// Stable identifier.
    pub id: String,
    /// Filesystem path.
    pub path: PathBuf,
    /// Permissions granted on this root.
    pub permissions: BTreeSet<Permission>,
}

/// Permissions that let a caller change or destroy what lives under a root.
///
/// `Backup` is deliberately absent: it is rename-only by the no-delete invariant.
/// `Execute` is absent too, because an allowed program's own writes are bounded by
/// the process token rather than by this permission set.
pub const MUTATING_PERMISSIONS: &[Permission] = &[
    Permission::Create,
    Permission::Write,
    Permission::Modify,
    Permission::Rename,
    Permission::Move,
    Permission::GitPublish,
];

/// A policy setting that is defensible on its own and dangerous in company.
///
/// These are not validation errors. Every one of them is a legitimate configuration
/// that an operator may have chosen deliberately, so nothing here refuses to start or
/// fails readiness. The point is that the combination stops being obvious once each
/// piece is documented as optional somewhere different, so the server states it in one
/// place instead of leaving it to be inferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureFinding {
    /// Stable identifier.
    pub id: &'static str,
    /// What was found.
    pub detail: String,
    /// How to resolve it.
    pub remediation: &'static str,
}

/// True when `path` denotes an entire volume (`C:\\`, `\\\\?\\C:\\`) rather than a directory in it.
fn is_whole_volume(path: &std::path::Path) -> bool {
    let text = path.to_string_lossy().to_string();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    let trimmed = text.trim_end_matches(['\\', '/']);
    trimmed.len() == 2
        && trimmed.ends_with(':')
        && trimmed
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A named execution environment for spawned programs.
pub struct ExecutionProfile {
    #[serde(default)]
    /// Directories prepended to PATH for this profile.
    pub path_prepend: Vec<PathBuf>,
    #[serde(default)]
    /// Environment variables set for this profile.
    pub env: BTreeMap<String, String>,
    #[serde(default = "default_inherit_service_env")]
    /// Whether to inherit the service environment.
    pub inherit_service_env: bool,
}

impl Default for ExecutionProfile {
    fn default() -> Self {
        Self {
            path_prepend: Vec::new(),
            env: BTreeMap::new(),
            inherit_service_env: default_inherit_service_env(),
        }
    }
}

/// How the gateway reaches an upstream MCP server.
///
/// Before DEC-007 an upstream was a URL and nothing else, which quietly meant the gateway
/// could only ever talk to a server somebody else had already started. The catalog
/// meanwhile described 30 servers distributed as stdio processes or containers, so
/// admitting one produced an upstream that was never going to connect. This enum is where
/// that assumption stops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UpstreamTransport {
    /// An MCP server somebody else is running, reachable over HTTP. The only transport
    /// implemented today.
    /// The `Http { url` field.
    Http {
        /// Upstream base URL.
        url: String,
    },
    /// An MCP server this gateway starts as a child process, speaking JSON-RPC over its
    /// standard input and output. Lands with G6-2.
    Stdio {
        /// Program to spawn.
        command: String,
        #[serde(default)]
        /// Arguments passed to the program.
        args: Vec<String>,
        #[serde(default)]
        /// Environment variables set for this profile.
        env: BTreeMap<String, String>,
        /// Environment variable name to secret store name (G6-4).
        ///
        /// `env` holds literal values, so anything put there lands in policy, in
        /// `GET /api/policy` and in every policy backup. This is where a credential goes
        /// instead: policy names the secret and the runtime resolves it at spawn.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env_secrets: BTreeMap<String, String>,
        #[serde(default)]
        /// Working directory for the child.
        cwd: Option<PathBuf>,
    },
    /// An MCP server this gateway starts in a container with stdio attached. Lands with
    /// G6-3. `image` is expected to be digest-pinned; a mutable tag is an unpinned
    /// dependency on somebody else, for the same reason `tools_sha256` exists.
    Container {
        /// Container image reference.
        image: String,
        #[serde(default)]
        /// Arguments passed to the program.
        args: Vec<String>,
        #[serde(default)]
        /// Environment variables set for this profile.
        env: BTreeMap<String, String>,
        /// Environment variable name to secret store name (G6-4). See the stdio variant.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env_secrets: BTreeMap<String, String>,
        #[serde(default)]
        /// Container runtime override.
        runtime: Option<String>,
    },
}

impl UpstreamTransport {
    /// Short name for logs, status payloads and error messages.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Http { .. } => "http",
            Self::Stdio { .. } => "stdio",
            Self::Container { .. } => "container",
        }
    }

    /// Whether the runtime can actually reach a server over this transport today.
    ///
    /// Deliberately conservative. Declaring a transport the runtime cannot honour is the
    /// exact defect DEC-007 exists to end, so policy validation refuses it rather than
    /// accepting a configuration that can only ever fail at refresh time.
    #[must_use]
    pub fn is_implemented(&self) -> bool {
        // Every variant has a runtime as of G6-3. The gate stays anyway: the next transport
        // added should be refused by name until its runtime lands, rather than accepted and
        // then failing forever at refresh time.
        matches!(
            self,
            Self::Http { .. } | Self::Stdio { .. } | Self::Container { .. }
        )
    }

    /// The required field this transport is missing, if any.
    ///
    /// Checked before `is_implemented` so a malformed transport reports what is wrong with
    /// it rather than only that its runtime has not landed yet.
    #[must_use]
    pub fn missing_required_field(&self) -> Option<&'static str> {
        match self {
            Self::Http { url } if url.trim().is_empty() => Some("url"),
            Self::Stdio { command, .. } if command.trim().is_empty() => Some("command"),
            Self::Container { image, .. } if image.trim().is_empty() => Some("image"),
            _ => None,
        }
    }

    /// The tracker item that lands this transport, for the rejection message.
    #[must_use]
    pub fn implemented_by(&self) -> &'static str {
        match self {
            Self::Http { .. } => "G6-1",
            Self::Stdio { .. } => "G6-2",
            Self::Container { .. } => "G6-3",
        }
    }

    /// Environment variable name to secret name, for a transport that starts a process.
    ///
    /// Empty for HTTP, which authenticates with a header rather than an environment.
    #[must_use]
    pub fn env_secrets(&self) -> &BTreeMap<String, String> {
        static EMPTY: std::sync::LazyLock<BTreeMap<String, String>> =
            std::sync::LazyLock::new(BTreeMap::new);
        match self {
            Self::Http { .. } => &EMPTY,
            Self::Stdio { env_secrets, .. } | Self::Container { env_secrets, .. } => env_secrets,
        }
    }

    /// The image reference, when a container upstream names a tag rather than a digest.
    ///
    /// Unconditional rather than gated on `require_upstream_pinning`, and the distinction is
    /// worth being clear about. `tools_sha256` is a stricter posture an operator opts into.
    /// A digest is not a posture: a tag is a name its publisher can repoint at different
    /// bytes tomorrow, so pinning the tool list of an image addressed by tag pins nothing at
    /// all. The digest is what makes the image a fixed thing worth pinning against.
    #[must_use]
    pub fn unpinned_container_image(&self) -> Option<&str> {
        match self {
            Self::Container { image, .. } if !digest_pinned_image(image) => Some(image),
            _ => None,
        }
    }

    /// The runtime name, when a container upstream names one in a form this build will not
    /// resolve.
    #[must_use]
    pub fn unusable_container_runtime(&self) -> Option<&str> {
        match self {
            Self::Container {
                runtime: Some(runtime),
                ..
            } if !usable_runtime(runtime) => Some(runtime),
            _ => None,
        }
    }
}

/// Whether an image reference carries an immutable `@sha256:` digest.
///
/// Lowercase hex only, because that is the one spelling a registry emits and accepting a
/// second spelling of the same digest would mean two policies that look different and are
/// not, which `PartialEq` on `UpstreamConfig` would then churn a provider over.
fn digest_pinned_image(image: &str) -> bool {
    let Some((name, digest)) = image.rsplit_once('@') else {
        return false;
    };
    if name.trim().is_empty() {
        return false;
    }
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Whether a container runtime is named in a form this build will start.
///
/// A bare program name is resolved on PATH, and an absolute path is taken as written, which
/// is what an operator whose Docker lives somewhere unusual needs. A relative path is
/// refused: it would resolve against whatever working directory the service happens to have,
/// and which program a policy file starts is not a thing to decide implicitly.
fn usable_runtime(runtime: &str) -> bool {
    if runtime.is_empty() || runtime != runtime.trim() || runtime.contains('\0') {
        return false;
    }
    if runtime.contains("..") {
        return false;
    }
    if runtime.contains('/') || runtime.contains('\\') {
        return Path::new(runtime).is_absolute();
    }
    true
}

/// Configuration for a single upstream MCP server proxy.
///
/// `PartialEq` is load-bearing: the policy hot-reload path compares a freshly loaded
/// upstream against the one a running provider was constructed with, and re-registers only
/// on a real difference. Without it, every reload would churn every provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Unique identifier used for tool namespacing: `id::tool_name`.
    pub id: String,
    /// Pre-DEC-007 shape: the HTTP base URL, with the transport left implicit.
    ///
    /// Retained so a policy written before DEC-007 loads and behaves identically.
    /// `normalize_transport` folds it into `transport` at load, so nothing downstream has
    /// to know which shape the file was written in, and the in-memory form is canonical.
    /// That matters for more than tidiness: `PartialEq` here drives hot-reload
    /// reconciliation, and two spellings of the same upstream would churn the provider on
    /// every reload.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    /// How the gateway reaches this server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<UpstreamTransport>,
    /// Human-readable label shown in the admin UI.
    #[serde(default)]
    pub label: String,
    /// If false, the provider registers no tools and proxies no calls.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional allowlist of tool names to expose. `None` means all tools.
    #[serde(default)]
    pub tool_allowlist: Option<Vec<String>>,
    /// Optional SHA-256 pin over the canonical `/result/tools` JSON payload from tools/list.
    #[serde(default)]
    pub tools_sha256: Option<String>,
    /// Optional Ed25519 public key, hex encoded, used to verify signed tools/list manifests.
    #[serde(default)]
    pub manifest_public_key: Option<String>,
    /// Name of an environment variable holding the credential sent to this upstream.
    ///
    /// Policy carries the variable NAME, never the secret. The daemon resolves it at
    /// request time, which keeps the credential out of the policy file, out of
    /// `GET /api/policy`, out of policy backups, and out of the audit log, and lets an
    /// operator rotate it by changing the service environment rather than by editing a
    /// governed file. `validate_semantics` rejects a value that looks like a pasted
    /// credential instead of a variable name.
    #[serde(default)]
    pub auth_header_env: Option<String>,
    /// Header the credential is sent in. Defaults to `Authorization` when
    /// `auth_header_env` or `auth_secret` is set, and is meaningless without either.
    #[serde(default)]
    pub auth_header_name: Option<String>,
    /// Name of a secret in the secret store holding the credential for this upstream (G6-4).
    ///
    /// The same posture as `auth_header_env`, which is that policy carries the name and never
    /// the value. The difference is where the value lives: `auth_header_env` needs an operator
    /// to set an environment variable on a `LocalSystem` service and restart it, which most
    /// operators cannot do and none should have to, while this names something they can write
    /// through the admin API into a store sealed at rest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_secret: Option<String>,
    /// Name of an entry in `oauth_providers` that brokers this upstream's token (G6-9).
    ///
    /// The third and last credential source, and the only one that changes on its own. The
    /// other two name something an operator set once and that stays set. This names a provider
    /// the operator authorized once, whose access token the broker replaces before it expires.
    /// Several upstreams naming the same provider share that one authorization, which is the
    /// point of it: six servers behind one sign-in is one sign-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_provider: Option<String>,
    /// The capability an operator must grant before this upstream's tools may be called
    /// (G4-28).
    ///
    /// The ring cannot govern what an admitted upstream *does*. A stdio or container upstream
    /// is a child process of the daemon, an HTTP one is somebody else's server, and neither
    /// goes through `mcp-fs`, so no root permission constrains it. What the ring can govern is
    /// whether its tools are reachable at all, and that is what this declares: some root must
    /// grant this permission or every tool from this upstream is refused.
    ///
    /// The same shape `m365` and `win.api` already use. Those are capability gates with no
    /// path involved, and m365 is a third-party integration governed exactly this way, so this
    /// generalises an existing pattern rather than adding a second one.
    ///
    /// Declared per upstream rather than per tool on purpose. A per-tool declaration is a line
    /// per tool of somebody else's server, and it goes stale silently the moment that server
    /// adds one.
    ///
    /// `validate_semantics` refuses an ENABLED upstream that leaves this unset, so admitting
    /// an upstream is a deliberate act rather than a default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_permission: Option<Permission>,
}

/// Whether an upstream's tools may be dispatched at all (G4-28).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamAdmission {
    /// A root grants the declared capability.
    /// The `Granted { permission` field.
    Granted {
        /// The capability a root grants.
        permission: Permission,
    },
    /// The capability is declared and no root grants it.
    /// The `MissingGrant { permission` field.
    MissingGrant {
        /// The declared capability no root grants.
        permission: Permission,
    },
    /// The upstream exists in policy and declares nothing. `validate_semantics` refuses this
    /// for an enabled upstream, so reaching it at dispatch means a policy got in by some route
    /// that did not validate. Fail closed rather than assume the validator ran.
    Undeclared,
    /// No upstream in policy carries this id. A provider registered outside policy is not a
    /// provider policy admitted.
    NotAdmitted,
}

fn default_true() -> bool {
    true
}

impl UpstreamConfig {
    /// `new`.
    pub fn new(id: impl Into<String>, url: impl Into<String>) -> Self {
        let id = id.into();
        let label = id.clone();
        Self {
            id,
            url: String::new(),
            transport: Some(UpstreamTransport::Http { url: url.into() }),
            label,
            enabled: true,
            tool_allowlist: None,
            tools_sha256: None,
            manifest_public_key: None,
            auth_header_env: None,
            auth_header_name: None,
            auth_secret: None,
            oauth_provider: None,
            required_permission: None,
        }
    }

    /// Build an upstream that the gateway starts itself as a child process.
    pub fn stdio(id: impl Into<String>, command: impl Into<String>, args: &[&str]) -> Self {
        let mut cfg = Self::new(id, "");
        cfg.transport = Some(UpstreamTransport::Stdio {
            command: command.into(),
            args: args.iter().map(|a| (*a).to_string()).collect(),
            env: BTreeMap::new(),
            env_secrets: BTreeMap::new(),
            cwd: None,
        });
        cfg
    }

    /// The transport this upstream reaches its server by.
    ///
    /// Total by construction. A config carrying only the pre-DEC-007 `url` answers `Http`,
    /// so no caller has to branch on which shape the policy was written in. An upstream
    /// with neither answers `Http` with an empty url, which `validate_semantics` rejects.
    #[must_use]
    pub fn transport(&self) -> UpstreamTransport {
        self.transport
            .clone()
            .unwrap_or_else(|| UpstreamTransport::Http {
                url: self.url.clone(),
            })
    }

    /// Fold the legacy `url` into `transport` so the in-memory form has exactly one
    /// spelling. Idempotent.
    pub fn normalize_transport(&mut self) {
        if self.transport.is_none() {
            self.transport = Some(UpstreamTransport::Http {
                url: std::mem::take(&mut self.url),
            });
        } else {
            self.url = String::new();
        }
    }

    /// The HTTP base URL, when this upstream is reached over HTTP.
    #[must_use]
    pub fn http_url(&self) -> Option<String> {
        match self.transport() {
            UpstreamTransport::Http { url } => Some(url),
            _ => None,
        }
    }
}

/// Action to take when an ABAC rule matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AbacAction {
    /// Deny the call immediately.
    Deny,
    /// Pause and require human approval (HITL).
    RequireApproval,
}

/// A single ABAC rule evaluated after base permission check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AbacRule {
    /// Restrict tools to specific hours of the day (local time).
    TimeOfDay {
        /// Optional tool-name filter. `None` matches all tools.
        #[serde(default)]
        tools: Option<Vec<String>>,
        /// Inclusive start hour (0–23).
        allow_start_hour: u32,
        /// Exclusive end hour (1–24).
        allow_end_hour: u32,
        /// Allow or deny when this rule matches.
        action: AbacAction,
    },
    /// Restrict tools to specific caller identities.
    CallerIdentity {
        /// Allowed agent IDs. Use `"*"` for any.
        allowed_callers: Vec<String>,
        #[serde(default)]
        /// Optional tool-name filter; `None` matches all tools.
        tools: Option<Vec<String>>,
        /// Allow or deny when this rule matches.
        action: AbacAction,
    },
    /// Restrict one caller to an explicit set of tools, denying everything else.
    ///
    /// The other rule kinds are deny-lists: they name what is restricted, so a tool added
    /// later is unrestricted until somebody remembers to add it. That is the wrong default
    /// for a third-party client. This one inverts it. `caller` may call the tools in
    /// `allowed_tools` and nothing else, so a new tool is denied to that caller from the
    /// moment it exists, without any policy edit.
    ///
    /// It applies to exactly one caller. Every other identity, including the operator's own
    /// client and unauthenticated local callers, is untouched by this rule.
    CallerToolAllowlist {
        /// The agent id this restriction applies to.
        caller: String,
        /// The only tools that caller may reach.
        allowed_tools: Vec<String>,
        /// Allow or deny when this rule matches.
        action: AbacAction,
    },
    /// Match argument content against a regex pattern.
    CommandContent {
        /// Regex pattern matched against the full args JSON (lowercased).
        pattern: String,
        #[serde(default)]
        /// Optional tool-name filter; `None` matches all tools.
        tools: Option<Vec<String>>,
        /// Allow or deny when this rule matches.
        action: AbacAction,
    },
}

/// Auth mode for the native Microsoft 365 provider.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M365AuthMode {
    /// Client-credentials (application permissions); headless service identity.
    #[default]
    AppOnly,
    /// Device-code / on-behalf-of a signed-in user (delegated permissions).
    Delegated,
}

/// Per-surface enable flags for the Microsoft 365 provider.
// One independent flag per surface, serialized as policy: that is the shape.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct M365Surfaces {
    #[serde(default = "default_true")]
    /// Whether the mail surface is enabled.
    pub mail: bool,
    #[serde(default = "default_true")]
    /// Whether the calendar surface is enabled.
    pub calendar: bool,
    #[serde(default = "default_true")]
    /// Whether the Teams surface is enabled.
    pub teams: bool,
    #[serde(default = "default_true")]
    /// Whether the files surface is enabled.
    pub files: bool,
}

impl Default for M365Surfaces {
    fn default() -> Self {
        Self {
            mail: true,
            calendar: true,
            teams: true,
            files: true,
        }
    }
}

/// Configuration for the native Microsoft 365 (Microsoft Graph) provider.
/// The client secret is never stored inline: it is sourced by reference from an
/// environment variable (`secret_env`) or a file (`secret_file`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct M365Config {
    #[serde(default = "default_true")]
    /// Whether this item is active.
    pub enabled: bool,
    /// Microsoft 365 tenant id.
    pub tenant_id: String,
    /// Microsoft 365 application (client) id.
    pub client_id: String,
    #[serde(default)]
    /// How the provider authenticates.
    pub auth_mode: M365AuthMode,
    #[serde(default)]
    /// Environment variable holding the client secret.
    pub secret_env: Option<String>,
    #[serde(default)]
    /// File holding the client secret.
    pub secret_file: Option<PathBuf>,
    /// Default mailbox/user (id or UPN) for app-only calls when no `user_id` arg is given.
    #[serde(default)]
    pub default_user_id: Option<String>,
    /// When false, write tools are not registered and are refused if called.
    #[serde(default)]
    pub allow_writes: bool,
    #[serde(default)]
    /// Which Microsoft 365 surfaces are enabled.
    pub surfaces: M365Surfaces,
    /// Maximum `@odata.nextLink` pages a single collection tool will follow.
    #[serde(default = "default_page_cap")]
    pub page_cap: usize,
    #[serde(default = "default_graph_base")]
    /// Microsoft Graph base URL.
    pub graph_base: String,
}

fn default_page_cap() -> usize {
    5
}

fn default_graph_base() -> String {
    "https://graph.microsoft.com/v1.0".to_string()
}

/// The full governance policy this server enforces.
// The policy file's own shape: each flag is an independent operator-facing
// setting, serialized by name. Packing them would change the file format.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Address the admin API binds to.
    pub admin_bind: String,
    /// Address the MCP endpoint binds to.
    pub mcp_bind: String,
    #[serde(default)]
    /// Allowed CORS origins for the MCP endpoint.
    pub mcp_allowed_origins: Vec<String>,
    #[serde(default)]
    /// Configured client credentials.
    pub mcp_clients: Vec<McpClientCredential>,
    /// When true, the MCP endpoint requires a configured client token and fails
    /// closed even if `mcp_clients` is empty. Default false preserves the
    /// loopback-only, no-token behavior for existing single-user setups.
    #[serde(default)]
    pub mcp_require_client_auth: bool,
    /// How repeated authentication failures from one source are throttled (G3-14, AF-8).
    #[serde(default)]
    pub auth_throttle: AuthThrottleConfig,
    /// When true, every enabled upstream (including loopback) must configure a
    /// `tools_sha256` pin or `manifest_public_key`. Default false keeps the loopback
    /// exemption: loopback traffic has no network MITM path, so pinning it adds
    /// friction without proportionate benefit for typical single-host setups.
    #[serde(default)]
    pub require_upstream_pinning: bool,
    /// Whether calls are auto-approved without a human gate.
    pub auto_approve: bool,
    /// Path to the audit chain.
    pub audit_path: PathBuf,
    #[serde(default = "default_exec_state_dir")]
    /// Durable execution state directory.
    pub exec_state_dir: PathBuf,
    #[serde(default)]
    /// Per-tool program path overrides.
    pub tool_paths: BTreeMap<String, PathBuf>,
    #[serde(default)]
    /// Named execution profiles.
    pub execution_profiles: BTreeMap<String, ExecutionProfile>,
    #[serde(default)]
    /// Profile used when none is named.
    pub default_execution_profile: Option<String>,
    #[serde(skip)]
    /// Resolved execution state directory, when computed.
    pub effective_exec_state_dir: Option<PathBuf>,
    /// Configured roots and their permissions.
    pub roots: Vec<RootRule>,
    #[serde(default)]
    /// Configured gateway upstreams.
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    /// Attribute-based access rules.
    pub abac_rules: Vec<AbacRule>,
    /// Named sets of upstreams, persisted, addressable and switchable.
    #[serde(default)]
    pub gateway_profiles: BTreeMap<String, GatewayProfile>,
    /// The profile in force, if any. `None` means every upstream answers for itself.
    #[serde(default)]
    pub active_gateway_profile: Option<String>,
    /// OAuth providers an upstream may broker a token from (G6-9).
    ///
    /// Two endpoints, a public client id, the scopes to ask for, and the name of a secret. No
    /// token appears here, so none appears in `GET /api/policy`, in a policy backup, or in the
    /// audit record of a policy change. A grant lives sealed in the secret store under a name
    /// reserved for the broker, and is replaced ahead of expiry without an operator present.
    #[serde(default)]
    pub oauth_providers: BTreeMap<String, OAuthProviderConfig>,
    /// Microsoft 365 (Graph) native provider config; absent disables the provider.
    #[serde(default)]
    pub m365: Option<M365Config>,
    /// Enable the SSE streaming lane (GET /mcp). Default true.
    #[serde(default = "default_true")]
    pub enable_sse_lane: bool,
    /// Enable the non-standard WebSocket lane (GET /mcp/ws). Opt-in NativeMCP
    /// extension, not standard MCP (see ADR-0001). Default false.
    #[serde(default)]
    pub enable_ws_lane: bool,
    /// Tools this server may answer with a task rather than a result (G5-6).
    ///
    /// Empty by default, and an empty set is a complete statement: the server never produces a
    /// task and never advertises `io.modelcontextprotocol/tasks`, so upgrading changes no
    /// client's behaviour. The extension leaves this choice to the server, and leaving it in
    /// policy rather than hardcoding it is what makes it an operator's choice rather than this
    /// crate's.
    ///
    /// Only a tool that creates a durable job can become a task here, because the job IS the
    /// task: there is no facility for running an arbitrary tool call in the background and
    /// persisting its result, and pretending otherwise would be the stub this project does not
    /// ship. `validate_semantics` refuses anything else by name.
    #[serde(default)]
    pub task_tools: BTreeSet<String>,
    /// OAuth 2.1 resource-server configuration (G3-11). Absent disables the whole feature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_resource: Option<OAuthResourceConfig>,
    /// Windows Event Log mirror configuration (M4-1). Absent leaves the environment in charge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_event_log: Option<AuditEventLogConfig>,
}

/// Windows Event Log mirror configuration (M4-1).
///
/// Absent means this policy says nothing about the mirror and the legacy environment variables
/// stay in charge, so an install that turned it on with `-EnableAuditEventLogMirror` keeps
/// working byte for byte. Present means policy is authoritative, including when it says
/// `enabled: false`, because an operator who writes the block down has decided.
///
/// It is a policy setting and not only an environment variable because the environment route
/// requires setting a variable on a `LocalSystem` service and restarting it, which most operators
/// cannot do, and because `PolicyConfig` is what G4-29's ADMX fleet floor acts on. Forwarding
/// the audit log to a collector is the one feature whose entire purpose is being turned on
/// fleet-wide by somebody who administers a fleet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEventLogConfig {
    /// Whether to mirror every audit record into the Windows Application log.
    #[serde(default)]
    pub enabled: bool,
    /// The event source to register under.
    ///
    /// Defaults to the product name. An operator changes it when a collector's subscription
    /// filters on a different source, which is the only reason to.
    #[serde(default = "default_event_log_source")]
    pub source: String,
}

fn default_event_log_source() -> String {
    "NativeMCP".to_string()
}

impl Default for AuditEventLogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            source: default_event_log_source(),
        }
    }
}

/// The ceiling on an Event Log source name.
///
/// Windows registers a source as a registry key under the Application log, and a key name is
/// bounded at 255 characters. A longer one fails at `RegisterEventSourceW` at the moment the
/// first record is written, which is the worst time to find out.
pub const MAX_EVENT_LOG_SOURCE_LEN: usize = 254;

/// OAuth 2.1 resource-server configuration (G3-11, ADR-0006).
///
/// Absent means the entire feature is absent: no metadata document is served, no
/// `WWW-Authenticate` challenge is issued, no bearer token is treated as an OAuth token, and the
/// static-token path behaves exactly as it did before this existed. That is RS-1, and it is the
/// same shape as the machine policy in G4-29 and the task tools in G5-6, for the same reason: a
/// security surface that appears on upgrade is a surface nobody decided to expose.
///
/// This server is a resource server and not an authorization server. Issuing tokens,
/// authenticating users and running consent belong to whatever is named in
/// `authorization_servers`. See ADR-0006 for why a `LocalSystem` process reachable from the
/// internet should not take that role on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthResourceConfig {
    /// The canonical URI of this MCP server, per RFC 8707 Section 2.
    ///
    /// Configured rather than inferred from a request header (RS-3). This is what an access
    /// token's audience is compared against, so deriving it from something a caller controls
    /// would let the caller choose what the audience check compares to.
    pub resource: String,
    /// Authorization servers that may issue tokens for this resource. At least one (RS-4).
    pub authorization_servers: Vec<String>,
    /// Token subject to the governed caller it becomes (RS-12).
    ///
    /// Explicit, and an unmapped subject is refused rather than given a default identity. Same
    /// reasoning as the undeclared upstream in G4-28: a default that silently grants is the
    /// failure mode the whole ring exists to prevent.
    ///
    /// Keyed on the `sub` claim, which RFC 7519 Section 4.1.2 makes unique only WITHIN one
    /// issuer. With more than one authorization server configured a bare `sub` is therefore
    /// ambiguous, and `OAuthSubject::issuer` is required to say whose subject this is. One
    /// consequence, deliberate: the same `sub` string cannot be mapped for two issuers at
    /// once. The other issuer's caller is refused as unmapped, which is the safe direction.
    #[serde(default)]
    pub subjects: BTreeMap<String, OAuthSubject>,
    /// Signing algorithms this server will accept (RS-9).
    ///
    /// Taken from here and never from the token's own `alg` header, which is the oldest trick
    /// in this particular book. `none` is refused at validation.
    #[serde(default = "default_oauth_algorithms")]
    pub algorithms: Vec<String>,
    /// Clock skew tolerance in seconds when checking `exp` and `nbf` (RS-9).
    #[serde(default = "default_oauth_clock_skew_secs")]
    pub clock_skew_secs: u64,
    /// Scopes to advertise in the metadata document, if the operator wants to name any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
}

/// What a validated token subject becomes inside the governance ring.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthSubject {
    /// The caller ABAC matches on, HITL gates, and the audit record names.
    pub agent_id: String,
    /// The gateway profile this subject is pinned to, if any (G6-8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Which authorization server's subject this is.
    ///
    /// Optional only where it cannot be ambiguous: validation requires it once more than one
    /// authorization server is configured, because `sub` is unique within an issuer and
    /// nowhere else. Without it an operator trusting two issuers has written "whoever either
    /// of these calls alice is alice", and someone who can register a subject at the weaker
    /// one inherits the identity meant for the stronger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

/// Throttling repeated authentication failures (G3-14, AF-8).
///
/// On by default, unlike most of this file's security features. The reason the usual
/// default-off argument does not apply: turning this on cannot deny a caller who holds a valid
/// credential, because only a FAILED attempt counts toward the threshold. There is no install
/// this silently breaks, so leaving it off would be leaving a gap for no benefit.
///
/// Keyed on source and never on `agent_id`, on a credential value, or on a global counter. The
/// failure mode being designed against is not the attacker being slowed, which is the point,
/// but one attacker causing a legitimate client to be refused.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthThrottleConfig {
    #[serde(default = "default_auth_throttle_enabled")]
    /// Whether this item is active.
    pub enabled: bool,
    /// Failed attempts from one source within the window before it is refused unevaluated.
    #[serde(default = "default_auth_throttle_threshold")]
    pub threshold: u32,
    /// How long the counting window is, and therefore how long a throttle lasts.
    #[serde(default = "default_auth_throttle_window_secs")]
    pub window_secs: u64,
}

impl Default for AuthThrottleConfig {
    fn default() -> Self {
        Self {
            enabled: default_auth_throttle_enabled(),
            threshold: default_auth_throttle_threshold(),
            window_secs: default_auth_throttle_window_secs(),
        }
    }
}

fn default_auth_throttle_enabled() -> bool {
    true
}

/// Twenty failures in a minute is far past a typo and far short of anything a working client
/// does, so it separates the two cases without an operator having to tune it.
fn default_auth_throttle_threshold() -> u32 {
    20
}

fn default_auth_throttle_window_secs() -> u64 {
    60
}

/// The ceiling on the throttle window. A window longer than this stops being a throttle and
/// becomes a lockout, which is the shape that turns one attacker into everyone's outage.
pub const MAX_AUTH_THROTTLE_WINDOW_SECS: u64 = 3_600;

fn default_oauth_algorithms() -> Vec<String> {
    vec!["RS256".to_string(), "ES256".to_string()]
}

fn default_oauth_clock_skew_secs() -> u64 {
    60
}

/// The ceiling on `clock_skew_secs`, above which expiry enforcement stops being enforcement.
pub const MAX_OAUTH_CLOCK_SKEW_SECS: u64 = 300;

/// Tools that create a durable job and can therefore answer as a task.
///
/// One entry today. The set exists rather than a boolean because the eligibility rule is a
/// property of the tool, so a second job-creating tool joins the list without changing the
/// shape of policy.
pub const TASK_ELIGIBLE_TOOLS: &[&str] = &["execute_start"];

/// An OAuth provider an operator authorizes once and several upstreams then share (G6-9).
///
/// Everything in here is safe in a governed, backed-up, readable file: two endpoint URLs, a
/// client id that is public by definition in a device flow, the scopes to ask for, and the name
/// of a secret. `validate_semantics` is what keeps the last one a name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OAuthProviderConfig {
    /// What the console calls this provider. Falls back to the map key when empty.
    #[serde(default)]
    pub label: String,
    /// RFC 8628 device authorization endpoint, where a user code is obtained.
    pub device_authorization_endpoint: String,
    /// Where a device code is exchanged for a grant, and where a refresh is performed.
    pub token_endpoint: String,
    /// The client identifier. Public by design in a device flow, so this one is not a secret.
    pub client_id: String,
    /// Name of a secret holding a client secret, for a provider that requires one.
    ///
    /// Optional, because a device flow client is normally public. Named and never carried,
    /// exactly like `UpstreamConfig::auth_secret`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_secret: Option<String>,
    /// Scopes requested at authorization and carried through every refresh.
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// One client credential accepted by the MCP endpoint.
pub struct McpClientCredential {
    /// The authenticated agent identity.
    pub agent_id: String,
    /// SHA-256 of the client token.
    pub token_sha256: String,
    /// The gateway profile this credential is pinned to, if any.
    ///
    /// This is what makes a profile a boundary rather than a convenience. A profile chosen
    /// purely by request header is a filter a client can decline to send; a profile named
    /// here travels with the credential and the client cannot get out from under it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

/// A named set of upstreams and whether each is live while this profile is in force.
///
/// The runtime object G6-5 asks for, as against the `profiles: Vec<String>` tag a catalog
/// entry carries. The two are deliberately different things and keeping them separate is the
/// point of the item. A catalog tag is a suggestion about where a piece of software belongs,
/// written by whoever curated the catalog. A profile is a statement about this machine,
/// written by the operator, persisted in policy, and answerable for what is running right
/// now.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayProfile {
    /// Display name for an admin surface. The map key is the identity.
    #[serde(default)]
    pub label: String,
    /// Upstream id to whether that upstream is live under this profile.
    ///
    /// An upstream absent from this map is not live while the profile is active. That is what
    /// makes activating a profile a complete statement about the machine rather than a set of
    /// edits layered on whatever happened to be running before it.
    #[serde(default)]
    pub servers: BTreeMap<String, bool>,
}

fn default_exec_state_dir() -> PathBuf {
    nmcp_identity::default_exec_state_dir()
}

/// `default_inherit_service_env`.
#[must_use]
pub fn default_inherit_service_env() -> bool {
    true
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            admin_bind: "127.0.0.1:18769".into(),
            mcp_bind: "127.0.0.1:18770".into(),
            mcp_allowed_origins: Vec::new(),
            mcp_clients: Vec::new(),
            auto_approve: true,
            mcp_require_client_auth: false,
            require_upstream_pinning: false,
            audit_path: nmcp_identity::default_audit_path(),
            exec_state_dir: default_exec_state_dir(),
            tool_paths: BTreeMap::new(),
            gateway_profiles: BTreeMap::new(),
            active_gateway_profile: None,
            oauth_providers: BTreeMap::new(),
            execution_profiles: BTreeMap::new(),
            default_execution_profile: None,
            effective_exec_state_dir: None,
            roots: vec![RootRule {
                id: "current-directory".into(),
                path: PathBuf::from("."),
                permissions: [
                    Permission::List,
                    Permission::Read,
                    Permission::Search,
                    Permission::Create,
                    Permission::Write,
                    Permission::Modify,
                    Permission::Rename,
                    Permission::Move,
                    Permission::Backup,
                    Permission::Execute,
                    Permission::Scan,
                    Permission::Report,
                ]
                .into_iter()
                .collect(),
            }],
            upstreams: Vec::new(),
            abac_rules: Vec::new(),
            m365: None,
            enable_sse_lane: true,
            enable_ws_lane: false,
            task_tools: BTreeSet::new(),
            oauth_resource: None,
            audit_event_log: None,
            auth_throttle: AuthThrottleConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The outcome of a single authorization check.
pub struct PolicyDecision {
    /// Whether the call is permitted.
    pub allowed: bool,
    /// The capability this concerns.
    pub permission: Permission,
    /// The root that decided it, when one did.
    pub root_id: Option<String>,
    /// The canonicalized path.
    pub normalized_path: String,
    /// Human-readable explanation.
    pub reason: String,
}

impl PolicyConfig {
    /// `require`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] describing what was refused.
    pub fn require(
        &self,
        permission: Permission,
        path: impl AsRef<Path>,
    ) -> Result<PolicyDecision, PolicyError> {
        let normalized = canonicalize_for_policy(path.as_ref());
        // Select the most specific (longest canonical prefix) matching root, so a
        // narrow restrictive root is never shadowed by a broader one declared
        // earlier. The chosen root's permissions are authoritative (deny if absent).
        let mut best: Option<(&RootRule, usize)> = None;
        for root in &self.roots {
            let root_norm = canonicalize_for_policy(&root.path);
            if normalized.starts_with(&root_norm) {
                let len = root_norm.as_os_str().len();
                if best.as_ref().is_none_or(|&(_, best_len)| len > best_len) {
                    best = Some((root, len));
                }
            }
        }
        match best {
            Some((root, _)) => {
                if root.permissions.contains(&permission) {
                    Ok(PolicyDecision {
                        allowed: true,
                        permission,
                        root_id: Some(root.id.clone()),
                        normalized_path: normalized.display().to_string(),
                        reason: "permission allowed by root policy".into(),
                    })
                } else {
                    Err(PolicyError::PermissionDenied {
                        permission,
                        path: normalized.display().to_string(),
                    })
                }
            }
            None => Err(PolicyError::OutsideRoots(normalized.display().to_string())),
        }
    }

    /// `canonicalize_roots_for_save`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] describing what was refused.
    pub fn canonicalize_roots_for_save(&mut self) -> Result<(), PolicyError> {
        for root in &mut self.roots {
            root.path = canonicalize_existing_root(&root.path)?;
        }
        Ok(())
    }

    /// `validate_service_roots`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] describing what was refused.
    pub fn validate_service_roots(&self) -> Result<(), PolicyError> {
        for root in &self.roots {
            if !root.path.is_absolute() {
                return Err(PolicyError::RelativeServiceRoot(
                    root.path.display().to_string(),
                ));
            }
            if !root.path.exists() {
                return Err(PolicyError::MissingRoot(root.path.display().to_string()));
            }
        }
        Ok(())
    }

    /// Parse policy JSON and enforce semantic validation in one step.
    ///
    /// Every file-based load path goes through here so that `NativeMCPctl validate`,
    /// daemon startup, and policy hot reload cannot drift apart on what counts as a valid
    /// policy. Before this existed all three parsed with serde and skipped
    /// `validate_semantics` entirely, so `validate` printed "valid policy" for
    /// configurations the enforcement layer forbids (identical admin and MCP binds,
    /// duplicate root ids, roots with no permissions, malformed client token digests).
    ///
    /// A leading UTF-8 BOM is tolerated. Windows editors and PowerShell 5.1
    /// `Set-Content -Encoding UTF8` emit one, and `serde_json` otherwise rejects the file
    /// with an opaque "expected value at line 1 column 1" that gives the operator no
    /// path to the cause.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] describing what was refused.
    pub fn from_json_str(text: &str) -> Result<Self, PolicyError> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut policy: Self =
            serde_json::from_str(text).map_err(|e| PolicyError::MalformedJson(e.to_string()))?;
        // Fold the pre-DEC-007 `url` spelling into `transport` before anything reads it, so
        // validation and hot-reload comparison both see exactly one canonical form.
        for upstream in &mut policy.upstreams {
            upstream.normalize_transport();
        }
        policy.validate_semantics()?;
        Ok(policy)
    }

    /// Roots that grant mutating permissions over a whole volume.
    ///
    /// A root like `\\?\C:\` with `write` is not a scoped grant, it is the volume. Under a
    /// service running as a privileged account the reachable blast radius is the machine.
    /// Whether any root grants this permission, with no path involved.
    ///
    /// The capability question, as distinct from the path question `require` answers. Used by
    /// the m365 and win.api gates and by upstream admission (G4-28).
    #[must_use]
    pub fn grants_capability(&self, permission: Permission) -> bool {
        self.roots
            .iter()
            .any(|root| root.permissions.contains(&permission))
    }

    /// Whether this upstream's tools may be dispatched (G4-28).
    #[must_use]
    pub fn upstream_admission(&self, upstream_id: &str) -> UpstreamAdmission {
        let Some(upstream) = self.upstreams.iter().find(|u| u.id == upstream_id) else {
            return UpstreamAdmission::NotAdmitted;
        };
        let Some(permission) = upstream.required_permission else {
            return UpstreamAdmission::Undeclared;
        };
        if self.grants_capability(permission) {
            UpstreamAdmission::Granted { permission }
        } else {
            UpstreamAdmission::MissingGrant { permission }
        }
    }

    /// `volume_wide_mutating_roots`.
    #[must_use]
    pub fn volume_wide_mutating_roots(&self) -> Vec<&RootRule> {
        self.roots
            .iter()
            .filter(|root| {
                is_whole_volume(&root.path)
                    && root
                        .permissions
                        .iter()
                        .any(|permission| MUTATING_PERMISSIONS.contains(permission))
            })
            .collect()
    }

    /// True when nothing on the MCP listener has to present a credential.
    ///
    /// The origin allowlist is not authentication and does not count here: it constrains
    /// browsers, which send `Origin`, and a native local process simply does not send one.
    #[must_use]
    pub fn mcp_surface_is_unauthenticated(&self) -> bool {
        !self.mcp_require_client_auth || self.mcp_clients.is_empty()
    }

    /// Posture weaknesses in the loaded policy, worst-compounding last.
    ///
    /// Advisory by construction. See [`PostureFinding`].
    #[must_use]
    pub fn posture_findings(&self) -> Vec<PostureFinding> {
        let mut findings = Vec::new();
        let unauthenticated = self.mcp_surface_is_unauthenticated();
        let volume_roots = self.volume_wide_mutating_roots();

        if unauthenticated {
            findings.push(PostureFinding {
                id: "mcp_surface_unauthenticated",
                detail: "the MCP listener requires no client credential, so any local process \
                         that can open a loopback socket can call every governed tool"
                    .to_string(),
                remediation:
                    "Set mcp_require_client_auth to true and give each client an mcp_clients entry.",
            });
        }
        if !volume_roots.is_empty() {
            let ids: Vec<&str> = volume_roots.iter().map(|root| root.id.as_str()).collect();
            findings.push(PostureFinding {
                id: "volume_wide_mutating_root",
                detail: format!(
                    "root(s) {} grant mutating permissions over an entire volume rather than over \
                     the directories that need them",
                    ids.join(", ")
                ),
                remediation:
                    "Narrow the root to the directories that need write access, or reduce it to \
                     non-mutating permissions.",
            });
        }
        // The compound. Each part above is a legitimate choice on its own, and each is
        // documented as optional in a different place, which is exactly why the
        // combination is easy to arrive at without ever deciding on it.
        if unauthenticated && self.auto_approve && !volume_roots.is_empty() {
            findings.push(PostureFinding {
                id: "unauthenticated_auto_approved_volume_write",
                detail: "no MCP client credential, auto_approve on, and a volume-wide mutating \
                         root are all active together: an uncredentialed local caller reaches \
                         volume-wide writes with no human checkpoint anywhere in the path"
                    .to_string(),
                remediation:
                    "Change any one of the three. Requiring a client credential is the smallest \
                     change that breaks the chain; narrowing the root is the one that limits it.",
            });
        }
        findings
    }

    /// The profile in force, with its name, if one is active and exists.
    #[must_use]
    pub fn active_profile(&self) -> Option<(&str, &GatewayProfile)> {
        let name = self.active_gateway_profile.as_deref()?;
        self.gateway_profiles.get(name).map(|p| (name, p))
    }

    /// Whether an upstream should be live right now.
    ///
    /// With no active profile this is the upstream's own `enabled`, which is what every build
    /// before G6-5 did and what a policy file with no profiles still does. With a profile
    /// active the profile decides, and an upstream it does not name is not live whatever its
    /// own flag says.
    ///
    /// That override is the difference between a profile and a bulk edit. A bulk edit stamps
    /// `enabled` across every upstream and cannot be undone; a profile is a statement you can
    /// switch away from and back with the per-upstream flags untouched underneath it.
    #[must_use]
    pub fn upstream_is_live(&self, upstream: &UpstreamConfig) -> bool {
        match self.active_profile() {
            Some((_, profile)) => profile.servers.get(&upstream.id).copied().unwrap_or(false),
            None => upstream.enabled,
        }
    }

    /// The gateway profile in force for one session (G6-8).
    ///
    /// The credential binds and the header selects within what the credential permits. A
    /// credential naming a profile pins the session and refuses a header that disagrees; a
    /// credential naming none lets the header choose, which is what one operator running
    /// several desktops against one service needs; and neither leaves the machine-wide
    /// profile in charge, which is exactly what this build did before sessions had profiles.
    ///
    /// The `Err` case is a refusal rather than a silent narrowing. A client that asked for a
    /// profile it may not have should be told, because the alternative is a session that
    /// quietly does less than the operator configured and gives no clue why.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] describing what was refused.
    pub fn session_profile(
        &self,
        credential_profile: Option<&str>,
        header_profile: Option<&str>,
    ) -> Result<Option<String>, String> {
        let header = header_profile
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if let Some(bound) = credential_profile {
            if let Some(header) = header
                && header != bound
            {
                return Err(format!(
                    "this credential is bound to gateway profile '{bound}' and the request asked for '{header}'"
                ));
            }
            if !self.gateway_profiles.contains_key(bound) {
                return Err(format!(
                    "this credential is bound to gateway profile '{bound}', which is not configured"
                ));
            }
            return Ok(Some(bound.to_string()));
        }
        let Some(header) = header else {
            return Ok(None);
        };
        if !self.gateway_profiles.contains_key(header) {
            return Err(format!("gateway profile '{header}' is not configured"));
        }
        Ok(Some(header.to_string()))
    }

    /// Whether a session scoped to `profile` can reach the tools of `provider_id`.
    ///
    /// A local provider carries an empty id and is never scoped by a profile. Profiles select
    /// among the upstream servers this gateway proxies; taking away the filesystem or the
    /// Windows tools would be a different feature wearing the same word, and the tool that
    /// does that is the caller allowlist G3-12 added.
    ///
    /// One function so that listing and calling cannot disagree. A session that can see a
    /// tool it cannot call, or call one it cannot see, is worse than either restriction on
    /// its own.
    #[must_use]
    pub fn provider_visible_to_session(&self, profile: Option<&str>, provider_id: &str) -> bool {
        if provider_id.is_empty() {
            return true;
        }
        let Some(profile) = profile else {
            return true;
        };
        self.gateway_profiles
            .get(profile)
            .and_then(|profile| profile.servers.get(provider_id))
            .copied()
            .unwrap_or(false)
    }

    /// The upstreams that should be registered with the router right now.
    ///
    /// Every caller that used to filter on `enabled` should use this instead, so there is one
    /// answer to what is live rather than one per call site.
    pub fn live_upstreams(&self) -> impl Iterator<Item = &UpstreamConfig> {
        self.upstreams.iter().filter(|u| self.upstream_is_live(u))
    }

    /// `validate_semantics`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] describing what was refused.
    // One exhaustive validator: every semantic rule in one place, in the order
    // an operator hits them. Splitting it would hide the ordering.
    #[allow(clippy::too_many_lines)]
    pub fn validate_semantics(&self) -> Result<(), PolicyError> {
        fn fail(message: impl Into<String>) -> Result<(), PolicyError> {
            Err(PolicyError::SemanticValidation(message.into()))
        }
        fn safe_id(value: &str) -> bool {
            !value.trim().is_empty()
                && value.len() <= 64
                && value
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.')
        }
        fn sha256_hex(value: &str) -> bool {
            value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
        }
        fn env_var_name(value: &str) -> bool {
            !value.is_empty()
                && value.len() <= 128
                && !value.starts_with(|ch: char| ch.is_ascii_digit())
                && value
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        }
        fn http_header_name(value: &str) -> bool {
            // Headers the HTTP client owns. Letting policy set them would either be
            // ignored or would corrupt the request framing.
            const RESERVED: &[&str] = &[
                "connection",
                "content-length",
                "content-type",
                "host",
                "transfer-encoding",
                "upgrade",
            ];
            !value.is_empty()
                && value.len() <= 64
                && value
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
                && !RESERVED.contains(&value.to_ascii_lowercase().as_str())
        }
        fn http_url(value: &str) -> bool {
            let Some(rest) = value
                .strip_prefix("http://")
                .or_else(|| value.strip_prefix("https://"))
            else {
                return false;
            };
            !rest.trim().is_empty() && !rest.starts_with('/') && !rest.contains(char::is_whitespace)
        }
        fn loopback_http_url(value: &str) -> bool {
            let Some(rest) = value
                .strip_prefix("http://")
                .or_else(|| value.strip_prefix("https://"))
            else {
                return false;
            };
            let host_port_path = rest.split('/').next().unwrap_or_default();
            let host = host_port_path
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or(host_port_path)
                .split(':')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1")
        }

        let admin_bind: std::net::SocketAddr = self.admin_bind.parse().map_err(|_| {
            PolicyError::SemanticValidation(format!(
                "admin_bind must be host:port: {}",
                self.admin_bind
            ))
        })?;
        let mcp_bind: std::net::SocketAddr = self.mcp_bind.parse().map_err(|_| {
            PolicyError::SemanticValidation(format!(
                "mcp_bind must be host:port: {}",
                self.mcp_bind
            ))
        })?;
        if admin_bind == mcp_bind {
            return fail("admin_bind and mcp_bind must be distinct");
        }
        if self.audit_path.as_os_str().is_empty() || self.audit_path.file_name().is_none() {
            return fail("audit_path must include a file name");
        }
        if self.exec_state_dir.as_os_str().is_empty() {
            return fail("exec_state_dir must not be empty");
        }
        if self.roots.is_empty() {
            return fail("at least one root must be configured");
        }
        let mut root_ids = BTreeSet::new();
        for root in &self.roots {
            if !safe_id(&root.id) {
                return fail(format!("root id is invalid: {}", root.id));
            }
            if !root_ids.insert(root.id.clone()) {
                return fail(format!("duplicate root id: {}", root.id));
            }
            if root.path.as_os_str().is_empty() {
                return fail(format!("root '{}' path must not be empty", root.id));
            }
            if root.permissions.is_empty() {
                return fail(format!(
                    "root '{}' must grant at least one permission",
                    root.id
                ));
            }
        }

        for origin in &self.mcp_allowed_origins {
            let origin = origin.trim();
            if origin.is_empty() || origin == "*" || origin.eq_ignore_ascii_case("null") {
                return fail(
                    "mcp_allowed_origins must not contain empty, wildcard, or null origins",
                );
            }
            if !http_url(origin) {
                return fail(format!(
                    "mcp_allowed_origins entry must be http(s): {origin}"
                ));
            }
        }

        let mut client_ids = BTreeSet::new();
        for client in &self.mcp_clients {
            if !safe_id(&client.agent_id) {
                return fail(format!(
                    "MCP client agent_id is invalid: {}",
                    client.agent_id
                ));
            }
            if !client_ids.insert(client.agent_id.clone()) {
                return fail(format!(
                    "duplicate MCP client agent_id: {}",
                    client.agent_id
                ));
            }
            if !sha256_hex(&client.token_sha256) {
                return fail(format!(
                    "MCP client '{}' token_sha256 must be a SHA-256 hex digest",
                    client.agent_id
                ));
            }
        }

        // Requiring client auth without configuring a credential is a contradiction the
        // server resolves by refusing every MCP call. That is fail-closed and therefore
        // safe, but it is also silent: there was no config-time error and no startup
        // warning, so the operator saw a healthy service that answered nothing.
        if self.mcp_require_client_auth && self.mcp_clients.is_empty() {
            return fail(
                "mcp_require_client_auth is set but mcp_clients is empty, so every MCP call \
                 would be refused; add at least one client credential or clear the flag",
            );
        }

        for (alias, path) in &self.tool_paths {
            if !safe_id(alias) {
                return fail(format!("tool alias is invalid: {alias}"));
            }
            if path.as_os_str().is_empty() {
                return fail(format!("tool alias '{alias}' path must not be empty"));
            }
        }
        for (name, profile) in &self.execution_profiles {
            if !safe_id(name) {
                return fail(format!("execution profile name is invalid: {name}"));
            }
            for key in profile.env.keys() {
                if key.trim().is_empty() || key.contains('=') || key.contains('\0') {
                    return fail(format!("execution profile '{name}' has invalid env key"));
                }
            }
        }
        if let Some(profile) = &self.default_execution_profile
            && !self.execution_profiles.contains_key(profile)
        {
            return fail(format!(
                "default_execution_profile does not exist: {profile}"
            ));
        }

        // G4-28, checked after every other upstream rule so a malformed configuration is
        // reported as malformed rather than as undeclared. An admitted upstream runs code this
        // server does not control: a stdio or container upstream is a child of the daemon,
        // which runs as LocalSystem. The ring cannot constrain what it does, so the one thing
        // it can do is refuse to dispatch its tools unless an operator granted a capability on
        // purpose. Refused rather than defaulted, because a default is the thing nobody reads.
        let undeclared: Vec<&str> = self
            .upstreams
            .iter()
            .filter(|u| u.enabled && u.required_permission.is_none())
            .map(|u| u.id.as_str())
            .collect();

        let mut upstream_ids = BTreeSet::new();
        for upstream in &self.upstreams {
            if !safe_id(&upstream.id) || upstream.id.contains('.') {
                return fail(format!("upstream id is invalid: {}", upstream.id));
            }
            if !upstream_ids.insert(upstream.id.clone()) {
                return fail(format!("duplicate upstream id: {}", upstream.id));
            }
            let transport = upstream.transport();
            if let Some(missing) = transport.missing_required_field() {
                return fail(format!(
                    "upstream '{}' declares the {} transport with no {missing}",
                    upstream.id,
                    transport.kind()
                ));
            }
            // Refuse a transport the runtime cannot honour rather than accepting a
            // configuration that can only ever fail at refresh time. Admitting a stdio or
            // container catalog entry against a runtime that speaks only HTTP is the exact
            // defect DEC-007 exists to end, and it is what left G4-22 retrying a dead port
            // for weeks.
            if !transport.is_implemented() {
                return fail(format!(
                    "upstream '{}' declares the {} transport, which this build does not implement yet (lands with {})",
                    upstream.id,
                    transport.kind(),
                    transport.implemented_by()
                ));
            }
            if let Some(image) = transport.unpinned_container_image() {
                return fail(format!(
                    "upstream '{}' names the container image '{image}' by tag; pin it by digest as image@sha256:<64 hex> so the tool list this gateway trusts belongs to bytes that cannot change under it",
                    upstream.id
                ));
            }
            if let Some(runtime) = transport.unusable_container_runtime() {
                return fail(format!(
                    "upstream '{}' names the container runtime '{runtime}'; use a bare program name or an absolute path",
                    upstream.id
                ));
            }
            // A stdio upstream has no url to check and no network hop to distrust. What it
            // has instead is a command line the operator wrote, which is why admission and
            // the catalog's risk tiers carry the weight there. Pinning still applies when
            // the operator asked for it, because the tool list is what gets trusted either
            // way.
            let is_remote = match &transport {
                UpstreamTransport::Http { url } => {
                    if !http_url(url) {
                        return fail(format!("upstream '{}' url must be http(s)", upstream.id));
                    }
                    !loopback_http_url(url)
                }
                _ => false,
            };
            if upstream.enabled
                && (self.require_upstream_pinning || is_remote)
                && upstream.tools_sha256.is_none()
                && upstream.manifest_public_key.is_none()
            {
                let scope = if self.require_upstream_pinning {
                    "admission (require_upstream_pinning is enabled)"
                } else {
                    "non-loopback admission"
                };
                let _ = &transport;
                return fail(format!(
                    "upstream '{}' must configure tools_sha256 or manifest_public_key for {scope}",
                    upstream.id
                ));
            }
            if let Some(pin) = &upstream.tools_sha256
                && !sha256_hex(pin)
            {
                return fail(format!(
                    "upstream '{}' tools_sha256 must be a SHA-256 hex digest",
                    upstream.id
                ));
            }
            if let Some(key) = &upstream.manifest_public_key
                && (key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return fail(format!(
                    "upstream '{}' manifest_public_key must be 32-byte hex",
                    upstream.id
                ));
            }
            if let Some(allowlist) = &upstream.tool_allowlist {
                for tool in allowlist {
                    if !safe_id(tool) || tool.contains('.') {
                        return fail(format!(
                            "upstream '{}' tool allowlist entry is invalid: {tool}",
                            upstream.id
                        ));
                    }
                }
            }
            // More than one credential source for one upstream is ambiguous, and the ambiguity
            // would be resolved silently at request time by whichever the code checks first.
            let sources = [
                upstream.oauth_provider.is_some(),
                upstream.auth_secret.is_some(),
                upstream.auth_header_env.is_some(),
            ]
            .into_iter()
            .filter(|set| *set)
            .count();
            if sources > 1 {
                return fail(format!(
                    "upstream '{}' names more than one credential source; pick one of \
                     oauth_provider, auth_secret and auth_header_env",
                    upstream.id
                ));
            }
            if let Some(provider) = &upstream.oauth_provider
                && !self.oauth_providers.contains_key(provider)
            {
                return fail(format!(
                    "upstream '{}' brokers from oauth provider '{provider}', which is not configured",
                    upstream.id
                ));
            }
            // Any credential source, not only the environment one. An upstream reached over
            // cleartext http to another host puts whatever it is sent on the wire, and which of
            // the three named it makes no difference to whoever is reading that wire. This used
            // to guard `auth_header_env` alone, which left the other two uncovered.
            if sources > 0
                && upstream.enabled
                && upstream
                    .http_url()
                    .is_some_and(|url| url.starts_with("http://") && !loopback_http_url(&url))
            {
                return fail(format!(
                    "upstream '{}' would send a credential in cleartext over http to a \
                     non-loopback host; use https or remove the credential",
                    upstream.id
                ));
            }
            if let Some(name) = &upstream.auth_secret
                && !safe_id(name)
            {
                return fail(format!(
                    "upstream '{}' auth_secret must be a secret name, not the credential itself",
                    upstream.id
                ));
            }
            for (variable, secret) in transport.env_secrets() {
                if !env_var_name(variable) {
                    return fail(format!(
                        "upstream '{}' env_secrets key '{variable}' is not an environment variable name",
                        upstream.id
                    ));
                }
                if !safe_id(secret) {
                    return fail(format!(
                        "upstream '{}' env_secrets '{variable}' must name a secret, not the credential itself",
                        upstream.id
                    ));
                }
            }
            // G4-30. auth_header_name is validated whichever source names it. This used to be
            // a match keyed on auth_header_env, so an upstream using auth_secret or
            // oauth_provider reached the empty arm and http_header_name never ran: an operator
            // writing auth_secret alongside an auth_header_name of "Host" or "Content-Length"
            // passed validation. Harmless today because the gateway reads the name only on the
            // env path, and exactly the shape that becomes a defect the moment the other paths
            // learn to honour it. The rule is a property of the FIELD, so it is checked where
            // the field is, once, rather than inside one source's arm.
            if let Some(name) = &upstream.auth_header_name {
                if !http_header_name(name) {
                    return fail(format!(
                        "upstream '{}' auth_header_name is not a header this proxy may set: \
                         {name}",
                        upstream.id
                    ));
                }
                // A header name with no credential source sends nothing. The upstream then
                // rejects every call and the operator debugs the wrong end. All three sources
                // count, because any of them satisfies "something will be sent".
                if upstream.auth_header_env.is_none()
                    && upstream.auth_secret.is_none()
                    && upstream.oauth_provider.is_none()
                {
                    return fail(format!(
                        "upstream '{}' sets auth_header_name '{name}' without auth_header_env, \
                         auth_secret or oauth_provider, so no credential would ever be sent",
                        upstream.id
                    ));
                }
            }
            if let Some(var) = &upstream.auth_header_env {
                // The field is a variable name by design. Rejecting anything that is not a
                // plausible name is what stops an operator from pasting the token here and
                // shipping the secret inside a governed, backed-up, readable file.
                if !env_var_name(var) {
                    return fail(format!(
                        "upstream '{}' auth_header_env must be an environment variable name \
                         (letters, digits, underscore), not the credential itself",
                        upstream.id
                    ));
                }
            }
        }

        for (id, provider) in &self.oauth_providers {
            if !safe_id(id) {
                return fail(format!("oauth provider id is invalid: {id}"));
            }
            for (field, url) in [
                (
                    "device_authorization_endpoint",
                    &provider.device_authorization_endpoint,
                ),
                ("token_endpoint", &provider.token_endpoint),
            ] {
                if url.trim().is_empty() {
                    return fail(format!("oauth provider '{id}' has no {field}"));
                }
                // A device code goes out over this wire and a refresh token comes back. In
                // cleartext to anything but the local machine that hands the whole grant to
                // whoever is on the path, which is worse than the access token alone.
                if !url.starts_with("https://") && !loopback_http_url(url) {
                    return fail(format!(
                        "oauth provider '{id}' {field} must be https, or http to loopback: {url}"
                    ));
                }
            }
            if provider.client_id.trim().is_empty() {
                return fail(format!("oauth provider '{id}' has no client_id"));
            }
            if let Some(name) = &provider.client_secret_secret
                && !safe_id(name)
            {
                return fail(format!(
                    "oauth provider '{id}' client_secret_secret must be a secret name, not the credential itself"
                ));
            }
        }

        for (idx, rule) in self.abac_rules.iter().enumerate() {
            match rule {
                AbacRule::TimeOfDay {
                    allow_start_hour,
                    allow_end_hour,
                    ..
                } => {
                    if *allow_start_hour > 23
                        || *allow_end_hour > 24
                        || allow_start_hour == allow_end_hour
                    {
                        return fail(format!("ABAC rule {idx} has invalid time window"));
                    }
                }
                AbacRule::CallerIdentity {
                    allowed_callers, ..
                } => {
                    if allowed_callers.is_empty() {
                        return fail(format!("ABAC rule {idx} caller list must not be empty"));
                    }
                    for caller in allowed_callers {
                        if caller != "*" && !safe_id(caller) {
                            return fail(format!("ABAC rule {idx} caller id is invalid: {caller}"));
                        }
                    }
                }
                AbacRule::CallerToolAllowlist {
                    caller,
                    allowed_tools,
                    ..
                } => {
                    if !safe_id(caller) {
                        return fail(format!("ABAC rule {idx} caller id is invalid: {caller}"));
                    }
                    if caller == "*" {
                        return fail(format!(
                            "ABAC rule {idx} caller must name one identity; '*' would deny every \
                         caller every tool outside the list"
                        ));
                    }
                    if allowed_tools.is_empty() {
                        return fail(format!(
                            "ABAC rule {idx} allowed_tools is empty, which denies this caller every \
                         tool; remove the client instead of configuring it to do nothing"
                        ));
                    }
                }
                AbacRule::CommandContent { pattern, .. } => {
                    regex::Regex::new(&pattern.to_lowercase()).map_err(|err| {
                        PolicyError::SemanticValidation(format!(
                            "ABAC rule {idx} command-content regex is invalid: {err}"
                        ))
                    })?;
                }
            }
        }

        // Gateway profiles. A profile naming an upstream that does not exist is refused
        // rather than tolerated, because of which direction the mistake runs: under an active
        // profile, selecting nothing means retracting everything, so a typo in a server id
        // would quietly take a server off the air instead of quietly doing nothing.
        for (name, profile) in &self.gateway_profiles {
            if !safe_id(name) {
                return fail(format!("gateway profile name is invalid: {name}"));
            }
            for id in profile.servers.keys() {
                if !upstream_ids.contains(id.as_str()) {
                    return fail(format!(
                        "gateway profile '{name}' selects upstream '{id}', which is not configured"
                    ));
                }
            }
        }
        for credential in &self.mcp_clients {
            if let Some(profile) = &credential.profile
                && !self.gateway_profiles.contains_key(profile)
            {
                return fail(format!(
                    "mcp client '{}' is bound to gateway profile '{profile}', which is not configured",
                    credential.agent_id
                ));
            }
        }
        if let Some(active) = &self.active_gateway_profile
            && !self.gateway_profiles.contains_key(active)
        {
            return fail(format!(
                "active_gateway_profile names '{active}', which is not a configured profile"
            ));
        }

        // G3-11. RS-2 and RS-3: an authorization server that is not HTTPS is not one, and a
        // resource identifier that is not canonical cannot be compared against an audience.
        if let Some(oauth) = &self.oauth_resource {
            if oauth.authorization_servers.is_empty() {
                return Err(PolicyError::SemanticValidation(
                    "oauth_resource names no authorization_servers; the protected resource \
                     metadata document must contain at least one"
                        .to_string(),
                ));
            }
            for issuer in &oauth.authorization_servers {
                if !issuer.starts_with("https://") {
                    return Err(PolicyError::SemanticValidation(format!(
                        "oauth_resource authorization server '{issuer}' is not https. Every \
                         authorization server endpoint must be served over HTTPS"
                    )));
                }
            }
            // RFC 8707 Section 2: absolute, and no fragment. The spec's own invalid examples
            // are a bare host and a URI carrying a fragment.
            if !oauth.resource.contains("://") {
                return Err(PolicyError::SemanticValidation(format!(
                    "oauth_resource resource '{}' has no scheme; RFC 8707 requires an absolute \
                     URI, for example https://mcp.example.com/mcp",
                    oauth.resource
                )));
            }
            if oauth.resource.contains('#') {
                return Err(PolicyError::SemanticValidation(format!(
                    "oauth_resource resource '{}' carries a fragment, which RFC 8707 does not \
                     permit in a resource identifier",
                    oauth.resource
                )));
            }
            if oauth.algorithms.is_empty() {
                return Err(PolicyError::SemanticValidation(
                    "oauth_resource names no algorithms; a server that accepts any algorithm \
                     accepts the one the token chose for it"
                        .to_string(),
                ));
            }
            for algorithm in &oauth.algorithms {
                if algorithm.eq_ignore_ascii_case("none") {
                    return Err(PolicyError::SemanticValidation(
                        "oauth_resource lists the 'none' algorithm, which is an unsigned token \
                         accepted as a signed one"
                            .to_string(),
                    ));
                }
            }
            // A skew this large stops being a tolerance and becomes an exemption. Five
            // minutes is already generous for two hosts running NTP, and a misplaced unit,
            // milliseconds written where seconds were meant, would otherwise turn expiry
            // enforcement off with no warning at load and no line in the log.
            if oauth.clock_skew_secs > MAX_OAUTH_CLOCK_SKEW_SECS {
                return Err(PolicyError::SemanticValidation(format!(
                    "oauth_resource clock_skew_secs is {}, above the \
                     {MAX_OAUTH_CLOCK_SKEW_SECS} second ceiling. A skew larger than this \
                     stops bounding clock drift and starts accepting expired tokens",
                    oauth.clock_skew_secs
                )));
            }
            for (subject, mapping) in &oauth.subjects {
                if mapping.agent_id.trim().is_empty() {
                    return Err(PolicyError::SemanticValidation(format!(
                        "oauth_resource subject '{subject}' maps to an empty agent_id"
                    )));
                }
                // A 'sub' is unique within one issuer and nowhere else, so an unqualified
                // subject is only unambiguous when there is exactly one issuer to be
                // unambiguous about.
                match mapping.issuer.as_deref() {
                    Some(issuer) => {
                        if !oauth.authorization_servers.iter().any(|trusted| {
                            trusted.trim_end_matches('/') == issuer.trim_end_matches('/')
                        }) {
                            return Err(PolicyError::SemanticValidation(format!(
                                "oauth_resource subject '{subject}' is bound to issuer \
                                 '{issuer}', which is not one of this resource's \
                                 authorization_servers"
                            )));
                        }
                    }
                    None => {
                        if oauth.authorization_servers.len() > 1 {
                            return Err(PolicyError::SemanticValidation(format!(
                                "oauth_resource subject '{subject}' names no issuer, but this \
                                 resource trusts {} authorization servers. A 'sub' claim is \
                                 unique only within one issuer, so an unqualified subject \
                                 would grant this identity to whichever of them names it first",
                                oauth.authorization_servers.len()
                            )));
                        }
                    }
                }
                if let Some(profile) = &mapping.profile
                    && !self.gateway_profiles.contains_key(profile)
                {
                    return Err(PolicyError::SemanticValidation(format!(
                        "oauth_resource subject '{subject}' is pinned to gateway profile \
                         '{profile}', which is not configured"
                    )));
                }
            }
        }

        // G3-14 AF-8. A throttle configured into uselessness reads as configured, and a
        // window long enough to be a lockout turns one attacker into everyone's outage.
        if self.auth_throttle.enabled {
            if self.auth_throttle.threshold == 0 {
                return Err(PolicyError::SemanticValidation(
                    "auth_throttle threshold is 0, which refuses the first attempt from every \
                     source including a correct one on its first try"
                        .to_string(),
                ));
            }
            if self.auth_throttle.window_secs == 0 {
                return Err(PolicyError::SemanticValidation(
                    "auth_throttle window_secs is 0, so no window ever contains an attempt and \
                     the throttle can never fire"
                        .to_string(),
                ));
            }
            if self.auth_throttle.window_secs > MAX_AUTH_THROTTLE_WINDOW_SECS {
                return Err(PolicyError::SemanticValidation(format!(
                    "auth_throttle window_secs is {}, above the \
                     {MAX_AUTH_THROTTLE_WINDOW_SECS} second ceiling. Beyond this a throttle \
                     stops slowing an attacker and starts locking out whoever shares their \
                     network",
                    self.auth_throttle.window_secs
                )));
            }
        }

        // M4-1. A mirror pointed at a source Windows will refuse reads as configured and
        // fails at RegisterEventSourceW when the first record is written, which is both the
        // worst time to find out and the time nobody is watching.
        if let Some(event_log) = &self.audit_event_log {
            let source = event_log.source.trim();
            if source.is_empty() {
                return fail(
                    "audit_event_log source is empty; name the event source the collector's \
                     subscription filters on, or omit the block to leave the mirror off",
                );
            }
            if source.len() > MAX_EVENT_LOG_SOURCE_LEN {
                return fail(format!(
                    "audit_event_log source is {} characters, above the \
                     {MAX_EVENT_LOG_SOURCE_LEN} character ceiling a Windows Event Log source \
                     key allows",
                    source.len()
                ));
            }
            // Backslash separates registry key components and the control characters would
            // corrupt the key path. Both produce a source that registers as something other
            // than what the operator wrote, which is worse than one that fails outright.
            if source.chars().any(|ch| ch == '\\' || ch.is_control()) {
                return fail(
                    "audit_event_log source contains a backslash or a control character, \
                     which are not legal in the registry key a Windows Event Log source \
                     registers as",
                );
            }
        }

        // G5-6. A tool that creates no job cannot become a task, so naming one here would be a
        // setting that reads as configured and does nothing.
        let ineligible: Vec<&str> = self
            .task_tools
            .iter()
            .map(String::as_str)
            .filter(|tool| !TASK_ELIGIBLE_TOOLS.contains(tool))
            .collect();
        if !ineligible.is_empty() {
            return Err(PolicyError::SemanticValidation(format!(
                "task_tools names '{}', which {} no durable job and therefore cannot answer as \
                 a task. Eligible tools: {}",
                ineligible.join("', '"),
                if ineligible.len() == 1 {
                    "creates"
                } else {
                    "create"
                },
                TASK_ELIGIBLE_TOOLS.join(", ")
            )));
        }

        if !undeclared.is_empty() {
            return fail(format!(
                "upstream '{}' is enabled and declares no required_permission; every tool it \
                 exposes would be reachable with no capability granted. Set \
                 required_permission to the capability an operator must grant before this \
                 upstream may be called, and grant it on a root chosen for that purpose",
                undeclared.join("', '")
            ));
        }

        Ok(())
    }

    /// `normalize_legacy_root_ids`.
    pub fn normalize_legacy_root_ids(&mut self) {
        let mut seen = BTreeSet::new();
        for (idx, root) in self.roots.iter_mut().enumerate() {
            let mut normalized = String::new();
            let mut last_underscore = false;
            for ch in root.id.trim().chars() {
                let out = if ch.is_ascii_alphanumeric() {
                    Some(ch.to_ascii_lowercase())
                } else if matches!(ch, '_' | '-' | '.') {
                    Some(ch)
                } else if !last_underscore {
                    Some('_')
                } else {
                    None
                };
                if let Some(ch) = out {
                    last_underscore = ch == '_';
                    normalized.push(ch);
                }
            }
            normalized = normalized.trim_matches('_').to_string();
            if normalized.is_empty() {
                normalized = format!("root_{idx}");
            }
            if normalized.len() > 64 {
                normalized.truncate(64);
                normalized = normalized.trim_matches('_').to_string();
            }
            let base = normalized.clone();
            let mut candidate = normalized;
            let mut suffix = 1usize;
            while !seen.insert(candidate.clone()) {
                let marker = format!("_{suffix}");
                let keep = 64usize.saturating_sub(marker.len());
                candidate = format!("{}{}", &base[..base.len().min(keep)], marker);
                suffix += 1;
            }
            root.id = candidate;
        }
    }

    /// `canonicalized_for_service`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] describing what was refused.
    pub fn canonicalized_for_service(mut self) -> Result<Self, PolicyError> {
        self.normalize_legacy_root_ids();
        self.validate_semantics()?;
        self.validate_service_roots()?;
        self.canonicalize_roots_for_save()?;
        self.validate_service_roots()?;
        self.validate_semantics()?;
        Ok(self)
    }

    /// Resolve runtime paths, expanding `%ENV_VAR%` tokens in roots, `audit_path`, and
    /// `exec_state_dir`. This makes policy files portable; they can contain tokens like
    /// `%APPDATA%\\NativeMCP\\audit\\audit.jsonl` and resolve correctly at runtime for
    /// both user-mode and service-mode starts.
    #[must_use]
    pub fn with_runtime_paths(mut self, policy_path: Option<&Path>) -> Self {
        self.audit_path = expand_path_env(&self.audit_path);
        self.exec_state_dir = expand_path_env(&self.exec_state_dir);
        for root in &mut self.roots {
            root.path = expand_path_env(&root.path);
        }
        self.effective_exec_state_dir =
            Some(resolve_exec_state_dir(&self.exec_state_dir, policy_path));
        self
    }

    /// Build a sensible default policy for a user-mode install (no Windows service).
    #[must_use]
    pub fn default_user_policy() -> Self {
        let appdata = std::env::var("APPDATA")
            .or_else(|_| std::env::var("USERPROFILE").map(|p| format!("{p}\\AppData\\Roaming")))
            .unwrap_or_else(|_| ".".into());
        let userprofile = std::env::var("USERPROFILE").unwrap_or_else(|_| appdata.clone());

        let audit_path = PathBuf::from(format!("{appdata}\\NativeMCP\\audit\\audit.jsonl"));
        let exec_state_dir = PathBuf::from(format!("{appdata}\\NativeMCP\\work\\exec-jobs"));

        Self {
            admin_bind: "127.0.0.1:18769".into(),
            mcp_bind: "127.0.0.1:18770".into(),
            mcp_allowed_origins: Vec::new(),
            mcp_clients: Vec::new(),
            auto_approve: true,
            mcp_require_client_auth: false,
            require_upstream_pinning: false,
            audit_path,
            exec_state_dir,
            enable_sse_lane: true,
            enable_ws_lane: false,
            task_tools: BTreeSet::new(),
            oauth_resource: None,
            audit_event_log: None,
            auth_throttle: AuthThrottleConfig::default(),
            tool_paths: BTreeMap::new(),
            gateway_profiles: BTreeMap::new(),
            active_gateway_profile: None,
            oauth_providers: BTreeMap::new(),
            execution_profiles: BTreeMap::new(),
            default_execution_profile: None,
            effective_exec_state_dir: None,
            roots: vec![
                RootRule {
                    id: "home".into(),
                    path: PathBuf::from(&userprofile),
                    permissions: [
                        Permission::List,
                        Permission::Read,
                        Permission::Search,
                        Permission::Report,
                    ]
                    .into_iter()
                    .collect(),
                },
                RootRule {
                    id: "documents".into(),
                    path: PathBuf::from(format!("{userprofile}\\Documents")),
                    permissions: [
                        Permission::List,
                        Permission::Read,
                        Permission::Search,
                        Permission::Create,
                        Permission::Write,
                        Permission::Modify,
                        Permission::Rename,
                        Permission::Move,
                        Permission::Backup,
                        Permission::Execute,
                        Permission::Scan,
                        Permission::Report,
                    ]
                    .into_iter()
                    .collect(),
                },
            ],
            upstreams: Vec::new(),
            abac_rules: Vec::new(),
            m365: None,
        }
    }

    /// `effective_exec_state_dir`.
    #[must_use]
    pub fn effective_exec_state_dir(&self) -> PathBuf {
        self.effective_exec_state_dir
            .clone()
            .unwrap_or_else(|| resolve_exec_state_dir(&self.exec_state_dir, None))
    }

    /// `forbid_delete`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] describing what was refused.
    pub fn forbid_delete() -> Result<(), PolicyError> {
        Err(PolicyError::PermanentlyUnavailable(
            "delete, unlink, rmdir, recycle-bin, and permanent removal operations are not part of this server",
        ))
    }
}

/// `resolve_exec_state_dir`.
#[must_use]
pub fn resolve_exec_state_dir(configured: &Path, policy_path: Option<&Path>) -> PathBuf {
    if configured.is_absolute() {
        return normalize_path(configured);
    }
    if let Some(path) = policy_path {
        let absolute_policy = absolute_path(path);
        if let Some(parent) = absolute_policy.parent() {
            return normalize_path(&parent.join(configured));
        }
    }
    normalize_path(&service_safe_state_base().join(configured))
}

fn service_safe_state_base() -> PathBuf {
    nmcp_identity::program_data_root()
}

/// `canonicalize_existing_root`.
///
/// # Errors
///
/// Returns [`PolicyError`] describing what was refused.
pub fn canonicalize_existing_root(path: &Path) -> Result<PathBuf, PolicyError> {
    if !path.exists() {
        return Err(PolicyError::MissingRoot(path.display().to_string()));
    }
    path.canonicalize()
        .map(|path| normalize_path(&path))
        .map_err(|_| PolicyError::MissingRoot(path.display().to_string()))
}

/// `canonicalize_for_policy`.
#[must_use]
pub fn canonicalize_for_policy(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return normalize_path(&canonical);
    }

    let absolute = absolute_path(path);
    let mut cursor = absolute.as_path();
    let mut missing_tail: Vec<OsString> = Vec::new();
    loop {
        if cursor.exists()
            && let Ok(mut base) = cursor.canonicalize()
        {
            for component in missing_tail.iter().rev() {
                base.push(component);
            }
            return normalize_path(&base);
        }
        let Some(parent) = cursor.parent() else {
            break;
        };
        if let Some(name) = cursor.file_name() {
            missing_tail.push(name.to_os_string());
        }
        cursor = parent;
    }

    absolute
}

/// `absolute_path`.
#[must_use]
pub fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return normalize_path(path);
    }
    std::env::current_dir().map_or_else(
        |_| normalize_path(path),
        |cwd| normalize_path(&cwd.join(path)),
    )
}

/// `normalize_path`.
#[must_use]
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        out.push(part.as_os_str());
    }
    out
}

/// `backup_name`.
#[must_use]
pub fn backup_name(path: &Path, ordinal: usize) -> PathBuf {
    let name = path.file_name().and_then(|x| x.to_str()).unwrap_or("file");
    let suffix = if ordinal == 0 {
        ".bak".to_string()
    } else {
        format!(".bak{ordinal}")
    };
    path.with_file_name(format!("{name}{suffix}"))
}

#[cfg(test)]
mod tests {
    // Tests assert on shapes, plans and verdicts, where expect/indexing ARE
    // the assertion: a panic in a test is the failure signal, so the
    // production rationale for the workspace denies does not apply.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    // Test config builders intentionally use `let mut cfg = Default::default();`
    // then set individual fields for readability.
    #![allow(clippy::field_reassign_with_default)]
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn normalize_legacy_root_ids_repairs_spaces_and_duplicates() {
        let mut policy = PolicyConfig::default();
        policy.roots[0].id = "Claude Projects".into();
        policy.roots.push(RootRule {
            id: "Claude/Projects".into(),
            path: PathBuf::from("."),
            permissions: [Permission::Read].into_iter().collect(),
        });
        policy.normalize_legacy_root_ids();
        assert_eq!(policy.roots[0].id, "claude_projects");
        assert_eq!(policy.roots[1].id, "claude_projects_1");
        assert!(policy.validate_semantics().is_ok());
    }

    #[test]
    fn posture_flags_the_unauthenticated_auto_approved_volume_write_combination() {
        // G3-7. Reproduces the live posture the pen test exercised: no client credential,
        // auto_approve on, and a root mapping a whole volume with write.
        let policy = PolicyConfig {
            mcp_require_client_auth: false,
            mcp_clients: Vec::new(),
            auto_approve: true,
            roots: vec![RootRule {
                id: "local-disk-c-".into(),
                path: PathBuf::from(r"\\?\C:\"),
                permissions: [Permission::List, Permission::Read, Permission::Write]
                    .into_iter()
                    .collect(),
            }],
            ..PolicyConfig::default()
        };
        let ids: Vec<&str> = policy
            .posture_findings()
            .iter()
            .map(|finding| finding.id)
            .collect();
        assert!(ids.contains(&"mcp_surface_unauthenticated"), "{ids:?}");
        assert!(ids.contains(&"volume_wide_mutating_root"), "{ids:?}");
        assert!(
            ids.contains(&"unauthenticated_auto_approved_volume_write"),
            "the compound finding is the whole point: {ids:?}"
        );
    }

    #[test]
    fn posture_is_clean_when_any_one_leg_of_the_combination_is_removed() {
        // Requiring a credential is the smallest change that breaks the chain, so the
        // compound finding must actually clear when it is made.
        let credentialed = PolicyConfig {
            mcp_require_client_auth: true,
            mcp_clients: vec![McpClientCredential {
                agent_id: "agent".into(),
                token_sha256: "0".repeat(64),
                profile: None,
            }],
            auto_approve: true,
            roots: vec![RootRule {
                id: "local-disk-c-".into(),
                path: PathBuf::from(r"\\?\C:\"),
                permissions: [Permission::Write].into_iter().collect(),
            }],
            ..PolicyConfig::default()
        };
        let ids: Vec<&str> = credentialed
            .posture_findings()
            .iter()
            .map(|finding| finding.id)
            .collect();
        assert!(
            !ids.contains(&"unauthenticated_auto_approved_volume_write"),
            "{ids:?}"
        );
        assert!(!ids.contains(&"mcp_surface_unauthenticated"), "{ids:?}");
        // The broad root is still worth saying on its own.
        assert!(ids.contains(&"volume_wide_mutating_root"), "{ids:?}");
    }

    #[test]
    fn a_scoped_root_is_not_a_volume_wide_root() {
        // The narrow roots are the normal case and must not produce noise, including the
        // volume path with only non-mutating permissions.
        let policy = PolicyConfig {
            mcp_require_client_auth: true,
            mcp_clients: vec![McpClientCredential {
                agent_id: "agent".into(),
                token_sha256: "0".repeat(64),
                profile: None,
            }],
            roots: vec![
                RootRule {
                    id: "dev".into(),
                    path: PathBuf::from(r"\\?\D:\dev"),
                    permissions: [Permission::Write, Permission::Modify]
                        .into_iter()
                        .collect(),
                },
                RootRule {
                    id: "system32".into(),
                    path: PathBuf::from(r"\\?\C:\Windows\System32"),
                    permissions: [Permission::Execute, Permission::Scan]
                        .into_iter()
                        .collect(),
                },
                RootRule {
                    id: "readonly-volume".into(),
                    path: PathBuf::from(r"\\?\E:\"),
                    permissions: [Permission::List, Permission::Read].into_iter().collect(),
                },
            ],
            ..PolicyConfig::default()
        };
        assert!(
            policy.volume_wide_mutating_roots().is_empty(),
            "scoped roots and a read-only volume must not be reported as volume-wide writes"
        );
    }

    /// G3-11 RS-1. Absent means absent: the default policy is unchanged and legal.
    #[test]
    fn a_policy_with_no_oauth_resource_is_unchanged() {
        let policy = PolicyConfig::default();
        assert!(policy.oauth_resource.is_none());
        policy.validate_semantics().expect("the default is legal");
    }

    fn oauth_fixture() -> OAuthResourceConfig {
        OAuthResourceConfig {
            resource: "https://mcp.example.com/mcp".into(),
            authorization_servers: vec!["https://login.example.com".into()],
            subjects: BTreeMap::new(),
            algorithms: default_oauth_algorithms(),
            clock_skew_secs: default_oauth_clock_skew_secs(),
            scopes_supported: Vec::new(),
        }
    }

    /// G3-11 RS-2. An authorization server reachable over plain HTTP is not one.
    #[test]
    fn an_authorization_server_that_is_not_https_is_refused() {
        let mut policy = PolicyConfig::default();
        let mut oauth = oauth_fixture();
        oauth.authorization_servers = vec!["http://login.example.com".into()];
        policy.oauth_resource = Some(oauth);
        let err = policy
            .validate_semantics()
            .expect_err("a cleartext authorization server must be refused");
        assert!(err.to_string().contains("https"), "{err}");
    }

    #[test]
    fn a_resource_with_no_authorization_server_is_refused() {
        // The metadata document must carry at least one, so a configuration that cannot produce
        // a legal document is refused before it is served rather than when it is read.
        let mut policy = PolicyConfig::default();
        let mut oauth = oauth_fixture();
        oauth.authorization_servers.clear();
        policy.oauth_resource = Some(oauth);
        assert!(policy.validate_semantics().is_err());
    }

    /// G3-11 RS-3. The identifier an audience is compared against has to be canonical.
    #[test]
    fn a_resource_identifier_must_be_absolute_and_carry_no_fragment() {
        for (bad, expect) in [
            ("mcp.example.com", "scheme"),
            ("https://mcp.example.com#fragment", "fragment"),
        ] {
            let mut policy = PolicyConfig::default();
            let mut oauth = oauth_fixture();
            oauth.resource = bad.into();
            policy.oauth_resource = Some(oauth);
            let err = policy.validate_semantics().unwrap_err().to_string();
            assert!(err.contains(expect), "{bad}: {err}");
        }
    }

    /// G3-11 RS-9. The algorithm is the server's choice, never the token's.
    #[test]
    fn the_none_algorithm_is_refused_by_name() {
        let mut policy = PolicyConfig::default();
        let mut oauth = oauth_fixture();
        oauth.algorithms.push("none".into());
        policy.oauth_resource = Some(oauth);
        let err = policy
            .validate_semantics()
            .expect_err("an unsigned token accepted as a signed one must be refused");
        assert!(err.to_string().contains("none"), "{err}");

        let mut policy = PolicyConfig::default();
        let mut oauth = oauth_fixture();
        oauth.algorithms.clear();
        policy.oauth_resource = Some(oauth);
        assert!(
            policy.validate_semantics().is_err(),
            "an empty allowlist accepts whatever the token chose"
        );
    }

    /// G3-11 RS-12. A subject pinned to a profile that does not exist would lock its caller out
    /// with no way to see why, exactly as a static credential would.
    #[test]
    fn an_oauth_subject_pinned_to_a_missing_profile_is_refused() {
        let mut policy = PolicyConfig::default();
        let mut oauth = oauth_fixture();
        oauth.subjects.insert(
            "user@example.com".into(),
            OAuthSubject {
                agent_id: "chatgpt".into(),
                profile: Some("ghost".into()),
                issuer: None,
            },
        );
        policy.oauth_resource = Some(oauth);
        let err = policy
            .validate_semantics()
            .expect_err("a dangling profile binding must be refused");
        assert!(err.to_string().contains("ghost"), "{err}");
    }

    #[test]
    fn an_oauth_subject_must_name_a_caller() {
        let mut policy = PolicyConfig::default();
        let mut oauth = oauth_fixture();
        oauth.subjects.insert(
            "user@example.com".into(),
            OAuthSubject {
                agent_id: "  ".into(),
                profile: None,
                issuer: None,
            },
        );
        policy.oauth_resource = Some(oauth);
        assert!(policy.validate_semantics().is_err());
    }

    /// A `sub` is unique within one issuer, so an unqualified binding on a resource that
    /// trusts several would grant the identity to whichever of them names the subject first.
    #[test]
    fn an_unqualified_subject_is_refused_once_a_second_issuer_is_trusted() {
        let mut policy = PolicyConfig::default();
        let mut oauth = oauth_fixture();
        oauth.subjects.insert(
            "user@example.com".into(),
            OAuthSubject {
                agent_id: "chatgpt".into(),
                profile: None,
                issuer: None,
            },
        );
        policy.oauth_resource = Some(oauth.clone());
        // One issuer: unambiguous, so permitted.
        policy
            .validate_semantics()
            .expect("one issuer is unambiguous");

        oauth
            .authorization_servers
            .push("https://partner.example.com".into());
        policy.oauth_resource = Some(oauth.clone());
        let err = policy
            .validate_semantics()
            .expect_err("two issuers make a bare sub ambiguous");
        assert!(format!("{err}").contains("names no issuer"), "{err}");

        // Naming the issuer resolves it.
        if let Some(resource) = policy.oauth_resource.as_mut()
            && let Some(binding) = resource.subjects.get_mut("user@example.com")
        {
            binding.issuer = Some("https://partner.example.com".into());
        }
        policy
            .validate_semantics()
            .expect("a qualified subject is unambiguous whatever the issuer count");
    }

    /// A binding pointing at an issuer this resource does not trust is dead configuration that
    /// reads as live, which is the shape this codebase refuses everywhere else.
    #[test]
    fn a_subject_bound_to_an_untrusted_issuer_is_refused() {
        let mut policy = PolicyConfig::default();
        let mut oauth = oauth_fixture();
        oauth.subjects.insert(
            "user@example.com".into(),
            OAuthSubject {
                agent_id: "chatgpt".into(),
                profile: None,
                issuer: Some("https://not-configured.example.com".into()),
            },
        );
        policy.oauth_resource = Some(oauth);
        let err = policy.validate_semantics().expect_err("untrusted issuer");
        assert!(format!("{err}").contains("authorization_servers"), "{err}");
    }

    /// A skew large enough to swallow every expiry is not a tolerance, and a misplaced unit
    /// would otherwise turn expiry enforcement off with nothing said about it.
    #[test]
    fn a_clock_skew_large_enough_to_disable_expiry_is_refused() {
        let mut policy = PolicyConfig::default();
        let mut oauth = oauth_fixture();
        oauth.clock_skew_secs = MAX_OAUTH_CLOCK_SKEW_SECS;
        policy.oauth_resource = Some(oauth.clone());
        policy
            .validate_semantics()
            .expect("the ceiling itself is allowed");

        // Seconds where milliseconds were meant, the way this is actually written wrong.
        oauth.clock_skew_secs = 300_000;
        policy.oauth_resource = Some(oauth);
        let err = policy.validate_semantics().expect_err("above the ceiling");
        assert!(format!("{err}").contains("clock_skew_secs"), "{err}");
    }

    /// G3-14 AF-8. A throttle configured into uselessness reads as configured, and a window
    /// long enough to be a lockout turns one attacker into everyone's outage.
    #[test]
    fn a_throttle_that_could_not_work_or_would_lock_out_is_refused() {
        let mut policy = PolicyConfig::default();
        // The shipped defaults are valid, which is the first thing worth proving.
        policy.validate_semantics().expect("defaults are valid");

        policy.auth_throttle.threshold = 0;
        let err = policy.validate_semantics().expect_err("threshold 0");
        assert!(format!("{err}").contains("threshold"), "{err}");

        policy.auth_throttle = AuthThrottleConfig::default();
        policy.auth_throttle.window_secs = 0;
        let err = policy.validate_semantics().expect_err("window 0");
        assert!(format!("{err}").contains("window_secs"), "{err}");

        policy.auth_throttle = AuthThrottleConfig::default();
        policy.auth_throttle.window_secs = MAX_AUTH_THROTTLE_WINDOW_SECS + 1;
        let err = policy
            .validate_semantics()
            .expect_err("window above the ceiling");
        assert!(format!("{err}").contains("locking out"), "{err}");

        // Disabled means the numbers are not consulted, so a nonsense value is not a failure
        // to load; it is a setting nobody is reading.
        policy.auth_throttle.enabled = false;
        policy
            .validate_semantics()
            .expect("a disabled throttle is not validated into a load failure");
    }

    #[test]
    fn a_complete_oauth_resource_validates() {
        let mut policy = PolicyConfig::default();
        let mut oauth = oauth_fixture();
        oauth.subjects.insert(
            "user@example.com".into(),
            OAuthSubject {
                agent_id: "chatgpt".into(),
                profile: None,
                issuer: None,
            },
        );
        policy.oauth_resource = Some(oauth);
        policy
            .validate_semantics()
            .expect("a complete block is legal");
    }

    /// G5-6. The default is off, and off is a complete statement rather than an omission.
    #[test]
    fn no_tool_answers_as_a_task_until_an_operator_names_one() {
        let policy = PolicyConfig::default();
        assert!(
            policy.task_tools.is_empty(),
            "upgrading must not change any client's behaviour"
        );
        policy.validate_semantics().expect("the default is legal");
    }

    #[test]
    fn a_tool_that_creates_no_job_cannot_be_named_a_task_tool() {
        // The footgun this closes: an operator lists a tool that looks long-running, the server
        // silently never produces a task for it, and the setting reads as configured.
        let mut policy = PolicyConfig::default();
        policy.task_tools.insert("scan_repo".into());
        let err = policy
            .validate_semantics()
            .expect_err("a tool with no job behind it must be refused by name");
        let message = err.to_string();
        assert!(
            message.contains("scan_repo") && message.contains("execute_start"),
            "the refusal names what was wrong and what is eligible: {message}"
        );

        policy.task_tools.clear();
        policy.task_tools.insert("execute_start".into());
        policy
            .validate_semantics()
            .expect("a job-creating tool is eligible");
    }

    #[test]
    fn an_enabled_upstream_must_declare_the_capability_it_needs() {
        // G4-28. The ring cannot govern what an admitted upstream does, so the one control it
        // has is refusing to dispatch its tools unless an operator granted something on
        // purpose. Refused at validation rather than defaulted, because a default is the thing
        // nobody reads, and because G4-16 already established that shape: requiring client auth
        // with no clients configured is refused here too rather than discovered at a call.
        let mut policy = PolicyConfig::default();
        let mut upstream = UpstreamConfig::new("vendor", "http://127.0.0.1:9/mcp");
        upstream.enabled = true;
        policy.upstreams = vec![upstream];

        let err = policy
            .validate_semantics()
            .expect_err("an enabled upstream with no declaration must be refused");
        let message = err.to_string();
        assert!(
            message.contains("vendor") && message.contains("required_permission"),
            "the refusal names the upstream and the field: {message}"
        );

        // Disabled is not a hazard: it registers no tools and proxies no calls, so it has
        // nothing to declare yet. This is what keeps the rule free to adopt.
        policy.upstreams[0].enabled = false;
        policy
            .validate_semantics()
            .expect("a disabled upstream declares nothing and that is fine");

        // Declared and enabled passes. Note that validation does not require the capability to
        // be GRANTED anywhere: an operator may declare it now and grant it later, and until
        // they do the router refuses the calls. Declaring is the policy statement; granting is
        // the operator's act.
        policy.upstreams[0].enabled = true;
        policy.upstreams[0].required_permission = Some(Permission::Execute);
        policy
            .validate_semantics()
            .expect("declared and enabled is a complete statement");
    }

    #[test]
    fn upstream_admission_answers_granted_missing_undeclared_and_unknown() {
        // Start from the shipped default on purpose. No default root grants `upstream.call`,
        // so the out-of-the-box answer for a declared upstream is a refusal. That is the
        // whole of G4-28: an upstream becomes reachable only when an operator says so.
        let mut policy = PolicyConfig::default();
        let mut upstream = UpstreamConfig::new("vendor", "http://127.0.0.1:9/mcp");
        upstream.required_permission = Some(Permission::UpstreamCall);
        policy.upstreams = vec![upstream];

        assert_eq!(
            policy.upstream_admission("vendor"),
            UpstreamAdmission::MissingGrant {
                permission: Permission::UpstreamCall
            },
            "the shipped default policy admits no upstream"
        );

        policy.roots.push(RootRule {
            id: "gateway".into(),
            path: std::env::temp_dir(),
            permissions: [Permission::UpstreamCall].into_iter().collect(),
        });
        assert_eq!(
            policy.upstream_admission("vendor"),
            UpstreamAdmission::Granted {
                permission: Permission::UpstreamCall
            }
        );

        // Granting something is not granting this. The default roots already carry Read,
        // Write and Execute, so this also proves the check reads the declared capability
        // rather than settling for any grant at all.
        let granting = policy.roots.len() - 1;
        policy.roots[granting].permissions =
            [Permission::Read, Permission::Write].into_iter().collect();
        assert_eq!(
            policy.upstream_admission("vendor"),
            UpstreamAdmission::MissingGrant {
                permission: Permission::UpstreamCall
            }
        );

        policy.upstreams[0].required_permission = None;
        assert_eq!(
            policy.upstream_admission("vendor"),
            UpstreamAdmission::Undeclared
        );

        assert_eq!(
            policy.upstream_admission("never-heard-of-it"),
            UpstreamAdmission::NotAdmitted
        );
    }

    /// M4-1. The name on an audit record has to be the name policy serializes, or a policy
    /// file and an audit record disagree about the same capability.
    #[test]
    fn permission_names_match_what_serde_writes() {
        for permission in [
            Permission::List,
            Permission::Read,
            Permission::Search,
            Permission::Create,
            Permission::Write,
            Permission::Modify,
            Permission::Rename,
            Permission::Move,
            Permission::Backup,
            Permission::Execute,
            Permission::Scan,
            Permission::Report,
            Permission::MemoryRead,
            Permission::MemoryWrite,
            Permission::WindowsApi,
            Permission::GitPublish,
            Permission::M365,
            Permission::WindowsApiWrite,
            Permission::UpstreamCall,
        ] {
            let serialized = serde_json::to_value(permission).expect("serialize");
            assert_eq!(
                serialized,
                serde_json::json!(permission.as_str()),
                "as_str disagrees with serde for {permission:?}"
            );
        }
    }

    /// M4-1. A mirror pointed at a source Windows will refuse reads as configured and fails
    /// when the first record is written, which is the worst time to find out.
    #[test]
    fn validate_semantics_rejects_an_unusable_event_log_source() {
        let mut policy = PolicyConfig::default();

        policy.audit_event_log = Some(AuditEventLogConfig {
            enabled: true,
            source: "   ".into(),
        });
        assert!(policy.validate_semantics().is_err(), "empty source");

        policy.audit_event_log = Some(AuditEventLogConfig {
            enabled: true,
            source: "Fleet\\Collector".into(),
        });
        assert!(policy.validate_semantics().is_err(), "backslash in source");

        policy.audit_event_log = Some(AuditEventLogConfig {
            enabled: true,
            source: "a".repeat(MAX_EVENT_LOG_SOURCE_LEN + 1),
        });
        assert!(
            policy.validate_semantics().is_err(),
            "source over the ceiling"
        );

        policy.audit_event_log = Some(AuditEventLogConfig {
            enabled: true,
            source: "FleetCollector".into(),
        });
        assert!(
            policy.validate_semantics().is_ok(),
            "a usable source passes"
        );

        // And a policy that says nothing about the mirror is still a valid policy, because
        // absent means the legacy environment route stays in charge.
        policy.audit_event_log = None;
        assert!(policy.validate_semantics().is_ok());
    }

    /// M4-1. Absent must round-trip as absent, or an upgrade would write the block into every
    /// policy file and turn "the environment decides" into "policy decided, disabled".
    #[test]
    fn a_policy_that_says_nothing_about_the_mirror_stays_silent_about_it() {
        let json = serde_json::to_string(&PolicyConfig::default()).expect("serialize");
        assert!(
            !json.contains("audit_event_log"),
            "the block must be skipped when absent"
        );
        let restored: PolicyConfig = serde_json::from_str(&json).expect("deserialize");
        assert!(restored.audit_event_log.is_none());
    }

    #[test]
    fn validate_semantics_rejects_duplicate_root_ids() {
        let mut policy = PolicyConfig::default();
        let first = policy.roots[0].clone();
        policy.roots.push(first);
        let err = policy
            .validate_semantics()
            .expect_err("duplicate root id rejected");
        assert!(err.to_string().contains("duplicate root id"));
    }

    #[test]
    fn validate_semantics_rejects_bad_bind_and_missing_default_profile() {
        let mut policy = PolicyConfig::default();
        policy.admin_bind = "not-a-socket".into();
        assert!(policy.validate_semantics().is_err());

        let mut policy = PolicyConfig::default();
        policy.default_execution_profile = Some("missing".into());
        let err = policy
            .validate_semantics()
            .expect_err("missing profile rejected");
        assert!(err.to_string().contains("default_execution_profile"));
    }

    #[test]
    fn validate_semantics_rejects_invalid_mcp_client_digest() {
        let mut policy = PolicyConfig::default();
        policy.mcp_clients = vec![McpClientCredential {
            agent_id: "agent-alpha".into(),
            token_sha256: "abc".into(),
            profile: None,
        }];
        let err = policy
            .validate_semantics()
            .expect_err("bad digest rejected");
        assert!(err.to_string().contains("token_sha256"));
    }

    #[test]
    fn validate_semantics_requires_trust_for_non_loopback_enabled_upstreams() {
        let mut policy = PolicyConfig::default();
        policy.upstreams.push(UpstreamConfig {
            id: "remote".into(),
            url: String::new(),
            transport: Some(UpstreamTransport::Http {
                url: "https://mcp.example.com".into(),
            }),
            label: "remote".into(),
            enabled: true,
            tool_allowlist: None,
            tools_sha256: None,
            manifest_public_key: None,
            auth_header_env: None,
            auth_header_name: None,
            auth_secret: None,
            oauth_provider: None,
            required_permission: Some(Permission::Read),
        });
        let err = policy
            .validate_semantics()
            .expect_err("remote upstream without trust rejected");
        assert!(
            err.to_string()
                .contains("tools_sha256 or manifest_public_key")
        );
        policy.upstreams[0].tools_sha256 = Some("a".repeat(64));
        assert!(policy.validate_semantics().is_ok());
    }

    /// A pinned https upstream, so these tests fail on what they are about rather than on trust.
    fn brokered_upstream(id: &str) -> UpstreamConfig {
        let mut upstream = UpstreamConfig::new(id, "https://upstream.example");
        upstream.tools_sha256 = Some("a".repeat(64));
        upstream
    }

    fn acme_provider() -> OAuthProviderConfig {
        OAuthProviderConfig {
            label: "Acme".into(),
            device_authorization_endpoint: "https://acme.example/device".into(),
            token_endpoint: "https://acme.example/token".into(),
            client_id: "public-client-id".into(),
            client_secret_secret: None,
            scopes: vec!["read".into()],
        }
    }

    #[test]
    fn an_upstream_may_name_only_one_credential_source() {
        let mut policy = PolicyConfig::default();
        policy
            .oauth_providers
            .insert("acme".into(), acme_provider());
        let mut upstream = brokered_upstream("brokered");
        upstream.oauth_provider = Some("acme".into());
        upstream.auth_secret = Some("partner_token".into());
        policy.upstreams.push(upstream);

        let err = policy
            .validate_semantics()
            .expect_err("two credential sources is ambiguous at request time");
        assert!(err.to_string().contains("more than one credential source"));
    }

    #[test]
    fn an_upstream_cannot_broker_from_a_provider_that_is_not_configured() {
        let mut policy = PolicyConfig::default();
        let mut upstream = brokered_upstream("brokered");
        upstream.oauth_provider = Some("ghost".into());
        // G4-28: an enabled upstream must declare the capability an operator has to grant.
        upstream.required_permission = Some(Permission::UpstreamCall);
        policy.upstreams.push(upstream);

        let err = policy
            .validate_semantics()
            .expect_err("a provider that does not exist can never produce a token");
        assert!(err.to_string().contains("which is not configured"));

        policy
            .oauth_providers
            .insert("ghost".into(), acme_provider());
        policy
            .validate_semantics()
            .expect("configuring the provider settles it");
    }

    #[test]
    fn an_oauth_endpoint_must_be_https_or_loopback() {
        let mut policy = PolicyConfig::default();
        let mut provider = acme_provider();
        provider.token_endpoint = "http://acme.example/token".into();
        policy.oauth_providers.insert("acme".into(), provider);

        let err = policy
            .validate_semantics()
            .expect_err("a refresh token in cleartext is the whole grant on the wire");
        assert!(err.to_string().contains("token_endpoint must be https"));

        // Loopback stays allowed, which is what makes the flow testable at all.
        let mut provider = acme_provider();
        provider.token_endpoint = "http://127.0.0.1:9443/token".into();
        provider.device_authorization_endpoint = "http://127.0.0.1:9443/device".into();
        policy.oauth_providers.insert("acme".into(), provider);
        policy
            .validate_semantics()
            .expect("loopback http is allowed");
    }

    #[test]
    fn an_oauth_client_secret_must_be_a_name_not_the_secret() {
        // The guard is on shape, not on entropy. A pasted credential that happens to look
        // exactly like a name gets through, both here and for auth_secret; what this stops is
        // the thing operators actually do, which is paste the header value they were given.
        let mut policy = PolicyConfig::default();
        let mut provider = acme_provider();
        provider.client_secret_secret = Some("Bearer ghp_A1b2C3+d4/E5==".into());
        policy.oauth_providers.insert("acme".into(), provider);

        let err = policy
            .validate_semantics()
            .expect_err("a pasted client secret in policy is a secret in every policy backup");
        assert!(err.to_string().contains("not the credential itself"));
    }

    #[test]
    fn cleartext_http_now_refuses_every_credential_source_not_only_the_environment_one() {
        // This guard used to sit inside the `auth_header_env` arm, so an upstream carrying a
        // stored secret or a brokered token to a plain http host went out unremarked.
        for wire in ["secret", "oauth"] {
            let mut policy = PolicyConfig::default();
            policy
                .oauth_providers
                .insert("acme".into(), acme_provider());
            let mut upstream = UpstreamConfig::new("plain", "http://partner.example:8080");
            upstream.tools_sha256 = Some("a".repeat(64));
            match wire {
                "secret" => upstream.auth_secret = Some("partner_token".into()),
                _ => upstream.oauth_provider = Some("acme".into()),
            }
            policy.upstreams.push(upstream);

            let err = policy.validate_semantics().unwrap_err().to_string();
            assert!(err.contains("cleartext over http"), "{wire}: {err}");
        }
    }

    #[test]
    fn validate_semantics_can_require_pinning_for_loopback_upstreams() {
        let mut policy = PolicyConfig::default();
        policy.require_upstream_pinning = true;
        policy.upstreams.push(UpstreamConfig {
            id: "localgw".into(),
            url: String::new(),
            transport: Some(UpstreamTransport::Http {
                url: "http://127.0.0.1:9000".into(),
            }),
            label: "local".into(),
            enabled: true,
            tool_allowlist: None,
            tools_sha256: None,
            manifest_public_key: None,
            auth_header_env: None,
            auth_header_name: None,
            auth_secret: None,
            oauth_provider: None,
            required_permission: Some(Permission::Read),
        });
        policy
            .validate_semantics()
            .expect_err("loopback upstream without pin rejected when pinning required");
        policy.upstreams[0].tools_sha256 = Some("a".repeat(64));
        assert!(policy.validate_semantics().is_ok());
    }

    #[test]
    fn validate_semantics_rejects_upstream_credential_pasted_into_policy() {
        let mut policy = PolicyConfig::default();
        let mut upstream = UpstreamConfig::new("remote", "https://mcp.example.com");
        upstream.tools_sha256 = Some("a".repeat(64));
        // The operator misreads the field and pastes the token instead of naming a variable.
        upstream.auth_header_env = Some("Bearer sk-live-not-a-variable".into());
        policy.upstreams.push(upstream);
        let err = policy
            .validate_semantics()
            .expect_err("a literal credential in auth_header_env must be rejected");
        assert!(err.to_string().contains("environment variable name"));
    }

    #[test]
    fn validate_semantics_rejects_upstream_credential_over_cleartext_http() {
        let mut policy = PolicyConfig::default();
        let mut upstream = UpstreamConfig::new("remote", "http://mcp.example.com");
        upstream.tools_sha256 = Some("a".repeat(64));
        upstream.auth_header_env = Some("NMCP_UPSTREAM_REMOTE_TOKEN".into());
        // G4-28: an enabled upstream must declare the capability an operator has to grant.
        upstream.required_permission = Some(Permission::UpstreamCall);
        policy.upstreams.push(upstream);
        let err = policy
            .validate_semantics()
            .expect_err("a credential must not be sent in cleartext to a remote host");
        assert!(err.to_string().contains("cleartext"));
        policy.upstreams[0].transport = Some(UpstreamTransport::Http {
            url: "https://mcp.example.com".into(),
        });
        assert!(policy.validate_semantics().is_ok());
    }

    #[test]
    fn validate_semantics_rejects_auth_header_name_without_a_source() {
        let mut policy = PolicyConfig::default();
        let mut upstream = UpstreamConfig::new("localgw", "http://127.0.0.1:9000");
        upstream.auth_header_name = Some("x-api-key".into());
        policy.upstreams.push(upstream);
        let err = policy
            .validate_semantics()
            .expect_err("a header name with no credential source is a silent no-auth config");
        let message = err.to_string();
        // G4-30. The message names every source that would have satisfied the rule, because
        // an operator who reached for auth_secret and read "without auth_header_env" would
        // conclude the wrong thing about which field to add.
        for source in ["auth_header_env", "auth_secret", "oauth_provider"] {
            assert!(message.contains(source), "{source} missing from: {message}");
        }
    }

    /// G4-30. The rule is a property of the field, so it has to hold whichever source names
    /// it. Both existing tests exercised only the `auth_header_env` path, which is precisely why
    /// the gap survived: the arm that validated was the arm that was tested.
    #[test]
    fn auth_header_name_is_validated_whichever_credential_source_names_it() {
        for (label, apply) in [
            (
                "auth_header_env",
                Box::new(|u: &mut UpstreamConfig| {
                    u.auth_header_env = Some("NMCP_UPSTREAM_LOCAL_TOKEN".into());
                }) as Box<dyn Fn(&mut UpstreamConfig)>,
            ),
            (
                "auth_secret",
                Box::new(|u: &mut UpstreamConfig| u.auth_secret = Some("upstream-token".into())),
            ),
            (
                "oauth_provider",
                Box::new(|u: &mut UpstreamConfig| u.oauth_provider = Some("acme".into())),
            ),
        ] {
            let mut policy = PolicyConfig::default();
            // Configured so the broker check, which runs first and is a different rule,
            // cannot be what refuses this policy.
            policy
                .oauth_providers
                .insert("acme".into(), acme_provider());
            let mut upstream = UpstreamConfig::new("localgw", "http://127.0.0.1:9000");
            apply(&mut upstream);
            upstream.auth_header_name = Some("Content-Length".into());
            policy.upstreams.push(upstream);
            let err = policy.validate_semantics().expect_err(&format!(
                "a request-framing header must be refused when the source is {label}"
            ));
            assert!(
                err.to_string().contains("not a header this proxy may set"),
                "{label}: {err}"
            );
        }
    }

    #[test]
    fn validate_semantics_rejects_upstream_auth_header_the_client_owns() {
        let mut policy = PolicyConfig::default();
        let mut upstream = UpstreamConfig::new("localgw", "http://127.0.0.1:9000");
        upstream.auth_header_env = Some("NMCP_UPSTREAM_LOCAL_TOKEN".into());
        upstream.auth_header_name = Some("Content-Length".into());
        policy.upstreams.push(upstream);
        let err = policy
            .validate_semantics()
            .expect_err("policy must not be able to set request framing headers");
        assert!(err.to_string().contains("not a header this proxy may set"));
    }

    #[test]
    fn validate_semantics_rejects_invalid_abac_rules() {
        let mut policy = PolicyConfig::default();
        policy.abac_rules = vec![AbacRule::CommandContent {
            pattern: "(".into(),
            tools: None,
            action: AbacAction::Deny,
        }];
        let err = policy.validate_semantics().expect_err("bad regex rejected");
        assert!(err.to_string().contains("ABAC rule"));

        let mut policy = PolicyConfig::default();
        policy.abac_rules = vec![AbacRule::TimeOfDay {
            tools: None,
            allow_start_hour: 25,
            allow_end_hour: 26,
            action: AbacAction::Deny,
        }];
        assert!(policy.validate_semantics().is_err());
    }
    #[test]
    fn require_uses_most_specific_root_even_when_broad_declared_first() {
        let policy = PolicyConfig {
            roots: vec![
                RootRule {
                    id: "broad".into(),
                    path: PathBuf::from("."),
                    permissions: [Permission::Read, Permission::Write].into_iter().collect(),
                },
                RootRule {
                    id: "narrow".into(),
                    path: PathBuf::from("./secrets"),
                    permissions: [Permission::Read].into_iter().collect(),
                },
            ],
            ..PolicyConfig::default()
        };
        // Write under the narrow read-only root is denied even though the broad
        // root (declared first) grants write.
        assert!(matches!(
            policy.require(Permission::Write, "./secrets/key.txt"),
            Err(PolicyError::PermissionDenied { .. })
        ));
        // Read under the narrow root is allowed.
        assert!(
            policy
                .require(Permission::Read, "./secrets/key.txt")
                .is_ok()
        );
        // Write outside the narrow root falls to the broad root and is allowed.
        assert!(policy.require(Permission::Write, "./outside.txt").is_ok());
    }

    #[test]
    fn delete_is_permanently_unavailable() {
        assert!(PolicyConfig::forbid_delete().is_err());
    }

    #[test]
    fn backup_names_are_sequential() {
        assert_eq!(
            backup_name(Path::new("a.txt"), 0),
            PathBuf::from("a.txt.bak")
        );
        assert_eq!(
            backup_name(Path::new("a.txt"), 2),
            PathBuf::from("a.txt.bak2")
        );
    }

    #[test]
    fn policy_distinguishes_rename_from_move() {
        let root = RootRule {
            id: "r".into(),
            path: PathBuf::from("."),
            permissions: [Permission::Rename].into_iter().collect(),
        };
        let policy = PolicyConfig {
            roots: vec![root],
            ..PolicyConfig::default()
        };
        assert!(policy.require(Permission::Rename, ".").is_ok());
        assert!(policy.require(Permission::Move, ".").is_err());
    }

    #[test]
    fn git_publish_permission_is_explicit() {
        assert_eq!(Permission::GitPublish.to_string(), "git.publish");
        let root = RootRule {
            id: "r".into(),
            path: PathBuf::from("."),
            permissions: [Permission::Execute].into_iter().collect(),
        };
        let policy = PolicyConfig {
            roots: vec![root],
            ..PolicyConfig::default()
        };
        assert!(policy.require(Permission::Execute, ".").is_ok());
        assert!(policy.require(Permission::GitPublish, ".").is_err());
    }

    #[test]
    fn path_escape_outside_root_is_rejected() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("nmcp-policy-{stamp}"));
        let inside = root.join("inside");
        fs::create_dir_all(&inside).expect("mkdir");
        let outside = root.parent().unwrap_or(&root).join("outside");
        let policy = PolicyConfig {
            roots: vec![RootRule {
                id: "root".into(),
                path: root.clone(),
                permissions: [Permission::Read].into_iter().collect(),
            }],
            ..PolicyConfig::default()
        };
        assert!(policy.require(Permission::Read, &inside).is_ok());
        assert!(policy.require(Permission::Read, &outside).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn admin_root_add_canonicalizes_absolute_path() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("nmcp-policy-canon-{stamp}"));
        fs::create_dir_all(&root).expect("mkdir");
        let mut policy = PolicyConfig {
            roots: vec![RootRule {
                id: "root".into(),
                path: root.join("."),
                permissions: [Permission::List].into_iter().collect(),
            }],
            ..PolicyConfig::default()
        };
        policy.canonicalize_roots_for_save().expect("canonicalize");
        assert!(policy.roots[0].path.is_absolute());
        assert_eq!(policy.roots[0].path, root.canonicalize().expect("root"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn service_mode_uses_absolute_configured_roots() {
        let relative = PolicyConfig::default();
        assert!(relative.canonicalized_for_service().is_err());

        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        let absolute = PolicyConfig {
            roots: vec![RootRule {
                id: "root".into(),
                path: root,
                permissions: [Permission::List].into_iter().collect(),
            }],
            ..PolicyConfig::default()
        };
        assert!(absolute.canonicalized_for_service().is_ok());
    }

    #[test]
    fn exec_state_dir_is_absolute_in_service_context() {
        let policy = PolicyConfig {
            exec_state_dir: PathBuf::from("work/exec-jobs"),
            ..PolicyConfig::default()
        }
        .with_runtime_paths(None);
        let effective = policy.effective_exec_state_dir();
        assert!(effective.is_absolute());
        assert!(
            !effective
                .display()
                .to_string()
                .to_ascii_lowercase()
                .starts_with(r"c:\windows\system32")
        );
    }

    #[test]
    fn exec_state_dir_relative_to_policy_file_not_system32() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nmcp-policy-state-{stamp}"));
        fs::create_dir_all(&dir).expect("mkdir");
        let policy_path = dir.join("policy.json");
        let policy = PolicyConfig {
            exec_state_dir: PathBuf::from("work/exec-jobs"),
            ..PolicyConfig::default()
        }
        .with_runtime_paths(Some(&policy_path));
        let effective = policy.effective_exec_state_dir();
        assert_eq!(effective, normalize_path(&dir.join("work/exec-jobs")));
        assert!(
            !effective
                .display()
                .to_string()
                .to_ascii_lowercase()
                .starts_with(r"c:\windows\system32")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn nativemcp_policy_defaults_use_programdata_paths() {
        let policy = PolicyConfig::default();
        assert!(policy.audit_path.ends_with(nmcp_identity::AUDIT_FILE));
        assert!(
            policy
                .audit_path
                .display()
                .to_string()
                .contains(nmcp_identity::DATA_DIR_NAME)
        );
        assert!(
            policy
                .exec_state_dir
                .ends_with(Path::new("work").join("exec-jobs"))
        );
        assert!(
            policy
                .exec_state_dir
                .display()
                .to_string()
                .contains(nmcp_identity::DATA_DIR_NAME)
        );
    }

    #[test]
    fn expand_env_vars_replaces_known_token() {
        // No env mutation: edition 2024 makes set_var unsafe and the
        // workspace forbids unsafe. The lookup seam proves the mechanism.
        let result = expand_env_vars_with("prefix_%_NMCP_TEST_VAR%_suffix", |name| {
            (name == "_NMCP_TEST_VAR").then(|| "expanded_value".to_string())
        });
        assert_eq!(result, "prefix_expanded_value_suffix");
    }

    #[test]
    fn expand_env_vars_leaves_unknown_tokens_intact() {
        let result = expand_env_vars("%THIS_VAR_DOES_NOT_EXIST_NMCP%\\path");
        assert!(
            result.contains("%THIS_VAR_DOES_NOT_EXIST_NMCP%"),
            "unknown token must be preserved: {result}"
        );
    }

    #[test]
    fn expand_env_vars_preserves_non_ascii_text() {
        let plain = r"C:\Temp\café\政策.json";
        assert_eq!(expand_env_vars(plain), plain);
    }

    #[test]
    fn expand_env_vars_no_op_for_plain_strings() {
        let plain = "C:\\ProgramData\\NativeMCP\\config\\policy.json";
        assert_eq!(expand_env_vars(plain), plain);
    }

    #[test]
    fn expand_env_vars_handles_empty_token() {
        let result = expand_env_vars("before%%after");
        assert!(!result.is_empty());
    }

    #[test]
    fn with_runtime_paths_expands_env_vars_in_roots() {
        // PATH exists in every test environment, so the expansion is proven
        // without mutating process env (unsafe in edition 2024, forbidden
        // workspace-wide). Only the substitution is asserted, not the value.
        let policy = PolicyConfig {
            roots: vec![RootRule {
                id: "test".into(),
                path: PathBuf::from("%PATH%"),
                permissions: [Permission::Read].into_iter().collect(),
            }],
            ..PolicyConfig::default()
        }
        .with_runtime_paths(None);
        assert_ne!(policy.roots[0].path, PathBuf::from("%PATH%"));
    }

    #[test]
    fn permission_display_memory_variants() {
        assert_eq!(Permission::MemoryRead.to_string(), "memory.read");
        assert_eq!(Permission::MemoryWrite.to_string(), "memory.write");
    }
}

#[cfg(test)]
mod lane_toggle_tests {
    // Tests assert on shapes, where expect/indexing ARE the assertion.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::PolicyConfig;

    fn base() -> String {
        r#"{"admin_bind":"127.0.0.1:18769","mcp_bind":"127.0.0.1:18770","auto_approve":true,"audit_path":"audit.jsonl","roots":[]"#.to_string()
    }

    #[test]
    fn lane_defaults_sse_on_ws_off() {
        // Omitting the lane fields defaults to SSE on, WS off (ADR-0001).
        let json = base() + "}";
        let cfg: PolicyConfig = serde_json::from_str(&json).expect("parse");
        assert!(cfg.enable_sse_lane, "SSE lane defaults on");
        assert!(!cfg.enable_ws_lane, "WS lane defaults off");
    }

    #[test]
    fn lane_flags_are_honored_when_set() {
        let json = base() + r#","enable_sse_lane":false,"enable_ws_lane":true}"#;
        let cfg: PolicyConfig = serde_json::from_str(&json).expect("parse");
        assert!(!cfg.enable_sse_lane);
        assert!(cfg.enable_ws_lane);
    }
}

#[cfg(test)]
mod client_auth_pairing_tests {
    // Tests assert on shapes, where expect/indexing ARE the assertion.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::PolicyConfig;

    fn base() -> String {
        r#"{"admin_bind":"127.0.0.1:18769","mcp_bind":"127.0.0.1:18770","auto_approve":true,
            "audit_path":"C:\\ProgramData\\NativeMCP\\audit\\a.jsonl",
            "exec_state_dir":"C:\\ProgramData\\NativeMCP\\work\\exec-jobs",
            "roots":[{"id":"r","path":"D:\\dev","permissions":["read"]}]"#
            .to_string()
    }

    #[test]
    fn require_client_auth_without_credentials_is_refused() {
        let json = base() + r#","mcp_require_client_auth":true}"#;
        let err = PolicyConfig::from_json_str(&json).expect_err("contradiction must be refused");
        assert!(
            err.to_string().contains("mcp_clients is empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn require_client_auth_with_a_credential_is_accepted() {
        let json = base()
            + r#","mcp_require_client_auth":true,
                 "mcp_clients":[{"agent_id":"a","token_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}"#;
        PolicyConfig::from_json_str(&json).expect("flag plus credential is a valid pairing");
    }

    #[test]
    fn not_requiring_client_auth_needs_no_credentials() {
        let json = base() + "}";
        PolicyConfig::from_json_str(&json).expect("default posture stays valid");
    }
}

#[cfg(test)]
mod policy_load_tests {
    // Tests assert on shapes, where expect/indexing ARE the assertion.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::{
        GatewayProfile, McpClientCredential, Permission, PolicyConfig, PolicyError, UpstreamConfig,
        UpstreamTransport,
    };
    use std::collections::BTreeMap;

    /// A complete valid policy with the given upstreams array spliced in.
    fn json_with_upstreams(upstreams: &str) -> String {
        valid_json().replace(
            "\"roots\":",
            &format!("\"upstreams\":{upstreams},\"roots\":"),
        )
    }

    fn valid_json() -> String {
        r#"{"admin_bind":"127.0.0.1:18769","mcp_bind":"127.0.0.1:18770","auto_approve":true,
            "audit_path":"C:\\ProgramData\\NativeMCP\\audit\\a.jsonl",
            "exec_state_dir":"C:\\ProgramData\\NativeMCP\\work\\exec-jobs",
            "roots":[{"id":"r","path":"D:\\dev","permissions":["read"]}]}"#
            .to_string()
    }

    #[test]
    fn from_json_str_accepts_a_valid_policy() {
        let policy = PolicyConfig::from_json_str(&valid_json()).expect("valid policy");
        assert_eq!(policy.roots.len(), 1);
    }

    #[test]
    fn from_json_str_tolerates_a_utf8_bom() {
        // Notepad and PowerShell 5.1 Set-Content -Encoding UTF8 both emit a BOM.
        let with_bom = format!("\u{feff}{}", valid_json());
        PolicyConfig::from_json_str(&with_bom).expect("BOM-prefixed policy must load");
    }

    #[test]
    fn from_json_str_enforces_semantic_validation() {
        // Parses as JSON, but identical binds are forbidden. This is the regression
        // that let `validate` report success on a policy the server would reject.
        let json = valid_json().replace("127.0.0.1:18770", "127.0.0.1:18769");
        let err = PolicyConfig::from_json_str(&json).expect_err("identical binds must fail");
        assert!(
            err.to_string().contains("distinct"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn from_json_str_reports_malformed_json_distinctly() {
        let err = PolicyConfig::from_json_str("{ not json").expect_err("must fail");
        assert!(
            matches!(err, PolicyError::MalformedJson(_)),
            "unexpected: {err}"
        );
    }

    /// The back-compatibility half of G6-1. The live policy carries upstreams written before
    /// DEC-007, and a policy that will not parse is now a readiness failure under G4-25, so
    /// "still loads" is not a nicety here.
    #[test]
    fn a_pre_dec_007_upstream_naming_only_a_url_still_loads_and_behaves_identically() {
        let text = json_with_upstreams(
            r#"[{"id": "legacy", "url": "http://127.0.0.1:9000", "enabled": false}]"#,
        );
        let policy = PolicyConfig::from_json_str(&text).expect("legacy upstream must still load");
        let upstream = &policy.upstreams[0];

        assert_eq!(
            upstream.transport(),
            UpstreamTransport::Http {
                url: "http://127.0.0.1:9000".into()
            }
        );
        assert_eq!(
            upstream.http_url().as_deref(),
            Some("http://127.0.0.1:9000"),
            "every caller that used to read .url reads this instead"
        );
        assert!(
            upstream.url.is_empty(),
            "normalization must leave exactly one spelling, or hot-reload churns the provider"
        );
    }

    /// Normalization has to be idempotent, because the hot-reload path compares a freshly
    /// loaded upstream against a running provider's config and re-registers on any
    /// difference. Two spellings of one upstream would churn it on every reload.
    #[test]
    fn normalizing_a_transport_is_idempotent_and_survives_a_round_trip() {
        let text = json_with_upstreams(
            r#"[{"id": "legacy", "url": "http://127.0.0.1:9000", "enabled": false}]"#,
        );
        let once = PolicyConfig::from_json_str(&text).expect("first load");
        let json = serde_json::to_string(&once).expect("serialize");
        let twice = PolicyConfig::from_json_str(&json).expect("second load");
        assert_eq!(once.upstreams, twice.upstreams);

        let mut third = twice.upstreams[0].clone();
        third.normalize_transport();
        assert_eq!(third, twice.upstreams[0]);
    }

    /// A digest-pinned image, for tests that are about something other than pinning.
    const PINNED_IMAGE: &str = "ghcr.io/example/mcp@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn container(image: &str, runtime: Option<&str>) -> UpstreamTransport {
        UpstreamTransport::Container {
            image: image.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            env_secrets: BTreeMap::new(),
            runtime: runtime.map(String::from),
        }
    }

    /// The defect DEC-007 exists to end: a configuration describing something the runtime
    /// cannot do, accepted at validation and failing forever at refresh time. G4-22 was that,
    /// and it retried a dead port every 62 seconds for weeks. Every transport has a runtime
    /// as of G6-3, so what this pins now is the gate itself, which is what the next transport
    /// added will be refused by until its runtime lands.
    #[test]
    fn every_declared_transport_has_a_runtime_behind_it() {
        for transport in [
            UpstreamTransport::Http {
                url: "http://127.0.0.1:9000".into(),
            },
            UpstreamTransport::Stdio {
                command: "npx".into(),
                args: Vec::new(),
                env: BTreeMap::new(),
                env_secrets: BTreeMap::new(),
                cwd: None,
            },
            container(PINNED_IMAGE, None),
        ] {
            assert!(
                transport.is_implemented(),
                "{} declares a runtime that does not exist",
                transport.kind()
            );
        }
    }

    /// G6-3. A tag is a name its publisher can repoint at different bytes tomorrow.
    #[test]
    fn a_container_image_that_is_not_digest_pinned_is_refused() {
        let unpinned = [
            "example/mcp:latest",
            "example/mcp",
            "example/mcp@sha256:abc",
            "example/mcp@sha1:0123456789abcdef0123456789abcdef01234567",
            "example/mcp@sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
            "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ];
        for image in unpinned {
            let mut policy = PolicyConfig::default();
            let mut upstream = UpstreamConfig::new("shipped", "");
            upstream.transport = Some(container(image, None));
            policy.upstreams.push(upstream);

            let err = policy.validate_semantics().expect_err(&format!(
                "'{image}' is not digest-pinned and must be refused"
            ));
            assert!(
                err.to_string().contains("digest"),
                "the refusal must say what to do about it: {err}"
            );
        }
    }

    #[test]
    fn a_digest_pinned_container_upstream_validates() {
        let mut policy = PolicyConfig::default();
        let mut upstream = UpstreamConfig::new("shipped", "");
        upstream.transport = Some(container(PINNED_IMAGE, Some("podman")));
        upstream.enabled = true;
        // G4-28: an enabled upstream must declare the capability an operator has to grant.
        upstream.required_permission = Some(Permission::UpstreamCall);
        policy.upstreams.push(upstream);

        policy
            .validate_semantics()
            .expect("a digest-pinned container upstream must validate now that G6-3 landed");
    }

    /// G6-5. A profile decides what is live; it does not rewrite what each upstream says
    /// about itself. That is what makes switching away from one lossless, and it is the whole
    /// difference between a profile and a bulk edit.
    #[test]
    fn an_active_profile_decides_what_is_live_without_rewriting_any_flag() {
        let mut policy = PolicyConfig::default();
        for (id, url) in [
            ("alpha", "http://127.0.0.1:9001"),
            ("bravo", "http://127.0.0.1:9002"),
        ] {
            let mut upstream = UpstreamConfig::new(id, url);
            // G4-28: an enabled upstream must declare the capability an operator has to
            // grant. A profile decides which declared upstream is live, not whether one
            // needs a declaration at all.
            upstream.required_permission = Some(Permission::UpstreamCall);
            policy.upstreams.push(upstream);
        }
        assert!(policy.upstreams.iter().all(|u| u.enabled));
        assert_eq!(policy.live_upstreams().count(), 2);

        policy.gateway_profiles.insert(
            "reading".to_string(),
            GatewayProfile {
                label: "Reading".into(),
                servers: BTreeMap::from([("alpha".to_string(), true)]),
            },
        );
        policy.active_gateway_profile = Some("reading".to_string());
        policy
            .validate_semantics()
            .expect("a profile naming a configured upstream must validate");

        let live: Vec<&str> = policy.live_upstreams().map(|u| u.id.as_str()).collect();
        assert_eq!(live, ["alpha"], "an upstream the profile omits is not live");
        assert!(
            policy.upstreams.iter().all(|u| u.enabled),
            "the profile must override the flags rather than overwrite them"
        );

        policy.active_gateway_profile = None;
        assert_eq!(
            policy.live_upstreams().count(),
            2,
            "switching away must restore what was there without the operator restating it"
        );
    }

    /// Refused rather than ignored, because of which direction the mistake runs: under an
    /// active profile, selecting nothing means retracting everything, so a mistyped server id
    /// would take a server off the air rather than do nothing.
    #[test]
    fn a_profile_selecting_an_upstream_that_does_not_exist_is_refused() {
        let mut policy = PolicyConfig::default();
        policy
            .upstreams
            .push(UpstreamConfig::new("alpha", "http://127.0.0.1:9001"));
        policy.gateway_profiles.insert(
            "typo".to_string(),
            GatewayProfile {
                label: String::new(),
                servers: BTreeMap::from([("aplha".to_string(), true)]),
            },
        );

        let err = policy
            .validate_semantics()
            .expect_err("a profile naming an upstream that does not exist must be refused");
        assert!(
            err.to_string().contains("aplha"),
            "the refusal must name the id that does not resolve: {err}"
        );
    }

    #[test]
    fn activating_a_profile_that_does_not_exist_is_refused() {
        let policy = PolicyConfig {
            active_gateway_profile: Some("ghost".to_string()),
            ..PolicyConfig::default()
        };

        let err = policy
            .validate_semantics()
            .expect_err("an active profile has to exist");
        assert!(err.to_string().contains("ghost"), "{err}");
    }

    /// G6-8. The credential binds and the header selects within what the credential permits.
    /// A profile chosen purely by header is a filter a client can decline to send, so a
    /// credential that names one has to win, and a header that disagrees is refused rather
    /// than quietly ignored.
    #[test]
    fn a_credential_bound_to_a_profile_pins_the_session() {
        let mut policy = PolicyConfig::default();
        policy
            .gateway_profiles
            .insert("reading".to_string(), GatewayProfile::default());
        policy
            .gateway_profiles
            .insert("writing".to_string(), GatewayProfile::default());

        // Bound and silent, bound and agreeing: the binding is in force either way.
        assert_eq!(
            policy
                .session_profile(Some("reading"), None)
                .expect("bound"),
            Some("reading".to_string())
        );
        assert_eq!(
            policy
                .session_profile(Some("reading"), Some("reading"))
                .expect("agreeing"),
            Some("reading".to_string())
        );

        let err = policy
            .session_profile(Some("reading"), Some("writing"))
            .expect_err("a bound credential must refuse a header that disagrees");
        assert!(err.contains("reading") && err.contains("writing"), "{err}");

        // Unbound: the header chooses, which is what one operator with several desktops needs.
        assert_eq!(
            policy
                .session_profile(None, Some("writing"))
                .expect("header"),
            Some("writing".to_string())
        );
        assert!(
            policy.session_profile(None, Some("ghost")).is_err(),
            "a profile that does not exist must be refused rather than silently ignored"
        );

        // Neither: unchanged from every build before sessions had profiles.
        assert_eq!(policy.session_profile(None, None).expect("neither"), None);
        assert_eq!(
            policy.session_profile(None, Some("  ")).expect("blank"),
            None
        );
    }

    /// A profile selects among proxied upstreams. Taking away the filesystem or the Windows
    /// tools is a different feature, and the one that does it is the caller allowlist.
    #[test]
    fn a_profile_never_scopes_away_a_local_provider() {
        let mut policy = PolicyConfig::default();
        policy.gateway_profiles.insert(
            "reading".to_string(),
            GatewayProfile {
                label: String::new(),
                servers: BTreeMap::from([("github".to_string(), true)]),
            },
        );

        assert!(policy.provider_visible_to_session(Some("reading"), ""));
        assert!(policy.provider_visible_to_session(Some("reading"), "github"));
        assert!(!policy.provider_visible_to_session(Some("reading"), "partner"));
        assert!(
            policy.provider_visible_to_session(None, "partner"),
            "an unscoped session reaches whatever is running"
        );
    }

    /// A credential pinned to a profile that does not exist would lock its client out with no
    /// way to see why, so it is refused at validation instead.
    #[test]
    fn a_credential_bound_to_a_profile_that_does_not_exist_is_refused() {
        let policy = PolicyConfig {
            mcp_clients: vec![McpClientCredential {
                agent_id: "desktop".into(),
                token_sha256: "a".repeat(64),
                profile: Some("ghost".into()),
            }],
            ..PolicyConfig::default()
        };

        let err = policy
            .validate_semantics()
            .expect_err("a dangling credential binding must be refused");
        assert!(err.to_string().contains("ghost"), "{err}");
    }

    /// Which program a policy file starts is not a thing to decide implicitly against
    /// whatever working directory a `LocalSystem` service happens to have.
    #[test]
    fn a_container_runtime_given_as_a_relative_path_is_refused() {
        for runtime in ["..\\tools\\docker.exe", "tools/docker", " docker", ""] {
            let mut policy = PolicyConfig::default();
            let mut upstream = UpstreamConfig::new("shipped", "");
            upstream.transport = Some(container(PINNED_IMAGE, Some(runtime)));
            policy.upstreams.push(upstream);

            assert!(
                policy.validate_semantics().is_err(),
                "runtime '{runtime}' must not be accepted"
            );
        }
    }

    /// G6-2 lifted the gate for stdio. A stdio upstream has no url to check and no network
    /// hop to distrust, so the url and pinning rules written for a remote server must not
    /// reject it by accident.
    #[test]
    fn a_stdio_upstream_validates_now_that_its_runtime_exists() {
        let mut policy = PolicyConfig::default();
        let mut upstream = UpstreamConfig::stdio(
            "filesystem",
            "npx",
            &["-y", "@modelcontextprotocol/server-filesystem"],
        );
        upstream.enabled = true;
        // G4-28: an enabled upstream must declare the capability an operator has to grant.
        upstream.required_permission = Some(Permission::UpstreamCall);
        policy.upstreams.push(upstream);

        policy
            .validate_semantics()
            .expect("a stdio upstream must validate now that the gateway can start one");
    }

    /// Pinning is a property of trusting a tool list, not of crossing a network, so asking
    /// for it must still bite on a transport that never touches the network.
    #[test]
    fn require_upstream_pinning_still_applies_to_a_stdio_upstream() {
        let policy_defaults = PolicyConfig::default();
        let mut policy = PolicyConfig {
            require_upstream_pinning: true,
            ..policy_defaults
        };
        let mut upstream = UpstreamConfig::stdio("filesystem", "npx", &["-y", "server"]);
        upstream.enabled = true;
        policy.upstreams.push(upstream);

        let err = policy
            .validate_semantics()
            .expect_err("pinning must be enforced regardless of transport");
        assert!(err.to_string().contains("tools_sha256"), "{err}");
    }

    #[test]
    fn a_transport_missing_its_required_field_is_refused_by_name() {
        let cases = [
            (
                UpstreamTransport::Stdio {
                    command: "   ".into(),
                    args: Vec::new(),
                    env: BTreeMap::new(),
                    env_secrets: BTreeMap::new(),
                    cwd: None,
                },
                "command",
            ),
            (
                UpstreamTransport::Container {
                    image: String::new(),
                    args: Vec::new(),
                    env: BTreeMap::new(),
                    env_secrets: BTreeMap::new(),
                    runtime: None,
                },
                "image",
            ),
            (UpstreamTransport::Http { url: String::new() }, "url"),
        ];
        for (transport, field) in cases {
            let mut policy = PolicyConfig::default();
            let mut upstream = UpstreamConfig::new("broken", "");
            upstream.transport = Some(transport);
            policy.upstreams.push(upstream);

            let err = policy
                .validate_semantics()
                .expect_err("a transport missing a required field must be refused");
            assert!(
                err.to_string().contains(field),
                "the refusal must name the missing field: {err}"
            );
        }
    }

    #[test]
    fn an_upstream_written_in_the_new_shape_loads_without_a_url() {
        let text = json_with_upstreams(
            r#"[{"id": "modern", "enabled": false, "transport": {"kind": "http", "url": "http://127.0.0.1:9100"}}]"#,
        );
        let policy = PolicyConfig::from_json_str(&text).expect("new shape must load");
        assert_eq!(
            policy.upstreams[0].http_url().as_deref(),
            Some("http://127.0.0.1:9100")
        );
        assert_eq!(policy.upstreams[0].transport().kind(), "http");
    }
}
