//! The policy write path: persisting an edit, and applying it without a restart.
//!
//! Six functions and a bag, from the base's crate root. `save_policy_update` is the one that
//! matters to everything downstream: twenty-seven handlers across the admin and gateway surfaces
//! call it, which is why it lands in its own issue ahead of them rather than inside whichever of
//! them happened to go first.
//!
//! # Why a policy edit reconciles upstreams instead of waiting for the watcher
//!
//! `PUT /api/policy` is named in G4-23 as the way to disable a compromised upstream. The file
//! watcher would pick the change up within two seconds, and two seconds during which the policy
//! document says an upstream is disabled while the gateway is still proxying to it is a window
//! worth not having. So this path reconciles directly, and the watcher remains the path for edits
//! made outside the admin surface.
//!
//! # The order inside a save is the whole safety property
//!
//! Validate, canonicalize, take the update lock, **persist, then apply**. A policy that reaches
//! memory without reaching disk is a policy that vanishes on restart, and an operator who
//! tightened a rule and saw it accepted would be shown the state they wanted rather than the
//! state they have. The failure runs in the dangerous direction, so the write happens first and a
//! failed write returns before anything in memory moves.
//!
//! # The secret seams, and NMCP-SPEC-002 SB-17
//!
//! Two lookups are wired here and nowhere else: `nmcp_gateway::UpstreamSecretLookup` for an
//! upstream's `auth_secret` and `env_secrets`, and `nmcp_oauth::ClientSecretLookup` for a
//! provider's client secret. Both fail closed under SB-8 until the daemon supplies one, which is
//! the state core has been in since those crates landed.
//!
//! Resolving needs a [`nmcp_secrets::BindingGrant`], which only comes from
//! `SealedStore::evaluate(name, request)`, and a `BindingRequest` carries a tool and a caller.
//! **An upstream credential has neither.** The `auth_secret` path runs per request but with no
//! bearing on who made it, and the refresh path runs on a timer with nothing in flight at all.
//!
//! SB-17 is the row that says what the daemon presents. It is a specification row rather than a
//! decision made here because the argument that makes the values safe rests on two character
//! classes in two other crates, and nothing in this file would fail if either were relaxed.

// Nothing routes here yet: `save_policy_update` is what the admin and gateway surfaces call,
// and those are I-077c and I-077d. `allow` rather than `expect` for the reason `admission` and
// `diagnostics` give: this module's own tests drive what they cover, so the lint fires in the lib
// target and not in the lib-test target, and an unfulfilled expectation in either is an error.
#![allow(
    dead_code,
    reason = "the admin surface is I-077c; the gateway surface is I-077d"
)]

use crate::AppState;
use axum::Json;
use axum::http::StatusCode;
use nmcp_audit::AuditSink;
use nmcp_gateway::{CatalogFeedSnapshot, GatewayRegistry, UpstreamProvider, UpstreamSecretLookup};
use nmcp_oauth::{Broker, ClientSecretLookup};
use nmcp_policy::PolicyConfig;
use nmcp_router::SharedRouter;
use nmcp_secrets::{BindingRequest, SealedStore};
use serde_json::{Value, json};
use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// The caller the daemon presents when it resolves a secret on its own behalf. SB-17.
///
/// Not `local`, which stage 5b uses for a tool call that arrived with no agent id, so an operator
/// binding `callers: ["local"]` to mean the CLI does not silently admit every upstream credential
/// resolution as well. Two different absences of an agent are two different values.
///
/// **Unforgeable as an agent id**, and nothing was added to make it so: `PolicyConfig`'s
/// `safe_id` admits ASCII alphanumeric, `_`, `-` and `.`, so a policy naming an agent
/// `daemon/self` is refused at validation by a rule written for other reasons.
pub(crate) const DAEMON_CALLER: &str = "daemon/self";

/// The tool the daemon presents for an OAuth provider's client secret. SB-17.
///
/// A constant rather than a per-provider value, because the broker holds one lookup for every
/// provider and calls it with the secret name alone. What this buys is intact regardless: a key
/// bound to it cannot be pulled through stage 5b by a tool naming it in a `secret_ref` slot, and
/// cannot be used as an upstream auth header.
pub(crate) const OAUTH_PROVIDER_TOOL: &str = "oauth-provider";

/// The tool the daemon presents for one upstream's credentials. SB-17.
///
/// **Unforgeable as a tool name**: `nmcp_schema::is_valid_public_tool_name` admits ASCII
/// alphanumeric, `_` and `-` only, so no registered tool can ever be called `upstream/github`.
fn upstream_tool(upstream_id: &str) -> String {
    format!("upstream/{upstream_id}")
}

/// Resolve a named secret for the daemon itself, under the request SB-17 specifies.
///
/// `None` on every refusal, which is what both seams' signatures allow and what SB-8 requires:
/// the caller reports the credential as unavailable by name rather than proceeding
/// unauthenticated. The denial's rule is logged here because it is the only place it exists; the
/// seam cannot carry it back.
fn resolve_for_daemon(
    store: &SealedStore,
    tool: &str,
    name: &str,
) -> Option<nmcp_secrets::Sealed<Vec<u8>>> {
    let Ok(secret_name) = nmcp_secrets::SecretName::parse(name) else {
        tracing::warn!(
            secret = name,
            tool = tool,
            "daemon secret resolution refused: the configured name is not a legal secret name"
        );
        return None;
    };
    let request = BindingRequest::new(tool, DAEMON_CALLER);
    match store.evaluate(&secret_name, &request) {
        Ok(grant) => match store.resolve(grant) {
            Ok(sealed) => Some(sealed),
            Err(err) => {
                tracing::warn!(
                    secret = name,
                    tool = tool,
                    "daemon secret resolution refused: {err}"
                );
                None
            }
        },
        Err(denial) => {
            tracing::warn!(
                secret = name,
                tool = tool,
                rule = denial.rule(),
                "daemon secret binding refused"
            );
            None
        }
    }
}

/// The upstream secret seam for one upstream, under SB-17.
///
/// One closure per upstream, capturing its id, which is what makes the binding per upstream. The
/// gateway holds this per provider instance, so the id is free here in a way it is not on the
/// broker.
pub(crate) fn upstream_secret_lookup(
    secrets: &Arc<SealedStore>,
    upstream_id: &str,
) -> UpstreamSecretLookup {
    let store = Arc::clone(secrets);
    let tool = upstream_tool(upstream_id);
    Arc::new(move |name: &str| resolve_for_daemon(&store, &tool, name))
}

/// The OAuth client-secret seam, under SB-17.
pub(crate) fn client_secret_lookup(secrets: &Arc<SealedStore>) -> ClientSecretLookup {
    let store = Arc::clone(secrets);
    Arc::new(move |name: &str| resolve_for_daemon(&store, OAUTH_PROVIDER_TOOL, name))
}

// The bag a policy change acts on ─────────────────────────────────────────────────────────

/// A bag rather than `AppState` itself, so the watcher and `reconcile_upstreams` stay callable
/// from a test that has not built a whole server, which is the reason the watcher was pulled out
/// of the serve path to begin with. It grew a fifth member with G6-9 and passing five loose
/// arguments through two layers was already the wrong shape before clippy said so.
#[derive(Clone)]
pub(crate) struct RuntimeWiring {
    pub(crate) gateway: GatewayRegistry,
    pub(crate) router: SharedRouter,
    pub(crate) audit: AuditSink,
    /// The handle, not a copy.
    ///
    /// The base's field is a `SecretStore`, which is `Clone`, so every consumer held its own
    /// copy of the thing whose entire job is being the one authority over sealed material.
    /// Core's `SealedStore` is deliberately not `Clone` for that reason, so this is an `Arc` and
    /// there is one store. The type change is why this struct could not simply be moved.
    pub(crate) secrets: Arc<SealedStore>,
    pub(crate) oauth: Arc<Broker>,
}

// Applying a policy change to the running gateway ─────────────────────────────────────────

/// Bring the live gateway registry and router in line with a freshly loaded policy.
///
/// Providers capture their `UpstreamConfig` by value at construction, and are registered once.
/// Swapping the policy arc therefore reaches roots, permissions, `mcp_clients` and `abac_rules`,
/// which are read per request, but never reaches the upstreams block. Before this, an operator
/// who disabled a compromised upstream by editing the policy file saw `GET /api/policy` report
/// it disabled while the gateway kept proxying to it until someone restarted the service. That
/// is fail-open on the one surface designed not to be.
///
/// Returns a human-readable list of what changed, for the log and for tests.
pub(crate) fn reconcile_upstreams(wiring: &RuntimeWiring, policy: &PolicyConfig) -> Vec<String> {
    let RuntimeWiring {
        gateway,
        router,
        audit,
        secrets,
        oauth,
    } = wiring;
    let mut changes = Vec::new();

    // The provider map is swapped rather than the broker rebuilt, so a grant already in memory,
    // a backoff already counting and a device authorization already in flight all survive a
    // reload of an unrelated part of policy. Done before the upstreams below, so an upstream
    // registered in this same pass finds its provider already there.
    oauth.reconfigure(policy.oauth_providers.clone());

    for cfg in policy.live_upstreams() {
        match gateway.get(&cfg.id) {
            // Already running with exactly this configuration: leave it alone. Re-registering
            // on every reload would drop the warm tool cache and restart the refresh clock.
            Some(existing) if existing.config() == cfg => {}
            Some(_) => {
                // The return says whether anything was removed. Ignored here on purpose: this
                // arm has already matched an existing provider, and a `false` would mean it
                // vanished between the match and the remove, which changes nothing about what
                // happens next. Core made this `#[must_use]` where the base did not.
                let _ = gateway.remove(&cfg.id);
                router.unregister_provider(&cfg.id);
                let Some(provider) = build_upstream(cfg, audit, secrets, oauth) else {
                    changes.push(format!("could not rebuild '{}'; left as it was", cfg.id));
                    continue;
                };
                gateway.add(provider.clone());
                let _ = router.register(provider);
                changes.push(format!("replaced '{}'", cfg.id));
            }
            None => {
                let Some(provider) = build_upstream(cfg, audit, secrets, oauth) else {
                    changes.push(format!("could not register '{}'; skipped", cfg.id));
                    continue;
                };
                gateway.add(provider.clone());
                let _ = router.register(provider);
                changes.push(format!("registered '{}'", cfg.id));
            }
        }
    }

    // Anything live that the new policy no longer wants, whether it was disabled, deleted, or
    // dropped by the profile now in force.
    let wanted: std::collections::BTreeSet<&str> =
        policy.live_upstreams().map(|u| u.id.as_str()).collect();
    for provider in gateway.all() {
        let id = provider.config().id.clone();
        if !wanted.contains(id.as_str()) {
            // As above: this id came from `gateway.all()` one line earlier.
            let _ = gateway.remove(&id);
            router.unregister_provider(&id);
            changes.push(format!("retracted '{id}'"));
        }
    }

    changes
}

/// Build one upstream provider, with its own SB-17 secret seam.
///
/// The lookup is constructed here, inside the reconcile loop, rather than once for the process:
/// it captures this upstream's id, which is what makes the binding per upstream. One `Arc` clone
/// per upstream per reconcile.
///
/// `None` on a build failure rather than a propagated error, and the caller reports it and moves
/// on. Construction became fallible in core (`GatewayBuildError`) where the base carried a
/// production `expect` on the HTTP client builder. A policy edit that adds one unbuildable
/// upstream must not take down the ones already running, and the base's version could not fail
/// at all so it never had to decide this.
fn build_upstream(
    cfg: &nmcp_policy::UpstreamConfig,
    audit: &AuditSink,
    secrets: &Arc<SealedStore>,
    oauth: &Arc<Broker>,
) -> Option<Arc<UpstreamProvider>> {
    match UpstreamProvider::new(
        cfg.clone(),
        audit.clone(),
        Some(upstream_secret_lookup(secrets, &cfg.id)),
        Some(Arc::clone(oauth)),
    ) {
        Ok(provider) => Some(provider),
        Err(err) => {
            tracing::error!(upstream = %cfg.id, "gateway: upstream could not be built: {err}");
            None
        }
    }
}

// Persisting a policy change ──────────────────────────────────────────────────────────────

pub(crate) fn save_policy_update(
    state: &AppState,
    mut policy: PolicyConfig,
) -> (StatusCode, Json<Value>) {
    policy.normalize_legacy_root_ids();
    let Some(policy_path) = state.policy_path.as_deref() else {
        return (
            StatusCode::CONFLICT,
            Json(
                json!({"ok":false,"error":"policy persistence is unavailable; start the daemon with --config to enable admin policy editing"}),
            ),
        );
    };
    if let Err(err) = policy.validate_semantics() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok":false,"error":err.to_string()})),
        );
    }
    if let Err(err) = policy.canonicalize_roots_for_save() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok":false,"error":err.to_string()})),
        );
    }
    let _guard = state.policy_update_lock.lock();
    if let Err(err) = write_policy_file(policy_path, &policy) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok":false,"error":format!("failed to persist policy: {err}")})),
        );
    }
    let policy = policy.with_runtime_paths(Some(policy_path));
    // Apply upstream changes on this path too rather than waiting up to two seconds for the
    // file watcher. PUT /api/policy is named in G4-23 as a way to disable a compromised
    // upstream, and a two second window where the arc says disabled while the gateway is
    // still proxying is a window worth not having.
    let changes = reconcile_upstreams(&state.wiring(), &policy);
    if !changes.is_empty() {
        tracing::info!("policy update: upstreams {}", changes.join(", "));
    }
    *state.policy.write() = policy;
    (StatusCode::OK, Json(json!({"ok":true})))
}
pub(crate) fn write_policy_file(path: &Path, policy: &PolicyConfig) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("policy path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|err| anyhow::anyhow!("creating policy directory {}: {err}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("policy path has no file name: {}", path.display()))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = parent.join(format!(".{file_name}.tmp.{}.{}", std::process::id(), stamp));
    let text = format!("{}\n", serde_json::to_string_pretty(policy)?);
    write_text_atomically(&temp_path, path, &text)
}

/// Write a config file the way policy has always been written: into a sibling temp file,
/// flushed, then replaced in one step, so a reader never sees a half-written file and a
/// failed write never destroys the previous one.
///
/// Shared with the catalog feed (G6-7) rather than copied, because a second implementation of
/// this is a second chance to get the ordering wrong.
fn write_text_atomically(temp_path: &Path, path: &Path, text: &str) -> anyhow::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp_path)
        .map_err(|err| anyhow::anyhow!("creating temporary file {}: {err}", temp_path.display()))?;
    file.write_all(text.as_bytes())
        .map_err(|err| anyhow::anyhow!("writing temporary file {}: {err}", temp_path.display()))?;
    file.sync_all()
        .map_err(|err| anyhow::anyhow!("flushing temporary file {}: {err}", temp_path.display()))?;
    drop(file);
    replace_file_atomically(temp_path, path)
}

/// Write the catalog feed snapshot beside the policy file.
pub(crate) fn write_catalog_feed(
    path: &Path,
    snapshot: &CatalogFeedSnapshot,
) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("catalog feed path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent).map_err(|err| {
        anyhow::anyhow!(
            "creating catalog feed directory {}: {err}",
            parent.display()
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("catalog feed path has no file name: {}", path.display()))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = parent.join(format!(".{file_name}.tmp.{}.{}", std::process::id(), stamp));
    let text = format!("{}\n", serde_json::to_string_pretty(snapshot)?);
    write_text_atomically(&temp_path, path, &text)
}

// Replacing a file in one step ────────────────────────────────────────────────────────────

/// Replace `path` with `temp_path` in one step.
///
/// # The Windows arm the base has and this workspace cannot write
///
/// The base carries two implementations. The portable one is this. The `#[cfg(windows)]` one
/// calls `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`, and the second
/// flag is the point: it forces the rename through to disk before returning.
///
/// **`unsafe_code = "forbid"` at the workspace root is what stops it coming across**, and `forbid`
/// is not `deny`: it cannot be lifted by an inner `allow`, which is the whole reason it is set
/// that way. Every route to `MoveFileExW` from safe Rust ends at an `unsafe` block. The
/// alternative on Unix, opening the parent directory and calling `sync_all` on it, has no Windows
/// counterpart because a directory cannot be opened as a `File` there.
///
/// So the invariant decides it, and the gap is named rather than worked around.
///
/// # What is kept and what is lost
///
/// **Kept: the replace is still atomic and still replaces.** `std::fs::rename` maps to
/// `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING` on Windows, so a reader never sees a
/// half-written file and a failed write never destroys the previous one. That is the correctness
/// property and it is intact.
///
/// **Kept: the contents are durable.** [`write_text_atomically`] calls `sync_all` on the temp
/// file before this runs, so the bytes are on disk.
///
/// **Lost: the directory entry update may sit in the OS cache when this returns.** A power loss
/// in that window leaves the previous policy in place on Windows, and the operator was told the
/// save succeeded. Narrow, and in the silent-and-dangerous direction this module's own header
/// argues about.
///
/// **Owner: the WinMCP lane.** It is the Windows half, it is where a platform primitive belongs,
/// and it is where an `unsafe` block could be reviewed against a different invariant if that lane
/// decides to carry one. This crate is cross-platform and should not be the place that decision
/// gets made by accident.
fn replace_file_atomically(temp_path: &Path, path: &Path) -> anyhow::Result<()> {
    std::fs::rename(temp_path, path).map_err(|err| {
        anyhow::anyhow!(
            "replacing {} with {}: {err}",
            path.display(),
            temp_path.display()
        )
    })
}

// Tests ─────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "a test that cannot fail loudly reports nothing"
    )]

    use super::*;
    use nmcp_policy::{McpClientCredential, UpstreamConfig};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("nmcp-policy-write-{label}-{stamp}"));
        std::fs::create_dir_all(&root).expect("mkdir");
        root
    }

    // ── NMCP-SPEC-002 SB-17: the two namespaces, pinned where they can break ─────────────

    /// SB-17's collision-freedom argument, asserted against the validators it rests on.
    ///
    /// This is the most important test in the issue and it looks like the least. SB-17 says the
    /// daemon may present `upstream/<id>` as a tool and `daemon/self` as a caller because neither
    /// can ever be a real tool name or a real agent id. **That argument is not a property of this
    /// crate.** It is a property of two character classes in two other crates, written for
    /// unrelated reasons, and nothing here fails if either is relaxed.
    ///
    /// So the row says a change to either is a change to the row, and this is what makes that
    /// enforceable rather than aspirational: relaxing either class turns a silent reopening of
    /// the namespace into a failing test with the reason attached.
    #[test]
    fn the_daemon_namespaces_cannot_be_forged_by_a_tool_or_an_agent() {
        assert!(
            !nmcp_schema::is_valid_public_tool_name(&upstream_tool("github")),
            "a `/` became legal in a tool name, so a registered tool can now be called \
             `upstream/github` and can present itself as the daemon resolving that upstream's \
             credential. NMCP-SPEC-002 SB-17 rests on this being impossible."
        );
        assert!(
            !nmcp_schema::is_valid_public_tool_name(OAUTH_PROVIDER_TOOL) || {
                // The OAuth value has no `/`, so it IS a legal tool name and the argument for it
                // is different: it is cross-door protection rather than unforgeability. Stated
                // here so the difference is visible rather than assumed from the pair above.
                true
            },
            "unreachable"
        );

        // The caller half. A policy naming an agent `daemon/self` must be refused at validation,
        // by a rule written to keep agent ids simple and not for this.
        let mut policy = PolicyConfig {
            mcp_clients: vec![McpClientCredential {
                agent_id: DAEMON_CALLER.to_string(),
                token_sha256: "0".repeat(64),
                profile: None,
            }],
            ..PolicyConfig::default()
        };
        assert!(
            policy.validate_semantics().is_err(),
            "a policy configured an agent named `{DAEMON_CALLER}`, so an agent can now present \
             itself as the daemon. SB-17 rests on `safe_id` refusing this."
        );

        // The negative control. Without it, a `validate_semantics` that had started refusing
        // everything would pass the assertion above.
        policy.mcp_clients[0].agent_id = "ordinary-agent".to_string();
        assert!(
            policy.validate_semantics().is_ok(),
            "an ordinary agent id was refused, so the assertion above proves nothing"
        );
    }

    /// The request the daemon presents, per upstream.
    #[test]
    fn the_upstream_tool_names_the_upstream_and_the_caller_is_not_the_cli() {
        assert_eq!(upstream_tool("github"), "upstream/github");
        assert_eq!(upstream_tool("internal-wiki"), "upstream/internal-wiki");
        assert_eq!(DAEMON_CALLER, "daemon/self");
        assert_eq!(OAUTH_PROVIDER_TOOL, "oauth-provider");

        // Not `local`. Stage 5b writes that for a tool call arriving with no agent id, which is
        // the CLI path, so an operator binding `callers: ["local"]` to mean the CLI would
        // silently admit every upstream credential resolution if the daemon reused it.
        assert_ne!(DAEMON_CALLER, "local");
    }

    /// A key with no binding resolves to nothing, and the upstream refuses by name.
    ///
    /// SB-8's fail-closed direction, asserted through the seam rather than described. The store
    /// here has the key; what it does not have is a binding admitting the daemon's request, and
    /// the difference between those two is the whole point of the binding model.
    #[test]
    fn a_key_with_no_binding_admitting_the_daemon_resolves_to_nothing() {
        let store = Arc::new(SealedStore::ephemeral());
        let lookup = upstream_secret_lookup(&store, "github");
        assert!(
            lookup("a-key-that-was-never-stored").is_none(),
            "an absent key must resolve to nothing"
        );
        assert!(
            lookup("not a legal secret name!").is_none(),
            "a configured name that is not a legal secret name resolves to nothing rather than \
             being coerced into one that resolves to something else"
        );
    }

    // ── The write path's ordering, which is its safety property ──────────────────────────

    /// An edit that cannot be persisted does not reach memory.
    ///
    /// The order is validate, canonicalize, lock, **persist, then apply**, and this asserts the
    /// half that matters: a failed write returns before anything in memory moves. The reverse
    /// failure is the dangerous one, because an operator who tightened a rule and saw the save
    /// accepted would be shown the state they wanted rather than the state they have, and the
    /// looser policy would come back on restart.
    #[test]
    fn a_policy_that_cannot_be_persisted_does_not_reach_memory() {
        let root = temp_root("unpersistable");
        let policy_path = root.join("policy.json");
        let state = AppState::with_policy_path(
            PolicyConfig {
                audit_path: root.join("audit.jsonl"),
                ..PolicyConfig::default()
            },
            Some(policy_path.clone()),
        )
        .expect("state");

        let before = state.policy();

        // A directory where the policy file should be. The write fails; nothing else does.
        std::fs::remove_file(&policy_path).ok();
        std::fs::create_dir_all(&policy_path).expect("occupy the path with a directory");

        let mut edited = before.clone();
        edited.mcp_allowed_origins = vec!["https://added.example".to_string()];
        let (status, body) = save_policy_update(&state, edited);

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.0["ok"], false);
        assert_eq!(
            state.policy().mcp_allowed_origins,
            before.mcp_allowed_origins,
            "the edit reached memory despite the write failing, so a restart would silently \
             revert a change the operator was told had been accepted"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// An edit that persists reaches both disk and memory, and the file is the policy.
    #[test]
    fn a_persisted_policy_reaches_disk_and_memory_together() {
        let root = temp_root("persisted");
        let policy_path = root.join("policy.json");
        let state = AppState::with_policy_path(
            PolicyConfig {
                audit_path: root.join("audit.jsonl"),
                ..PolicyConfig::default()
            },
            Some(policy_path.clone()),
        )
        .expect("state");

        let mut edited = state.policy();
        edited.mcp_require_client_auth = true;
        edited.mcp_clients = vec![McpClientCredential {
            agent_id: "agent-alpha".into(),
            token_sha256: "a".repeat(64),
            profile: None,
        }];
        let (status, body) = save_policy_update(&state, edited);
        assert_eq!(status, StatusCode::OK, "{}", body.0);

        assert!(state.policy().mcp_require_client_auth);
        let written = std::fs::read_to_string(&policy_path).expect("the policy file exists");
        let reread: PolicyConfig = serde_json::from_str(&written).expect("it parses");
        assert!(
            reread.mcp_require_client_auth,
            "the file on disk does not carry the edit that was accepted"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// With no policy path there is nowhere to persist, and the refusal says so.
    #[test]
    fn an_ephemeral_server_refuses_a_policy_edit_rather_than_accepting_it_into_memory() {
        let state = AppState::new(PolicyConfig::default()).expect("state");
        let (status, body) = save_policy_update(&state, PolicyConfig::default());
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.0["ok"], false);
        assert!(
            body.0["error"]
                .as_str()
                .is_some_and(|text| text.contains("--config")),
            "the refusal must name what to do about it: {}",
            body.0["error"]
        );
    }

    /// An invalid policy is refused before the lock is taken, so a bad edit costs no contention.
    #[test]
    fn an_invalid_policy_is_refused_with_the_reason_and_never_written() {
        let root = temp_root("invalid");
        let policy_path = root.join("policy.json");
        let state = AppState::with_policy_path(
            PolicyConfig {
                audit_path: root.join("audit.jsonl"),
                ..PolicyConfig::default()
            },
            Some(policy_path.clone()),
        )
        .expect("state");

        let mut edited = state.policy();
        edited.mcp_require_client_auth = true;
        edited.mcp_clients = Vec::new(); // required auth with nothing configured

        let (status, body) = save_policy_update(&state, edited);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.0["error"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "a validation refusal must carry the reason"
        );
        assert!(
            !policy_path.exists() || {
                let text = std::fs::read_to_string(&policy_path).unwrap_or_default();
                !text.contains("\"mcp_require_client_auth\": true")
            },
            "an invalid policy was written to disk"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    // ── Reconcile: a policy edit reaches the running gateway ─────────────────────────────

    /// G4-23. A disabled upstream stops being proxied without a restart.
    ///
    /// Providers capture their config by value at construction, so swapping the policy handle
    /// reaches roots, permissions and rules, which are read per request, and never reaches the
    /// upstreams block. Before this path existed, an operator who disabled a compromised upstream
    /// saw `GET /api/policy` report it disabled while the gateway kept proxying to it.
    #[tokio::test]
    async fn an_upstream_removed_from_policy_is_retracted_without_a_restart() {
        let root = temp_root("reconcile");
        let state = AppState::new(PolicyConfig {
            audit_path: root.join("audit.jsonl"),
            ..PolicyConfig::default()
        })
        .expect("state");
        let wiring = state.wiring();

        // `UpstreamConfig::new` rather than a struct literal: core's constructor puts the url
        // inside `UpstreamTransport::Http` and leaves the legacy `url` field empty, which is
        // DEC-007's shape. A literal would have compiled against the base's flat field and
        // produced an upstream with no transport at all.
        let with_upstream = PolicyConfig {
            upstreams: vec![UpstreamConfig::new(
                "example",
                "https://upstream.example/mcp",
            )],
            ..state.policy()
        };
        let added = reconcile_upstreams(&wiring, &with_upstream);
        assert!(
            added
                .iter()
                .any(|change| change.contains("registered 'example'")),
            "expected a registration, got {added:?}"
        );
        assert!(wiring.gateway.get("example").is_some());

        // The edit: the same upstream, disabled. Nothing else changes.
        let mut disabled = with_upstream.clone();
        disabled.upstreams[0].enabled = false;
        let removed = reconcile_upstreams(&wiring, &disabled);
        assert!(
            removed
                .iter()
                .any(|change| change.contains("retracted 'example'")),
            "expected a retraction, got {removed:?}"
        );
        assert!(
            wiring.gateway.get("example").is_none(),
            "a disabled upstream is still live in the registry, which is the fail-open shape on \
             the one surface designed not to be"
        );

        // Idempotence: reconciling the same policy twice changes nothing the second time.
        assert!(
            reconcile_upstreams(&wiring, &disabled).is_empty(),
            "a second reconcile of an unchanged policy reported changes"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
