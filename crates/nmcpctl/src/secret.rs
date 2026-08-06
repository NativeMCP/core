//! The operator write surface for the secret broker, and its read half.
//!
//! NMCP-SPEC-002 SB-13 (set, rotate, quarantine, restore, bind), SB-14 (suspend and resume,
//! the reversible withdrawal pair), SB-12 (migrate), SB-R2 (list: names and metadata, never
//! values, never digests), and section 8 item 2 (the below-floor warning on write). Every
//! function here drives `nmcp-secrets` and prints what it did with enough identity to audit
//! by hand: name, version, prior state, new state. The store's own errors are returned
//! unwrapped, so a refusal prints the governing rule in the store's words (SB-8).
//!
//! ## What "authenticated as local admin" means here
//!
//! SB-13's own definition for headless Linux: the invoking uid owns the store directory and
//! is in the configured operator group. This binary adds no authentication layer of its own;
//! the store and the sealer verify ownership and modes on every open and refuse an exposed
//! file, so an invoker who does not own the store does not get past `open`. On Windows the
//! answer is the platform sealer and its DACL at W3, as the store's documentation records.
//!
//! ## Audit records for these operations
//!
//! A named gap, not an oversight: the store exposes no audit hook, deliberately, because a
//! second hash-chain writer beside `nmcp-audit`'s would break the one-chain property INV-3
//! depends on ('adding one would put a second chain writer beside `nmcp-audit`'s', the
//! store's words). Ring-path secret use is audited since I-034. Chain records for operator
//! writes belong to the daemon wave, where the one process that owns the chain can offer
//! this surface a path to it; until then every mutating subcommand prints the transition it
//! performed, which is the by-hand record.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use nmcp_secrets::{
    BindingSummary, FileSealer, KEY_FILE, KeyBinding, KeyProtection, MigrationReport, SealedStore,
    Sealer, SecretMeta, SecretName, Version,
};

use crate::error::CtlError;
use crate::input::{confirm, read_secret_value};

/// Where a store and its sealer key live for one invocation, already resolved from the
/// global flags and the platform default.
pub(crate) struct StorePaths {
    /// The store directory.
    pub(crate) store_dir: PathBuf,
    /// The sealer key directory (SB-11: separate from the store).
    pub(crate) key_dir: PathBuf,
}

/// Write one line of command output.
fn put(out: &mut dyn Write, line: std::fmt::Arguments<'_>) -> Result<(), CtlError> {
    writeln!(out, "{line}").map_err(|error| CtlError::io("writing output", &error))
}

/// Open an existing store, refusing to conjure one.
///
/// `SealedStore::open` treats an absent directory as an empty store and `FileSealer::open`
/// mints a key on first use, which is right for the daemon and wrong for an operator tool: a
/// mistyped `--store` would silently create an empty store, and a mistyped `--key-dir` would
/// mint a fresh key under which nothing unseals, both reported as mysteries later rather
/// than refusals now. Every subcommand except `init` and `migrate`'s target therefore
/// requires both to exist already.
fn open_existing(paths: &StorePaths) -> Result<SealedStore, CtlError> {
    if !paths.store_dir.is_dir() {
        return Err(CtlError::refusal(format!(
            "no secret store at {}; run `nmcpctl secret init` to create one, or pass --store",
            paths.store_dir.display()
        )));
    }
    let key_file = paths.key_dir.join(KEY_FILE);
    if !key_file.is_file() {
        return Err(CtlError::refusal(format!(
            "no sealer key at {}; opening this store without its own key would mint a fresh key \
             under which nothing unseals. Pass --key-dir if the key lives elsewhere",
            key_file.display()
        )));
    }
    let sealer = FileSealer::open(&paths.key_dir)?;
    Ok(SealedStore::open(&paths.store_dir, Box::new(sealer))?)
}

/// `nmcpctl secret init`: create a store directory and a sealer key, refusing if either
/// exists.
///
/// Never adopts and never overwrites (the INV-1 posture): a pre-existing directory, even an
/// empty one, is somebody's state, and the remedy for wanting a fresh store there is a human
/// action outside this tool.
pub(crate) fn init(paths: &StorePaths, out: &mut dyn Write) -> Result<(), CtlError> {
    for (what, dir) in [
        ("store directory", &paths.store_dir),
        ("sealer key directory", &paths.key_dir),
    ] {
        if dir.symlink_metadata().is_ok() {
            return Err(CtlError::refusal(format!(
                "refusing to initialize: the {what} {} already exists, and this tool never \
                 overwrites; choose another location or move it aside by hand",
                dir.display()
            )));
        }
    }
    let sealer = FileSealer::open(&paths.key_dir)?;
    let protection = match sealer.key_protection() {
        KeyProtection::UnixMode { file, directory } => {
            format!("unix modes {directory:o}/{file:o}, verified on every open")
        }
        KeyProtection::PlatformDefault => "platform default access control (a platform sealer \
                                           replaces the file sealer at deployment)"
            .to_string(),
    };
    let sealer_id = sealer.id();
    let store = SealedStore::open(&paths.store_dir, Box::new(sealer))?;
    put(
        out,
        format_args!("initialized secret store at {}", paths.store_dir.display()),
    )?;
    put(
        out,
        format_args!(
            "  sealer: {sealer_id} (key at {})",
            paths.key_dir.join(KEY_FILE).display()
        ),
    )?;
    put(out, format_args!("  key protection: {protection}"))?;
    put(
        out,
        format_args!(
            "  tripwire arming floor: {} bytes; rotation overlap window: {}s (store defaults)",
            store.tripwire_floor(),
            store.overlap_window().as_secs()
        ),
    )
}

/// The metadata for `name`, when the store holds it.
fn meta_for(store: &SealedStore, name: &SecretName) -> Option<SecretMeta> {
    store.names().into_iter().find(|meta| meta.name == *name)
}

/// The state transitions between two readings of one key, one line per moved version.
fn transition_lines(before: Option<&SecretMeta>, after: &SecretMeta) -> Vec<String> {
    let prior_state = |version: Version| {
        before.and_then(|meta| {
            meta.versions
                .iter()
                .find(|entry| entry.version == version)
                .map(|entry| entry.state)
        })
    };
    after
        .versions
        .iter()
        .filter_map(|entry| match prior_state(entry.version) {
            Some(previous) if previous != entry.state => Some(format!(
                "  version {}: {previous} -> {}",
                entry.version, entry.state
            )),
            _ => None,
        })
        .collect()
}

/// Warn on the below-floor fact for the version just written (section 8 item 2): the
/// operator learns detection is off for that key now, at creation, not after a leak the
/// tripwire would not have caught.
fn warn_if_below_floor(
    store: &SealedStore,
    meta: Option<&SecretMeta>,
    version: Version,
    err: &mut dyn Write,
) -> Result<(), CtlError> {
    let below = meta.is_some_and(|meta| {
        meta.versions
            .iter()
            .any(|entry| entry.version == version && entry.below_tripwire_floor)
    });
    if below {
        writeln!(
            err,
            "warning: the value is below the tripwire arming floor of {} bytes, so exfiltration \
             detection is off for this key (NMCP-SPEC-002 SB-9); it still stores and resolves",
            store.tripwire_floor()
        )
        .map_err(|error| CtlError::io("writing the warning", &error))?;
    }
    Ok(())
}

/// `nmcpctl secret set <name>`: store the first version, value from stdin or the prompt.
pub(crate) fn set(
    paths: &StorePaths,
    name_text: &str,
    input: &mut dyn BufRead,
    input_is_tty: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CtlError> {
    let name = SecretName::parse(name_text)?;
    let store = open_existing(paths)?;
    let value = read_secret_value(name.as_str(), input, input_is_tty)?;
    let version = store.set(&name, value)?;
    let after = meta_for(&store, &name);
    put(
        out,
        format_args!(
            "stored secret {name}: version {version} active (new secret; sealed by {})",
            store.sealer_id()
        ),
    )?;
    warn_if_below_floor(&store, after.as_ref(), version, err)
}

/// `nmcpctl secret rotate <name>`: store a new version and say when the prior one retires.
pub(crate) fn rotate(
    paths: &StorePaths,
    name_text: &str,
    input: &mut dyn BufRead,
    input_is_tty: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CtlError> {
    let name = SecretName::parse(name_text)?;
    let store = open_existing(paths)?;
    let before = meta_for(&store, &name);
    let value = read_secret_value(name.as_str(), input, input_is_tty)?;
    let version = store.rotate(&name, value)?;
    let after = meta_for(&store, &name);
    let window_secs = store.overlap_window().as_secs();
    put(
        out,
        format_args!(
            "rotated secret {name}: version {version} active (sealed by {})",
            store.sealer_id()
        ),
    )?;
    // The overlap reminder (SB-14): what the prior version is doing and until when. Read
    // from the store's own record rather than recomputed, so the printed instant is the one
    // the sweep will honour.
    if let Some(prior_version) = before.as_ref().and_then(|meta| meta.current_version)
        && let Some(prior) = after.as_ref().and_then(|meta| {
            meta.versions
                .iter()
                .find(|entry| entry.version == prior_version)
        })
    {
        match prior.superseded_at_unix_ms {
            Some(at) if window_secs > 0 => put(
                out,
                format_args!(
                    "  version {prior_version}: active -> {}; resolvable until unix-ms {} \
                     (overlap window {window_secs}s)",
                    prior.state,
                    at.saturating_add(window_secs.saturating_mul(1_000))
                ),
            )?,
            _ => put(
                out,
                format_args!(
                    "  version {prior_version}: active -> {} (overlap window {window_secs}s: \
                     hard cutover)",
                    prior.state
                ),
            )?,
        }
    }
    warn_if_below_floor(&store, after.as_ref(), version, err)
}

/// One FSM write (quarantine, restore, suspend, resume), reported as transitions.
fn fsm_write(
    paths: &StorePaths,
    name_text: &str,
    verb: &str,
    note: &str,
    op: impl FnOnce(&SealedStore, &SecretName) -> Result<(), nmcp_secrets::StoreError>,
    out: &mut dyn Write,
) -> Result<(), CtlError> {
    let name = SecretName::parse(name_text)?;
    let store = open_existing(paths)?;
    let before = meta_for(&store, &name);
    op(&store, &name)?;
    let Some(after) = meta_for(&store, &name) else {
        // The operation succeeded, so the key exists; this arm is unreachable and still
        // prints the truth if it ever fires.
        return put(out, format_args!("{verb} secret {name}"));
    };
    put(out, format_args!("{verb} secret {name}{note}:"))?;
    for line in transition_lines(before.as_ref(), &after) {
        put(out, format_args!("{line}"))?;
    }
    Ok(())
}

/// `nmcpctl secret quarantine <name>`: immediate revocation, FSM-backed, reversible.
pub(crate) fn quarantine(
    paths: &StorePaths,
    name_text: &str,
    out: &mut dyn Write,
) -> Result<(), CtlError> {
    fsm_write(
        paths,
        name_text,
        "quarantined",
        " (revocation is immediate; in-flight calls fail closed)",
        SealedStore::quarantine,
        out,
    )
}

/// `nmcpctl secret restore <name>`: reverse a quarantine, each version back where it was.
pub(crate) fn restore(
    paths: &StorePaths,
    name_text: &str,
    out: &mut dyn Write,
) -> Result<(), CtlError> {
    fsm_write(paths, name_text, "restored", "", SealedStore::restore, out)
}

/// `nmcpctl secret suspend <name>`: reversible withdrawal through `Active -> Suspended`.
pub(crate) fn suspend(
    paths: &StorePaths,
    name_text: &str,
    out: &mut dyn Write,
) -> Result<(), CtlError> {
    fsm_write(
        paths,
        name_text,
        "suspended",
        " (reversible; `nmcpctl secret resume` returns it to service)",
        SealedStore::suspend,
        out,
    )
}

/// `nmcpctl secret resume <name>`: the reverse edge, `Suspended -> Active`, operator only.
pub(crate) fn resume(
    paths: &StorePaths,
    name_text: &str,
    out: &mut dyn Write,
) -> Result<(), CtlError> {
    fsm_write(paths, name_text, "resumed", "", SealedStore::resume, out)
}

/// One line summarizing a binding's shape: sizes, expiry, budget spent and remaining, and
/// the on-trip action. No contents and no material (SB-R2).
fn summary_line(summary: &BindingSummary) -> String {
    let expiry = summary
        .expires_at_unix_ms
        .map_or_else(|| "none".to_string(), |at| format!("unix-ms {at}"));
    let budget = summary.budget.map_or_else(
        || "unmetered".to_string(),
        |budget| {
            if summary.used_in_open_window == 0 {
                // No window is open (the boundary belongs to the closed side), so the whole
                // budget is available to whatever use opens the next one.
                format!(
                    "{} per {}s window, none used in an open window",
                    budget.uses, budget.window_secs
                )
            } else {
                format!(
                    "{} used of {}, {} remaining in the open window ({}s window)",
                    summary.used_in_open_window,
                    budget.uses,
                    budget.uses.saturating_sub(summary.used_in_open_window),
                    budget.window_secs
                )
            }
        },
    );
    format!(
        "tools={} programs={} roots={} callers={}; expiry={expiry}; budget={budget}; on-trip={}",
        summary.tools, summary.programs, summary.roots, summary.callers, summary.on_trip
    )
}

/// `nmcpctl secret bind <name>`: binding from a JSON file or stdin, echoed back and
/// confirmed before anything is written.
///
/// A misread allowlist is a policy change, so the parsed object is printed exactly as it
/// will be persisted and the write needs `--yes` or an interactive yes. A binding that
/// arrived on stdin cannot also prompt on it, so the piped path requires `--yes` and says
/// so.
pub(crate) fn bind(
    paths: &StorePaths,
    name_text: &str,
    file: Option<&Path>,
    yes: bool,
    input: &mut dyn BufRead,
    input_is_tty: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CtlError> {
    let name = SecretName::parse(name_text)?;
    let store = open_existing(paths)?;
    let (text, from_stdin) = if let Some(path) = file {
        let text = std::fs::read_to_string(path).map_err(|error| {
            CtlError::io(
                format!("reading the binding file {}", path.display()),
                &error,
            )
        })?;
        (text, false)
    } else {
        let mut text = String::new();
        input
            .read_to_string(&mut text)
            .map_err(|error| CtlError::io("reading the binding from standard input", &error))?;
        (text, true)
    };
    let binding: KeyBinding = serde_json::from_str(&text).map_err(|error| {
        CtlError::refusal(format!(
            "the binding does not parse as a KeyBinding and nothing was written: {error}"
        ))
    })?;
    let echo = serde_json::to_string_pretty(&binding).map_err(|error| {
        CtlError::refusal(format!(
            "the parsed binding could not be re-encoded: {error}"
        ))
    })?;
    put(
        out,
        format_args!("binding for secret {name}, as parsed (exactly this will be written):"),
    )?;
    put(out, format_args!("{echo}"))?;
    for (label, len) in [
        ("tools", binding.tools.len()),
        ("programs", binding.programs.len()),
        ("roots", binding.roots.len()),
        ("callers", binding.callers.len()),
    ] {
        if len == 0 {
            put(
                out,
                format_args!("  note: the {label} allowlist is empty and admits none (SB-6)"),
            )?;
        }
    }
    if !yes {
        if from_stdin {
            return Err(CtlError::refusal(
                "confirmation required: the binding arrived on standard input, so there is no \
                 way to prompt; check the echo above and re-run with --yes",
            ));
        }
        if !input_is_tty {
            return Err(CtlError::refusal(
                "confirmation required: standard input is not a terminal; check the echo above \
                 and re-run with --yes",
            ));
        }
        if !confirm(
            &format!("write this binding for secret {name}?"),
            input,
            err,
        )? {
            return Err(CtlError::refusal("binding not written: declined"));
        }
    }
    let prior = store.binding_summary(&name)?;
    store.bind(&name, binding)?;
    let written = store.binding_summary(&name)?.ok_or_else(|| {
        // `bind` just succeeded, so the summary exists; unreachable, and truthful if not.
        CtlError::refusal(format!("the binding for {name} did not read back"))
    })?;
    put(
        out,
        format_args!("bound secret {name}: {}", summary_line(&written)),
    )?;
    match prior {
        Some(previous) => put(
            out,
            format_args!(
                "  replaces the prior binding ({}); the budget's spend state is reset",
                summary_line(&previous)
            ),
        ),
        None => put(
            out,
            format_args!("  first binding for this key (it admitted nothing until now)"),
        ),
    }
}

/// `nmcpctl secret list`: names, per-version states, binding summary, below-floor flag.
///
/// Never values and never digests (SB-R2). Reserved-namespace entries cannot appear because
/// the store's list is typed on `SecretName`, whose parser refuses them; nothing is
/// re-filtered here. Damaged documents are reported at the end from the store's own
/// unreadable record, because a list that silently showed one key fewer is how a missing
/// credential goes unnoticed.
pub(crate) fn list(paths: &StorePaths, out: &mut dyn Write) -> Result<(), CtlError> {
    let store = open_existing(paths)?;
    let metas = store.names();
    let unreadable = store.unreadable();
    put(
        out,
        format_args!(
            "secrets at {} (sealer {})",
            paths.store_dir.display(),
            store.sealer_id()
        ),
    )?;
    if metas.is_empty() && unreadable.is_empty() {
        put(out, format_args!("no secrets stored"))?;
    }
    for meta in &metas {
        let current = meta.current_version.map_or_else(
            || "none in service".to_string(),
            |version| format!("current v{version}"),
        );
        let floor_flag = if meta.below_tripwire_floor {
            "below-floor=YES (detection is off for this key)"
        } else {
            "below-floor=no"
        };
        put(
            out,
            format_args!(
                "{}: {}, {current}, created unix-ms {}, {floor_flag}",
                meta.name, meta.state, meta.created_at_unix_ms
            ),
        )?;
        for version in &meta.versions {
            let superseded = version
                .superseded_at_unix_ms
                .map_or_else(String::new, |at| format!(", superseded unix-ms {at}"));
            let below = if version.below_tripwire_floor {
                ", below-floor"
            } else {
                ""
            };
            put(
                out,
                format_args!(
                    "  v{}: {} (created unix-ms {}{superseded}){below}",
                    version.version, version.state, version.created_at_unix_ms
                ),
            )?;
        }
        match store.binding_summary(&meta.name)? {
            Some(summary) => put(out, format_args!("  binding: {}", summary_line(&summary)))?,
            None => put(
                out,
                format_args!("  binding: none (a key with no binding is usable by nothing)"),
            )?,
        }
    }
    if !unreadable.is_empty() {
        put(
            out,
            format_args!(
                "unreadable documents, isolated and not listed above (move aside by hand to \
                 recover; nothing overwrites them):"
            ),
        )?;
        for entry in &unreadable {
            put(out, format_args!("  {}: {}", entry.file, entry.reason))?;
        }
    }
    Ok(())
}

/// `nmcpctl secret migrate`: reseal every blob the source sealer holds under a target file
/// sealer, retaining every prior blob.
///
/// What the store supports today is file-sealer-to-file-sealer, which is key rotation of the
/// store itself; the v1-entropy half of SB-12, unsealing the base generation's blobs, needs
/// the platform sealer and is Windows-only, landing at W3 where its fixture tests live. The
/// source is asserted by identifier exactly as `SealedStore::migrate`'s frozen signature
/// takes it, and the store refuses a mismatch with its own error. The target is a key
/// directory, because a file sealer's identity contains a deployment component that is
/// generated with the key and cannot be known before the key exists; `--to` asserts it
/// after opening, for the operator who already knows which key they mean.
pub(crate) fn migrate(
    paths: &StorePaths,
    from_text: &str,
    to_key_dir: &Path,
    to_assertion: Option<&str>,
    out: &mut dyn Write,
) -> Result<(), CtlError> {
    let store = open_existing(paths)?;
    let target = FileSealer::open(to_key_dir)?;
    let target_id = target.id();
    if let Some(expected) = to_assertion
        && expected != target_id.as_str()
    {
        return Err(CtlError::refusal(format!(
            "the sealer at {} is {target_id}, not the asserted {expected}; nothing was migrated",
            to_key_dir.display()
        )));
    }
    let from = sealer_id_from_text(from_text)?;
    let report = store.migrate(from, &target)?;
    print_migration(paths, &report, &target_id, to_key_dir, out)
}

/// A [`nmcp_secrets::SealerId`] from its canonical text: the identifier's encoding is its
/// own string, and serde is the type's public constructor from one.
fn sealer_id_from_text(text: &str) -> Result<nmcp_secrets::SealerId, CtlError> {
    serde_json::from_value(serde_json::Value::String(text.to_string())).map_err(|error| {
        CtlError::Usage {
            reason: format!("the sealer id could not be read: {error}"),
        }
    })
}

/// The migration report, printed name by name so an operator can audit it by hand.
fn print_migration(
    paths: &StorePaths,
    report: &MigrationReport,
    target_id: &nmcp_secrets::SealerId,
    to_key_dir: &Path,
    out: &mut dyn Write,
) -> Result<(), CtlError> {
    put(
        out,
        format_args!(
            "migrated store at {} to sealer {target_id} (key at {})",
            paths.store_dir.display(),
            to_key_dir.display()
        ),
    )?;
    put(
        out,
        format_args!("  resealed: {} version(s)", report.migrated.len()),
    )?;
    for entry in &report.migrated {
        put(out, format_args!("    {} v{}", entry.name, entry.version))?;
    }
    let (at_target, elsewhere): (Vec<_>, Vec<_>) = report
        .skipped
        .iter()
        .partition(|entry| entry.already_at_target);
    put(
        out,
        format_args!(
            "  skipped, already at the target: {} version(s)",
            at_target.len()
        ),
    )?;
    for entry in at_target {
        put(out, format_args!("    {} v{}", entry.name, entry.version))?;
    }
    put(
        out,
        format_args!(
            "  skipped, no blob under the source: {} version(s)",
            elsewhere.len()
        ),
    )?;
    for entry in elsewhere {
        let held_by: Vec<&str> = entry
            .sealed_by
            .iter()
            .map(nmcp_secrets::SealerId::as_str)
            .collect();
        put(
            out,
            format_args!(
                "    {} v{} (held by: {})",
                entry.name,
                entry.version,
                held_by.join(", ")
            ),
        )?;
    }
    put(
        out,
        format_args!(
            "  failed, left exactly as they were: {} version(s)",
            report.failed.len()
        ),
    )?;
    for entry in &report.failed {
        put(out, format_args!("    {} v{}", entry.name, entry.version))?;
    }
    put(
        out,
        format_args!(
            "every prior blob is retained and the store still opens under the old sealer \
             (INV-1). To adopt the target, pass --key-dir {} from now on, and keep the old \
             key directory until every key has resolved once under the target",
            to_key_dir.display()
        ),
    )
}
