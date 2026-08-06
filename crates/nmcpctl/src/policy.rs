//! Policy tools ported from the base ctl: scaffold, validate, and the verdict diff.
//!
//! Three deviations from the base surface, each deliberate and none behavioural for a
//! command that succeeds:
//!
//! - The base's top-level `init` and `validate` live under `policy` here, beside `diff`
//!   where the base already grouped its third policy command: `secret init` exists on this
//!   surface too, and two commands named `init` doing unrelated things is the kind of
//!   footgun an operator tool does not ship.
//! - `init` refuses an existing output file. The base overwrote in place, and overwriting a
//!   policy an operator has edited is destroying their work (the INV-1 posture applied to
//!   this tool's own writes).
//! - `diff --from` is required. The base defaulted it to the daemon's deployed policy path,
//!   which is a location the base daemon defines and this workspace does not; inventing one
//!   here would be configuration nobody declared.

use std::io::Write;
use std::path::Path;

use nmcp_policy::PolicyConfig;

use crate::error::CtlError;

/// Write one line of command output.
fn put(out: &mut dyn Write, line: std::fmt::Arguments<'_>) -> Result<(), CtlError> {
    writeln!(out, "{line}").map_err(|error| CtlError::io("writing output", &error))
}

/// `nmcpctl policy init`: write the default policy as a starting point.
pub(crate) fn init(output: &Path, out: &mut dyn Write) -> Result<(), CtlError> {
    if output.symlink_metadata().is_ok() {
        return Err(CtlError::refusal(format!(
            "refusing to write: {} already exists, and overwriting a policy an operator may \
             have edited is not this tool's call; move it aside by hand or choose another path",
            output.display()
        )));
    }
    let json = serde_json::to_string_pretty(&PolicyConfig::default()).map_err(|error| {
        CtlError::refusal(format!("the default policy could not be encoded: {error}"))
    })?;
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| CtlError::io(format!("creating {}", parent.display()), &error))?;
    }
    std::fs::write(output, json)
        .map_err(|error| CtlError::io(format!("writing {}", output.display()), &error))?;
    put(
        out,
        format_args!("wrote the default policy to {}", output.display()),
    )
}

/// `nmcpctl policy validate`: load a policy through the same loader the daemon uses.
///
/// A policy this refuses is one the service would refuse too, rather than one only this
/// tool dislikes (the base ctl's own words, still true of `PolicyConfig::from_json_str`).
pub(crate) fn validate(config: &Path, out: &mut dyn Write) -> Result<(), CtlError> {
    let text = std::fs::read_to_string(config)
        .map_err(|error| CtlError::io(format!("reading {}", config.display()), &error))?;
    let policy = PolicyConfig::from_json_str(&text)?;
    put(
        out,
        format_args!(
            "valid policy: {} roots; admin={}; mcp={}",
            policy.roots.len(),
            policy.admin_bind,
            policy.mcp_bind
        ),
    )
}

/// `nmcpctl policy diff`: exactly which calls a policy change newly allows or denies.
///
/// Ported whole: the planner is `nmcp-policy`'s and answers the question a textual diff
/// cannot. `--fail-on-change` turns any verdict change into a refusal, for use as a gate in
/// a pipeline that should stop on an unreviewed widening.
pub(crate) fn diff(
    from: &Path,
    to: &Path,
    json: bool,
    fail_on_change: bool,
    out: &mut dyn Write,
) -> Result<(), CtlError> {
    let before = PolicyConfig::from_json_str(
        &std::fs::read_to_string(from)
            .map_err(|error| CtlError::io(format!("reading {}", from.display()), &error))?,
    )?;
    let after = PolicyConfig::from_json_str(
        &std::fs::read_to_string(to)
            .map_err(|error| CtlError::io(format!("reading {}", to.display()), &error))?,
    )?;
    let plan = nmcp_policy::diff::plan(&before, &after);
    if json {
        let rendered = serde_json::to_string_pretty(&plan).map_err(|error| {
            CtlError::refusal(format!("the plan could not be encoded: {error}"))
        })?;
        put(out, format_args!("{rendered}"))?;
    } else {
        write!(out, "{}", plan.render()).map_err(|error| CtlError::io("writing output", &error))?;
    }
    if fail_on_change && !plan.is_verdict_neutral() {
        return Err(CtlError::refusal(format!(
            "policy change alters {} verdicts and --fail-on-change was set",
            plan.newly_allowed.len()
                + plan.newly_denied.len()
                + plan.caller_tool_changes.len()
                + plan.reachability_changes.len()
        )));
    }
    Ok(())
}
