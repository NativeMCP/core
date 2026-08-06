//! Container transport: the gateway runs an MCP server inside a container and speaks
//! JSON-RPC over the runtime CLI's pipes.
//!
//! Mechanically this is [`crate::stdio`] with a different command line, and that is the
//! design rather than a shortcut. The process this gateway starts is the container runtime
//! CLI, the CLI relays the container's standard input and output, and everything downstream
//! of the spawn is the same code path an ordinary stdio upstream takes. Nothing here
//! re-implements a transport, and nothing here federates to another gateway: per DEC-007 a
//! container desktop product is not a dependency of this gateway, it is a container runtime
//! that gets used when it happens to be present.
//!
//! ## Two things this module is careful about
//!
//! **Secrets never reach a command line.** `--env KEY` is the pass-through form: it tells the
//! runtime to forward a variable it already holds, rather than `--env KEY=VALUE`, which would
//! put the value in the runtime's own process arguments, in the runtime's own inspect
//! output, and in the audit record this gateway writes for every spawn. The values ride in
//! the CLI child's environment, which [`crate::stdio`] already builds from nothing rather
//! than inheriting.
//!
//! **The image is pinned by digest.** Policy validation refuses a tag, for the same reason
//! `tools_sha256` exists on an HTTP upstream: a mutable tag is an unpinned dependency on
//! somebody else's registry, and pinning the tool list of an image that can change underneath
//! you pins nothing.

use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// The runtime used when a container upstream does not name one.
pub const DEFAULT_RUNTIME: &str = "docker";

/// How long to wait for the runtime to answer `version`.
///
/// Generous, because on Windows the first runtime CLI call after a cold boot can wait on the
/// engine coming up, and reporting a starting runtime as a missing one would be a lie that
/// clears itself a minute later.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// The runtime a container upstream should be started with.
#[must_use]
pub fn runtime_or_default(runtime: Option<&str>) -> String {
    match runtime {
        Some(r) if !r.trim().is_empty() => r.to_string(),
        _ => DEFAULT_RUNTIME.to_string(),
    }
}

/// Build the program and arguments that start one container with its stdio attached.
///
/// `env_keys` are forwarded by name only. See the module header.
pub fn command_line<'a>(
    image: &str,
    args: &[String],
    env_keys: impl Iterator<Item = &'a String>,
    runtime: &str,
) -> (String, Vec<String>) {
    let mut composed = vec![
        "run".to_string(),
        // The container is this provider's, and it lives exactly as long as the link does.
        "--rm".to_string(),
        // Stdin stays open, which is the whole transport. Deliberately no --tty: a pseudo
        // terminal would rewrite the byte stream that carries the JSON-RPC framing.
        "--interactive".to_string(),
    ];
    for key in env_keys {
        composed.push("--env".to_string());
        composed.push(key.clone());
    }
    composed.push(image.to_string());
    composed.extend(args.iter().cloned());
    (runtime.to_string(), composed)
}

/// Ask the runtime whether it is actually usable, and say why when it is not.
///
/// Two failures look identical from a caller's seat and should not: a runtime that is not
/// installed, and a runtime whose engine is not running. `version` catches both, because the
/// CLI contacts the engine to answer it, and both are reported as this upstream's runtime
/// being unavailable rather than as the upstream being offline. The distinction is the point
/// of the check: an operator who reads "offline" goes looking at the server, and an operator
/// who reads "the runtime is not available" goes and starts it.
///
/// # Errors
///
/// A one-line reason naming the runtime, so the operator knows what to install or start.
pub async fn probe(runtime: &str) -> Result<(), String> {
    let mut command = Command::new(runtime);
    command
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    crate::stdio::apply_isolated_env(&mut command);
    #[cfg(windows)]
    command.creation_flags(crate::stdio::CREATE_NO_WINDOW);

    let output = match timeout(PROBE_TIMEOUT, command.output()).await {
        Err(_) => {
            return Err(format!(
                "'{runtime} version' did not answer within {}s",
                PROBE_TIMEOUT.as_secs()
            ));
        }
        Ok(Err(e)) => return Err(format!("could not run '{runtime}': {e}")),
        Ok(Ok(output)) => output,
    };
    if output.status.success() {
        return Ok(());
    }
    let detail = first_line(&output.stderr)
        .or_else(|| first_line(&output.stdout))
        .unwrap_or_else(|| "no output".to_string());
    Err(format!("'{runtime} version' failed: {detail}"))
}

/// The first non-empty line of a captured stream, for a one-line failure reason.
fn first_line(bytes: &[u8]) -> Option<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(String::from)
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
    use super::*;
    use crate::{UpstreamProvider, UpstreamStatus};
    use nmcp_audit::AuditSink;
    use nmcp_policy::{UpstreamConfig, UpstreamTransport};
    use nmcp_schema::{
        HeldAuthority, ToolAuthority, ToolEffect, ToolProvider, ToolReach, authorize,
    };
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::time::Duration;

    /// A digest-pinned image. Never pulled: the stand-in runtime below ignores it, and that
    /// it is handed over unchanged is what gets asserted.
    const PINNED_IMAGE: &str = "ghcr.io/example/mcp@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn test_audit() -> AuditSink {
        AuditSink::open(std::env::temp_dir().join(format!(
            "nmcp-gateway-container-{}.jsonl",
            uuid::Uuid::new_v4()
        )))
        .expect("audit sink")
    }

    fn container_upstream(runtime: &str, env: BTreeMap<String, String>) -> UpstreamConfig {
        let mut upstream = UpstreamConfig::new("boxed", "");
        upstream.enabled = true;
        upstream.transport = Some(UpstreamTransport::Container {
            image: PINNED_IMAGE.into(),
            args: Vec::new(),
            env,
            env_secrets: BTreeMap::new(),
            runtime: Some(runtime.to_string()),
        });
        upstream
    }

    async fn wait_for_status(provider: &Arc<UpstreamProvider>, want: &str) -> UpstreamStatus {
        for _ in 0..300 {
            let status = provider.status();
            if status.as_str() == want {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!(
            "upstream never reached '{want}'; last status was '{}' ({:?})",
            provider.status().as_str(),
            provider.status().detail()
        );
    }

    #[test]
    fn the_command_line_forwards_environment_by_name_and_never_by_value() {
        let env = ["EXAMPLE_TOKEN".to_string(), "REGION".to_string()];
        let (program, argv) = command_line(
            "ghcr.io/example/server@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            &["--verbose".to_string()],
            env.iter(),
            "docker",
        );

        assert_eq!(program, "docker");
        assert_eq!(
            argv,
            vec![
                "run",
                "--rm",
                "--interactive",
                "--env",
                "EXAMPLE_TOKEN",
                "--env",
                "REGION",
                "ghcr.io/example/server@sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "--verbose",
            ]
        );

        // The property that matters: a value can never appear here, because no value was
        // ever passed to this function. The keys are the whole interface.
        assert!(
            !argv.iter().any(|a| a.contains('=')),
            "an --env KEY=VALUE pair would put a secret in the audited command line: {argv:?}"
        );
    }

    #[test]
    fn a_container_upstream_that_names_no_runtime_gets_the_default() {
        assert_eq!(runtime_or_default(None), "docker");
        assert_eq!(runtime_or_default(Some("   ")), "docker");
        assert_eq!(runtime_or_default(Some("podman")), "podman");
    }

    #[tokio::test]
    async fn a_runtime_that_is_not_installed_is_named_in_the_failure() {
        let err = probe("nmcp-no-such-container-runtime")
            .await
            .expect_err("a runtime that does not exist must not probe clean");
        assert!(
            err.contains("nmcp-no-such-container-runtime"),
            "the reason must name the runtime so an operator knows what to install: {err}"
        );
    }

    /// The runtime hop, driven against a real process.
    ///
    /// The stand-in answers `version` so the probe is clean, records the argv it was handed,
    /// and exits. That covers what is this codebase's claim to make: the command line
    /// composed, the environment discipline around it, and that both are delivered to a
    /// process rather than only to a string builder. Deliberately it does not relay a
    /// session, because a batch stand-in relaying stdio ends up testing the Windows shell
    /// chain rather than this module, and the base learned that the hard way: it passed
    /// locally and hung on a CI runner. The session over an identical `StdioLink` is already
    /// driven end to end by
    /// `stdio::tests::a_real_child_process_completes_the_handshake_and_answers_tools_list`,
    /// and the container path builds that same link.
    ///
    /// A real container engine is not here either. What a daemon would add is proof that the
    /// engine honours its own flags, which is not this codebase's claim and would put an
    /// engine in the critical path of every CI run.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_container_upstream_hands_the_composed_command_line_to_the_runtime() {
        let tmp = std::env::temp_dir();
        let tag = uuid::Uuid::new_v4();
        let runtime = tmp.join(format!("nmcp-container-runtime-{tag}.cmd"));
        let log = tmp.join(format!("nmcp-container-argv-{tag}.txt"));

        std::fs::write(
            &runtime,
            format!(
                "@echo off\r\n\
                 if \"%~1\"==\"version\" (\r\n\
                 echo stand-in runtime 0.0\r\n\
                 exit /b 0\r\n\
                 )\r\n\
                 > \"{log}\" echo argv: %*\r\n\
                 >> \"{log}\" echo forwarded: %NMCP_TEST_FORWARDED%\r\n\
                 exit /b 0\r\n",
                log = log.display(),
            ),
        )
        .expect("write stand-in runtime");

        let mut env = BTreeMap::new();
        env.insert(
            "NMCP_TEST_FORWARDED".to_string(),
            "sentinel-never-on-a-command-line".to_string(),
        );
        let config = container_upstream(runtime.to_str().expect("runtime path"), env);

        // Admission first. A runtime that works against a configuration policy would reject
        // is worth nothing.
        let mut policy = nmcp_policy::PolicyConfig::default();
        let mut admitted = config.clone();
        admitted.required_permission = Some(nmcp_policy::Permission::UpstreamCall);
        policy.upstreams.push(admitted);
        policy
            .validate_semantics()
            .expect("a digest-pinned container upstream must be admissible");

        let provider =
            UpstreamProvider::new(config, test_audit(), None, None).expect("provider construction");

        // The stand-in exits without speaking MCP, so the upstream settles offline, and that
        // is the other half of the classification worth pinning: the runtime answered, so
        // this is a broken server and must not be reported as a missing runtime.
        let status = wait_for_status(&provider, "offline").await;
        assert!(
            matches!(status, UpstreamStatus::Offline { .. }),
            "a runtime that answers version must not be reported as unavailable"
        );

        let recorded = std::fs::read_to_string(&log).expect("the runtime must have been started");
        // Quotes stripped: how arguments are escaped for a batch stand-in is an artefact of
        // the stand-in, not of what this module composed.
        let argv = recorded
            .lines()
            .find(|l| l.starts_with("argv:"))
            .expect("the runtime must have recorded its argv")
            .replace('"', "");
        assert!(
            argv.contains("run --rm --interactive --env NMCP_TEST_FORWARDED")
                && argv.contains(PINNED_IMAGE),
            "the runtime did not receive the container command line: {argv}"
        );
        // The property the module header claims, checked against the process that ran: the
        // value reached the runtime's environment and never its arguments.
        assert!(
            recorded.contains("forwarded: sentinel-never-on-a-command-line"),
            "the environment was not forwarded to the runtime: {recorded}"
        );
        assert!(
            !argv.contains("sentinel-never"),
            "a secret reached the audited command line: {argv}"
        );

        provider.shutdown();
        let _ = std::fs::remove_file(&runtime);
        let _ = std::fs::remove_file(&log);
    }

    /// The other half of the acceptance. A runtime that is not installed must not read as the
    /// server being offline, because those two send an operator to different places.
    #[tokio::test]
    async fn a_missing_runtime_is_reported_as_its_own_status_and_not_as_offline() {
        let config = container_upstream("nmcp-no-such-container-runtime", BTreeMap::new());
        let provider =
            UpstreamProvider::new(config, test_audit(), None, None).expect("provider construction");

        let status = wait_for_status(&provider, "runtime_unavailable").await;
        let UpstreamStatus::RuntimeUnavailable { runtime, reason } = status else {
            panic!("wait_for_status returned the wrong variant");
        };
        assert_eq!(runtime, "nmcp-no-such-container-runtime");
        assert!(
            reason.contains("nmcp-no-such-container-runtime"),
            "the detail must name the runtime to install or start: {reason}"
        );

        // And the call path says the same thing rather than a generic failure. The proof of
        // authorization is minted the only way one can be: by asking.
        let ctx = nmcp_schema::CallContext::new(Some("container-test".to_string()));
        let granted = authorize(
            &ToolAuthority {
                permission: None,
                path_args: Vec::new(),
                grants: Vec::new(),
                effect: ToolEffect::Mutate,
                reach: ToolReach::Remote,
            },
            &HeldAuthority {
                roots: Vec::new(),
                grants: BTreeSet::new(),
                agent_id: None,
            },
            &json!({}),
        )
        .expect("an upstream declaration authorizes holding nothing");
        let result = provider.call("anything", json!({}), &ctx, &granted).await;
        assert!(result.is_error);
        let text = result.content[0]["text"].as_str().unwrap_or_default();
        assert!(
            text.contains("nmcp-no-such-container-runtime"),
            "the caller must be told what is missing: {text}"
        );

        provider.shutdown();
    }
}
