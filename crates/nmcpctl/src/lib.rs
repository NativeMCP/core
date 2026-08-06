//! `nmcpctl`
//!
//! The NativeMCP operator command surface: NMCP-SPEC-001 R-5, named per NDEC-6, landing
//! I-037 and I-038 together. One local binary, operator-run. Nothing here is reachable from
//! an agent, an MCP tool or a network listener, which is NMCP-SPEC-002 SB-13's boundary
//! expressed as architecture rather than as a permission: the operations below exist only on
//! this surface, and there is no policy knob that grants an agent any of them.
//!
//! The governance invariants in `docs/GOVERNANCE.md` are normative for every item here.
//!
//! ## The secret surface (I-037; NMCP-SPEC-002, RATIFIED v1.1)
//!
//! `nmcpctl secret` is the write half SB-13 names, the reversal pair SB-14 declares, and the
//! read half SB-R2 permits: `init`, `set`, `rotate`, `quarantine`, `restore`, `suspend`,
//! `resume`, `bind`, `list` and `migrate`, all driving `nmcp-secrets` and printing name,
//! version, prior state and new state so an operator can audit each write by hand.
//!
//! A value arrives over piped standard input or over a no-echo terminal prompt
//! ([`rpassword`], which reads from the controlling terminal with echo disabled), and never
//! as an argument or an environment variable. That is structural, not procedural: the
//! command definition carries no value argument and reads no environment variable, so the
//! argv modality is unrepresentable, exactly as SB-A2 removes it from injection; the test
//! suite asserts both against the parsed command tree. `secret set` warns when the value is
//! below the store's tripwire arming floor, so the operator learns detection is off for that
//! key at the moment they create it (NMCP-SPEC-002 section 8 item 2).
//!
//! `secret migrate` drives `SealedStore::migrate`, which today is file sealer to file
//! sealer: key rotation of the store itself, every prior blob retained. The other half of
//! SB-12, unsealing the base generation's blobs under their v1 entropy, needs the platform
//! sealer that reads them and is Windows-only; it lands at W3 with that sealer, where the
//! SB-12 fixture tests live. Stated here so nobody reads this command as the whole of SB-12.
//!
//! ## Port provenance (I-038)
//!
//! Ported from the base workspace's operator CLI, selectively, the way `xtask` was ported at
//! I-022: commands that operate surfaces this workspace actually has, gaps named for the
//! rest. The base binary carried eight top-level commands; the disposition of each:
//!
//! - **`policy diff`**: ported whole. The planner is `nmcp-policy`'s and core has it.
//! - **`init` and `validate`** (top level in the base): ported, regrouped under `policy`
//!   beside `diff`. `secret init` exists on this surface, and two unrelated `init`s is a
//!   footgun; the policy module documents this and the other two deviations (refusing to
//!   overwrite an existing output, and dropping the base's default paths, which pointed
//!   into the base daemon's deployment tree that this workspace does not define).
//! - **`audit verify`**: ported whole; `--path` required for the same default-path reason.
//! - **`rotate-signing-key`**: ported under `abac`. The surface exists in core
//!   (`nmcp-abac` verifies manifest signatures against an operator-held public key file);
//!   the module documents the two deviations (the prior key is retained, not overwritten,
//!   and the completion note is platform-neutral).
//! - **`doctor`**: a named gap. It probes the daemon's admin HTTP listener, and this
//!   workspace serves no HTTP listener at all; the daemon and its admin surface belong to
//!   the platform repositories at W3, and porting the probe would be a stub against a
//!   server that cannot exist here (INV-6 forbids exactly that).
//! - **`install-report`**: a named gap for the same reason twice over. It compares a
//!   release binary against an installed one and probes the admin and MCP listeners;
//!   installers and listeners are both platform-repository surfaces (W3).
//! - **The interactive sign-in for the retired first-party productivity-suite
//!   integration**: removed entirely, not gapped. NMCP-PLAN-001 I-038 extracts its device
//!   login to the private-layer backlog, and NMCP-SPEC-003 RC-D9 then removed the
//!   integration from the kernel altogether, which makes the subtraction total: no such
//!   subcommand, no such dependency, and the only place the old permission's name survives
//!   is `nmcp-policy`'s `RETIRED_PERMISSIONS` refusal table, the one named exception
//!   (RC-19).
//!
//! What remains of the base ctl after that subtraction is thin (the base's operator surface
//! was mostly HTTP calls against its daemon), so the secret surface above is this crate's
//! primary content and the port is the residue, exactly as I-038 anticipated.
//!
//! ## Named gaps in this crate
//!
//! - **Chain audit records for operator writes.** The store exposes no audit hook,
//!   deliberately: a second hash-chain writer beside `nmcp-audit`'s would break the
//!   one-chain property INV-3 depends on. Ring-path secret use is audited since I-034; the
//!   chain record for an operator write belongs to the daemon wave, where the one process
//!   that owns the chain can offer this surface a path to it. Until then each mutating
//!   subcommand prints the transition it performed, which is the by-hand record.
//! - **The tty prompt path is untestable in CI**, which has no terminal. The piped-stdin
//!   path is the one the suite drives end to end; the prompt path's no-echo and erasure
//!   guarantees are [`rpassword`]'s own (prompting on the controlling terminal, line buffer
//!   erased via `rtoolbox::SafeString`), named here rather than claimed as covered.
//!
//! ## Exit discipline
//!
//! Three distinct codes, documented on [`error`]: refusals print the refusing library's own
//! error text (the governing rule named, SB-8) and exit 1; usage errors exit 2, matching
//! `clap`; this tool's own failed reads and writes exit 3. No panics anywhere: the
//! workspace denies them, and every failure path is a printed refusal.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod abac;
mod audit;
pub mod error;
mod input;
mod locate;
mod policy;
mod secret;

pub use error::{CtlError, EXIT_IO, EXIT_REFUSAL, EXIT_USAGE, ExitClass};

use secret::StorePaths;

/// The streams one invocation runs against.
///
/// A struct rather than process globals so the whole surface is drivable as a library: the
/// integration suite passes cursors and buffers here and asserts on them, which is the
/// house's answer to having no process-spawn harness for ctl binaries.
pub struct CtlIo<'a> {
    /// Standard input: the value source for `secret set` and `secret rotate` when piped,
    /// the binding source for `secret bind` without `--file`, and the confirmation line.
    pub input: &'a mut dyn BufRead,
    /// Whether standard input is a terminal: selects the no-echo prompt over the piped read.
    pub input_is_tty: bool,
    /// Standard output: command results.
    pub out: &'a mut dyn Write,
    /// Standard error: warnings and interactive prompts.
    pub err: &'a mut dyn Write,
}

/// The NativeMCP operator command line (NMCP-SPEC-001 R-5).
#[derive(Debug, Parser)]
#[command(
    name = "nmcpctl",
    version,
    about = "nMCP operator commands: the secret broker's operator surface, policy tools \
             and audit verification"
)]
pub struct Cli {
    /// Store directory (documented per-platform default).
    #[arg(long, global = true, value_name = "DIR", help = locate::STORE_HELP)]
    pub store: Option<PathBuf>,

    /// Sealer key directory. Default: the store's sibling, `<store>-sealer` (SB-11 keeps
    /// the key out of the store directory so a backup of one does not capture the other)
    #[arg(long, global = true, value_name = "DIR")]
    pub key_dir: Option<PathBuf>,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// The secret broker's operator surface (NMCP-SPEC-002 SB-13): local admin only,
    /// never an MCP tool
    Secret {
        /// The operation.
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Policy tools: scaffold, validate, and the verdict diff
    Policy {
        /// The operation.
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Audit log tools
    Audit {
        /// The operation.
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// ABAC key management (CLI only, never an MCP tool)
    Abac {
        /// The operation.
        #[command(subcommand)]
        command: AbacCommand,
    },
}

/// `nmcpctl secret` operations.
///
/// No variant takes a secret value as an argument, and none ever will: the value arrives
/// over piped standard input or a no-echo terminal prompt (SB-R1). The integration suite
/// asserts this against the parsed command definition, so the property cannot regress
/// silently.
#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// Create a store directory and sealer key with restricted modes; refuses if either
    /// already exists (never overwrites)
    Init,
    /// Store the first version of a secret. The value is read from stdin when piped, or
    /// from a no-echo prompt on the terminal; never from an argument or the environment.
    /// Exactly one trailing newline is stripped from piped input
    Set {
        /// The secret's name (SB-2 grammar: lowercase, digits, `_ . -`, max 64; reserved
        /// namespaces refused).
        name: String,
    },
    /// Store a new version; the prior version keeps resolving for the overlap window.
    /// Value input rules are exactly those of `set`
    Rotate {
        /// The secret's name.
        name: String,
    },
    /// Revoke immediately and reversibly: every version stops resolving now, nothing is
    /// deleted, `restore` reverses it
    Quarantine {
        /// The secret's name.
        name: String,
    },
    /// Reverse a quarantine: every version returns to the state it was revoked from
    Restore {
        /// The secret's name.
        name: String,
    },
    /// Withdraw from service reversibly (Active to Suspended); `resume` reverses it
    Suspend {
        /// The secret's name.
        name: String,
    },
    /// Return a suspended secret to service (Suspended to Active)
    Resume {
        /// The secret's name.
        name: String,
    },
    /// Write what may use a secret (SB-6), from a JSON file or stdin. The parsed binding
    /// is echoed back and written only under --yes or an interactive yes: a misread
    /// allowlist is a policy change
    Bind {
        /// The secret's name.
        name: String,
        /// Read the binding from this JSON file instead of stdin.
        #[arg(long, value_name = "PATH")]
        file: Option<PathBuf>,
        /// Write without prompting (required when the binding arrives on stdin).
        #[arg(long)]
        yes: bool,
    },
    /// List names, per-version lifecycle states, binding summaries and below-floor flags.
    /// Never values, never digests (SB-R2)
    List,
    /// Reseal every blob under a new file sealer, retaining every prior blob (SB-12's
    /// store-key rotation; the v1-entropy platform half lands at W3)
    Migrate {
        /// The source sealer's identifier, exactly as `secret list` prints it; the store
        /// refuses a mismatch.
        #[arg(long, value_name = "SEALER-ID")]
        from: String,
        /// The target file sealer's key directory (a key is created there on first use).
        #[arg(long, value_name = "DIR")]
        to_key_dir: PathBuf,
        /// Assert the target sealer's identifier after opening; refused on mismatch. Omit
        /// when this run creates the target key, since the identifier does not exist
        /// before the key does.
        #[arg(long, value_name = "SEALER-ID")]
        to: Option<String>,
    },
}

/// `nmcpctl policy` operations.
#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Write the default policy to a new file (refuses to overwrite)
    Init {
        /// Where to write it.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Validate a policy through the same loader the daemon uses
    Validate {
        /// The policy file.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
    },
    /// Show exactly which calls a policy change newly allows or denies
    Diff {
        /// The policy in force now.
        #[arg(long, value_name = "PATH")]
        from: PathBuf,
        /// The policy being considered.
        #[arg(long, value_name = "PATH")]
        to: PathBuf,
        /// Emit the plan as JSON instead of text.
        #[arg(long)]
        json: bool,
        /// Exit nonzero when any call changes verdict, as a pipeline gate.
        #[arg(long)]
        fail_on_change: bool,
    },
}

/// `nmcpctl audit` operations.
#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Verify the tamper-evident hash chain of an audit log
    Verify {
        /// The audit log.
        #[arg(long, value_name = "PATH")]
        path: PathBuf,
        /// Verify from this chain sequence onward (skips a legacy pre-chain head).
        #[arg(long, value_name = "N")]
        from_sequence: Option<u64>,
    },
}

/// `nmcpctl abac` operations.
#[derive(Debug, Subcommand)]
pub enum AbacCommand {
    /// Replace the manifest-signing public verification key, retaining the prior key
    RotateSigningKey {
        /// The new public key file (raw 32-byte Ed25519 key, or 64 hex characters).
        #[arg(long, value_name = "PATH")]
        new_key: PathBuf,
        /// Where the verification key lives (must be outside all policy roots).
        #[arg(long, value_name = "PATH")]
        key_path: PathBuf,
    },
}

/// Run one parsed invocation against the given streams.
///
/// The whole binary behind the argument parser, callable as a library: `main` wires the
/// real streams, the suite wires cursors. Output goes to `io.out`, warnings and prompts to
/// `io.err`; the caller prints the returned error and maps [`CtlError::class`] to the exit
/// code.
///
/// # Errors
///
/// [`CtlError`], with the class deciding the exit code: a refusal names its governing rule
/// in the refusing library's own words (SB-8).
pub fn execute(cli: Cli, io: &mut CtlIo<'_>) -> Result<(), CtlError> {
    let Cli {
        store,
        key_dir,
        command,
    } = cli;
    match command {
        Command::Secret { command } => {
            let store_dir = locate::resolve_store_dir(store)?;
            let key_dir = locate::resolve_key_dir(key_dir, &store_dir);
            let paths = StorePaths { store_dir, key_dir };
            match command {
                SecretCommand::Init => secret::init(&paths, io.out),
                SecretCommand::Set { name } => {
                    secret::set(&paths, &name, io.input, io.input_is_tty, io.out, io.err)
                }
                SecretCommand::Rotate { name } => {
                    secret::rotate(&paths, &name, io.input, io.input_is_tty, io.out, io.err)
                }
                SecretCommand::Quarantine { name } => secret::quarantine(&paths, &name, io.out),
                SecretCommand::Restore { name } => secret::restore(&paths, &name, io.out),
                SecretCommand::Suspend { name } => secret::suspend(&paths, &name, io.out),
                SecretCommand::Resume { name } => secret::resume(&paths, &name, io.out),
                SecretCommand::Bind { name, file, yes } => secret::bind(
                    &paths,
                    &name,
                    file.as_deref(),
                    yes,
                    io.input,
                    io.input_is_tty,
                    io.out,
                    io.err,
                ),
                SecretCommand::List => secret::list(&paths, io.out),
                SecretCommand::Migrate {
                    from,
                    to_key_dir,
                    to,
                } => secret::migrate(&paths, &from, &to_key_dir, to.as_deref(), io.out),
            }
        }
        Command::Policy { command } => match command {
            PolicyCommand::Init { output } => policy::init(&output, io.out),
            PolicyCommand::Validate { config } => policy::validate(&config, io.out),
            PolicyCommand::Diff {
                from,
                to,
                json,
                fail_on_change,
            } => policy::diff(&from, &to, json, fail_on_change, io.out),
        },
        Command::Audit { command } => match command {
            AuditCommand::Verify {
                path,
                from_sequence,
            } => audit::verify(&path, from_sequence, io.out),
        },
        Command::Abac { command } => match command {
            AbacCommand::RotateSigningKey { new_key, key_path } => {
                abac::rotate_signing_key(&new_key, &key_path, io.out)
            }
        },
    }
}

/// Semantic version of this crate, taken from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate identity as it appears in operator messages.
pub const COMPONENT: &str = "nmcpctl";

/// Integration suite for `nmcpctl`, driving the binary's logic as a library.
///
/// The house has no process-spawn harness for ctl binaries, and the tty prompt path cannot
/// run under CI, which has no terminal, so this suite drives [`execute`] directly with
/// cursors and buffers: the piped-stdin path end to end, the interactive confirmation with
/// a simulated terminal flag, and the store on real directories. The no-echo prompt path's
/// guarantees are `rpassword`'s own and are named in the crate documentation rather than
/// claimed as covered here. In-crate rather than a `tests/` directory, deliberately: it
/// drives only the public surface, and an integration-test crate is compiled without
/// `cfg(test)`, which would put its self-cleaning temp directories inside the INV-1
/// scanner's production scope when they are exactly the test-only cleanup it excludes.
///
/// The one test that is about the command definition rather than about behaviour is
/// `value_via_argv_is_structurally_impossible`: SB-R1 says the value never arrives on argv
/// or from the environment, and the proof is that the parsed command tree has no such
/// argument at all.
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

    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::{Cli, CtlError, CtlIo, ExitClass, execute};
    use clap::{CommandFactory, Parser};
    use nmcp_secrets::Sealer;

    /// Distinctive material with no English substring, so the never-in-output assertions
    /// cannot collide with legitimate prose.
    const MATERIAL: &[u8] = b"vmk83q-w72xr-r51tp-p94zh-h30cj";

    /// A second distinctive value for rotations and second keys.
    const MATERIAL_TWO: &[u8] = b"zn19fk-e66um-b40sw-d85yl-g22vt";

    /// Distinguishes directories within one process; the process id distinguishes runs.
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A directory under the system temporary root that removes itself on drop.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("nmcpctl-{label}-{}-{unique}", std::process::id()));
            std::fs::create_dir_all(&path).expect("test temp dir is creatable");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        /// The store and key-dir locations every test passes explicitly, so no test depends
        /// on the invoking environment's home.
        fn store_args(&self) -> (String, String) {
            (
                self.path.join("store").display().to_string(),
                self.path.join("keys").display().to_string(),
            )
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Parse `args` and run them against captured streams.
    fn run(args: &[&str], piped: &[u8], tty: bool) -> (Result<(), CtlError>, String, String) {
        let cli = Cli::try_parse_from(args).expect("test arguments parse");
        let mut input = Cursor::new(piped.to_vec());
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let result = execute(
            cli,
            &mut CtlIo {
                input: &mut input,
                input_is_tty: tty,
                out: &mut out,
                err: &mut err,
            },
        );
        (
            result,
            String::from_utf8(out).expect("stdout is utf-8"),
            String::from_utf8(err).expect("stderr is utf-8"),
        )
    }

    /// `run` for a store rooted in `dir`, prefixing the global flags.
    fn run_store(
        dir: &TempDir,
        tail: &[&str],
        piped: &[u8],
        tty: bool,
    ) -> (Result<(), CtlError>, String, String) {
        let (store, keys) = dir.store_args();
        let mut args = vec!["nmcpctl", "--store", &store, "--key-dir", &keys];
        args.extend_from_slice(tail);
        run(&args, piped, tty)
    }

    /// Initialize a store in `dir` and return the init output.
    fn init_store(dir: &TempDir) -> String {
        let (result, out, _) = run_store(dir, &["secret", "init"], b"", false);
        result.expect("init succeeds");
        out
    }

    /// No byte window of `material` four bytes or longer appears in `rendered` (SB-1 and
    /// SB-R2 applied to this surface's output).
    fn assert_material_absent(rendered: &str, material: &[u8]) {
        let bytes = rendered.as_bytes();
        for width in 4..=material.len() {
            for window in material.windows(width) {
                assert!(
                    !bytes.windows(width).any(|candidate| candidate == window),
                    "a {width}-byte window of the material appears in: {rendered}"
                );
            }
        }
    }

    /// A piped value with its trailing newline, as `echo value |` would deliver it.
    fn piped(material: &[u8]) -> Vec<u8> {
        let mut value = material.to_vec();
        value.push(b'\n');
        value
    }

    // - SB-R1: the argv and environment modalities do not exist -

    #[test]
    fn value_via_argv_is_structurally_impossible() {
        // A trailing value argument is rejected by the parser, on both value-taking commands.
        for command in ["set", "rotate"] {
            let parsed =
                Cli::try_parse_from(["nmcpctl", "secret", command, "api.token", "hunter2x"]);
            assert!(
                parsed.is_err(),
                "secret {command} must reject a trailing value argument"
            );
        }
        // The definition itself: `secret set` and `secret rotate` carry exactly one positional,
        // the name, and no argument anywhere in the tree is value-like or reads an environment
        // variable. This is the structural proof: the modality is unrepresentable, not refused.
        let cli = Cli::command();
        let secret = cli
            .find_subcommand("secret")
            .expect("the secret subtree exists");
        for command in ["set", "rotate"] {
            let sub = secret.find_subcommand(command).expect("subcommand exists");
            let positionals: Vec<_> = sub.get_positionals().collect();
            assert_eq!(
                positionals.len(),
                1,
                "secret {command} takes the name and nothing else"
            );
            assert_eq!(positionals[0].get_id().as_str(), "name");
        }
        assert_tree_has_no_value_arg_and_no_env(&cli);
    }

    /// Walk the whole command tree: no argument id is value-like, and none reads the
    /// environment (the `env` clap feature is enabled workspace-wide, so an `env = ...`
    /// attribute would compile; this asserts nobody wrote one).
    fn assert_tree_has_no_value_arg_and_no_env(command: &clap::Command) {
        for arg in command.get_arguments() {
            let id = arg.get_id().as_str().to_ascii_lowercase();
            assert!(
                !id.contains("value") && !id.contains("password") && !id.contains("token"),
                "argument {id} of {} looks like a value channel",
                command.get_name()
            );
            assert!(
                arg.get_env().is_none(),
                "argument {id} of {} reads an environment variable",
                command.get_name()
            );
        }
        for sub in command.get_subcommands() {
            assert_tree_has_no_value_arg_and_no_env(sub);
        }
    }

    // - init -

    #[test]
    fn init_creates_a_restricted_store_and_never_a_second_one() {
        let dir = TempDir::new("init");
        let out = init_store(&dir);
        assert!(out.contains("initialized secret store"), "{out}");
        assert!(out.contains("sealer: file/"), "{out}");
        assert!(out.contains("tripwire arming floor: 16 bytes"), "{out}");
        assert!(out.contains("rotation overlap window: 300s"), "{out}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let store_mode = std::fs::metadata(dir.path().join("store")).unwrap().mode() & 0o777;
            assert_eq!(store_mode, 0o700, "store directory mode");
            let key_mode = std::fs::metadata(dir.path().join("keys").join("sealer-key.json"))
                .unwrap()
                .mode()
                & 0o777;
            assert_eq!(key_mode, 0o600, "sealer key file mode");
            assert!(out.contains("unix modes 700/600"), "{out}");
        }

        // A second init refuses on the existing directories: never overwrites (INV-1 spirit).
        let (again, _, _) = run_store(&dir, &["secret", "init"], b"", false);
        let refused = again.expect_err("second init must refuse");
        assert_eq!(refused.class(), ExitClass::Refusal);
        assert!(refused.to_string().contains("already exists"), "{refused}");

        // And no other command conjures a store: a mistyped --store is a refusal, not an
        // empty store plus a fresh key.
        let elsewhere = TempDir::new("init-absent");
        let (missing, _, _) = run_store(&elsewhere, &["secret", "list"], b"", false);
        let refused = missing.expect_err("list against no store must refuse");
        assert!(
            refused.to_string().contains("nmcpctl secret init"),
            "{refused}"
        );
    }

    // - set, list, and the round trip -

    #[test]
    fn set_then_list_round_trips_and_output_never_carries_the_value() {
        let dir = TempDir::new("set-list");
        init_store(&dir);
        let (result, set_out, set_err) = run_store(
            &dir,
            &["secret", "set", "api.token"],
            &piped(MATERIAL),
            false,
        );
        result.expect("set succeeds");
        assert!(
            set_out.contains("stored secret api.token: version 1 active"),
            "{set_out}"
        );
        assert!(set_err.is_empty(), "no warning above the floor: {set_err}");

        let (result, list_out, _) = run_store(&dir, &["secret", "list"], b"", false);
        result.expect("list succeeds");
        assert!(list_out.contains("api.token: active"), "{list_out}");
        assert!(list_out.contains("v1: active"), "{list_out}");
        assert!(list_out.contains("below-floor=no"), "{list_out}");
        assert!(
            list_out.contains("binding: none (a key with no binding is usable by nothing)"),
            "{list_out}"
        );
        // SB-R2 on this surface: names and states, never values and never digests.
        assert_material_absent(&set_out, MATERIAL);
        assert_material_absent(&list_out, MATERIAL);

        // A second set is the store's own refusal, naming rotation as the remedy.
        let (duplicate, _, _) = run_store(
            &dir,
            &["secret", "set", "api.token"],
            &piped(MATERIAL_TWO),
            false,
        );
        let refused = duplicate.expect_err("a duplicate set must refuse");
        assert_eq!(refused.class(), ExitClass::Refusal);
        assert!(refused.to_string().contains("is a rotation"), "{refused}");
    }

    #[test]
    fn the_below_floor_warning_fires_at_set_and_shows_in_list() {
        let dir = TempDir::new("below-floor");
        init_store(&dir);
        // Nine bytes, under the sixteen-byte default floor.
        let (result, _, warn) =
            run_store(&dir, &["secret", "set", "short.pin"], b"012345678\n", false);
        result.expect("a below-floor value still stores");
        assert!(
            warn.contains("below the tripwire arming floor of 16 bytes"),
            "{warn}"
        );
        assert!(warn.contains("detection is off for this key"), "{warn}");

        let (_, list_out, _) = run_store(&dir, &["secret", "list"], b"", false);
        assert!(
            list_out.contains("below-floor=YES (detection is off for this key)"),
            "{list_out}"
        );
    }

    #[test]
    fn a_reserved_namespace_is_refused_with_the_grammar_error_before_any_read() {
        let dir = TempDir::new("reserved");
        init_store(&dir);
        let (result, _, _) = run_store(&dir, &["secret", "set", "oauth/provider"], b"", false);
        let refused = result.expect_err("a reserved name must refuse");
        assert_eq!(refused.class(), ExitClass::Refusal);
        let message = refused.to_string();
        assert!(
            message.starts_with("not a usable secret name:"),
            "{message}"
        );
        assert!(message.contains("reserved"), "{message}");
    }

    // - rotate and the overlap reminder -

    #[test]
    fn rotate_reminds_about_the_overlap_window_and_when_the_prior_version_retires() {
        let dir = TempDir::new("rotate");
        init_store(&dir);
        run_store(
            &dir,
            &["secret", "set", "api.token"],
            &piped(MATERIAL),
            false,
        )
        .0
        .expect("set succeeds");
        let (result, out, _) = run_store(
            &dir,
            &["secret", "rotate", "api.token"],
            &piped(MATERIAL_TWO),
            false,
        );
        result.expect("rotate succeeds");
        assert!(
            out.contains("rotated secret api.token: version 2 active"),
            "{out}"
        );
        assert!(
            out.contains("version 1: active -> superseded; resolvable until unix-ms"),
            "{out}"
        );
        assert!(out.contains("(overlap window 300s)"), "{out}");
        assert_material_absent(&out, MATERIAL);
        assert_material_absent(&out, MATERIAL_TWO);

        // At a window of zero the reminder reports the hard cutover the store performed.
        let (store_dir, key_dir) = dir.store_args();
        {
            let sealer = nmcp_secrets::FileSealer::open(Path::new(&key_dir)).unwrap();
            let store =
                nmcp_secrets::SealedStore::open(Path::new(&store_dir), Box::new(sealer)).unwrap();
            store
                .set_overlap_window(std::time::Duration::ZERO)
                .expect("window is settable");
        }
        let (result, out, _) = run_store(
            &dir,
            &["secret", "rotate", "api.token"],
            &piped(MATERIAL),
            false,
        );
        result.expect("rotate at window zero succeeds");
        assert!(
            out.contains("version 2: active -> retained (overlap window 0s: hard cutover)"),
            "{out}"
        );

        // Rotating an absent key is the store's refusal.
        let (missing, _, _) = run_store(
            &dir,
            &["secret", "rotate", "absent"],
            &piped(MATERIAL),
            false,
        );
        assert!(
            missing.unwrap_err().to_string().contains("no secret named"),
            "the store's own text names the refusal"
        );
    }

    // - quarantine, restore, suspend, resume: the FSM round trips -

    #[test]
    fn quarantine_and_restore_round_trip_and_print_the_transitions() {
        let dir = TempDir::new("quarantine");
        init_store(&dir);
        run_store(
            &dir,
            &["secret", "set", "db.password"],
            &piped(MATERIAL),
            false,
        )
        .0
        .expect("set succeeds");
        let (result, out, _) =
            run_store(&dir, &["secret", "quarantine", "db.password"], b"", false);
        result.expect("quarantine succeeds");
        assert!(out.contains("quarantined secret db.password"), "{out}");
        assert!(out.contains("revocation is immediate"), "{out}");
        assert!(out.contains("version 1: active -> quarantined"), "{out}");

        let (_, list_out, _) = run_store(&dir, &["secret", "list"], b"", false);
        assert!(list_out.contains("db.password: quarantined"), "{list_out}");

        let (result, out, _) = run_store(&dir, &["secret", "restore", "db.password"], b"", false);
        result.expect("restore succeeds");
        assert!(out.contains("version 1: quarantined -> active"), "{out}");

        let (again, _, _) = run_store(&dir, &["secret", "restore", "db.password"], b"", false);
        assert!(
            again
                .unwrap_err()
                .to_string()
                .contains("nothing to restore"),
            "a second restore is the store's own refusal"
        );
    }

    #[test]
    fn suspend_and_resume_round_trip_through_the_fsm() {
        let dir = TempDir::new("suspend-resume");
        init_store(&dir);
        run_store(
            &dir,
            &["secret", "set", "deploy.key"],
            &piped(MATERIAL),
            false,
        )
        .0
        .expect("set succeeds");

        let (result, out, _) = run_store(&dir, &["secret", "suspend", "deploy.key"], b"", false);
        result.expect("suspend succeeds");
        assert!(out.contains("version 1: active -> suspended"), "{out}");
        assert!(
            out.contains("`nmcpctl secret resume` returns it to service"),
            "{out}"
        );

        let (_, list_out, _) = run_store(&dir, &["secret", "list"], b"", false);
        assert!(list_out.contains("deploy.key: suspended"), "{list_out}");

        let (result, out, _) = run_store(&dir, &["secret", "resume", "deploy.key"], b"", false);
        result.expect("resume succeeds");
        assert!(out.contains("resumed secret deploy.key"), "{out}");
        assert!(out.contains("version 1: suspended -> active"), "{out}");

        let (_, list_out, _) = run_store(&dir, &["secret", "list"], b"", false);
        assert!(list_out.contains("deploy.key: active"), "{list_out}");

        // A second resume is the store's own refusal, naming both shapes the variant covers.
        let (again, _, _) = run_store(&dir, &["secret", "resume", "deploy.key"], b"", false);
        let refused = again.unwrap_err();
        assert_eq!(refused.class(), ExitClass::Refusal);
        assert!(
            refused.to_string().contains("nothing to resume"),
            "{refused}"
        );
    }

    // - bind: echo, confirm, and the summary -

    /// A binding admitting one tool and one caller, as a JSON document.
    const BINDING_JSON: &str = r#"{
      "tools": ["keyed_run"],
      "programs": [],
      "roots": [],
      "callers": ["local"]
    }"#;

    #[test]
    fn bind_echoes_the_parsed_binding_and_writes_nothing_without_confirmation() {
        let dir = TempDir::new("bind-confirm");
        init_store(&dir);
        run_store(
            &dir,
            &["secret", "set", "api.token"],
            &piped(MATERIAL),
            false,
        )
        .0
        .expect("set succeeds");

        // Piped binding without --yes: the echo prints, then the refusal, and nothing is bound.
        let (result, out, _) = run_store(
            &dir,
            &["secret", "bind", "api.token"],
            BINDING_JSON.as_bytes(),
            false,
        );
        let refused = result.expect_err("bind without confirmation must refuse");
        assert_eq!(refused.class(), ExitClass::Refusal);
        assert!(
            refused.to_string().contains("confirmation required"),
            "{refused}"
        );
        assert!(refused.to_string().contains("--yes"), "{refused}");
        assert!(
            out.contains("binding for secret api.token, as parsed"),
            "{out}"
        );
        assert!(
            out.contains("\"keyed_run\""),
            "the echo shows the parsed object: {out}"
        );
        assert!(
            out.contains("note: the programs allowlist is empty and admits none"),
            "{out}"
        );
        let (_, list_out, _) = run_store(&dir, &["secret", "list"], b"", false);
        assert!(
            list_out.contains("binding: none"),
            "nothing was written: {list_out}"
        );

        // With --yes the same binding writes, and the summary reads back.
        let (result, out, _) = run_store(
            &dir,
            &["secret", "bind", "api.token", "--yes"],
            BINDING_JSON.as_bytes(),
            false,
        );
        result.expect("bind --yes succeeds");
        assert!(out.contains("bound secret api.token:"), "{out}");
        assert!(out.contains("first binding for this key"), "{out}");
        assert!(
            out.contains("tools=1 programs=0 roots=0 callers=1"),
            "{out}"
        );
        assert!(out.contains("on-trip=suspend"), "{out}");

        // Re-binding names what it replaces and resets the spend state.
        let (result, out, _) = run_store(
            &dir,
            &["secret", "bind", "api.token", "--yes"],
            BINDING_JSON.as_bytes(),
            false,
        );
        result.expect("re-bind succeeds");
        assert!(out.contains("replaces the prior binding"), "{out}");
    }

    #[test]
    fn bind_from_a_file_confirms_interactively_and_a_decline_writes_nothing() {
        let dir = TempDir::new("bind-tty");
        init_store(&dir);
        run_store(
            &dir,
            &["secret", "set", "api.token"],
            &piped(MATERIAL),
            false,
        )
        .0
        .expect("set succeeds");
        let binding_path = dir.path().join("binding.json");
        std::fs::write(&binding_path, BINDING_JSON).expect("binding file writes");
        let binding_file = binding_path.display().to_string();

        // A terminal answering n: echoed, prompted on stderr, declined, nothing written.
        let (result, out, err) = run_store(
            &dir,
            &["secret", "bind", "api.token", "--file", &binding_file],
            b"n\n",
            true,
        );
        let refused = result.expect_err("a declined confirmation must refuse");
        assert!(refused.to_string().contains("declined"), "{refused}");
        assert!(out.contains("as parsed"), "{out}");
        assert!(err.contains("[y/N]"), "the prompt goes to stderr: {err}");
        let (_, list_out, _) = run_store(&dir, &["secret", "list"], b"", false);
        assert!(list_out.contains("binding: none"), "{list_out}");

        // The same terminal answering y writes it.
        let (result, out, _) = run_store(
            &dir,
            &["secret", "bind", "api.token", "--file", &binding_file],
            b"y\n",
            true,
        );
        result.expect("a confirmed bind succeeds");
        assert!(out.contains("bound secret api.token:"), "{out}");

        // A file that is not a KeyBinding refuses with the parse reason; unknown fields are
        // refused too (`deny_unknown_fields`), because a field somebody misspelled is a rule
        // somebody believes is in force.
        let bad_path = dir.path().join("bad.json");
        std::fs::write(
            &bad_path,
            r#"{"tools": [], "programs": [], "roots": [], "callers": [], "extra": 1}"#,
        )
        .expect("bad binding file writes");
        let bad_file = bad_path.display().to_string();
        let (result, _, _) = run_store(
            &dir,
            &["secret", "bind", "api.token", "--file", &bad_file, "--yes"],
            b"",
            false,
        );
        let refused = result.expect_err("an unknown field must refuse");
        assert!(
            refused
                .to_string()
                .contains("does not parse as a KeyBinding"),
            "{refused}"
        );

        // A missing binding file is the I/O class, distinct from a refusal.
        let (result, _, _) = run_store(
            &dir,
            &[
                "secret",
                "bind",
                "api.token",
                "--file",
                "/nonexistent/binding.json",
                "--yes",
            ],
            b"",
            false,
        );
        assert_eq!(result.unwrap_err().class(), ExitClass::Io);
    }

    #[test]
    fn list_shows_budget_spend_and_remaining_from_the_live_binding() {
        let dir = TempDir::new("list-budget");
        init_store(&dir);
        run_store(
            &dir,
            &["secret", "set", "api.token"],
            &piped(MATERIAL),
            false,
        )
        .0
        .expect("set succeeds");
        let budgeted = r#"{
          "tools": ["keyed_run"],
          "programs": [],
          "roots": [],
          "callers": ["local"],
          "budget": {"uses": 3, "window_secs": 3600}
        }"#;
        run_store(
            &dir,
            &["secret", "bind", "api.token", "--yes"],
            budgeted.as_bytes(),
            false,
        )
        .0
        .expect("bind succeeds");

        // Spend one use through the store's own evaluator, as the ring would at stage 5b.
        let (store_dir, key_dir) = dir.store_args();
        {
            let sealer = nmcp_secrets::FileSealer::open(Path::new(&key_dir)).unwrap();
            let store =
                nmcp_secrets::SealedStore::open(Path::new(&store_dir), Box::new(sealer)).unwrap();
            let name = nmcp_secrets::SecretName::parse("api.token").unwrap();
            let request = nmcp_secrets::BindingRequest::new("keyed_run", "local");
            let grant = store.evaluate(&name, &request).expect("the binding admits");
            let value = store.resolve(grant).expect("the grant resolves");
            assert_eq!(value.with_exposed(Vec::clone), MATERIAL.to_vec());
        }

        let (result, list_out, _) = run_store(&dir, &["secret", "list"], b"", false);
        result.expect("list succeeds");
        assert!(
            list_out.contains("1 used of 3, 2 remaining in the open window (3600s window)"),
            "{list_out}"
        );
        assert_material_absent(&list_out, MATERIAL);
    }

    // - migrate: file sealer to file sealer -

    /// A store with two secrets, the source sealer's identifier, and a target key directory:
    /// the fixture both migration tests start from.
    fn migration_fixture(dir: &TempDir) -> (String, String) {
        init_store(dir);
        for (name, value) in [("api.token", MATERIAL), ("db.password", MATERIAL_TWO)] {
            run_store(dir, &["secret", "set", name], &piped(value), false)
                .0
                .expect("set succeeds");
        }
        let (_, key_dir) = dir.store_args();
        let source_id = nmcp_secrets::FileSealer::open(Path::new(&key_dir))
            .unwrap()
            .id()
            .as_str()
            .to_string();
        let target_dir = dir.path().join("keys-two").display().to_string();
        (source_id, target_dir)
    }

    /// Run `secret migrate` against `dir` with the given source and target.
    fn run_migrate(
        dir: &TempDir,
        from: &str,
        target_dir: &str,
    ) -> (Result<(), CtlError>, String, String) {
        run_store(
            dir,
            &[
                "secret",
                "migrate",
                "--from",
                from,
                "--to-key-dir",
                target_dir,
            ],
            b"",
            false,
        )
    }

    #[test]
    fn migrate_reseals_under_a_second_file_sealer_and_material_survives() {
        let dir = TempDir::new("migrate");
        let (source_id, target_dir) = migration_fixture(&dir);
        let (store_dir, _) = dir.store_args();

        // A wrong source assertion is the store's own refusal, before anything moves.
        let (mismatch, _, _) = run_migrate(
            &dir,
            "file/NativeMCP.secrets.v2/0000000000000000",
            &target_dir,
        );
        assert!(
            mismatch
                .unwrap_err()
                .to_string()
                .contains("open the store with the source sealer"),
            "the store names the remedy"
        );

        // The real migration reseals both versions and retains every prior blob.
        let (result, out, _) = run_migrate(&dir, &source_id, &target_dir);
        result.expect("migrate succeeds");
        assert!(out.contains("resealed: 2 version(s)"), "{out}");
        assert!(out.contains("api.token v1"), "{out}");
        assert!(out.contains("db.password v1"), "{out}");
        assert!(out.contains("every prior blob is retained"), "{out}");
        assert_material_absent(&out, MATERIAL);
        assert_material_absent(&out, MATERIAL_TWO);

        // The proof that the migration is real: the store opened under the target sealer
        // resolves the same material end to end.
        let target = nmcp_secrets::FileSealer::open(Path::new(&target_dir)).unwrap();
        let store =
            nmcp_secrets::SealedStore::open(Path::new(&store_dir), Box::new(target)).unwrap();
        let name = nmcp_secrets::SecretName::parse("api.token").unwrap();
        store
            .bind(
                &name,
                serde_json::from_str::<nmcp_secrets::KeyBinding>(BINDING_JSON).unwrap(),
            )
            .unwrap();
        let grant = store
            .evaluate(
                &name,
                &nmcp_secrets::BindingRequest::new("keyed_run", "local"),
            )
            .expect("the binding admits under the target sealer");
        let value = store.resolve(grant).expect("the target sealer unseals");
        assert_eq!(value.with_exposed(Vec::clone), MATERIAL.to_vec());
    }

    #[test]
    fn migrate_is_idempotent_and_the_target_assertion_refuses_a_mismatch() {
        let dir = TempDir::new("migrate-again");
        let (source_id, target_dir) = migration_fixture(&dir);
        run_migrate(&dir, &source_id, &target_dir)
            .0
            .expect("first migrate succeeds");

        // Idempotent: a second run skips everything as already at the target.
        let (result, out, _) = run_migrate(&dir, &source_id, &target_dir);
        result.expect("a second migrate succeeds");
        assert!(out.contains("resealed: 0 version(s)"), "{out}");
        assert!(
            out.contains("skipped, already at the target: 2 version(s)"),
            "{out}"
        );

        // A wrong target assertion refuses in this tool, naming both identifiers.
        let (asserted, _, _) = run_store(
            &dir,
            &[
                "secret",
                "migrate",
                "--from",
                &source_id,
                "--to-key-dir",
                &target_dir,
                "--to",
                "file/NativeMCP.secrets.v2/ffffffffffffffff",
            ],
            b"",
            false,
        );
        let refused = asserted.unwrap_err();
        assert_eq!(refused.class(), ExitClass::Refusal);
        assert!(
            refused.to_string().contains("not the asserted"),
            "{refused}"
        );
    }

    // - the ported residue: policy, audit, abac -

    #[test]
    fn policy_init_validate_and_diff_port_the_base_surface() {
        let dir = TempDir::new("policy");
        let scaffold = dir.path().join("policy.json").display().to_string();
        let (result, out, _) = run(
            &["nmcpctl", "policy", "init", "--output", &scaffold],
            b"",
            false,
        );
        result.expect("policy init succeeds");
        assert!(out.contains("wrote the default policy"), "{out}");

        // Never overwrites: the second write refuses.
        let (again, _, _) = run(
            &["nmcpctl", "policy", "init", "--output", &scaffold],
            b"",
            false,
        );
        assert_eq!(again.unwrap_err().class(), ExitClass::Refusal);

        let (result, out, _) = run(
            &["nmcpctl", "policy", "validate", "--config", &scaffold],
            b"",
            false,
        );
        result.expect("the scaffold validates under the daemon's loader");
        assert!(out.contains("valid policy:"), "{out}");

        // A policy diffed against itself is verdict neutral, even under the gate flag.
        let (result, out, _) = run(
            &[
                "nmcpctl",
                "policy",
                "diff",
                "--from",
                &scaffold,
                "--to",
                &scaffold,
                "--fail-on-change",
            ],
            b"",
            false,
        );
        result.expect("a self-diff is neutral");
        assert!(!out.is_empty(), "the plan renders");

        // Malformed policy is the loader's refusal, verbatim.
        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, "{ not json").expect("broken file writes");
        let broken_path = broken.display().to_string();
        let (result, _, _) = run(
            &["nmcpctl", "policy", "validate", "--config", &broken_path],
            b"",
            false,
        );
        assert_eq!(result.unwrap_err().class(), ExitClass::Refusal);
    }

    #[test]
    fn audit_verify_reports_the_chain_and_tampering_is_a_refusal() {
        let dir = TempDir::new("audit");
        // A missing log verifies clean, exactly as the verifier documents.
        let missing = dir.path().join("absent.jsonl").display().to_string();
        let (result, out, _) = run(
            &["nmcpctl", "audit", "verify", "--path", &missing],
            b"",
            false,
        );
        result.expect("a missing log is ok: true");
        assert!(out.contains("\"ok\": true"), "{out}");

        // A log that is not chain records is an ok: false report and a refusal exit.
        let tampered = dir.path().join("tampered.jsonl");
        std::fs::write(&tampered, "this is not a chain record\n").expect("log writes");
        let tampered_path = tampered.display().to_string();
        let (result, out, _) = run(
            &["nmcpctl", "audit", "verify", "--path", &tampered_path],
            b"",
            false,
        );
        let refused = result.expect_err("tampering must refuse");
        assert_eq!(refused.class(), ExitClass::Refusal);
        assert!(refused.to_string().contains("FAILED"), "{refused}");
        assert!(out.contains("\"ok\": false"), "{out}");
    }

    #[test]
    fn abac_rotate_signing_key_validates_retains_and_replaces() {
        let dir = TempDir::new("abac");
        let new_key = dir.path().join("new.pub");
        std::fs::write(&new_key, [7_u8; 32]).expect("key file writes");
        let key_path = dir.path().join("keys").join("sig-verify.pub");
        let new_key_arg = new_key.display().to_string();
        let key_path_arg = key_path.display().to_string();

        let (result, out, _) = run(
            &[
                "nmcpctl",
                "abac",
                "rotate-signing-key",
                "--new-key",
                &new_key_arg,
                "--key-path",
                &key_path_arg,
            ],
            b"",
            false,
        );
        result.expect("first rotation succeeds");
        assert!(out.contains("rotated the ABAC verification key"), "{out}");
        assert!(key_path.is_file(), "the key landed");

        // A second rotation retains the prior key under a timestamped name.
        let second = dir.path().join("second.pub");
        std::fs::write(&second, [9_u8; 32]).expect("second key writes");
        let second_arg = second.display().to_string();
        let (result, out, _) = run(
            &[
                "nmcpctl",
                "abac",
                "rotate-signing-key",
                "--new-key",
                &second_arg,
                "--key-path",
                &key_path_arg,
            ],
            b"",
            false,
        );
        result.expect("second rotation succeeds");
        assert!(out.contains("prior key retained at"), "{out}");
        assert_eq!(std::fs::read(&key_path).unwrap(), vec![9_u8; 32]);
        let retained = std::fs::read_dir(key_path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".retired-"))
            .count();
        assert_eq!(retained, 1, "the prior key still exists");

        // A key of the wrong size is a refusal naming the expectation.
        let wrong = dir.path().join("wrong.pub");
        std::fs::write(&wrong, [1_u8; 16]).expect("wrong key writes");
        let wrong_arg = wrong.display().to_string();
        let (result, _, _) = run(
            &[
                "nmcpctl",
                "abac",
                "rotate-signing-key",
                "--new-key",
                &wrong_arg,
                "--key-path",
                &key_path_arg,
            ],
            b"",
            false,
        );
        let refused = result.expect_err("a wrong-size key must refuse");
        assert!(
            refused.to_string().contains("32 raw bytes or 64 hex"),
            "{refused}"
        );
    }

    // - list surfaces damaged documents -

    #[test]
    fn list_reports_unreadable_documents_instead_of_hiding_them() {
        let dir = TempDir::new("unreadable");
        init_store(&dir);
        run_store(
            &dir,
            &["secret", "set", "good.key"],
            &piped(MATERIAL),
            false,
        )
        .0
        .expect("set succeeds");
        // Plant a damaged document beside the good one, restricted like the store's own.
        let damaged = dir
            .path()
            .join("store")
            .join("secrets")
            .join("broken.key.json");
        std::fs::write(&damaged, "{ not a document").expect("damaged file writes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&damaged, std::fs::Permissions::from_mode(0o600))
                .expect("mode is settable");
        }
        let (result, out, _) = run_store(&dir, &["secret", "list"], b"", false);
        result.expect("list succeeds around the damage");
        assert!(out.contains("good.key: active"), "{out}");
        assert!(out.contains("unreadable documents"), "{out}");
        assert!(out.contains("broken.key.json"), "{out}");
        assert!(out.contains("does not parse as a secret document"), "{out}");
    }
}
