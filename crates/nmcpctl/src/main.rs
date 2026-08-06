//! The `nmcpctl` binary: parse, wire the real streams, run, map the exit code.
//!
//! Deliberately thin. Everything with behaviour lives in the library so the integration
//! suite can drive it without spawning a process; this file owns only what a process owns:
//! the argument vector, the standard streams, the terminal question and the exit code.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use clap::Parser;
use nmcpctl::{Cli, CtlIo, execute};

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        // `clap`'s own printing and codes: help and version exit 0 on stdout, a command
        // line that does not parse exits 2 on stderr, which is this surface's usage class.
        Err(error) => return exit_after_clap(&error),
    };
    let stdin = std::io::stdin();
    let input_is_tty = stdin.is_terminal();
    let mut input = stdin.lock();
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let mut io = CtlIo {
        input: &mut input,
        input_is_tty,
        out: &mut out,
        err: &mut err,
    };
    match execute(cli, &mut io) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The refusal text is the library's own, governing rule included (SB-8).
            let mut stderr = std::io::stderr();
            let _ = writeln!(stderr, "error: {error}");
            ExitCode::from(error.class().code())
        }
    }
}

/// Print a parse outcome the way `clap` documents and return its exit code.
fn exit_after_clap(error: &clap::Error) -> ExitCode {
    // `Error::print` writes help and version to stdout and true errors to stderr. A failed
    // write of the message itself leaves nothing more to say; the code still reports.
    let _ = error.print();
    if error.use_stderr() {
        ExitCode::from(nmcpctl::EXIT_USAGE)
    } else {
        ExitCode::SUCCESS
    }
}
