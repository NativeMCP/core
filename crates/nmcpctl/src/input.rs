//! How a secret value enters this process, and how a confirmation is asked.
//!
//! NMCP-SPEC-002 SB-R1 and SB-13: the value arrives over piped standard input or over an
//! interactive no-echo prompt, and never as an argument or an environment variable. The argv
//! modality does not exist in the command definition at all, which is the same construction
//! SB-A2 uses for injection: not refused, unrepresentable. The structural test in this
//! crate's suite proves both halves against the parsed command tree.
//!
//! ## The two paths
//!
//! - **Piped standard input** (stdin is not a terminal): everything to end of stream, minus
//!   exactly one trailing line terminator (`\n` or `\r\n`), because `echo value |` appends
//!   one and a credential with a stray newline fails at its consumer with no visible cause.
//!   A value that genuinely ends in a newline is stored by piping it with two.
//! - **Interactive prompt** (stdin is a terminal): [`rpassword`]'s `prompt_password`, which
//!   prompts on the controlling terminal (`/dev/tty` on Unix, the console on Windows), reads
//!   from it with echo disabled, and erases its own line buffer on drop
//!   (`rtoolbox::SafeString`, volatile writes). The prompt path cannot run under CI, which
//!   has no terminal; its guarantee is the library's, named here, and the piped path is the
//!   one the test suite drives.
//!
//! ## What is erased, and the honest bound
//!
//! The returned buffer is moved into [`Sealed`], whose drop zeroizes it, and no copy is made
//! on the way. The bound is the one `nmcp-secrets` documents for `Sealed` itself: one owned
//! allocation is erased; a reallocation the reader performed while growing the buffer is the
//! allocator's residue, outside any wrapper's reach.

use std::io::BufRead;

use nmcp_secrets::Sealed;

use crate::error::CtlError;

/// Read a secret value for `name`, from the prompt when interactive, from `input` otherwise.
///
/// # Errors
///
/// [`CtlError::Io`] when the stream or terminal cannot be read, and [`CtlError::Refusal`]
/// for an empty value: storing a zero-byte credential is almost always a mis-piped command,
/// and the store would otherwise seal it without complaint.
pub(crate) fn read_secret_value(
    name: &str,
    input: &mut dyn BufRead,
    input_is_tty: bool,
) -> Result<Sealed<Vec<u8>>, CtlError> {
    let mut value = if input_is_tty {
        // The terminal path: no echo, read from the controlling terminal, line terminator
        // already stripped by the library.
        rpassword::prompt_password(format!("value for secret {name} (echo is off): "))
            .map_err(|error| CtlError::io("reading the value from the terminal", &error))?
            .into_bytes()
    } else {
        let mut buffer = Vec::new();
        input
            .read_to_end(&mut buffer)
            .map_err(|error| CtlError::io("reading the value from standard input", &error))?;
        strip_one_line_terminator(&mut buffer);
        buffer
    };
    if value.is_empty() {
        // Erase before refusing, though there is nothing but the allocation to erase.
        let sealed_empty = Sealed::new(value);
        drop(sealed_empty);
        return Err(CtlError::refusal(
            "the value is empty; an empty credential is refused because it is almost always a \
             mis-piped command (pipe the value on stdin, or run on a terminal for a no-echo \
             prompt)",
        ));
    }
    let sealed = Sealed::new(std::mem::take(&mut value));
    Ok(sealed)
}

/// Remove exactly one trailing `\n` or `\r\n`, and nothing else.
fn strip_one_line_terminator(buffer: &mut Vec<u8>) {
    if buffer.last() == Some(&b'\n') {
        buffer.pop();
        if buffer.last() == Some(&b'\r') {
            buffer.pop();
        }
    }
}

/// Ask the operator to confirm on the terminal, reading one line from `input`.
///
/// Only called when standard input is a terminal and is not already carrying data (the
/// caller enforces both); the prompt goes to `err` so that stdout stays parseable output.
/// Everything except an explicit `y` or `yes`, case-insensitive, declines: the default
/// answer to a policy change is no.
///
/// # Errors
///
/// [`CtlError::Io`] when the prompt cannot be written or the line cannot be read.
pub(crate) fn confirm(
    question: &str,
    input: &mut dyn BufRead,
    err: &mut dyn std::io::Write,
) -> Result<bool, CtlError> {
    write!(err, "{question} [y/N] ").map_err(|error| CtlError::io("writing the prompt", &error))?;
    err.flush()
        .map_err(|error| CtlError::io("writing the prompt", &error))?;
    let mut line = String::new();
    input
        .read_line(&mut line)
        .map_err(|error| CtlError::io("reading the confirmation", &error))?;
    let answer = line.trim();
    Ok(answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"))
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
    use std::io::Cursor;

    use super::{confirm, read_secret_value, strip_one_line_terminator};
    use crate::error::{CtlError, ExitClass};

    fn exposed(value: &nmcp_secrets::Sealed<Vec<u8>>) -> Vec<u8> {
        value.with_exposed(Vec::clone)
    }

    #[test]
    fn the_piped_path_takes_the_bytes_minus_one_terminator() {
        for (piped, stored) in [
            (&b"tok-w9x2-kq47-mm81\n"[..], &b"tok-w9x2-kq47-mm81"[..]),
            (b"tok-w9x2-kq47-mm81\r\n", b"tok-w9x2-kq47-mm81"),
            (b"tok-w9x2-kq47-mm81", b"tok-w9x2-kq47-mm81"),
            // Exactly one terminator comes off: a deliberate trailing newline survives.
            (b"ends-in-newline\n\n", b"ends-in-newline\n"),
            // Interior whitespace and terminators are value bytes, untouched.
            (b"line one\nline two\n", b"line one\nline two"),
        ] {
            let mut input = Cursor::new(piped.to_vec());
            let value = read_secret_value("api.token", &mut input, false).unwrap();
            assert_eq!(exposed(&value), stored.to_vec(), "piped {piped:?}");
        }
    }

    #[test]
    fn an_empty_value_is_refused_not_stored() {
        for piped in [&b""[..], b"\n", b"\r\n"] {
            let mut input = Cursor::new(piped.to_vec());
            let refused = read_secret_value("api.token", &mut input, false).unwrap_err();
            assert_eq!(refused.class(), ExitClass::Refusal);
            assert!(refused.to_string().contains("empty"), "{refused}");
        }
    }

    #[test]
    fn stripping_is_exact_and_single() {
        let mut buffer = b"a\r\n".to_vec();
        strip_one_line_terminator(&mut buffer);
        assert_eq!(buffer, b"a");
        let mut bare_cr = b"a\r".to_vec();
        strip_one_line_terminator(&mut bare_cr);
        assert_eq!(
            bare_cr, b"a\r",
            "a bare CR is a value byte, not a terminator"
        );
    }

    #[test]
    fn confirmation_defaults_to_no_and_admits_only_yes() {
        for (line, expected) in [
            ("y\n", true),
            ("Y\n", true),
            ("yes\n", true),
            ("YES\n", true),
            ("n\n", false),
            ("\n", false),
            ("anything else\n", false),
            ("", false),
        ] {
            let mut input = Cursor::new(line.as_bytes().to_vec());
            let mut err: Vec<u8> = Vec::new();
            let answer = confirm("write this binding?", &mut input, &mut err).unwrap();
            assert_eq!(answer, expected, "answer {line:?}");
            let prompt = String::from_utf8(err).unwrap();
            assert!(prompt.contains("[y/N]"), "{prompt}");
        }
    }

    #[test]
    fn io_failures_are_the_io_class() {
        /// A reader that always fails, for driving the error path.
        struct Failing;
        impl std::io::Read for Failing {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("stream broke"))
            }
        }
        let mut reader = std::io::BufReader::new(Failing);
        let error = read_secret_value("api.token", &mut reader, false).unwrap_err();
        assert!(matches!(&error, CtlError::Io { .. }));
        assert_eq!(error.class(), ExitClass::Io);
    }
}
