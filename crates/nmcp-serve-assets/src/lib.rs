//! The nMCP admin UI, embedded at compile time.
//!
//! Two single-page surfaces, each assembled from three files: an HTML template with two
//! `{{...}}` placeholders, a stylesheet, and a script. The substitution happens here rather
//! than at request time so the served bytes are fixed at build time and the router has
//! nothing to assemble per request.
//!
//! Part of the NativeMCP `core` workspace. The governance invariants in
//! `docs/GOVERNANCE.md` apply.
//!
//! # Why the assets are embedded rather than served from disk
//!
//! An admin surface read from disk at request time is a file an attacker who can write to
//! the install directory can replace, and the admin listener is the surface that edits
//! policy. `include_str!` makes the UI part of the binary the installer verified.
//!
//! # The two coupling points a reader will otherwise discover the hard way
//!
//! The scripts here name two things the served crate must agree with, and neither
//! agreement is checked by the compiler:
//!
//! - The admin token header is `x-nmcp-admin-token` (NMCP-DEC-001 row B-10). The server's
//!   extraction must read the same name or every authenticated admin call fails.
//! - The icon is served from `/assets/icons/nmcp.png` (rows B-23 and D-6). That path is one
//!   entry in the reviewed tokenless route allowlist, so it is pinned on the server side and
//!   a rename in one place without the other either 404s the logo or opens an unreviewed
//!   unauthenticated route.

/// The classic admin console's HTML shell.
const ADMIN_HTML_TEMPLATE: &str = include_str!("admin.html");
/// The classic admin console's stylesheet.
const ADMIN_CSS: &str = include_str!("admin.css");
/// The classic admin console's script.
const ADMIN_JS: &str = include_str!("admin.js");
/// The operator matrix's HTML shell.
const ADMIN_MATRIX_HTML_TEMPLATE: &str = include_str!("admin_matrix.html");
/// The operator matrix's stylesheet.
const ADMIN_MATRIX_CSS: &str = include_str!("admin_matrix.css");
/// The operator matrix's script.
const ADMIN_MATRIX_JS: &str = include_str!("admin_matrix.js");

/// The classic admin console, as one self-contained HTML document.
#[must_use]
pub fn admin_html() -> String {
    ADMIN_HTML_TEMPLATE
        .replace("{{ADMIN_CSS}}", ADMIN_CSS)
        .replace("{{ADMIN_JS}}", ADMIN_JS)
}

/// The operator matrix, as one self-contained HTML document.
#[must_use]
pub fn matrix_admin_html() -> String {
    ADMIN_MATRIX_HTML_TEMPLATE
        .replace("{{ADMIN_MATRIX_CSS}}", ADMIN_MATRIX_CSS)
        .replace("{{ADMIN_MATRIX_JS}}", ADMIN_MATRIX_JS)
}

#[cfg(test)]
mod tests {
    // Tests assert on shapes, verdicts and rendered documents, where expect/indexing ARE
    // the assertion: a panic in a test is the failure signal, so the production rationale
    // for the workspace denies (availability plus an audit gap) does not apply. Scoped to
    // the test module, named in the PR.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::{admin_html, matrix_admin_html};

    #[test]
    fn admin_html_renders_embedded_assets() {
        let html = admin_html();
        assert!(html.contains("Runtime"));
        assert!(html.contains("/api/diagnostics/runtime"));
        assert!(html.contains("function renderDiagnostics"));
        assert!(html.contains("body"));
        assert!(html.contains("rel=\"icon\" type=\"image/x-icon\" href=\"/favicon.ico\""));
        assert!(html.contains("class=\"sb-logo-mark\""));
        assert!(html.contains("/assets/icons/nmcp.png"));
        assert!(!html.contains("{{ADMIN_CSS}}"));
        assert!(!html.contains("{{ADMIN_JS}}"));
    }

    #[test]
    fn matrix_admin_html_renders_parallel_operator_surface() {
        let html = matrix_admin_html();
        assert!(html.contains("OPERATOR MATRIX"));
        assert!(html.contains("MCP GATEWAY STORE"));
        assert!(html.contains("POLICY MATRIX"));
        assert!(html.contains("SESSIONS & STREAMS"));
        assert!(html.contains("Enterprise Classic remains"));
        assert!(html.contains("function matrixNav"));
        assert!(html.contains(".om-shell"));
        assert!(html.contains("/assets/icons/nmcp.png"));
        assert!(!html.contains("{{ADMIN_MATRIX_CSS}}"));
        assert!(!html.contains("{{ADMIN_MATRIX_JS}}"));
    }

    #[test]
    fn matrix_admin_uses_same_origin_existing_admin_apis() {
        let html = matrix_admin_html();
        for endpoint in [
            "/healthz",
            "/readyz",
            "/api/policy",
            "/api/doctor",
            "/api/diagnostics/runtime",
            "/api/audit/recent?limit=100",
            "/api/gateway/catalog",
            "/api/gateway/catalog/summary",
            "/api/gateway/decisions/export",
            "/api/upstreams",
        ] {
            assert!(
                html.contains(endpoint),
                "matrix UI missing endpoint {endpoint}"
            );
        }
        assert!(!html.contains("http://127.0.0.1:18769"));
        assert!(!html.contains("http://localhost:18769"));
    }

    #[test]
    fn admin_html_bounds_loading_calls_and_treats_stream_abort_as_disconnect() {
        let html = admin_html();
        assert!(html.contains("function isAbortError"));
        assert!(html.contains("ctl.signal.aborted||isAbortError(e)"));
        assert!(html.contains("jsonFetchTimeout('/api/audit/recent?limit=5',{},5000)"));
        assert!(html.contains("jsonFetchTimeout('/api/upstreams',{},5000)"));
        assert!(
            html.contains("Promise.allSettled([jsonFetchTimeout('/api/gateway/catalog/summary'")
        );
        assert!(!html.contains("Disconnected: signal is aborted without reason"));
    }

    #[test]
    fn admin_html_uses_token_capable_admin_api_transports() {
        let html = admin_html();
        assert!(html.contains("downloadAdminApi"));
        assert!(html.contains("openAdminJson"));
        assert!(html.contains("/api/inspector/events"));
        assert!(html.contains("args_for_approval"));
        assert!(html.contains("AbortController"));
        assert!(!html.contains("new EventSource"));
        assert!(!html.contains("href=\"/api"));
        assert!(!html.contains("Live stream disabled while admin API token auth is enforced"));
    }

    /// The header and the browser storage keys are the two places this crate names something
    /// the server or the operator's browser must agree with, and neither agreement is
    /// checked by the compiler.
    ///
    /// The storage keys are the reason this test exists rather than leaving the point to
    /// INV-8. Renaming them is not cosmetic: an operator who had persisted an admin token is
    /// logged out by the rename, because the new build reads a key the old build never
    /// wrote. NMCP-REF-002 surveyed the Rust and script trees and has no row for browser
    /// storage, so this is the only place that fact is recorded next to the code.
    #[test]
    fn the_client_side_contract_names_are_pinned() {
        let classic = admin_html();
        let matrix = matrix_admin_html();
        for (name, html) in [("classic", &classic), ("matrix", &matrix)] {
            assert!(
                html.contains("x-nmcp-admin-token"),
                "{name}: the admin token header must match what the server extracts"
            );
            assert!(
                html.contains("nmcp.admin.token"),
                "{name}: the persisted admin token key is operator-visible state"
            );
        }
        assert!(
            matrix.contains("nmcp.matrix.profile"),
            "the matrix profile key is operator-visible state"
        );
    }

    /// INV-8 already fails the build on a retired brand reference anywhere in the tree. This
    /// asserts the same property over the *rendered* documents, which is not the same thing:
    /// the gate reads the files, and a template that assembled a retired name from fragments
    /// at render time would pass the gate and still ship it to an operator's screen.
    #[test]
    fn no_retired_brand_name_reaches_a_rendered_document() {
        // Both patterns are assembled from fragments so this file does not itself contain
        // the names it rejects. That is the same technique the INV-8 workflow step uses,
        // and for the same reason: a gate that trips on its own definition is a gate
        // nobody keeps.
        let previous = format!("{}{}", "signal", "desk");
        let pre_previous = [
            format!("{}-{}", "local", "repo"),
            format!("{}_{}", "local", "repo"),
        ];
        for (name, html) in [("classic", admin_html()), ("matrix", matrix_admin_html())] {
            let lowered = html.to_ascii_lowercase();
            assert!(
                !lowered.contains(&previous),
                "{name}: a retired brand name reached the rendered document"
            );
            for fragment in &pre_previous {
                assert!(
                    !lowered.contains(fragment),
                    "{name}: a pre-previous brand name reached the rendered document"
                );
            }
        }
    }
}
