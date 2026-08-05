//! The per-call context and the per-call result.
//!
//! NMCP-SPEC-003 section 4.3, RATIFIED v1.1: both types move here from `nmcp-router` field
//! for field, and `nmcp-router` re-exports them so no `use` path breaks. They move together
//! because they are the two halves of one call's data, and because 4.3's `ToolProvider`
//! names both in the same signature.
//!
//! `CallContext` takes exactly the two changes 4.3 requires and no others: `matched_root`
//! becomes private with a reader, and a private `secrets` field appears with a reader.
//! `ToolCallResult` is unchanged. `ToolProvider` itself does not move here in I-047b and
//! neither does dispatch: 4.3 changes `call` to take a `&GrantedAuthority` and replaces
//! `tool_names`/`tool_list` with `contracts`, and those three changes are one atomic unit,
//! because a provider cannot be handed a [`GrantedAuthority`](crate::GrantedAuthority)
//! until dispatch produces one, dispatch cannot produce one until it calls
//! [`authorize`](crate::authorize), and `authorize` needs the declaration only `contracts`
//! supplies. Named gap per INV-6, owner I-047c.

use nmcp_policy::RootRule;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::scope::MemoryScope;
use crate::secrets::ResolvedSecrets;

// - CallContext -

/// Immutable context threaded through every tool call in the ring.
/// Constructed by the router before entering the middleware ring.
/// Providers receive it read-only - they must not modify it.
#[derive(Debug, Clone)]
pub struct CallContext {
    /// Unique ID for this tool invocation. Written to every audit event.
    pub call_id: Uuid,
    /// MCP session this call arrived on. `None` for calls from tests/CLI.
    pub session_id: Option<String>,
    /// Agent-supplied identity, if the transport provided one.
    pub agent_id: Option<String>,
    /// Policy root matched to the primary path argument of this call.
    /// `None` for tools that don't operate on a filesystem path.
    ///
    /// Private, read through [`CallContext::matched_root`], and set only by
    /// [`CallContext::with_root`]. NMCP-SPEC-003 section 4.3 requires the privacy: the
    /// field is `pub` in the base, so anything holding a `CallContext` can set the resolved
    /// root, and once `ToolProvider::call` takes a `&GrantedAuthority` that token would
    /// prove only that root resolution happened while the caller of `call` remained free to
    /// fabricate what it resolved to.
    matched_root: Option<RootRule>,
    /// For proxied (gateway) calls: the upstream ID this will be forwarded to.
    /// `None` for local providers.
    pub upstream_id: Option<String>,
    /// Memory scope for this call - defaults to matched root ID, falls back to session.
    pub memory_scope: MemoryScope,
    /// Gateway profile this session is scoped to, if any (G6-8).
    ///
    /// `None` means the session is not scoped and reaches whatever the machine-wide profile
    /// leaves running, which is what every call did before sessions had profiles.
    pub profile: Option<String>,
    /// Where the call arrived from, ALREADY REDACTED (G3-15, AF-5).
    ///
    /// A `String` rather than a richer type because mcp-router must not depend on mcp-server,
    /// and because a field that can only hold the redacted form is the point: the truncation
    /// happens at the transport boundary, so a full address cannot reach this struct rather
    /// than being trusted not to. `loopback` for a loopback caller.
    ///
    /// `None` for every caller with no transport, which is the CLI and every test path.
    pub peer: Option<String>,
    /// Which credential path authenticated this caller (G3-15, AF-7).
    ///
    /// `static` or `oauth`. A `&'static str` from a closed set, so it cannot carry
    /// caller-supplied bytes. Without it an OAuth subject mapped to `agent_id: chatgpt` and a
    /// static credential using the same `agent_id` produce byte-identical audit records, and
    /// an operator asking whether a destructive call came from the console or from the
    /// internet cannot answer it from the chain.
    pub credential_path: Option<&'static str>,
    /// What the client said it was, when the revision carries it (G5-9).
    ///
    /// Recorded, never read. Nothing in the ring branches on this, because it is
    /// transport-supplied text and SEP-2243 forbids treating that as trusted input for a
    /// security-sensitive decision. `agent_id` remains the only identity ABAC authorizes on.
    pub client_info: Option<String>,
    /// Secret material the kernel resolved for this call, on its way to the provider that
    /// performs the injection (NMCP-SPEC-003 section 4.3).
    ///
    /// Private, read through [`CallContext::secrets`], which hands out a borrow rather than
    /// an owned copy. Empty for every call today; see [`ResolvedSecrets`] for what that
    /// means and for why the field is carried before NMCP-SPEC-002 defines its contents.
    secrets: ResolvedSecrets,
}

impl CallContext {
    #[must_use]
    /// `new`.
    pub fn new(session_id: Option<String>) -> Self {
        Self::with_agent(session_id, None)
    }

    /// `with_agent`.
    pub fn with_agent(session_id: Option<String>, agent_id: Option<String>) -> Self {
        let scope = session_id
            .as_deref()
            .map_or_else(|| MemoryScope::named("default"), MemoryScope::session);
        Self {
            call_id: Uuid::new_v4(),
            session_id,
            agent_id,
            matched_root: None,
            upstream_id: None,
            memory_scope: scope,
            profile: None,
            client_info: None,
            peer: None,
            credential_path: None,
            secrets: ResolvedSecrets::default(),
        }
    }

    /// Scope this call to a gateway profile.
    #[must_use]
    pub fn with_profile(mut self, profile: Option<String>) -> Self {
        self.profile = profile;
        self
    }

    /// Attach what the client said it was, for the audit record.
    #[must_use]
    pub fn with_client_info(mut self, client_info: Option<String>) -> Self {
        self.client_info = client_info;
        self
    }

    /// Attach where the call arrived from and which credential admitted it (G3-15, AF-7).
    ///
    /// `peer` must already be redacted. See the field doc.
    #[must_use]
    pub fn with_provenance(
        mut self,
        peer: Option<String>,
        credential_path: Option<&'static str>,
    ) -> Self {
        self.peer = peer;
        self.credential_path = credential_path;
        self
    }

    /// Resolve the memory scope from the matched root, falling back to session.
    ///
    /// The only setter for `matched_root`, and a waypoint rather than the destination. What
    /// the privacy buys today is narrow and worth stating plainly: the field can be set by
    /// one named method in this crate instead of by an assignment anywhere, so the setting
    /// is greppable and the reader is the only way back out. The kernel still resolves the
    /// root itself and still hands the answer in here. I-047c replaces this builder with
    /// construction from a [`GrantedAuthority`](crate::GrantedAuthority), at which point a
    /// resolved root reaches a context only as a consequence of an authorization having
    /// happened, which is the property RC-A2 is actually after. Until then, do not read the
    /// privacy as more than it is.
    #[must_use]
    pub fn with_root(mut self, root: Option<RootRule>) -> Self {
        if let Some(ref r) = root {
            self.memory_scope = MemoryScope::root(&r.id);
        }
        self.matched_root = root;
        self
    }

    /// The policy root this call resolved to, if any.
    ///
    /// `None` for a tool that operates on no filesystem path, and for a call whose root
    /// resolution has not run yet.
    #[must_use]
    pub fn matched_root(&self) -> Option<&RootRule> {
        self.matched_root.as_ref()
    }

    /// Secret material resolved for this call.
    ///
    /// A borrow, never an owned copy, per NMCP-SPEC-003 section 4.3. Empty for every call
    /// with no schema-declared secret slot, which is every call until NMCP-SPEC-002 defines
    /// the slot.
    #[must_use]
    pub fn secrets(&self) -> &ResolvedSecrets {
        &self.secrets
    }
}

// - ToolCallResult -

/// The result of a single tool call, as returned by a `ToolProvider`.
/// The ring uses `audit_payload` to build the `AuditEvent`; providers fill it
/// with tool-specific detail (path, command, upstream, etc.).
#[derive(Debug, Clone)]
pub struct ToolCallResult {
    /// MCP content array to return to the caller.
    pub content: Vec<Value>,
    /// True if this result represents an error condition.
    pub is_error: bool,
    /// Structured audit payload. Provider fills this; ring records it.
    /// If `None`, the ring records the tool name and `call_id` only.
    pub audit_payload: Option<Value>,
    /// Preserved `structuredContent` from `tool_result_json`, if the provider
    /// produced one. Threaded through so the MCP response retains the field.
    pub structured_content: Option<Value>,
}

impl ToolCallResult {
    #[must_use]
    /// `ok`.
    // The constructors take owned values: a caller builds a result and hands
    // it over, matching the JSON it becomes on the wire.
    #[allow(clippy::needless_pass_by_value)]
    pub fn ok(content: Value) -> Self {
        Self {
            content: vec![json!({"type": "text", "text": content.to_string()})],
            is_error: false,
            audit_payload: None,
            structured_content: None,
        }
    }

    /// Construct from a pre-built `tool_result_json` value, preserving
    /// `content` and `structuredContent` fields as-is.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_tool_result_json(v: Value, audit: Value) -> Self {
        let content = v.get("content").cloned().unwrap_or(json!([]));
        let structured = v.get("structuredContent").cloned();
        let content_arr = if let Value::Array(arr) = content {
            arr
        } else {
            vec![]
        };
        Self {
            content: content_arr,
            is_error: false,
            audit_payload: Some(audit),
            structured_content: structured,
        }
    }

    /// `err`.
    pub fn err(message: impl Into<String>) -> Self {
        Self::err_with_metadata(message, "runtime_error", None)
    }

    /// `err_with_metadata`.
    pub fn err_with_metadata(
        message: impl Into<String>,
        error_kind: impl Into<String>,
        remediation: Option<&str>,
    ) -> Self {
        let msg = message.into();
        let kind = error_kind.into();
        let structured = json!({
            "ok": false,
            "error_kind": kind,
            "message": msg,
            "remediation": remediation,
        });
        Self {
            content: vec![json!({"type": "text", "text": msg.clone()})],
            is_error: true,
            audit_payload: Some(structured.clone()),
            structured_content: Some(structured),
        }
    }

    /// Convert to the JSON-RPC response value expected by `dispatch_tool`.
    #[must_use]
    pub fn into_dispatch_json(self) -> Value {
        let mut v = json!({
            "content": self.content,
            "isError": self.is_error
        });
        if let Some(sc) = self.structured_content
            && let Some(object) = v.as_object_mut()
        {
            // Insert rather than index: serde_json's IndexMut panics on a
            // non-object, and the workspace denies indexing. `v` is the object
            // literal above, so this branch always takes; writing it this way
            // makes that provable instead of assumed.
            object.insert("structuredContent".into(), sc);
        }
        v
    }
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
    use super::CallContext;
    use nmcp_policy::{Permission, RootRule};
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    /// G3-11 RS-11. A caller's token must never reach an upstream, and here it cannot,
    /// because there is no field for one to travel in. `CallContext` is everything a
    /// provider is given besides the tool arguments, and `authenticate_mcp_client` turns a
    /// credential into an `agent_id` and a profile before this type is ever built.
    ///
    /// Destructured rather than field-accessed on purpose: adding a field to `CallContext`
    /// breaks this compile, which puts the confused-deputy question in front of whoever adds
    /// it instead of letting a header ride along unnoticed.
    ///
    /// It lives here rather than in `nmcp-router`, where it was written, because the type it
    /// pins moved and two of the fields it names are now private to this module. A pattern
    /// with `..` would still compile in `nmcp-router` and would assert nothing, since the
    /// whole value of this test is that the pattern is exhaustive. So it moved with the
    /// type, unchanged in name, in intent and in every line of its body except the one the
    /// move required.
    ///
    /// `secrets` is that line, and it clears the bar the doc above sets for a new field. It
    /// holds material the kernel resolved from a slot the tool's own input schema declared;
    /// a caller can neither name a slot nor put bytes in one, and the reader hands out a
    /// borrow, so nothing here can be lifted out and forwarded. It is also empty for every
    /// call that exists today (NMCP-SPEC-003 section 4.3).
    #[test]
    fn a_call_context_has_no_field_a_caller_credential_could_travel_in() {
        let CallContext {
            call_id: _,
            session_id: _,
            agent_id: _,
            matched_root: _,
            upstream_id: _,
            memory_scope: _,
            profile: _,
            client_info: _,
            // G3-15 added these two, and both are incapable of holding a credential BY TYPE
            // rather than by convention: `peer` is redacted at the transport boundary before
            // it can reach here, and `credential_path` is a compile-time constant from a
            // closed set. That is the bar a new field has to clear to be added here.
            peer: _,
            credential_path: _,
            secrets: _,
        } = CallContext::new(Some("session-1".to_string()));
    }

    /// The reader is the whole of the new surface, so it is worth pinning that it reports
    /// what the one setter set and that the memory scope still follows the root. Both halves
    /// of `with_root` are behaviour `nmcp-router` depends on and neither changed in the move.
    #[test]
    fn the_reader_reports_the_root_the_only_setter_set() {
        let ctx = CallContext::new(Some("sess".to_string()));
        assert!(ctx.matched_root().is_none());
        assert_eq!(ctx.memory_scope.to_string(), "session:sess");

        let root = RootRule {
            id: "docs".to_string(),
            path: PathBuf::from("/tmp"),
            permissions: BTreeSet::from([Permission::Read]),
        };
        let ctx = ctx.with_root(Some(root));
        assert_eq!(ctx.matched_root().map(|r| r.id.as_str()), Some("docs"));
        assert_eq!(ctx.memory_scope.to_string(), "root:docs");
    }

    /// Every call carries an empty `ResolvedSecrets`, and the accessor is a borrow. The
    /// second half is asserted by the signature rather than by an assertion: a reader
    /// returning an owned copy would let material outlive the call, which NMCP-SPEC-003
    /// section 4.3 forbids, and this line would not compile against one.
    #[test]
    fn every_call_carries_an_empty_secret_channel() {
        let ctx = CallContext::new(None);
        let borrowed: &crate::ResolvedSecrets = ctx.secrets();
        assert!(borrowed.is_empty());
    }
}
