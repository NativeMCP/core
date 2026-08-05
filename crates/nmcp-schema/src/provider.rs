//! The provider trait every tool provider implements.
//!
//! NMCP-SPEC-003 section 4.3, RATIFIED v1.2, now in the frozen shape. The trait lives here for
//! RC-D1's reason: a provider crate depends on the contract and never on the kernel, which is
//! what makes the open-core split hold at the dependency level rather than by convention.
//! `nmcp-router` re-exports it, so every existing `use nmcp_router::ToolProvider` keeps
//! compiling.
//!
//! I-047c landed the trait here with `call` still taking four parameters and with the base's
//! `tool_names` and `tool_list` carried as transitional defaults. I-047d lands the rest as one
//! change, because it is one change: a provider cannot be handed a
//! [`GrantedAuthority`](crate::GrantedAuthority) until dispatch produces one, dispatch cannot
//! produce one until it calls [`authorize`](crate::authorize), and `authorize` needs the
//! declaration only [`contracts`](ToolProvider::contracts) supplies. There is no waypoint left.

use async_trait::async_trait;
use serde_json::Value;

use crate::authority::GrantedAuthority;
use crate::context::{CallContext, ToolCallResult};
use crate::contract::ToolContract;

/// The single interface every tool provider implements.
///
/// Providers **must not** perform policy checks or audit writes: those happen in the ring
/// before and after `call`. Providers also must not call other tools directly; cross-tool
/// composition belongs to the kernel. Both sentences carry over in intent from the base trait
/// doc, and both are checkable rather than advisory now that a provider declares what it needs
/// through [`contracts`](ToolProvider::contracts) instead of evaluating policy itself.
///
/// The first sentence became load-bearing rather than hygienic at NMCP-SPEC-003 v1.2. Until
/// I-047d the ring resolved a root from a compiled-in table whose path-argument lists named
/// arguments the tools' own schemas did not define, so `DevToolsProvider` re-checked policy on
/// the argument it actually read and that check was the only thing standing between the
/// mismatch and a confused deputy. The ring now authorizes on the schema-filtered declaration,
/// which makes the set the kernel authorizes on and the set the tool reads the same set by
/// construction, which is what made removing that check safe (RC-20).
#[async_trait]
pub trait ToolProvider: Send + Sync {
    /// Contract version this provider was built against.
    ///
    /// No default body on purpose. An implementor states a literal, so the number is a
    /// deliberate claim rather than whatever the linked schema crate happens to say. With
    /// Cargo unifying the workspace on one `nmcp-schema`, a defaulted version would be
    /// tautologically correct and the check would never fire (NMCP-SPEC-003 section 4.3, and
    /// G-9 for why the check is carried while it is still inert).
    fn contract_version(&self) -> u32;

    /// Stable, unique prefix for this provider's tools.
    ///
    /// `""` for first-party providers, whose tools are published unprefixed. An upstream uses
    /// its ID, so its tools become `upstream_id::tool_name` and `upstream_id_tool_name`.
    fn provider_id(&self) -> &str;

    /// Every tool this provider owns, fully declared.
    ///
    /// Replaces the base's `tool_names` and `tool_list` pair: two methods that had to agree and
    /// were never checked against each other. May change between calls for a provider whose
    /// catalogue is remote; the registry re-reads it on `refresh`, never on dispatch (RC-9).
    fn contracts(&self) -> Vec<ToolContract>;

    /// Execute a single tool call.
    ///
    /// `granted` is proof the kernel authorized this specific call, and it is unforgeable
    /// outside this crate. It is a parameter rather than an implicit precondition so that "the
    /// provider was called without authorization" is not an expression that type-checks
    /// (RC-A2). A provider that needs the matched root reads it from
    /// [`GrantedAuthority::matched_root`] rather than from `ctx.matched_root()`: both carry the
    /// same root, and only one of them is proof that root resolution happened.
    ///
    /// The provider receives arguments, context and proof, and nothing else. Policy and audit
    /// are handled by the ring, before and after this returns.
    async fn call(
        &self,
        name: &str,
        args: Value,
        ctx: &CallContext,
        granted: &GrantedAuthority,
    ) -> ToolCallResult;
}
