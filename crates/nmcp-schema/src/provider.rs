//! The provider trait every tool provider implements.
//!
//! NMCP-SPEC-003 section 4.3, RATIFIED v1.1. The trait moves here from `nmcp-router`, which
//! re-exports it, so every existing `use nmcp_router::ToolProvider` keeps compiling. It lives
//! here for RC-D1's reason: a provider crate depends on the contract and never on the kernel,
//! which is what makes the open-core split hold at the dependency level rather than by
//! convention.
//!
//! **The trait here is not yet 4.3's frozen shape, and the difference is named rather than
//! hidden.** 4.3 freezes `call` with a fifth parameter, `granted: &GrantedAuthority`, and
//! deletes `tool_names` and `tool_list` in favour of `contracts`. Landing the parameter means
//! dispatch has to produce a [`GrantedAuthority`](crate::GrantedAuthority), which means
//! dispatch has to call [`authorize`](crate::authorize), which is one atomic change to the
//! ring rather than a change to this trait. Owner I-047c's successor, I-047d, which lands the
//! parameter and deletes the two transitional methods together.

use async_trait::async_trait;
use serde_json::Value;

use crate::context::{CallContext, ToolCallResult};
use crate::contract::ToolContract;

/// The single interface every tool provider implements.
///
/// Providers **must not** perform policy checks or audit writes: those happen in the ring
/// before and after `call`. Providers also must not call other tools directly; cross-tool
/// composition belongs to the kernel. Both sentences carry over in intent from the base trait
/// doc, and both become checkable rather than advisory as providers move from evaluating
/// policy to declaring what they need through [`contracts`](ToolProvider::contracts).
///
/// # What I-047d changes
///
/// `call` keeps its four-parameter shape here. NMCP-SPEC-003 section 4.3 freezes a fifth,
/// `granted: &GrantedAuthority`, which is proof the kernel authorized this specific call and
/// is unforgeable outside this crate. It is a parameter rather than an implicit precondition
/// so that "the provider was called without authorization" is not an expression that
/// type-checks (RC-A2). It is not here yet because dispatch cannot produce one until it calls
/// [`authorize`](crate::authorize), and rewiring dispatch is I-047d. Read the signature below
/// as a waypoint, not as the contract's final form.
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
    /// Replaces the base's [`tool_names`](ToolProvider::tool_names) and
    /// [`tool_list`](ToolProvider::tool_list) pair: two methods that had to agree and were
    /// never checked against each other. May change between calls for a provider whose
    /// catalogue is remote; the registry re-reads it on `refresh`, never on dispatch (RC-9).
    fn contracts(&self) -> Vec<ToolContract>;

    /// Tool names owned by this provider, without the provider prefix.
    ///
    /// **Transitional, deleted by I-047d.** It exists here only so that the trait's move into
    /// this crate breaks no implementor and changes no dispatch decision: `nmcp-router`'s
    /// `resolve` still walks this, and every byte it returns today is a byte it returns after
    /// the move. The default derives it from [`contracts`](ToolProvider::contracts), which is
    /// the direction of travel and the reason an implementor may stop overriding it.
    fn tool_names(&self) -> Vec<String> {
        self.contracts()
            .into_iter()
            .map(|contract| contract.name)
            .collect()
    }

    /// MCP-formatted `tools/list` entries for this provider's tools.
    ///
    /// **Transitional, deleted by I-047d**, for the same reason as
    /// [`tool_names`](ToolProvider::tool_names).
    ///
    /// The default emits each entry under its **local** name, not its public one, because
    /// that is what every implementor emits today and the local-to-public rewrite belongs to
    /// whatever lists the tools. `ToolRegistry::list_for` does that rewrite from the index and
    /// passes the derived public name to
    /// [`ToolContract::to_list_entry`](crate::ToolContract::to_list_entry) itself, so nothing
    /// downstream depends on the naming this default chooses.
    fn tool_list(&self) -> Vec<Value> {
        self.contracts()
            .iter()
            .map(|contract| contract.to_list_entry(&contract.name))
            .collect()
    }

    /// Execute a single tool call.
    ///
    /// The provider receives arguments and context only. Policy and audit are handled by the
    /// ring, before and after this returns. See the trait doc for the fifth parameter
    /// NMCP-SPEC-003 section 4.3 freezes and I-047d lands.
    async fn call(&self, name: &str, args: Value, ctx: &CallContext) -> ToolCallResult;
}
