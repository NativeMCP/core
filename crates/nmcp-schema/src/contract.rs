//! The tool descriptor a provider declares.
//!
//! NMCP-SPEC-003 section 4.2, RATIFIED v1.3. `published_annotations` arrived at v1.3, which is
//! the amendment I-047d's escalation forced: section 4.3 deletes the `ToolProvider::tool_list`
//! that used to carry a proxied upstream's own annotations, and until v1.3 this descriptor had
//! nowhere to put them.

use serde_json::{Value, json};

use crate::authority::{ToolAuthority, ToolEffect, ToolReach};

/// A tool as its provider declares it. Supersedes `nmcp_proto::ToolSpec`, which carried
/// name, description and schema only and left everything else to be looked up by name in
/// the kernel.
#[derive(Debug, Clone)]
pub struct ToolContract {
    /// Local name, without the provider prefix. May contain dots.
    pub name: String,
    /// One-paragraph behaviour description shown to callers.
    pub description: String,
    /// JSON Schema for the arguments.
    pub input_schema: Value,
    /// Everything the kernel needs to govern the call.
    pub authority: ToolAuthority,
    /// Annotations the tool's own publisher supplied, carried through verbatim.
    ///
    /// Meaningful only for a provider with a non-empty `provider_id`. A proxied
    /// upstream is somebody else's software: this server keeps what that server
    /// published and invents nothing. Deriving an upstream's annotations from
    /// its own declaration would be inventing them on its behalf from data it
    /// controls, which is the same thing wearing a different hat.
    ///
    /// A first-party provider setting this is a registration error. First-party
    /// annotations are derived from `authority` by [`ToolContract::to_list_entry`], and a
    /// second source that could disagree with the first is exactly the defect RC-A4
    /// exists to make unrepresentable. `None` for every first-party tool, always.
    pub published_annotations: Option<Value>,
}

impl ToolContract {
    /// The MCP `tools/list` entry for this tool under `public_name`.
    ///
    /// Annotations are derived here from `authority`, which is why they cannot disagree
    /// with what the kernel authorizes against (RC-A4). Emits all three hints:
    /// `readOnlyHint` from `effect`, `openWorldHint` from `reach`, and
    /// `destructiveHint: false` unconditionally, which restates the no-destructive-action
    /// guarantee rather than describing this tool.
    ///
    /// Absent annotations are not neutral, which is why all three are emitted rather than
    /// only the two that carry information. A client that receives none applies the
    /// protocol defaults, and `destructiveHint` and `openWorldHint` both default to true:
    /// a sane default for an unknown server and exactly wrong for this one, which has no
    /// delete surface to annotate. Dropping `destructiveHint` would advertise every tool
    /// in this catalogue as destructive in every client. `nmcp_proto::tool_annotations` made
    /// the same claim from a table of tool names and said the same thing about it; I-047d
    /// deleted it, and this is where the claim lives now, read off the same declaration the
    /// kernel authorizes against rather than off a second table that could disagree (RC-A4).
    /// If a tool is ever added for which `false` would be a lie, INV-1 is what broke, not
    /// this function.
    ///
    /// The public name is passed in rather than computed, because the mapping from local
    /// to public belongs to the registry, and computing it in two places is the shape of
    /// the defect NMCP-SPEC-003 section 1 measures.
    ///
    /// Called only for first-party providers. A proxied upstream is somebody else's
    /// software: this server keeps whatever annotations the upstream published and invents
    /// none, which is the existing rule in `nmcp-router`'s merged tool list and stays the
    /// rule. [`ToolContract::published_annotations`] is where an upstream's own annotations
    /// travel, and the registry emits that field verbatim instead of calling this (RC-21).
    #[must_use]
    pub fn to_list_entry(&self, public_name: &str) -> Value {
        json!({
            "name": public_name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "readOnlyHint": self.authority.effect == ToolEffect::Observe,
                "destructiveHint": false,
                "openWorldHint": self.authority.reach == ToolReach::Remote,
            },
        })
    }
}
