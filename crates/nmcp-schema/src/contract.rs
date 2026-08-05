//! The tool descriptor a provider declares.
//!
//! NMCP-SPEC-003 section 4.2, RATIFIED v1.0.

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
    /// in this catalogue as destructive in every client. `nmcp_proto::tool_annotations`
    /// makes the same claim from a table of tool names, and says the same thing about it.
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
    /// rule.
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
