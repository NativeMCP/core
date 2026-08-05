//! Registration refusals and the per-caller catalogue view.
//!
//! NMCP-SPEC-003 section 4.4, RATIFIED v1.0, minus the `ToolRegistry` trait itself: that
//! trait's methods take `Arc<dyn ToolProvider>`, and `ToolProvider` has not moved into
//! this crate yet. Named gap, not a silent absence: the trait and the registry that
//! implements it land with the rest of section 4.3 and 4.4, and the two value types here
//! are the half that has no such dependency.

use crate::authority::HeldAuthority;

/// Why a provider was refused at registration. Every variant is a condition the base
/// detected at call time on a caller's request, or not at all.
///
/// `non_exhaustive` because NMCP-SPEC-002 needs a `MissingRequiredSecret` variant and this
/// enum is frozen before that spec ratifies. Adding a variant to an exhaustive public enum
/// is a breaking change; adding one here is not. The cost is that matchers need a wildcard
/// arm, which is correct anyway for an error type a caller cannot exhaustively handle.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegistrationError {
    /// The provider declares a contract version this build does not accept.
    #[error(
        "provider {provider_id:?} declares contract version {found}, this build accepts up to {accepted}"
    )]
    UnsupportedContractVersion {
        /// The provider that was refused.
        provider_id: String,
        /// The contract version the provider declared.
        found: u32,
        /// The highest contract version this build accepts.
        accepted: u32,
    },

    /// Two providers derive the same public tool name. Both are named, because a collision
    /// an operator has to infer is a collision an operator does not fix.
    #[error("public tool name {name:?} is claimed by both {owner:?} and {claimant:?}")]
    DuplicateToolName {
        /// The contested public name.
        name: String,
        /// The provider that already holds it.
        owner: String,
        /// The provider that tried to take it.
        claimant: String,
    },

    /// A local name derives a public name no MCP client would accept.
    #[error(
        "tool {local:?} from provider {provider_id:?} derives public name {public:?}, which is not a valid MCP tool name"
    )]
    InvalidToolName {
        /// The provider that was refused.
        provider_id: String,
        /// The local name as declared.
        local: String,
        /// The derived public name that failed validation.
        public: String,
    },

    /// A declared path argument is absent from the tool's own input schema, so the root
    /// resolution it describes could never fire.
    #[error(
        "tool {name:?} declares path argument {arg:?}, which its own input schema does not define"
    )]
    UndeclaredPathArgument {
        /// The tool that was refused.
        name: String,
        /// The declared path argument the schema does not define.
        arg: String,
    },

    /// The tool is on the INV-1 delete denylist, so the operator wiring the server learns
    /// it rather than a caller being denied forever (RC-A3).
    #[error("tool {name:?} is on the INV-1 delete denylist and could never be called")]
    DeleteDeniedName {
        /// The tool that was refused.
        name: String,
    },
}

/// What a given caller may see in `tools/list`.
#[derive(Debug, Clone, Default)]
pub struct CatalogView {
    /// Gateway profile scoping, as today.
    pub profile: Option<String>,
    /// Authenticated caller. Required for `CallerToolAllowlist`, which `list_for` applies
    /// unconditionally (RC-D8): it is already policy, and filtering by it makes the list
    /// agree with what a call would do.
    pub agent_id: Option<String>,
    /// RC-D8, second part. When `Some`, tools whose declared authority the holder does not
    /// satisfy are omitted. `None`, the default, lists everything the profile and
    /// allowlist allow and refuses at call time with a reason.
    pub filter_by: Option<HeldAuthority>,
}
