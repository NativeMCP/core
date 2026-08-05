//! The registry contract: the trait, its refusals, and the per-caller catalogue view.
//!
//! NMCP-SPEC-003 section 4.4, RATIFIED v1.3. The trait lives here and the index that
//! implements it lives in `nmcp-host`, which is the split section 4.4's own header states:
//! the contract belongs where every provider can see it, and the implementation belongs in
//! the kernel that owns the dispatch path.

use std::sync::Arc;

use serde_json::Value;

use crate::authority::{HeldAuthority, ToolAuthority};
use crate::provider::ToolProvider;
use crate::secret_ref::SecretSlotError;

/// Why a provider was refused at registration. Every variant is a condition the base
/// detected at call time on a caller's request, or not at all.
///
/// `non_exhaustive` because NMCP-SPEC-002 needs a `MissingRequiredSecret` variant and this
/// enum is frozen before that spec ratifies. Adding a variant to an exhaustive public enum
/// is a breaking change; adding one here is not. The cost is that matchers need a wildcard
/// arm, which is correct anyway for an error type a caller cannot exhaustively handle.
///
/// [`RegistrationError::PublishedAnnotationsFromFirstParty`] is the first use of that headroom
/// and it came from a caller NMCP-SPEC-002 had nothing to do with, exactly as
/// `Denial::MissingPathArgument` did at v1.1. Two markings taken for one spec's benefit have
/// now each paid for themselves against a different one.
///
/// I-032 is the marking finally paying out for the spec it was taken for, in
/// [`RegistrationError::UndeclaredSecretSlot`] and [`RegistrationError::MalformedSecretSlot`].
/// **SB-6's `MissingRequiredSecret` is not among them and arrives with I-036.** That refusal
/// asks whether the operator has stored the key a slot names, which needs a store to ask, and
/// I-032 lands the declaration only: no store, no sealer, no resolution (I-033, I-034). A
/// variant added now could be raised by nothing, and an enum variant nothing can produce is a
/// placeholder INV-6 forbids however carefully it is worded. The `non_exhaustive` marking is
/// exactly what makes adding it then a non-breaking change. Owner: I-036, with I-033's store
/// as its precondition.
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

    /// A first-party provider supplied [`crate::ToolContract::published_annotations`], which
    /// only a proxied upstream may carry (RC-21).
    ///
    /// The refusal is the point rather than tidiness. First-party annotations are derived from
    /// the declared authority by `ToolContract::to_list_entry`, so a first-party tool that also
    /// published its own would be two sources that can disagree about one tool, which is
    /// precisely the defect RC-A4 exists to make unrepresentable. An optional field with no
    /// refusal behind it would reintroduce it quietly, which is the whole reason section 4.4
    /// gained a variant rather than section 4.2 gaining a field on its own.
    #[error(
        "first-party tool {name:?} supplies published annotations, which only a proxied upstream may carry"
    )]
    PublishedAnnotationsFromFirstParty {
        /// The tool that was refused.
        name: String,
    },

    /// A declared `secret_ref` slot sits somewhere the tool's own input schema gives it no
    /// argument to bind, so nothing could ever be resolved into it (NMCP-SPEC-002 SB-3).
    ///
    /// The sibling of [`RegistrationError::UndeclaredPathArgument`] and refused for the same
    /// reason RC-5 refuses that one: a declaration the schema cannot deliver on is a defect an
    /// operator can fix at wire-up and a caller can only be confused by. The direction of the
    /// failure is what makes it worth a refusal rather than a warning. A slot the kernel
    /// cannot see is a slot nothing injects into, so the tool runs without the credential it
    /// declared, which fails open.
    #[error(
        "tool {name:?} declares a secret slot at {at:?}, which its own input schema does not define as a property"
    )]
    UndeclaredSecretSlot {
        /// The tool that was refused.
        name: String,
        /// JSON pointer into `input_schema` locating the annotation.
        at: String,
    },

    /// A declared `secret_ref` slot's injection modality is not one SB-4 defines, or is
    /// missing the name that SB-4 requires the contract rather than the caller to supply.
    #[error("tool {name:?} declares a malformed secret slot: {source}")]
    MalformedSecretSlot {
        /// The tool that was refused.
        name: String,
        /// What was wrong with the declaration.
        ///
        /// Named in the `Display` message as well as carried as a source, because an operator
        /// reads whatever the wire-up path printed and error chains are routinely not walked.
        #[source]
        source: SecretSlotError,
    },
}

impl SecretSlotError {
    /// Attribute a malformed secret-slot declaration to the tool that made it.
    ///
    /// The mapping lives beside the variants it maps rather than in the kernel that calls it,
    /// so a variant added to either enum is a variant added in the same file as the match that
    /// has to account for it. `nmcp-host` supplies the public tool name, because the
    /// local-to-public mapping belongs to the registry (RC-D6) and deriving it a second time
    /// here is the shape of the defect NMCP-SPEC-003 section 1 measures.
    #[must_use]
    pub fn at_tool(self, name: impl Into<String>) -> RegistrationError {
        let name = name.into();
        match self {
            Self::NotAProperty { pointer } => {
                RegistrationError::UndeclaredSecretSlot { name, at: pointer }
            }
            source => RegistrationError::MalformedSecretSlot { name, source },
        }
    }
}

/// The index every governed call resolves through.
///
/// Every method takes `&self` (RC-D7): wire-up has one mutability rule, so a registry behind
/// an `Arc` is still a registry an upstream can be registered into at runtime. The asymmetry
/// the base has, where `register` takes `&self` and `set_abac` takes `&mut self`, is
/// defensible as an accident and not as a design.
pub trait ToolRegistry: Send + Sync {
    /// Register a provider, or refuse it with a reason.
    ///
    /// All-or-nothing (RC-D5): a provider whose third tool is a duplicate registers none of
    /// its tools. A half-registered provider is a state no operator asked for and no error
    /// message can describe.
    ///
    /// # Errors
    ///
    /// Returns the [`RegistrationError`] naming what was refused and what an operator has to
    /// change. There is deliberately no `EmptyProvider`: an upstream legitimately declares no
    /// tools until its catalogue warms, so refusing an empty provider would refuse every
    /// upstream (RC-D5, RC-18).
    fn register(&self, provider: Arc<dyn ToolProvider>) -> Result<(), RegistrationError>;

    /// Re-read one provider's `contracts()` and rebuild its slice of the index.
    ///
    /// The path a `notifications/tools/list_changed` and the upstream poll both take.
    /// All-or-nothing like [`register`](ToolRegistry::register): a refresh that would
    /// introduce a duplicate leaves the previous index in place, because a provider whose
    /// catalogue half-updated is worse than one whose catalogue is stale, and the stale one
    /// at least matches what the last successful registration said.
    ///
    /// # Errors
    ///
    /// Returns the same [`RegistrationError`] set as [`register`](ToolRegistry::register).
    fn refresh(&self, provider_id: &str) -> Result<(), RegistrationError>;

    /// Remove a provider and all its tools. `true` if one was present.
    fn unregister_provider(&self, provider_id: &str) -> bool;

    /// Resolve a public tool name to its owner and local name.
    ///
    /// One hash lookup, no allocation beyond cloning the `Arc` and the local name. RC-9 is
    /// the requirement this signature exists to satisfy: dispatch resolves without asking any
    /// provider to enumerate anything.
    fn resolve(&self, public_name: &str) -> Option<(Arc<dyn ToolProvider>, String)>;

    /// The declaration for a public tool name.
    ///
    /// Returns an owned handle rather than a reference: the index sits behind an `RwLock`
    /// because RC-D7 requires `&self` mutation, and a reference into it cannot outlive the
    /// guard. Separate from [`resolve`](ToolRegistry::resolve) because authorization must read
    /// the declaration without thereby obtaining the ability to call.
    fn authority_of(&self, public_name: &str) -> Option<Arc<ToolAuthority>>;

    /// The `tools/list` array for a caller.
    fn list_for(&self, view: &CatalogView) -> Vec<Value>;
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
