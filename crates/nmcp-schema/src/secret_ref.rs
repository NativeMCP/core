//! The `secret_ref` slot type: the reference, the declaration, and the extractor.
//!
//! NMCP-SPEC-002 SB-2, SB-3 and SB-4, RATIFIED v1.0. I-032 lands the vocabulary and nothing
//! else. There is no store, no sealer, no resolution and no injection here; those are I-033
//! and I-034. What this module makes possible is that a tool can *declare* a secret slot and
//! the kernel can *recognise* one, so that when resolution lands there is somewhere for it to
//! attach.
//!
//! ## Where the declaration lives
//!
//! NMCP-SPEC-003 freezes [`ToolContract`] at five fields and `ToolAuthority` at five, and its
//! G-4 defers secret slots to NMCP-SPEC-002 rather than making room for them. SB-3 takes the
//! deferral and rules that the modality rides in the `secret_ref` slot's own schema
//! annotation, which is part of `input_schema` and therefore inside the one field G-4 handed
//! over. Nothing on either frozen descriptor changes, and no field is added to anything.
//!
//! The extractor is a free function rather than a method on [`ToolContract`], for the same
//! reason: section 4.2 of NMCP-SPEC-003 freezes an `impl` block as well as a struct, and a
//! second method in it would be an edit to frozen text for no gain. [`secret_slots`] reads the
//! descriptor from outside and the descriptor does not know it exists.
//!
//! ## The JSON shape
//!
//! A `secret_ref` slot is a property of the tool's own input schema carrying one extra
//! keyword, [`SECRET_SLOT_ANNOTATION`]:
//!
//! ```json
//! {
//!   "type": "object",
//!   "properties": {
//!     "credential": {
//!       "type": "string",
//!       "x-nmcp-secret-ref": { "inject": "header", "name": "Authorization" }
//!     },
//!     "message": { "type": "string" }
//!   }
//! }
//! ```
//!
//! The keyword is namespaced and `x-` prefixed because `input_schema` travels verbatim to
//! every MCP client on `tools/list`. JSON Schema requires an unrecognised keyword to be
//! ignored rather than to fail validation, so a client validating arguments against this
//! schema sees an ordinary string property and a client that understands the annotation sees
//! the slot. The whole modality sits inside one object under one key, so a slot cannot be
//! half-declared across sibling keywords that disagree, and the inner key names are the field
//! names of [`InjectionModality`] so there is one vocabulary rather than two.
//!
//! `message` above is the case SB-2 exists to protect. A reference in it is literal text.

use std::fmt;
use std::str::FromStr;

use serde_json::{Map, Value, json};

use crate::contract::ToolContract;

/// The scheme and path prefix every secret reference carries (SB-2).
pub const SECRET_REF_PREFIX: &str = "nmcp://secret/";

/// The longest secret name the SB-2 grammar admits, in characters.
pub const SECRET_NAME_MAX_CHARS: usize = 64;

/// The namespace label the OAuth broker owns (SB-2, and the SB-10 carve-out).
///
/// The broker's grant names are this label, a separator, and a provider id. The label is
/// defined once, here, because two spellings of one namespace is how a reserving parser and
/// the broker that owns the namespace come to disagree about what is reserved; `nmcp-oauth`
/// re-exports this constant rather than carrying a copy, and
/// [`RESERVED_SECRET_NAMESPACES`] is built from it rather than restating it.
pub const OAUTH_GRANT_NAMESPACE: &str = "oauth";

/// Namespaces no reference may address, whoever owns the store underneath.
///
/// [`OAUTH_GRANT_NAMESPACE`] is the OAuth broker's (SB-2). The broker's own grant names are
/// `oauth/<provider>`,
/// and the separator is outside the SB-2 character class, so the grammar alone already refuses
/// every one of them. That is exactly why this table cannot be only a prefix test: the one
/// name the grammar would otherwise admit is the bare namespace label, so the label is refused
/// too, and the check is written to hold whether or not the caller supplied the separator.
/// Refusing the label refuses one name a store could in principle hold, which is the narrowing
/// direction and the safe one for a deny rule.
///
/// The refusal happens in [`SecretRef::parse`] rather than in a filter applied afterwards,
/// because a filter is a thing a later caller can forget to call and a parse is not.
pub const RESERVED_SECRET_NAMESPACES: &[&str] = &[OAUTH_GRANT_NAMESPACE];

/// The input-schema keyword that marks a property as a `secret_ref` slot (SB-3).
pub const SECRET_SLOT_ANNOTATION: &str = "x-nmcp-secret-ref";

/// What ring stage 5b writes over a slot argument whose reference it resolved (I-034).
///
/// The provider receives material through the context channel, never through the argument,
/// so the reference is removed from the arguments the provider sees and this marker takes
/// its place. Removal is SB-A2's point applied one step further: a reference is a name and
/// not material, but a name that reaches a confused provider can reach a child process's
/// argv, and telling an attacker which credential a call carries is metadata the provider
/// has no use for. The marker is deliberately not in the SB-2 grammar and not a valid
/// reference, so a provider that mistakenly forwards it forwards an obviously inert token.
pub const SECRET_SLOT_MARKER: &str = "[nmcp:secret-slot]";

/// Where ring stage 5b reads a resolved tool's declared `secret_ref` slots (I-034).
///
/// The registry index in `nmcp-host` implements this over the slots it already extracts and
/// validates at registration, so the lookup is one hash probe and dispatch never asks a
/// provider to enumerate its catalogue (NMCP-SPEC-003 RC-9). It is a separate trait rather
/// than a method on [`crate::ToolRegistry`] because that trait's five methods are frozen by
/// NMCP-SPEC-003 section 4.4, while stage 5b's interior is exactly what that spec's 4.6
/// leaves to NMCP-SPEC-002; the surface the stage consumes is therefore this spec's to
/// define, and it lives here so the implementation in `nmcp-host` and the consumer in
/// `nmcp-router` can both see it without either depending on the other.
///
/// The composer must hand the ring the same object behind this trait and behind
/// [`crate::ToolRegistry`]: two indexes is how the slots the stage reads and the tool that
/// resolves come to disagree, which is the drift NMCP-SPEC-003 section 1 measures.
pub trait SecretSlotCatalog: Send + Sync {
    /// The declared `secret_ref` slots of the tool registered under `tool_name`, in
    /// argument-name order, or `None` when no tool is registered under that name.
    ///
    /// `Some(vec![])` and `None` differ on purpose: a registered tool with no slots is a
    /// tool stage 5b passes through untouched (SB-2 inertness), while an unregistered name
    /// is a tool the stage cannot read a declaration for, and what it does about that is
    /// the stage's fail-closed decision, not this trait's.
    fn secret_slots_of(&self, tool_name: &str) -> Option<Vec<SecretSlot>>;
}

/// The annotation key naming the injection modality.
const MODALITY_KEY: &str = "inject";

/// A reference to a stored secret, by name, in the SB-2 grammar.
///
/// Holds the name rather than the whole reference text, because the prefix is a constant and
/// storing it twice invites the two copies to disagree. [`fmt::Display`] renders the reference
/// back, so the round trip is total.
///
/// A reference is inert everywhere except a schema-declared slot (SB-2, SB-A1). Constructing
/// one proves that a string is well formed and proves nothing else: it does not mean the named
/// secret exists, that the caller may use it, or that anything will be resolved. Free-string
/// interpolation is rejected by SB-A1 and there is deliberately no function here that scans a
/// string for references.
///
/// No `serde` implementation, deliberately. The whole content of this type is an invariant
/// that [`SecretRef::parse`] establishes, and a derived `Deserialize` over a private `String`
/// would reconstruct one without ever running the parse, which is the invariant being handed
/// to whoever sends the JSON. A caller that has a `Value` calls the parse.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretRef(String);

impl SecretRef {
    /// Parse `text` as a secret reference.
    ///
    /// Total and fallible: every input either yields a reference or a [`SecretRefError`] that
    /// names what was wrong. The order of the checks is part of the contract, because the
    /// error an operator reads is chosen by it. The reserved-namespace check sits above the
    /// character-class check so that an operator holding an `oauth/<provider>` grant name
    /// learns that the namespace is reserved rather than that `/` is not in the class, which
    /// is true and useless. The length check sits above both so that no error message can echo
    /// an unbounded string.
    ///
    /// # Errors
    ///
    /// [`SecretRefError`], naming the prefix, the length, the reserved namespace or the first
    /// character outside the grammar.
    pub fn parse(text: &str) -> Result<Self, SecretRefError> {
        let Some(name) = text.strip_prefix(SECRET_REF_PREFIX) else {
            return Err(SecretRefError::NotASecretReference);
        };
        if name.is_empty() {
            return Err(SecretRefError::EmptyName);
        }
        let length = name.chars().count();
        if length > SECRET_NAME_MAX_CHARS {
            return Err(SecretRefError::NameTooLong { length });
        }
        if let Some(namespace) = reserved_namespace(name) {
            return Err(SecretRefError::ReservedNamespace {
                name: name.to_string(),
                namespace,
            });
        }
        if let Some((position, character)) = name
            .chars()
            .enumerate()
            .find(|(_, character)| !is_secret_name_char(*character))
        {
            return Err(SecretRefError::IllegalCharacter {
                name: name.to_string(),
                character,
                position,
            });
        }
        Ok(Self(name.to_string()))
    }

    /// The referenced name, without the scheme.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SECRET_REF_PREFIX}{}", self.0)
    }
}

impl FromStr for SecretRef {
    type Err = SecretRefError;

    /// Delegates to [`SecretRef::parse`], which is the one place the grammar is decided.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// Whether `character` is admitted by the SB-2 class `[a-z0-9_.-]`.
fn is_secret_name_char(character: char) -> bool {
    character.is_ascii_lowercase()
        || character.is_ascii_digit()
        || character == '_'
        || character == '.'
        || character == '-'
}

/// The reserved namespace `name` sits in, if any.
///
/// Matches the bare label and the label followed by its separator, so `oauth` and
/// `oauth/anything` are both refused and neither reading of "names a reserved namespace" is
/// the one that gets through.
fn reserved_namespace(name: &str) -> Option<&'static str> {
    RESERVED_SECRET_NAMESPACES
        .iter()
        .copied()
        .find(|namespace| {
            name.strip_prefix(namespace)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
}

/// Why a string is not a secret reference.
///
/// No variant carries the caller's original text. SB-1 forbids material in error text, and the
/// one plausible way material reaches a parser is a caller pasting a credential where a
/// reference belongs; echoing the input would copy it into whatever log the error reaches. The
/// variants raised after the prefix has been stripped and the length bounded do carry the
/// name, because a name is not material (SB-R2 lists names to the agent) and an operator
/// holding a name the grammar refuses cannot act on a message that will not say which.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretRefError {
    /// The text does not begin with [`SECRET_REF_PREFIX`].
    ///
    /// Says what a reference is rather than what was given, which is both the SB-1-safe answer
    /// and the more useful one: a caller who wrote something else needs the grammar, not their
    /// own input read back.
    #[error(
        "not a secret reference: a reference is \"nmcp://secret/<name>\" with <name> matching [a-z0-9_.-] and at most 64 characters"
    )]
    NotASecretReference,

    /// The prefix was present and nothing followed it.
    #[error("secret reference names nothing after \"nmcp://secret/\"")]
    EmptyName,

    /// The name is longer than the grammar admits.
    #[error(
        "secret name is {length} characters and the reference grammar admits at most {SECRET_NAME_MAX_CHARS}"
    )]
    NameTooLong {
        /// The name's length in characters.
        length: usize,
    },

    /// The name addresses a namespace that is owned elsewhere and unaddressable by reference.
    #[error(
        "secret name {name:?} is in the reserved {namespace:?} namespace, which its own broker owns and which no reference may address"
    )]
    ReservedNamespace {
        /// The refused name.
        name: String,
        /// The namespace it sits in, from [`RESERVED_SECRET_NAMESPACES`].
        namespace: &'static str,
    },

    /// The name contains a character the grammar does not admit.
    ///
    /// The remedy is in the message because this is the error a name created under an older
    /// grammar produces, and SB-2 records that three of those exist in the base and that none
    /// of them is this one. An uppercase name or one carrying a namespace separator is not
    /// migrated by this code and is not lost: SB-12's operator surface reports it and offers a
    /// rename, and until then it stays readable by that surface and unreferenceable here,
    /// which is a state an operator can see rather than one that fails at first use.
    #[error(
        "secret name {name:?} contains {character:?} at position {position}, which the reference grammar [a-z0-9_.-] does not admit; a name created under an older grammar stays readable by the operator surface and unreferenceable until it is renamed there"
    )]
    IllegalCharacter {
        /// The refused name, at most [`SECRET_NAME_MAX_CHARS`] characters because the length
        /// check runs first.
        name: String,
        /// The first character outside the class.
        character: char,
        /// Its zero-based position in characters, not bytes.
        position: usize,
    },
}

/// Where the kernel injects a resolved secret, and under what name.
///
/// Exactly two in contract version 1, and SB-4 fixes both. The enum is deliberately **not**
/// `#[non_exhaustive]`: a third modality is a revision of a ratified spec, and adding a variant
/// to an exhaustive public enum breaks every `match` on it, which is the loud signal that
/// wants to happen. [`InjectionModality::tag`] is the match that breaks first, and
/// [`InjectionModality::TAGS`] is the table the extractor and the tests read, so a variant
/// added without a tag does not compile and a tag added without a variant fails the test that
/// walks the table.
///
/// Both variants carry a name, and both names come from the tool's contract. There is no
/// variant meaning "wherever the caller says", and neither name is an `Option` that could fall
/// back to one: SB-A2 makes injection contract-defined rather than caller-defined, and this is
/// where that is a property of the type rather than of a check somebody remembered to write.
/// There is no argv modality, which is how T5 is asserted (SB-A2): a secret cannot reach a
/// process listing through a slot that does not exist.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum InjectionModality {
    /// Injected into the child process environment as `var`, by the executing provider.
    Env {
        /// The environment variable name, declared by the contract.
        var: String,
    },
    /// Injected into the outbound request as the header `name`, by the gateway.
    Header {
        /// The header name, declared by the contract.
        name: String,
    },
}

impl InjectionModality {
    /// Every modality tag SB-4 defines, in the order the specification lists them.
    ///
    /// Public because the closed vocabulary is part of the contract: a provider author and a
    /// schema author both need to know that the set has two members and which two.
    pub const TAGS: [&'static str; 2] = ["env", "header"];

    /// This modality's tag, as it appears under `inject` in the annotation.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Env { .. } => "env",
            Self::Header { .. } => "header",
        }
    }

    /// The annotation key carrying this modality's declared name.
    #[must_use]
    pub fn name_key(&self) -> &'static str {
        match self {
            Self::Env { .. } => "var",
            Self::Header { .. } => "name",
        }
    }

    /// The name the contract declared: the variable for `env`, the header for `header`.
    #[must_use]
    pub fn declared_name(&self) -> &str {
        match self {
            Self::Env { var } => var,
            Self::Header { name } => name,
        }
    }
}

/// One `secret_ref` slot, as a tool declares it.
///
/// The argument name and the injection modality, and nothing else. A slot says where a
/// reference may be supplied and where its resolved value goes; it says nothing about which
/// secret, because that is the caller's reference, and nothing about whether the caller may use
/// it, because that is SB-6's binding and it is not part of the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSlot {
    /// The argument name, which is a property of the tool's own input schema.
    pub arg: String,
    /// Where the resolved value is injected, and under what name.
    pub modality: InjectionModality,
}

impl SecretSlot {
    /// The annotation object this slot serialises to, for a schema builder.
    ///
    /// The inverse of what [`secret_slots`] reads, which is what makes the round trip
    /// testable in both directions rather than only from JSON inwards.
    #[must_use]
    pub fn annotation(&self) -> Value {
        json!({
            MODALITY_KEY: self.modality.tag(),
            self.modality.name_key(): self.modality.declared_name(),
        })
    }
}

/// Why a tool's declared `secret_ref` slots are not usable.
///
/// Every variant is a defect in a declaration rather than in a call, which is why the registry
/// turns each of them into a [`crate::RegistrationError`] and refuses the provider. A slot the
/// kernel cannot bind or cannot read is worse than no slot at all: the tool believes it
/// declared a credential and would run without one.
///
/// Exhaustive rather than `#[non_exhaustive]`, unlike [`crate::RegistrationError`]. That enum
/// is frozen by a ratified specification and needed headroom to grow without breaking it; this
/// one is owned by NMCP-SPEC-002 itself, and a new way for a declaration to be malformed
/// arrives with the specification revision that invents it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretSlotError {
    /// The annotation appears somewhere other than a direct property of the input schema.
    ///
    /// Reachable and worth refusing rather than theoretical. An annotation nested under
    /// `allOf`, `items`, `$defs` or a property's own `properties` names an argument the kernel
    /// has no top-level name to bind, so nothing would ever be resolved into it and the tool
    /// would run without the credential it declared. That is the same defect RC-5 refuses for
    /// `path_args`, one level in.
    #[error(
        "secret slot annotation at {pointer:?} is not a direct property of the input schema, so no argument can carry its reference"
    )]
    NotAProperty {
        /// RFC 6901 JSON pointer to the annotated subschema, so an operator can find it.
        pointer: String,
    },

    /// The annotation is present and is not an object.
    #[error(
        "secret slot on argument {arg:?} is not an object; the annotation carries the injection modality the contract declares"
    )]
    NotAnObject {
        /// The property the annotation sits on.
        arg: String,
    },

    /// The annotation declares no modality.
    #[error("secret slot on argument {arg:?} declares no {MODALITY_KEY:?} modality name")]
    MissingModality {
        /// The property the annotation sits on.
        arg: String,
    },

    /// The annotation declares a modality SB-4 does not define.
    #[error(
        "secret slot on argument {arg:?} declares injection modality {found:?}, and this contract version defines exactly \"env\" and \"header\""
    )]
    UnknownModality {
        /// The property the annotation sits on.
        arg: String,
        /// The tag that was declared.
        found: String,
    },

    /// The modality's name is absent, is not a string, or is empty.
    #[error(
        "secret slot on argument {arg:?} declares modality {modality:?} without a non-empty {key:?} string, and that name is supplied by the contract rather than by the caller"
    )]
    MissingModalityName {
        /// The property the annotation sits on.
        arg: String,
        /// The modality that was declared.
        modality: &'static str,
        /// The annotation key that should have carried the name.
        key: &'static str,
    },

    /// The annotation carries a key the declared modality does not define.
    ///
    /// Refused rather than ignored, which is the same argument NMCP-SPEC-002 G-3 makes against
    /// a configuration format that tolerates a key it does not read: a `name` beside an `env`
    /// modality is somebody declaring a header injection that will not happen, and silence
    /// tells them it will.
    #[error(
        "secret slot on argument {arg:?} declares modality {modality:?} with unrecognised key {key:?}; {modality:?} takes {MODALITY_KEY:?} and {expected:?}"
    )]
    UnknownAnnotationKey {
        /// The property the annotation sits on.
        arg: String,
        /// The modality that was declared.
        modality: &'static str,
        /// The key that is not part of it.
        key: String,
        /// The key that modality does define.
        expected: &'static str,
    },
}

/// Every `secret_ref` slot `contract` declares, in argument-name order.
///
/// Reads the declaration back out of `input_schema` and validates it. An empty result is the
/// answer for every tool in this workspace today and is not a failure: a tool that declares no
/// slot has none, which is a different thing from one whose declaration could not be read.
///
/// Deterministic in both success and failure. Slots come back in the order `properties`
/// iterates, which `serde_json` keeps sorted, and when several things are wrong the refusal
/// names the one earliest in document order, so two runs over one schema do not disagree about
/// which defect to report.
///
/// This is the whole of what recognition means at I-032. Nothing here resolves a reference,
/// consults a store, or reads a call's arguments: the parameter is a `&ToolContract` and there
/// is no second parameter through which a caller's data could arrive.
///
/// # Errors
///
/// [`SecretSlotError`] when an annotation sits where no argument can carry it, or when a
/// modality is malformed. The registry turns both into a registration refusal.
pub fn secret_slots(contract: &ToolContract) -> Result<Vec<SecretSlot>, SecretSlotError> {
    let mut slots = Vec::new();
    for (pointer, arg, annotation) in annotations_in(&contract.input_schema) {
        let Some(arg) = arg else {
            return Err(SecretSlotError::NotAProperty { pointer });
        };
        let modality = parse_modality(&arg, annotation)?;
        slots.push(SecretSlot { arg, modality });
    }
    Ok(slots)
}

/// Every occurrence of the annotation in `schema`, with its pointer and the top-level property
/// it annotates when it annotates one.
///
/// Walks the whole document rather than only `properties`, because the occurrences that are
/// **not** properties are exactly the ones worth refusing, and a walk that only looked where
/// the answer is supposed to be would silently drop them.
///
/// Iterative with an explicit stack rather than recursive. A proxied upstream's `input_schema`
/// is somebody else's JSON, and a deeply nested one is a stack overflow, which is an abort the
/// workspace's panic lints cannot catch and no audit record survives.
fn annotations_in(schema: &Value) -> Vec<(String, Option<String>, &Value)> {
    /// Where a subschema sits relative to the document root, to the depth that matters.
    enum Position {
        /// The document root.
        Root,
        /// The root's own `properties` map.
        Properties,
        /// A direct property of the root, carrying its name.
        Property(String),
        /// Anywhere else, at any depth.
        Elsewhere,
    }

    let mut found = Vec::new();
    let mut stack = vec![(String::new(), Position::Root, schema)];
    while let Some((pointer, position, value)) = stack.pop() {
        match value {
            Value::Object(map) => {
                if let Some(annotation) = map.get(SECRET_SLOT_ANNOTATION) {
                    let arg = match &position {
                        Position::Property(name) => Some(name.clone()),
                        _ => None,
                    };
                    found.push((pointer.clone(), arg, annotation));
                }
                for (key, child) in map {
                    if key == SECRET_SLOT_ANNOTATION {
                        continue;
                    }
                    let child_position = match (&position, key.as_str()) {
                        (Position::Root, "properties") => Position::Properties,
                        (Position::Properties, name) => Position::Property(name.to_string()),
                        _ => Position::Elsewhere,
                    };
                    stack.push((
                        format!("{pointer}/{}", escape_pointer_token(key)),
                        child_position,
                        child,
                    ));
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    stack.push((format!("{pointer}/{index}"), Position::Elsewhere, item));
                }
            }
            _ => {}
        }
    }
    // The stack yields children in reverse, so sorting by pointer restores document order and
    // makes both the slot list and the choice of which defect to report deterministic.
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

/// RFC 6901 token escaping, so a property name containing `/` or `~` produces a pointer that
/// still addresses it.
fn escape_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Read one annotation object as a modality.
fn parse_modality(arg: &str, annotation: &Value) -> Result<InjectionModality, SecretSlotError> {
    let Some(object) = annotation.as_object() else {
        return Err(SecretSlotError::NotAnObject {
            arg: arg.to_string(),
        });
    };
    let Some(tag) = object.get(MODALITY_KEY).and_then(Value::as_str) else {
        return Err(SecretSlotError::MissingModality {
            arg: arg.to_string(),
        });
    };
    // The modality is built from its own tag before its name is read, so `name_key` and the
    // accepted key set come from the same `match` the enum forces rather than from a table
    // beside it that could drift.
    let empty = match tag {
        "env" => InjectionModality::Env { var: String::new() },
        "header" => InjectionModality::Header {
            name: String::new(),
        },
        other => {
            return Err(SecretSlotError::UnknownModality {
                arg: arg.to_string(),
                found: other.to_string(),
            });
        }
    };
    let (modality_tag, name_key) = (empty.tag(), empty.name_key());
    reject_unknown_keys(arg, object, modality_tag, name_key)?;
    let name = object
        .get(name_key)
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| SecretSlotError::MissingModalityName {
            arg: arg.to_string(),
            modality: modality_tag,
            key: name_key,
        })?
        .to_string();
    Ok(match empty {
        InjectionModality::Env { .. } => InjectionModality::Env { var: name },
        InjectionModality::Header { .. } => InjectionModality::Header { name },
    })
}

/// Refuse any annotation key the declared modality does not define.
fn reject_unknown_keys(
    arg: &str,
    object: &Map<String, Value>,
    modality: &'static str,
    name_key: &'static str,
) -> Result<(), SecretSlotError> {
    if let Some(key) = object
        .keys()
        .find(|key| key.as_str() != MODALITY_KEY && key.as_str() != name_key)
    {
        return Err(SecretSlotError::UnknownAnnotationKey {
            arg: arg.to_string(),
            modality,
            key: key.clone(),
            expected: name_key,
        });
    }
    Ok(())
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
    use super::*;
    use crate::authority::{ToolAuthority, ToolEffect, ToolReach};

    // - Fixtures -

    fn contract(input_schema: Value) -> ToolContract {
        ToolContract {
            name: "call".to_string(),
            description: "a tool".to_string(),
            input_schema,
            authority: ToolAuthority {
                permission: None,
                path_args: Vec::new(),
                grants: Vec::new(),
                effect: ToolEffect::Observe,
                reach: ToolReach::Local,
            },
            published_annotations: None,
        }
    }

    /// An object schema whose named properties are supplied verbatim.
    fn schema(properties: &Value) -> Value {
        json!({ "type": "object", "properties": properties })
    }

    // - SB-2: the reference grammar -

    #[test]
    fn a_well_formed_reference_parses_and_yields_its_name() {
        let parsed = SecretRef::parse("nmcp://secret/api.token-1_v2").unwrap();
        assert_eq!(parsed.name(), "api.token-1_v2");
    }

    /// Every character the SB-2 class admits, in one name, so a class narrowed by a later edit
    /// fails here rather than at whichever operator's key used the character that was dropped.
    #[test]
    fn the_grammar_admits_exactly_its_stated_class() {
        let all = "abcdefghijklmnopqrstuvwxyz0123456789_.-";
        assert!(SecretRef::parse(&format!("{SECRET_REF_PREFIX}{all}")).is_ok());
        for refused in ['A', '/', ' ', ':', '*', '\\', 'é'] {
            let text = format!("{SECRET_REF_PREFIX}name{refused}");
            assert!(
                matches!(
                    SecretRef::parse(&text),
                    Err(SecretRefError::IllegalCharacter { character, .. }) if character == refused
                ),
                "{refused:?} must be refused by name"
            );
        }
    }

    #[test]
    fn the_length_bound_is_inclusive_at_sixty_four() {
        let sixty_four = "a".repeat(SECRET_NAME_MAX_CHARS);
        assert!(SecretRef::parse(&format!("{SECRET_REF_PREFIX}{sixty_four}")).is_ok());
        let sixty_five = "a".repeat(SECRET_NAME_MAX_CHARS + 1);
        assert_eq!(
            SecretRef::parse(&format!("{SECRET_REF_PREFIX}{sixty_five}")),
            Err(SecretRefError::NameTooLong { length: 65 })
        );
    }

    #[test]
    fn parsing_is_total_over_the_shapes_that_are_not_references() {
        assert_eq!(
            SecretRef::parse(""),
            Err(SecretRefError::NotASecretReference)
        );
        assert_eq!(
            SecretRef::parse("nmcp://secrets/x"),
            Err(SecretRefError::NotASecretReference)
        );
        assert_eq!(
            SecretRef::parse("https://example.invalid/secret/x"),
            Err(SecretRefError::NotASecretReference)
        );
        assert_eq!(
            SecretRef::parse("nmcp://secret/"),
            Err(SecretRefError::EmptyName)
        );
    }

    /// SB-1. A caller who pastes a credential where a reference belongs must not have it
    /// copied into an error string, and the error an unparseable input produces is the one
    /// that would do it.
    #[test]
    fn a_refusal_never_echoes_the_input_it_could_not_parse() {
        let material = "an-unusually-guessable-credential";
        let refusal = SecretRef::parse(material).unwrap_err();
        assert!(!format!("{refusal}").contains(material));
        assert!(!format!("{refusal:?}").contains(material));
    }

    /// SB-2's reserved namespace, refused at parse rather than filtered afterwards.
    ///
    /// Both readings are covered because both are reachable: `oauth/<provider>` is the shape
    /// the broker's own grants take, and bare `oauth` is the one shape the character class
    /// would otherwise admit, which is what makes this check more than a restatement of the
    /// grammar.
    #[test]
    fn the_reserved_namespace_is_unaddressable_by_any_reference() {
        for name in ["oauth", "oauth/provider", "oauth/a.b-c"] {
            let refused = SecretRef::parse(&format!("{SECRET_REF_PREFIX}{name}"));
            assert!(
                matches!(
                    refused,
                    Err(SecretRefError::ReservedNamespace { namespace, .. }) if namespace == "oauth"
                ),
                "{name:?} must be refused as reserved, got {refused:?}"
            );
        }
    }

    /// The refusal must not widen past the namespace it names: a key whose name merely starts
    /// with the same letters is an ordinary key.
    #[test]
    fn a_name_that_only_begins_like_the_reserved_namespace_is_ordinary() {
        assert!(SecretRef::parse("nmcp://secret/oauth_provider").is_ok());
        assert!(SecretRef::parse("nmcp://secret/oauthority").is_ok());
    }

    /// SB-2 records three grammars in the base and that none of them is this one. This pins
    /// what an operator holding a name from each of the other two is told.
    #[test]
    fn a_legacy_name_is_refused_with_the_remedy_in_the_message() {
        let uppercase = SecretRef::parse("nmcp://secret/API_TOKEN").unwrap_err();
        let message = format!("{uppercase}");
        assert!(message.contains("API_TOKEN"), "{message}");
        assert!(message.contains("[a-z0-9_.-]"), "{message}");
        assert!(message.contains("renamed"), "{message}");

        // The grant grammar's separator reaches the reserved refusal, not the character class,
        // because "the namespace is reserved" is actionable and "/ is not in the class" is not.
        let grant = SecretRef::parse("nmcp://secret/oauth/provider").unwrap_err();
        assert!(matches!(grant, SecretRefError::ReservedNamespace { .. }));
    }

    #[test]
    fn display_and_parse_round_trip() {
        for name in [
            "a",
            "a.b",
            "a-b",
            "a_b",
            "0",
            &"z".repeat(SECRET_NAME_MAX_CHARS),
        ] {
            let text = format!("{SECRET_REF_PREFIX}{name}");
            let parsed = SecretRef::parse(&text).unwrap();
            assert_eq!(parsed.to_string(), text);
            assert_eq!(SecretRef::parse(&parsed.to_string()).unwrap(), parsed);
        }
    }

    #[test]
    fn from_str_is_the_same_parse() {
        assert_eq!(
            "nmcp://secret/x".parse::<SecretRef>(),
            SecretRef::parse("nmcp://secret/x")
        );
        assert_eq!("nope".parse::<SecretRef>(), SecretRef::parse("nope"));
    }

    // - SB-4: the two modalities -

    /// The closed vocabulary, from three directions at once. The table has two entries, every
    /// entry round-trips through the annotation the extractor reads, and the `match` in `tag`
    /// is what stops compiling if a third variant is added without a specification revision.
    #[test]
    fn exactly_two_injection_modalities_exist_and_both_round_trip() {
        assert_eq!(InjectionModality::TAGS.len(), 2);
        let both = [
            InjectionModality::Env {
                var: "SERVICE_TOKEN".to_string(),
            },
            InjectionModality::Header {
                name: "Authorization".to_string(),
            },
        ];
        for (modality, tag) in both.iter().zip(InjectionModality::TAGS) {
            assert_eq!(modality.tag(), tag);
            let slot = SecretSlot {
                arg: "credential".to_string(),
                modality: modality.clone(),
            };
            let read = secret_slots(&contract(schema(&json!({
                "credential": { "type": "string", SECRET_SLOT_ANNOTATION: slot.annotation() },
            }))))
            .unwrap();
            assert_eq!(read, vec![slot]);
        }
        // Names the variants out loud, so a third one added without a specification revision
        // fails here as well as at `tag`.
        for modality in &both {
            match modality {
                InjectionModality::Env { var } => assert_eq!(var, "SERVICE_TOKEN"),
                InjectionModality::Header { name } => assert_eq!(name, "Authorization"),
            }
        }
    }

    /// SB-A2 and T5. The modality vocabulary has no argv member, so a slot cannot ask for a
    /// secret on a command line, and the refusal says the set is closed.
    #[test]
    fn there_is_no_argv_modality_to_declare() {
        assert!(!InjectionModality::TAGS.contains(&"argv"));
        let refused = secret_slots(&contract(schema(&json!({
            "credential": {
                "type": "string",
                SECRET_SLOT_ANNOTATION: { "inject": "argv", "var": "TOKEN" },
            },
        }))))
        .unwrap_err();
        assert_eq!(
            refused,
            SecretSlotError::UnknownModality {
                arg: "credential".to_string(),
                found: "argv".to_string(),
            }
        );
        assert!(format!("{refused}").contains("exactly \"env\" and \"header\""));
    }

    // - SB-3: the declaration, read back out of the input schema -

    #[test]
    fn a_schema_declaring_no_slot_yields_none() {
        assert_eq!(
            secret_slots(&contract(schema(
                &json!({ "message": { "type": "string" } })
            )))
            .unwrap(),
            Vec::new()
        );
        assert_eq!(
            secret_slots(&contract(json!({ "type": "object" }))).unwrap(),
            Vec::new()
        );
        assert_eq!(secret_slots(&contract(Value::Null)).unwrap(), Vec::new());
    }

    #[test]
    fn several_slots_come_back_in_argument_order_beside_ordinary_properties() {
        let read = secret_slots(&contract(schema(&json!({
            "message": { "type": "string" },
            "bearer": {
                "type": "string",
                SECRET_SLOT_ANNOTATION: { "inject": "header", "name": "Authorization" },
            },
            "api_key": {
                "type": "string",
                SECRET_SLOT_ANNOTATION: { "inject": "env", "var": "API_KEY" },
            },
        }))))
        .unwrap();
        assert_eq!(
            read,
            vec![
                SecretSlot {
                    arg: "api_key".to_string(),
                    modality: InjectionModality::Env {
                        var: "API_KEY".to_string()
                    },
                },
                SecretSlot {
                    arg: "bearer".to_string(),
                    modality: InjectionModality::Header {
                        name: "Authorization".to_string()
                    },
                },
            ]
        );
    }

    /// The round trip both ways: a declaration read into slots, re-emitted from those slots,
    /// and read again to the same slots. The re-emission is what makes this more than an
    /// assertion that the reader agrees with a literal somebody typed.
    #[test]
    fn slots_round_trip_through_the_annotation_they_serialise_to() {
        let declared = vec![
            SecretSlot {
                arg: "api_key".to_string(),
                modality: InjectionModality::Env {
                    var: "API_KEY".to_string(),
                },
            },
            SecretSlot {
                arg: "bearer".to_string(),
                modality: InjectionModality::Header {
                    name: "X-Service-Authorization".to_string(),
                },
            },
        ];
        let mut properties = Map::new();
        for slot in &declared {
            properties.insert(
                slot.arg.clone(),
                json!({ "type": "string", SECRET_SLOT_ANNOTATION: slot.annotation() }),
            );
        }
        let rebuilt = contract(schema(&Value::Object(properties)));
        assert_eq!(secret_slots(&rebuilt).unwrap(), declared);
        assert_eq!(
            declared[0].annotation(),
            json!({ "inject": "env", "var": "API_KEY" })
        );
        assert_eq!(
            declared[1].annotation(),
            json!({ "inject": "header", "name": "X-Service-Authorization" })
        );
    }

    /// A slot the kernel has no argument name to bind is refused rather than dropped. Each of
    /// these places the annotation somewhere a reader that only walked `properties` would not
    /// have looked, which is the whole reason the walk covers the document.
    #[test]
    fn a_slot_that_is_not_a_property_is_refused_with_a_pointer_to_it() {
        let cases = [
            (
                json!({ "type": "object", "allOf": [ { "properties": {
                    "credential": { SECRET_SLOT_ANNOTATION: { "inject": "env", "var": "T" } },
                } } ] }),
                "/allOf/0/properties/credential",
            ),
            (
                schema(&json!({ "config": { "type": "object", "properties": {
                    "credential": { SECRET_SLOT_ANNOTATION: { "inject": "env", "var": "T" } },
                } } })),
                "/properties/config/properties/credential",
            ),
            (
                json!({
                    "type": "object",
                    SECRET_SLOT_ANNOTATION: { "inject": "env", "var": "T" },
                }),
                "",
            ),
            (
                json!({ "type": "object", "$defs": {
                    "credential": { SECRET_SLOT_ANNOTATION: { "inject": "env", "var": "T" } },
                } }),
                "/$defs/credential",
            ),
        ];
        for (input_schema, pointer) in cases {
            assert_eq!(
                secret_slots(&contract(input_schema)).unwrap_err(),
                SecretSlotError::NotAProperty {
                    pointer: pointer.to_string(),
                }
            );
        }
    }

    #[test]
    fn a_pointer_escapes_the_characters_rfc_6901_reserves() {
        let refused = secret_slots(&contract(json!({ "type": "object", "$defs": {
            "a/b~c": { SECRET_SLOT_ANNOTATION: { "inject": "env", "var": "T" } },
        } })))
        .unwrap_err();
        assert_eq!(
            refused,
            SecretSlotError::NotAProperty {
                pointer: "/$defs/a~1b~0c".to_string(),
            }
        );
    }

    /// Every way a modality can be malformed, with the exact refusal asserted rather than
    /// "some error", because a check that fires for the wrong reason keeps passing after the
    /// reason it was testing has gone.
    #[test]
    fn every_malformed_modality_is_refused_by_name() {
        let cases: Vec<(Value, SecretSlotError)> = vec![
            (
                json!("env"),
                SecretSlotError::NotAnObject {
                    arg: "credential".to_string(),
                },
            ),
            (
                json!({ "var": "TOKEN" }),
                SecretSlotError::MissingModality {
                    arg: "credential".to_string(),
                },
            ),
            (
                json!({ "inject": 1, "var": "TOKEN" }),
                SecretSlotError::MissingModality {
                    arg: "credential".to_string(),
                },
            ),
            (
                json!({ "inject": "environment", "var": "TOKEN" }),
                SecretSlotError::UnknownModality {
                    arg: "credential".to_string(),
                    found: "environment".to_string(),
                },
            ),
            (
                json!({ "inject": "env" }),
                SecretSlotError::MissingModalityName {
                    arg: "credential".to_string(),
                    modality: "env",
                    key: "var",
                },
            ),
            (
                json!({ "inject": "env", "var": "" }),
                SecretSlotError::MissingModalityName {
                    arg: "credential".to_string(),
                    modality: "env",
                    key: "var",
                },
            ),
            (
                json!({ "inject": "header", "name": 7 }),
                SecretSlotError::MissingModalityName {
                    arg: "credential".to_string(),
                    modality: "header",
                    key: "name",
                },
            ),
            (
                json!({ "inject": "env", "name": "Authorization" }),
                SecretSlotError::UnknownAnnotationKey {
                    arg: "credential".to_string(),
                    modality: "env",
                    key: "name".to_string(),
                    expected: "var",
                },
            ),
            (
                json!({ "inject": "header", "name": "Authorization", "from": "caller" }),
                SecretSlotError::UnknownAnnotationKey {
                    arg: "credential".to_string(),
                    modality: "header",
                    key: "from".to_string(),
                    expected: "name",
                },
            ),
        ];
        for (annotation, expected) in cases {
            let refused = secret_slots(&contract(schema(&json!({
                "credential": { "type": "string", SECRET_SLOT_ANNOTATION: annotation },
            }))))
            .unwrap_err();
            assert_eq!(refused, expected, "for annotation {annotation}");
        }
    }

    // - SB-2 and SB-A1: inertness -

    /// The property this pull request exists to keep true.
    ///
    /// A well-formed reference in a parameter that is not a declared slot is literal text. It
    /// is well formed, which is the point: well-formedness is not what makes a reference
    /// resolve, declaration is, and a future contributor adding a convenience string scan
    /// makes this test red rather than making the server interesting.
    ///
    /// Three assertions, because the scan could be added in three places. The extractor names
    /// only the declared slot. The arguments a caller sent are not read by anything here and
    /// are unchanged after everything this change adds has run over the contract. And with the
    /// annotation removed, the identical arguments produce no slots at all, so it is the
    /// declaration doing the work rather than the text of the value.
    #[test]
    fn a_reference_in_a_free_text_argument_is_literal_text() {
        let reference = "nmcp://secret/x";
        assert!(
            SecretRef::parse(reference).is_ok(),
            "the fixture must be a well-formed reference or it proves nothing"
        );

        let declared = contract(schema(&json!({
            "credential": {
                "type": "string",
                SECRET_SLOT_ANNOTATION: { "inject": "env", "var": "SERVICE_TOKEN" },
            },
            "message": { "type": "string" },
            "note": { "type": "string", "description": "free text" },
        })));

        let arguments = json!({
            "credential": reference,
            "message": reference,
            "note": format!("see {reference} for the key, and nmcp://secret/y for the other"),
        });
        let untouched = arguments.clone();

        let slots = secret_slots(&declared).unwrap();
        assert_eq!(
            slots
                .iter()
                .map(|slot| slot.arg.as_str())
                .collect::<Vec<_>>(),
            vec!["credential"],
            "only a declared slot is a slot, whatever any other argument happens to say"
        );
        assert_eq!(
            arguments, untouched,
            "nothing this change adds reads or rewrites a caller's arguments"
        );

        let undeclared = contract(schema(&json!({
            "credential": { "type": "string" },
            "message": { "type": "string" },
            "note": { "type": "string", "description": "free text" },
        })));
        assert_eq!(
            secret_slots(&undeclared).unwrap(),
            Vec::new(),
            "with the annotation gone the same three references are three strings"
        );
    }
}
