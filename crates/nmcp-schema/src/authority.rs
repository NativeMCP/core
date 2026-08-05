//! Declared authority, held authority, and the seam where one becomes a decision.
//!
//! NMCP-SPEC-003 sections 4.1 and 4.5, RATIFIED v1.0. The signatures here are frozen at
//! ratification and implemented as written.
//!
//! The load-bearing decision is RC-D4: a declaration narrows, never widens, and never
//! exempts. A provider that declares [`nmcp_policy::Permission::Read`] is a provider
//! constraining itself; it is not a provider asserting that its caller holds Read. Every
//! check the kernel would have made without the declaration is still made, and the
//! declaration adds preconditions on top.

use std::collections::BTreeSet;
use std::path::Path;

use nmcp_policy::{Permission, RootRule, canonicalize_for_policy};
use serde_json::Value;

/// What a tool needs in order to run. Declared by the provider that owns the tool,
/// consumed by the kernel, and never a grant: see RC-D4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolAuthority {
    /// Root-scoped permission the caller must hold. `None` means the tool performs no
    /// root-scoped operation, which is a constraint on the tool, not an exemption for it.
    pub permission: Option<Permission>,

    /// Argument fields that carry filesystem paths, in the order the kernel tries them
    /// when resolving the matched root. Every name here must appear as a property of the
    /// tool's own input schema; one that does not is a registration error (RC-D5), because
    /// a path argument the schema cannot receive is a root resolution that can never fire.
    ///
    /// Empty with `permission: Some(p)` is legal and means "the caller must hold `p` on
    /// some root, and no root is resolved for this call". Five Windows tools are exactly
    /// this shape today, and the base reaches the same outcome by accident: its policy
    /// check returns early on an empty `path_args`, so their declared permission is never
    /// enforced. Making the case explicit turns that accident into a decision.
    pub path_args: Vec<String>,

    /// Capability grants required beyond the root permission. Each must resolve through
    /// `Permission::as_str`; one that does not is refused at authorization, not silently
    /// ignored (RC-D3).
    pub grants: Vec<CapabilityGrant>,

    /// Whether the tool changes observable state. Drives `readOnlyHint` and, for
    /// first-party providers only, the approval gate.
    pub effect: ToolEffect,

    /// Whether the tool reaches beyond this machine. Drives `openWorldHint`.
    pub reach: ToolReach,
}

/// A named capability grant, in the canonical form `Permission::as_str` produces. Closed
/// over `Permission` at contract version 1: see RC-D3 and G-3.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityGrant(String);

impl CapabilityGrant {
    /// Declare a grant by its canonical name.
    ///
    /// Deliberately infallible: a provider crate declares grants in a `const` context at
    /// startup, and a `Result` there would be checked by an `unwrap` the workspace lints
    /// forbid. Resolution failure surfaces at authorization as [`Denial::UnknownGrant`],
    /// which fails closed.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The canonical name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CapabilityGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a tool changes observable state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolEffect {
    /// Observes only. Creates, modifies, renames, moves and sends nothing.
    Observe,
    /// Changes state under a root the caller holds permission on.
    Mutate,
}

/// Whether a tool reaches beyond this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolReach {
    /// Confined to this machine.
    Local,
    /// Contacts a network peer. Drives `openWorldHint`.
    Remote,
}

/// What a caller actually holds, assembled by the kernel from effective policy and the
/// authenticated identity. The other half of every [`authorize`] call, and the half a
/// provider never sees or supplies.
#[derive(Debug, Clone)]
pub struct HeldAuthority {
    /// Roots the caller may reach, with the permissions granted on each.
    pub roots: Vec<RootRule>,
    /// Capability grants the caller holds, derived from the union of root permissions.
    /// Precomputed so [`authorize`] does not walk roots per grant.
    pub grants: BTreeSet<CapabilityGrant>,
    /// Authenticated caller, for `CallerToolAllowlist`. `None` for the CLI and every test
    /// path, which is the same population `CallContext.agent_id` leaves `None`.
    pub agent_id: Option<String>,
}

/// Proof that the kernel authorized a specific call. Constructible only by [`authorize`]:
/// the private field makes forging it `E0451` in any other crate. Consumed by
/// `ToolProvider::call`, which is what makes RC-A2 a property of the type system rather
/// than of the ring's good behaviour.
///
/// The compile-time half of that claim, as a pair of doc tests, which `rustdoc` builds as
/// their own crates linking this one. That is the population the seal is aimed at: a
/// provider crate holding a `&GrantedAuthority` and wanting one it was not handed.
///
/// The pair is what carries the assertion, not either test alone. `rustdoc` treats a
/// `compile_fail` block as passing on any compilation error, so a `compile_fail` test on
/// its own would stay green if the type were renamed out from under it. The second test
/// names the same path and asserts it resolves, so the only way both pass is that the type
/// exists under that name and a struct literal for it is refused.
///
/// ```compile_fail,E0451
/// // A struct literal cannot name a private field from another crate.
/// let forged = nmcp_schema::GrantedAuthority {
///     _seal: (),
///     matched_root: None,
///     permission: None,
/// };
/// ```
///
/// The only way to get one is to ask for a decision and be told yes.
///
/// ```
/// use nmcp_schema::{
///     Denial, GrantedAuthority, HeldAuthority, ToolAuthority, ToolEffect, ToolReach, authorize,
/// };
/// use std::collections::BTreeSet;
///
/// # fn main() -> Result<(), Denial> {
/// // A tool that needs no root-scoped authority and no capability grant.
/// let declared = ToolAuthority {
///     permission: None,
///     path_args: Vec::new(),
///     grants: Vec::new(),
///     effect: ToolEffect::Observe,
///     reach: ToolReach::Local,
/// };
/// let held = HeldAuthority {
///     roots: Vec::new(),
///     grants: BTreeSet::new(),
///     agent_id: None,
/// };
///
/// let granted: GrantedAuthority = authorize(&declared, &held, &serde_json::json!({}))?;
/// assert!(granted.matched_root().is_none());
/// assert!(granted.permission().is_none());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct GrantedAuthority {
    _seal: (),
    /// The root this call resolved to, if the tool declared path arguments.
    matched_root: Option<RootRule>,
    /// The permission that was checked, if the tool declared one.
    permission: Option<Permission>,
}

impl GrantedAuthority {
    /// The root this call resolved to, if the tool declared path arguments.
    #[must_use]
    pub fn matched_root(&self) -> Option<&RootRule> {
        self.matched_root.as_ref()
    }

    /// The permission that was checked, if the tool declared one.
    #[must_use]
    pub fn permission(&self) -> Option<Permission> {
        self.permission
    }
}

/// Why a call was refused at authorization.
///
/// `non_exhaustive` for the same reason as [`crate::RegistrationError`]: NMCP-SPEC-002
/// needs a `SecretUnavailable { rule }` variant for SB-8, and it must be able to add it
/// without a breaking change to a ratified contract. [`Denial::MissingPathArgument`] is
/// the first use of that headroom: it arrived in NMCP-SPEC-003 v1.1 after v1.0 shipped
/// without a way to say which of two root-resolution failures happened.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Denial {
    /// The caller holds no such permission on the root this call resolved to.
    #[error("caller holds no {0:?} permission on the resolved root")]
    Permission(Permission),
    /// A declared path argument was supplied and did not resolve to any configured root.
    #[error("path argument {arg:?} resolves outside every configured root")]
    OutsideRoots {
        /// The declared path argument the kernel tried.
        arg: String,
    },
    /// The tool requires a capability grant the caller does not hold.
    #[error("caller lacks required capability grant {0}")]
    MissingGrant(CapabilityGrant),
    /// The tool requires a capability grant no permission in this build defines.
    #[error("tool requires capability grant {0}, which no permission in this build defines")]
    UnknownGrant(CapabilityGrant),
    /// The tool declares no path authority and was called with one of its path arguments.
    #[error("tool declares no path authority but was called with path argument {arg:?}")]
    UndeclaredPathUse {
        /// The declared path argument the call supplied.
        arg: String,
    },
    /// The tool declares path arguments and the call supplied none of them, so no root
    /// could be resolved.
    ///
    /// Distinct from [`Denial::OutsideRoots`] on purpose, and the distinction is the
    /// reason the variant exists: an argument that was sent and points somewhere
    /// ungoverned and an argument that was never sent are different events, and an audit
    /// record that cannot tell them apart cannot answer which one happened.
    #[error(
        "tool declares path argument {arg:?} and the call supplied none of its declared path arguments"
    )]
    MissingPathArgument {
        /// The first declared path argument, which is the one the caller most likely
        /// meant to send.
        arg: String,
    },
    /// A secret this call references could not be resolved for it (NMCP-SPEC-002 SB-5,
    /// SB-8).
    ///
    /// Raised at ring stage 5b, the one stage this enum serves that is not [`authorize`]:
    /// binding evaluation refused, the store refused the resolution, or the declared slot
    /// carried something that is not a reference. The variant NMCP-SPEC-003 section 4.5
    /// named when it marked this enum `non_exhaustive`, added here by I-034 exactly as that
    /// headroom was reserved for.
    #[error("a secret this call references is unavailable: {rule} is the governing rule")]
    SecretUnavailable {
        /// The stable name of the governing rule (SB-8): a `BindingDenial` rule, a
        /// `ResolveError` rule, or one of the stage's own, such as
        /// `slot-requires-reference:<argument>` for a declared slot whose argument is not
        /// a reference.
        rule: String,
    },
}

/// The one place a declaration becomes a decision.
///
/// Takes what the tool says it needs and what the caller actually holds, and returns proof
/// or a reason. There is deliberately no other constructor of [`GrantedAuthority`]: RC-D4
/// is not a convention here, it is the absence of an alternative.
///
/// # Order of evaluation
///
/// Grants first, then path authority, and within grants every declared grant is resolved
/// before any is checked against what the caller holds. An unresolvable grant is a defect
/// in the declaration that no policy can satisfy; a grant that resolves but is not held is
/// a policy gap an operator can close. Reporting the closable one while a permanent defect
/// is also present sends the operator to widen policy for a call that would still be
/// refused, so the permanent defect is reported first (RC-D3, fail closed and loudly).
///
/// Of the three variants that carry an `arg`, exactly one can be reached when the call
/// supplied none of the tool's declared path arguments, and that is
/// [`Denial::MissingPathArgument`]. [`Denial::UndeclaredPathUse`] and
/// [`Denial::OutsideRoots`] both sit behind a successful lookup of a declared path
/// argument, so neither can name an argument the request did not carry. A future edit that
/// moved either out from behind that lookup would reintroduce exactly the ambiguity
/// NMCP-SPEC-003 v1.1 exists to remove.
///
/// # Errors
///
/// Returns the [`Denial`] naming what was refused. Every path out of this function that is
/// not `Ok` is a refusal with a reason a caller can be shown, and the variants do not
/// overlap: exactly one describes any given refusal, which is what lets the audit record
/// carry the reason rather than a category. [`Denial::SecretUnavailable`] is never returned
/// here: it belongs to ring stage 5b, which runs after this function and raises it through
/// the same refusal path (NMCP-SPEC-002 SB-5).
pub fn authorize(
    declared: &ToolAuthority,
    held: &HeldAuthority,
    args: &Value,
) -> Result<GrantedAuthority, Denial> {
    for grant in &declared.grants {
        if Permission::from_canonical(grant.as_str()).is_none() {
            return Err(Denial::UnknownGrant(grant.clone()));
        }
    }
    for grant in &declared.grants {
        if !held.grants.contains(grant) {
            return Err(Denial::MissingGrant(grant.clone()));
        }
    }

    let Some(permission) = declared.permission else {
        // RC-D4: a tool that declares no permission is not thereby unrestricted, it is
        // restricted to operations needing no root-scoped authority. A path argument
        // reaching it is refused rather than being a permission it silently gained. The
        // arguments the kernel can recognise as paths are the ones this tool declared as
        // paths; recognising any others would need a table of path-shaped argument names
        // in the kernel, which is the coupling RC-A1 denies.
        if let Some((arg, _)) = first_declared_path(declared, args) {
            return Err(Denial::UndeclaredPathUse { arg });
        }
        return Ok(GrantedAuthority {
            _seal: (),
            matched_root: None,
            permission: None,
        });
    };

    // Section 4.1: empty `path_args` with a declared permission means the caller must hold
    // it on some root and no root is resolved. This is the one place the contract
    // deliberately narrows what the base allowed (RC-6), because the base returns early
    // here and never enforces the permission at all.
    let Some(first_declared) = declared.path_args.first() else {
        if held
            .roots
            .iter()
            .any(|root| root.permissions.contains(&permission))
        {
            return Ok(GrantedAuthority {
                _seal: (),
                matched_root: None,
                permission: Some(permission),
            });
        }
        return Err(Denial::Permission(permission));
    };

    // The tool declared path arguments, so a root has to resolve or the call is refused.
    //
    // The two ways that fails are kept apart. An argument the call never supplied is
    // `MissingPathArgument`, naming the first declared one because that is the one the
    // caller most likely meant to send; an argument that was supplied and lands outside
    // every governed root is `OutsideRoots`, naming the one actually tried. NMCP-SPEC-003
    // v1.0 had only the second and this implementation had to fold the first into it,
    // which made the refusal state something untrue about a request that carried no such
    // argument. v1.1 added the variant so the audit record can say which happened.
    let Some((arg, path)) = first_declared_path(declared, args) else {
        return Err(Denial::MissingPathArgument {
            arg: first_declared.clone(),
        });
    };
    let Some(root) = resolve_root(&held.roots, &path) else {
        return Err(Denial::OutsideRoots { arg });
    };
    if !root.permissions.contains(&permission) {
        return Err(Denial::Permission(permission));
    }
    Ok(GrantedAuthority {
        _seal: (),
        matched_root: Some(root.clone()),
        permission: Some(permission),
    })
}

/// The first declared path argument present in `args` as a string, with its value.
///
/// First present wins, in declaration order, which is the order the provider chose and the
/// order the base's own path-argument lookup used.
fn first_declared_path(declared: &ToolAuthority, args: &Value) -> Option<(String, String)> {
    declared.path_args.iter().find_map(|name| {
        args.get(name)
            .and_then(Value::as_str)
            .map(|value| (name.clone(), value.to_string()))
    })
}

/// The most specific root containing `path`, or `None` when it is outside every root.
///
/// Longest canonical prefix wins, so a narrow restrictive root is never shadowed by a
/// broader one declared earlier, and the chosen root's permissions are authoritative. That
/// is `PolicyConfig::require`'s rule, reproduced here because [`HeldAuthority`] carries the
/// caller's effective roots rather than the whole policy. Canonicalization happens before
/// the containment test and never after it (INV-2).
fn resolve_root<'a>(roots: &'a [RootRule], path: &str) -> Option<&'a RootRule> {
    let normalized = canonicalize_for_policy(Path::new(path));
    let mut best: Option<(&RootRule, usize)> = None;
    for root in roots {
        let root_normalized = canonicalize_for_policy(&root.path);
        if normalized.starts_with(&root_normalized) {
            let len = root_normalized.as_os_str().len();
            if best.as_ref().is_none_or(|&(_, best_len)| len > best_len) {
                best = Some((root, len));
            }
        }
    }
    best.map(|(root, _)| root)
}
