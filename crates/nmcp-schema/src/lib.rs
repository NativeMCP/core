//! `nmcp-schema`
//!
//! Part of the NativeMCP `core` workspace. The governance invariants in
//! `docs/GOVERNANCE.md` are normative for every item in this crate.
//!
//! ## The provider contract
//!
//! NMCP-SPEC-003, RATIFIED v1.0, puts the provider contract here rather than in the
//! kernel, and RC-D1 gives three reasons. It breaks the dependency cycle instead of
//! reproducing it, so a crate like `nmcp-memory` can depend on the contract and ship its
//! own provider. A provider crate then depends on the contract rather than on the kernel,
//! which is what makes the open-core split hold at the dependency level rather than by
//! convention. And the contract gets a version number that already exists here and already
//! has refusal semantics, in [`accepts_contract_version`].
//!
//! This crate's only direct workspace dependency is `nmcp-policy` (RC-1), which depends on
//! `nmcp-identity` and nothing else in the workspace, so the edge closes no cycle.
//!
//! ## What is here, and what is not here yet
//!
//! I-047a landed the value types: [`ToolAuthority`] and its parts, [`ToolContract`],
//! [`GrantedAuthority`], [`Denial`], [`authorize`], [`RegistrationError`], [`CatalogView`],
//! [`MemoryScope`], and the public tool name derivation. I-047b added the two types
//! section 4.3 moves alongside the trait: [`CallContext`], with `matched_root` private
//! behind a reader and a private [`ResolvedSecrets`] channel, and [`ToolCallResult`]
//! unchanged. I-047c adds [`ToolProvider`] itself and the [`ToolRegistry`] trait section 4.4
//! freezes, whose index lives in `nmcp-host`. `nmcp-router` re-exports every moved item, so
//! no `use` path breaks.
//!
//! Named gaps, per INV-6, with owners rather than as silent absences. [`ToolProvider::call`]
//! still takes four parameters and [`ToolProvider`] still carries
//! [`tool_names`](ToolProvider::tool_names) and [`tool_list`](ToolProvider::tool_list).
//! Section 4.3 adds `granted: &GrantedAuthority` to `call` and deletes both methods, and that
//! is one atomic change rather than three: a provider cannot be handed a
//! [`GrantedAuthority`] until dispatch produces one, dispatch cannot produce one until it
//! calls [`authorize`], and [`authorize`] needs the declaration only
//! [`contracts`](ToolProvider::contracts) supplies. Owner I-047d, which also lands RC-6's
//! property test, because that test's oracle is the base's per-tool policy table and the
//! table only stops being authoritative once dispatch reads the declaration instead.

mod authority;
mod context;
mod contract;
mod names;
mod provider;
mod registry;
mod scope;
mod secrets;

pub use authority::{
    CapabilityGrant, Denial, GrantedAuthority, HeldAuthority, ToolAuthority, ToolEffect, ToolReach,
    authorize,
};
pub use context::{CallContext, ToolCallResult};
pub use contract::ToolContract;
pub use names::{
    DELETE_DENIED_NAMES, contains_delete_intent, is_valid_public_tool_name, public_tool_name,
};
pub use provider::ToolProvider;
pub use registry::{CatalogView, RegistrationError, ToolRegistry};
pub use scope::MemoryScope;
pub use secrets::ResolvedSecrets;

/// Semantic version of this crate, taken from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate identity as it appears in audit records and capability manifests.
pub const COMPONENT: &str = "nmcp-schema";

/// Version of the tool-contract schema this build emits and accepts.
///
/// Independent of both the crate version and the MCP protocol revision:
/// the contract shape and the wire format change on different schedules,
/// and collapsing them into one number loses the ability to say which
/// one moved.
pub const CONTRACT_SCHEMA_VERSION: u32 = 1;

/// Returns `true` when a peer advertising `version` can be understood.
///
/// Backward compatible within a major version: this build reads any
/// contract at or below its own version and refuses anything newer
/// rather than guessing at fields it does not know.
#[must_use]
pub fn accepts_contract_version(version: u32) -> bool {
    version > 0 && version <= CONTRACT_SCHEMA_VERSION
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
    use nmcp_policy::{Permission, RootRule};
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    #[test]
    fn current_version_is_accepted() {
        assert!(accepts_contract_version(CONTRACT_SCHEMA_VERSION));
    }

    #[test]
    fn future_version_is_refused_not_guessed_at() {
        assert!(!accepts_contract_version(CONTRACT_SCHEMA_VERSION + 1));
    }

    #[test]
    fn zero_is_not_a_version() {
        assert!(!accepts_contract_version(0));
    }

    // - Fixtures -

    /// A root under the system temporary directory, which exists on every runner, so
    /// `canonicalize_for_policy` resolves it the same way policy would at run time.
    fn root(id: &str, suffix: &str, permissions: &[Permission]) -> RootRule {
        RootRule {
            id: id.to_string(),
            path: std::env::temp_dir().join(suffix),
            permissions: permissions.iter().copied().collect(),
        }
    }

    fn inside(root: &RootRule, leaf: &str) -> String {
        root.path.join(leaf).display().to_string()
    }

    fn held(roots: Vec<RootRule>, grants: &[&str]) -> HeldAuthority {
        HeldAuthority {
            roots,
            grants: grants.iter().map(|g| CapabilityGrant::new(*g)).collect(),
            agent_id: None,
        }
    }

    fn declared(permission: Option<Permission>, path_args: &[&str]) -> ToolAuthority {
        ToolAuthority {
            permission,
            path_args: path_args.iter().map(|a| (*a).to_string()).collect(),
            grants: Vec::new(),
            effect: ToolEffect::Observe,
            reach: ToolReach::Local,
        }
    }

    // - authorize: the permission by held by path-state grid -

    /// RC-D4 and RC-6, in the strongest self-contained form available at I-047a.
    ///
    /// Every `Permission` crossed with held and not-held, crossed with the three states a
    /// declared path argument can be in: present and inside a root, present and outside
    /// every root, and absent. The exact `Denial` is asserted rather than "some error",
    /// because a check that fires for the wrong reason is a check that will keep passing
    /// after the reason it was testing has gone.
    ///
    /// The full RC-6 property test is graded against a per-tool oracle built from the
    /// base's `tool_policy_spec` table. That oracle needs the kernel internals I-047b
    /// moves, so it lands with I-047c and this is not it.
    #[test]
    fn authorize_grades_every_permission_against_every_path_state() {
        for permission in Permission::ALL {
            let granting = root("granting", "nmcp-authorize-granting", &[permission]);
            let path_inside = inside(&granting, "file.txt");
            // A second root that exists and grants nothing, so "no permission on the
            // resolved root" is reached with a root actually resolved rather than by
            // there being no roots at all.
            let barren = root("barren", "nmcp-authorize-barren", &[]);
            let path_in_barren = inside(&barren, "file.txt");
            let declared = declared(Some(permission), &["path"]);

            // Held, path inside the granting root: authorized, and the proof names the
            // root that decided it and the permission that was checked.
            let granted = authorize(
                &declared,
                &held(vec![granting.clone()], &[]),
                &json!({ "path": path_inside }),
            )
            .expect("a held permission on a path inside the root is authorized");
            assert_eq!(
                granted.matched_root().map(|r| r.id.as_str()),
                Some("granting"),
                "{permission:?}: the proof must name the root that decided the call"
            );
            assert_eq!(granted.permission(), Some(permission));

            // Not held, path inside a root that resolves: refused on the permission, not
            // on the root. RC-D4's first bullet: declaring a permission does not assert
            // the caller has it.
            let denial = authorize(
                &declared,
                &held(vec![barren.clone()], &[]),
                &json!({ "path": path_in_barren }),
            )
            .expect_err("a permission absent from the resolved root is refused");
            assert!(
                matches!(denial, Denial::Permission(p) if p == permission),
                "{permission:?}: expected Denial::Permission, got {denial:?}"
            );

            // Held, but the path resolves outside every root: refused anyway. RC-D4's
            // first bullet again, the other half: a declared permission is an additional
            // precondition, never a substitute for root resolution.
            let outside = std::env::temp_dir().join("nmcp-authorize-elsewhere/file.txt");
            let denial = authorize(
                &declared,
                &held(vec![granting.clone()], &[]),
                &json!({ "path": outside.display().to_string() }),
            )
            .expect_err("a path outside every root is refused even when the permission is held");
            assert!(
                matches!(&denial, Denial::OutsideRoots { arg } if arg == "path"),
                "{permission:?}: expected Denial::OutsideRoots, got {denial:?}"
            );

            // Declared path argument absent from the call: no root resolves, so the call
            // is refused, and the refusal says the argument was missing rather than that
            // it pointed somewhere ungoverned (NMCP-SPEC-003 v1.1).
            let denial = authorize(&declared, &held(vec![granting.clone()], &[]), &json!({}))
                .expect_err("a declared path argument that was never supplied is refused");
            assert!(
                matches!(&denial, Denial::MissingPathArgument { arg } if arg == "path"),
                "{permission:?}: expected Denial::MissingPathArgument, got {denial:?}"
            );

            // No roots at all: the deny-by-default floor. Asserted per permission because
            // a permission that fell through this would be invisible in the aggregate.
            let denial = authorize(
                &declared,
                &held(Vec::new(), &[]),
                &json!({ "path": path_in_barren }),
            )
            .expect_err("a caller holding no roots is refused");
            assert!(
                matches!(&denial, Denial::OutsideRoots { arg } if arg == "path"),
                "{permission:?}: expected Denial::OutsideRoots, got {denial:?}"
            );
        }
    }

    /// Section 4.1: `path_args: []` with a declared permission is legal and means the
    /// caller must hold the permission on some root while no root is resolved. Five
    /// Windows tools are this shape. The base returns early here and never enforces the
    /// declared permission at all, so this is the one deliberate narrowing in the
    /// contract, and it is graded in both directions for every permission.
    #[test]
    fn empty_path_args_requires_the_permission_on_some_root_and_resolves_none() {
        for permission in Permission::ALL {
            let declared = declared(Some(permission), &[]);

            let granting = root("granting", "nmcp-empty-path-args", &[permission]);
            let granted = authorize(&declared, &held(vec![granting], &[]), &json!({}))
                .expect("holding the permission on some root authorizes");
            assert!(
                granted.matched_root().is_none(),
                "{permission:?}: no root is resolved when no path argument is declared"
            );
            assert_eq!(granted.permission(), Some(permission));

            let barren = root("barren", "nmcp-empty-path-args-barren", &[]);
            let denial = authorize(&declared, &held(vec![barren], &[]), &json!({}))
                .expect_err("holding the permission on no root is refused");
            assert!(
                matches!(denial, Denial::Permission(p) if p == permission),
                "{permission:?}: expected Denial::Permission, got {denial:?}"
            );

            let denial = authorize(&declared, &held(Vec::new(), &[]), &json!({}))
                .expect_err("holding no roots at all is refused");
            assert!(
                matches!(denial, Denial::Permission(p) if p == permission),
                "{permission:?}: expected Denial::Permission, got {denial:?}"
            );
        }
    }

    /// The permission is required on some root, not on the root a path would have resolved
    /// to, and arguments are not consulted at all in this shape. Separated from the case
    /// above because an implementation that quietly resolved a root here would still pass
    /// that one.
    #[test]
    fn empty_path_args_ignores_arguments_entirely() {
        let granting = root("granting", "nmcp-empty-ignores-args", &[Permission::Read]);
        let declared = declared(Some(Permission::Read), &[]);
        let granted = authorize(
            &declared,
            &held(vec![granting], &[]),
            &json!({"path": "/somewhere/entirely/else", "cwd": "/nor/here"}),
        )
        .expect("a tool declaring no path arguments is not refused for carrying one");
        assert!(granted.matched_root().is_none());
    }

    /// RC-D4's second bullet. A tool that declares no permission is not unrestricted, it
    /// is restricted to operations needing no root-scoped authority, and a path argument
    /// reaching it is a refusal rather than a permission it silently gained.
    #[test]
    fn no_declared_permission_plus_a_path_argument_is_undeclared_path_use() {
        let mut declared = declared(None, &["path"]);
        declared.effect = ToolEffect::Mutate;

        let granting = root("granting", "nmcp-undeclared", &[Permission::Write]);
        let denial = authorize(
            &declared,
            &held(vec![granting.clone()], &[]),
            &json!({ "path": inside(&granting, "file.txt") }),
        )
        .expect_err("a path argument on a tool declaring no path authority is refused");
        assert!(
            matches!(&denial, Denial::UndeclaredPathUse { arg } if arg == "path"),
            "expected Denial::UndeclaredPathUse, got {denial:?}"
        );

        // Refused even when the path is inside a root the caller holds everything on,
        // which is the point: the refusal is about what the tool declared, not about what
        // the caller holds.
        let omnipotent = RootRule {
            id: "omnipotent".into(),
            path: std::env::temp_dir().join("nmcp-undeclared"),
            permissions: Permission::ALL.into_iter().collect(),
        };
        let denial = authorize(
            &declared,
            &held(vec![omnipotent.clone()], &[]),
            &json!({ "path": inside(&omnipotent, "file.txt") }),
        )
        .expect_err("holding every permission does not make an undeclared path use legal");
        assert!(matches!(denial, Denial::UndeclaredPathUse { .. }));

        // The same tool without the path argument is authorized and resolves nothing.
        let granted = authorize(&declared, &held(vec![omnipotent], &[]), &json!({}))
            .expect("a tool needing no root-scoped authority is authorized without one");
        assert!(granted.matched_root().is_none());
        assert!(granted.permission().is_none());
    }

    /// A tool that declares neither a permission nor path arguments is authorized against
    /// an empty holder. The floor case, and the one `GrantedAuthority`'s doc test uses.
    #[test]
    fn a_tool_needing_no_authority_is_authorized_holding_nothing() {
        let granted = authorize(
            &declared(None, &[]),
            &held(Vec::new(), &[]),
            &json!({"path": "/anywhere"}),
        )
        .expect("declaring nothing and holding nothing authorizes");
        assert!(granted.matched_root().is_none());
        assert!(granted.permission().is_none());
    }

    // - authorize: grants -

    /// RC-D3, fail closed. A grant string outside the `Permission` enum can be declared
    /// and refused but can never be held, so it is refused loudly at authorization rather
    /// than silently ignored. The retired `m365` name is included deliberately: RC-19
    /// retired it, and a grant resolver that resolved it would hand back the capability
    /// the retirement removed.
    #[test]
    fn a_grant_no_permission_defines_is_refused() {
        for name in ["not.a.permission", "m365", "", "READ", "read "] {
            let mut declared = declared(None, &[]);
            declared.grants = vec![CapabilityGrant::new(name)];

            // Refused even when the caller happens to hold a grant by that literal name,
            // which is the fail-closed half: holding a string is not holding a capability.
            let denial = authorize(&declared, &held(Vec::new(), &[name]), &json!({}))
                .expect_err("an unresolvable grant is refused");
            assert!(
                matches!(&denial, Denial::UnknownGrant(g) if g.as_str() == name),
                "expected Denial::UnknownGrant({name:?}), got {denial:?}"
            );
        }
    }

    /// A grant that resolves but is absent from what the caller holds. Graded over every
    /// permission, since every canonical permission name is a legal grant.
    #[test]
    fn a_resolvable_grant_the_caller_does_not_hold_is_missing_not_unknown() {
        for permission in Permission::ALL {
            let mut declared = declared(None, &[]);
            declared.grants = vec![CapabilityGrant::new(permission.as_str())];

            let denial = authorize(&declared, &held(Vec::new(), &[]), &json!({}))
                .expect_err("a grant the caller does not hold is refused");
            assert!(
                matches!(&denial, Denial::MissingGrant(g) if g.as_str() == permission.as_str()),
                "{permission:?}: expected Denial::MissingGrant, got {denial:?}"
            );

            authorize(
                &declared,
                &held(Vec::new(), &[permission.as_str()]),
                &json!({}),
            )
            .expect("a grant the caller holds is authorized");
        }
    }

    /// An unresolvable grant is reported ahead of a resolvable one the caller lacks, even
    /// when the resolvable one is declared first. A grant no build defines can never be
    /// satisfied by any policy; a grant the caller lacks can. Reporting the fixable one
    /// while a permanent defect is present sends an operator to widen policy for a call
    /// that would still be refused.
    #[test]
    fn an_unknown_grant_outranks_a_missing_one() {
        let mut declared = declared(None, &[]);
        declared.grants = vec![
            CapabilityGrant::new(Permission::Read.as_str()),
            CapabilityGrant::new("not.a.permission"),
        ];
        let denial = authorize(&declared, &held(Vec::new(), &[]), &json!({}))
            .expect_err("both grants fail, so one of them is reported");
        assert!(
            matches!(&denial, Denial::UnknownGrant(g) if g.as_str() == "not.a.permission"),
            "expected the unresolvable grant to be reported first, got {denial:?}"
        );
    }

    /// Grants are an additional precondition, never a substitute for the root check. A
    /// caller holding every grant and no root permission is still refused, which is RC-D4
    /// in the one shape where a provider might expect otherwise.
    #[test]
    fn holding_every_grant_does_not_satisfy_a_declared_permission() {
        let mut declared = declared(Some(Permission::Write), &["path"]);
        declared.grants = vec![CapabilityGrant::new(Permission::WindowsApi.as_str())];

        let barren = root("barren", "nmcp-grants-do-not-substitute", &[]);
        let all: Vec<&str> = Permission::ALL.iter().map(|p| p.as_str()).collect();
        let denial = authorize(
            &declared,
            &held(vec![barren.clone()], &all),
            &json!({ "path": inside(&barren, "file.txt") }),
        )
        .expect_err("grants do not stand in for the declared root permission");
        assert!(
            matches!(denial, Denial::Permission(Permission::Write)),
            "expected Denial::Permission(Write), got {denial:?}"
        );
    }

    // - authorize: path argument resolution -

    /// Section 4.1: the kernel tries `path_args` in the order the provider declared them
    /// and the first present one wins. Asserted by making the two candidates resolve to
    /// different roots, so the answer says which was used rather than only that one was.
    #[test]
    fn the_first_declared_path_argument_present_wins() {
        let first = root("first", "nmcp-order-first", &[Permission::Read]);
        let second = root("second", "nmcp-order-second", &[Permission::Read]);
        let declared = declared(Some(Permission::Read), &["repo", "path"]);

        let granted = authorize(
            &declared,
            &held(vec![first.clone(), second.clone()], &[]),
            &json!({"repo": inside(&first, "a.txt"), "path": inside(&second, "b.txt")}),
        )
        .expect("both arguments resolve, so the call is authorized");
        assert_eq!(
            granted.matched_root().map(|r| r.id.as_str()),
            Some("first"),
            "declaration order decides, not the order the arguments appear in the call"
        );

        // With the first absent, the second is tried.
        let granted = authorize(
            &declared,
            &held(vec![first, second.clone()], &[]),
            &json!({ "path": inside(&second, "b.txt") }),
        )
        .expect("the second declared argument resolves when the first is absent");
        assert_eq!(
            granted.matched_root().map(|r| r.id.as_str()),
            Some("second")
        );
    }

    /// A non-string value is not a path. The lookup reads strings only, which is the
    /// base's own rule, so a numeric `path` falls through to the next candidate rather
    /// than being stringified into a root resolution nobody declared.
    #[test]
    fn a_non_string_path_argument_is_not_a_path() {
        let granting = root("granting", "nmcp-non-string", &[Permission::Read]);
        let declared = declared(Some(Permission::Read), &["path", "cwd"]);
        let granted = authorize(
            &declared,
            &held(vec![granting.clone()], &[]),
            &json!({"path": 42, "cwd": inside(&granting, "a.txt")}),
        )
        .expect("the string-valued candidate resolves");
        assert_eq!(
            granted.matched_root().map(|r| r.id.as_str()),
            Some("granting")
        );
    }

    /// NMCP-SPEC-003 v1.1, and the reason the variant was added. An argument that was sent
    /// and points somewhere ungoverned and an argument that was never sent are different
    /// events, and the two refusals must not be confusable: an audit record that cannot
    /// tell them apart cannot answer which one happened, which is the question anybody
    /// reading it after the fact is asking. Both directions are asserted, so a future
    /// implementation that collapsed either into the other fails here.
    #[test]
    fn an_absent_path_argument_and_an_ungoverned_one_are_different_refusals() {
        let granting = root("granting", "nmcp-missing-vs-outside", &[Permission::Read]);
        let declared = declared(Some(Permission::Read), &["repo", "path"]);
        let holder = held(vec![granting.clone()], &[]);

        // Present, and outside every configured root.
        let ungoverned = std::env::temp_dir().join("nmcp-missing-vs-outside-elsewhere/a.txt");
        let denial = authorize(
            &declared,
            &holder,
            &json!({ "path": ungoverned.display().to_string() }),
        )
        .expect_err("a supplied path outside every root is refused");
        assert!(
            matches!(&denial, Denial::OutsideRoots { arg } if arg == "path"),
            "a supplied argument must name itself, got {denial:?}"
        );
        assert!(
            denial.to_string().contains("resolves outside"),
            "the message must say the path resolved somewhere ungoverned: {denial}"
        );

        // Absent, with the same tool and the same holder, so the only thing that changed
        // is whether the argument was sent.
        let denial = authorize(&declared, &holder, &json!({"unrelated": "value"}))
            .expect_err("supplying none of the declared path arguments is refused");
        assert!(
            matches!(&denial, Denial::MissingPathArgument { arg } if arg == "repo"),
            "an absent argument must name the first declared one, got {denial:?}"
        );
        assert!(
            denial.to_string().contains("supplied none"),
            "the message must say nothing was supplied rather than that something resolved \
             outside: {denial}"
        );

        // The two are not the same variant, which is the whole point of the revision.
        let outside = authorize(
            &declared,
            &holder,
            &json!({ "repo": ungoverned.display().to_string() }),
        )
        .expect_err("outside");
        let missing = authorize(&declared, &holder, &json!({})).expect_err("missing");
        assert!(
            !matches!(outside, Denial::MissingPathArgument { .. }),
            "a supplied argument must never report as missing"
        );
        assert!(
            !matches!(missing, Denial::OutsideRoots { .. }),
            "an absent argument must never report as outside roots"
        );
    }

    /// The most specific root decides, so a narrow restrictive root is never shadowed by
    /// a broader one declared earlier. That is `PolicyConfig::require`'s rule, and
    /// `authorize` has to reproduce it because `HeldAuthority` carries roots rather than
    /// the whole policy. A copy that got this wrong would silently widen every deployment
    /// that nests a read-only root inside a writable one.
    #[test]
    fn the_most_specific_root_decides_not_the_first_declared() {
        let broad = RootRule {
            id: "broad".into(),
            path: std::env::temp_dir().join("nmcp-specificity"),
            permissions: [Permission::Read, Permission::Write].into_iter().collect(),
        };
        let narrow = RootRule {
            id: "narrow".into(),
            path: std::env::temp_dir().join("nmcp-specificity/readonly"),
            permissions: [Permission::Read].into_iter().collect(),
        };
        let target = narrow.path.join("file.txt").display().to_string();

        let granted = authorize(
            &declared(Some(Permission::Read), &["path"]),
            &held(vec![broad.clone(), narrow.clone()], &[]),
            &json!({ "path": target.clone() }),
        )
        .expect("read is granted on the narrow root");
        assert_eq!(
            granted.matched_root().map(|r| r.id.as_str()),
            Some("narrow")
        );

        let denial = authorize(
            &declared(Some(Permission::Write), &["path"]),
            &held(vec![broad, narrow], &[]),
            &json!({ "path": target }),
        )
        .expect_err("write is not granted on the narrow root and the broad one does not shadow it");
        assert!(
            matches!(denial, Denial::Permission(Permission::Write)),
            "expected Denial::Permission(Write), got {denial:?}"
        );
    }

    // - CapabilityGrant -

    #[test]
    fn a_capability_grant_displays_as_its_canonical_name() {
        let grant = CapabilityGrant::new(Permission::WindowsApiWrite.as_str());
        assert_eq!(grant.as_str(), "win.api.write");
        assert_eq!(grant.to_string(), "win.api.write");
        // `Denial`'s `{0}` formatting is why the `Display` impl exists at all.
        assert_eq!(
            Denial::MissingGrant(grant).to_string(),
            "caller lacks required capability grant win.api.write"
        );
    }

    #[test]
    fn every_permission_name_is_a_grant_that_resolves() {
        for permission in Permission::ALL {
            let grant = CapabilityGrant::new(permission.as_str());
            assert_eq!(
                Permission::from_canonical(grant.as_str()),
                Some(permission),
                "the grant vocabulary is closed over Permission (RC-D3)"
            );
        }
    }

    // - to_list_entry -

    fn contract(effect: ToolEffect, reach: ToolReach) -> ToolContract {
        ToolContract {
            name: "dev.git_log".into(),
            description: "Show git log for a repository path.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            }),
            authority: ToolAuthority {
                permission: Some(Permission::Read),
                path_args: vec!["path".into()],
                grants: Vec::new(),
                effect,
                reach,
            },
        }
    }

    /// RC-A4. The two informative hints are read off the same declaration `authorize`
    /// consumes, so a tool declared `Mutate` and advertised read-only is no longer two
    /// tables that can disagree but one field that cannot.
    #[test]
    fn annotations_derive_from_the_declaration_in_both_directions() {
        for (effect, reach, read_only, open_world) in [
            (ToolEffect::Observe, ToolReach::Local, true, false),
            (ToolEffect::Observe, ToolReach::Remote, true, true),
            (ToolEffect::Mutate, ToolReach::Local, false, false),
            (ToolEffect::Mutate, ToolReach::Remote, false, true),
        ] {
            let entry = contract(effect, reach).to_list_entry("dev_git_log");
            assert_eq!(
                entry["annotations"]["readOnlyHint"], read_only,
                "readOnlyHint disagrees with {effect:?}"
            );
            assert_eq!(
                entry["annotations"]["openWorldHint"], open_world,
                "openWorldHint disagrees with {reach:?}"
            );
        }
    }

    /// INV-1 restated where a client can read it. If this ever fails, either a destructive
    /// tool was added, which breaks the invariant, or `to_list_entry` stopped telling the
    /// truth. Both are release blockers and neither is fixed by editing this assertion.
    #[test]
    fn no_contract_is_annotated_destructive() {
        for effect in [ToolEffect::Observe, ToolEffect::Mutate] {
            for reach in [ToolReach::Local, ToolReach::Remote] {
                let entry = contract(effect, reach).to_list_entry("dev_git_log");
                assert_eq!(
                    entry["annotations"]["destructiveHint"], false,
                    "{effect:?}/{reach:?} is annotated destructive; the guarantee says no tool is"
                );
            }
        }
    }

    /// All three hints, always. An absent hint is not neutral: the protocol defaults for
    /// `destructiveHint` and `openWorldHint` are both true, so a dropped key advertises
    /// the opposite of what this catalogue guarantees.
    #[test]
    fn all_three_hints_are_emitted() {
        let entry = contract(ToolEffect::Observe, ToolReach::Local).to_list_entry("dev_git_log");
        let annotations = entry["annotations"]
            .as_object()
            .expect("annotations is an object");
        let mut keys: Vec<&str> = annotations.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["destructiveHint", "openWorldHint", "readOnlyHint"]);
    }

    /// The entry carries the public name it was handed, not the local name it was declared
    /// under. Computing the mapping here as well as in the registry is the defect
    /// NMCP-SPEC-003 section 1 measures, so the mapping arrives as an argument.
    #[test]
    fn the_entry_carries_the_public_name_it_was_given() {
        let declared = contract(ToolEffect::Observe, ToolReach::Local);
        let entry = declared.to_list_entry("dev_git_log");
        assert_eq!(entry["name"], "dev_git_log");
        assert_eq!(declared.name, "dev.git_log", "the local name is unchanged");
        assert_eq!(entry["description"], declared.description);
        assert_eq!(entry["inputSchema"], declared.input_schema);
    }

    // - Names -

    /// RC-D6. The same table `nmcp-router`'s `public_tool_names_are_claude_safe` asserts,
    /// kept here as well: the function moved, and the crate that owns it now grades it.
    #[test]
    fn public_tool_names_are_derived_and_valid() {
        for (provider, local, expected) in [
            ("", "mem.write", "mem_write"),
            ("", "win.eventlog_query", "win_eventlog_query"),
            ("dev", "git_log", "dev_git_log"),
            ("", "dev.git_publish", "dev_git_publish"),
            ("upstream", "ping", "upstream_ping"),
        ] {
            let name = public_tool_name(provider, local);
            assert_eq!(name, expected);
            assert!(is_valid_public_tool_name(&name));
        }
    }

    /// Validation applies to the derived public name and never to the local one. Local
    /// names legitimately contain dots and the validator rejects dots, so validating a
    /// local name would refuse the existing first-party catalogue.
    #[test]
    fn a_local_name_is_not_a_public_name() {
        assert!(!is_valid_public_tool_name("mem.write"));
        assert!(is_valid_public_tool_name(&public_tool_name(
            "",
            "mem.write"
        )));
        assert!(!is_valid_public_tool_name(""));
        assert!(!is_valid_public_tool_name(&"a".repeat(65)));
    }

    /// Truncation at 64 characters means two distinct local names can derive one public
    /// name. That is a duplicate the registry refuses by naming both contributors (RC-D6),
    /// and it is asserted here so the collision is a known property rather than a surprise
    /// found by an operator.
    #[test]
    fn truncation_can_collide_two_local_names_into_one_public_name() {
        let prefix = "a".repeat(64);
        let first = public_tool_name("", &format!("{prefix}_one"));
        let second = public_tool_name("", &format!("{prefix}_two"));
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    // - MemoryScope -

    /// RC-2. The type moved here and kept its shape; `nmcp-memory` re-exports it and
    /// `nmcp-router` imports it from there unchanged.
    #[test]
    fn memory_scope_keeps_its_prefixes_and_its_wire_form() {
        assert_eq!(MemoryScope::root("docs").to_string(), "root:docs");
        assert_eq!(MemoryScope::session("s1").to_string(), "session:s1");
        assert_eq!(MemoryScope::named("default").to_string(), "default");

        let scope = MemoryScope::root("docs");
        let encoded = serde_json::to_value(&scope).expect("serialize");
        assert_eq!(encoded, json!("root:docs"));
        let decoded: MemoryScope = serde_json::from_value(encoded).expect("deserialize");
        assert_eq!(decoded, scope);
    }

    // - Registration refusals -

    /// RC-D6: a duplicate names both contributors, because a collision an operator has to
    /// infer is a collision an operator does not fix. The registry that raises these is
    /// I-047c; the messages are frozen here.
    #[test]
    fn registration_errors_name_what_an_operator_has_to_change() {
        let duplicate = RegistrationError::DuplicateToolName {
            name: "dev_git_log".into(),
            owner: "devtools".into(),
            claimant: "upstream".into(),
        };
        let rendered = duplicate.to_string();
        assert!(rendered.contains("dev_git_log"));
        assert!(rendered.contains("devtools"));
        assert!(rendered.contains("upstream"));

        let version = RegistrationError::UnsupportedContractVersion {
            provider_id: "upstream".into(),
            found: CONTRACT_SCHEMA_VERSION + 1,
            accepted: CONTRACT_SCHEMA_VERSION,
        };
        assert!(version.to_string().contains("accepts up to 1"));
    }

    /// A `CatalogView` with no filters is the default and is what a first-party session
    /// gets: RC-D8's permission filtering is available and off, so a tool that would be
    /// refused is listed and refused at call time with a reason rather than vanishing.
    #[test]
    fn the_default_catalog_view_filters_nothing() {
        let view = CatalogView::default();
        assert!(view.profile.is_none());
        assert!(view.agent_id.is_none());
        assert!(
            view.filter_by.is_none(),
            "permission filtering is off by default (RC-D8)"
        );
    }

    /// The declared and held halves are separate types on purpose: a provider supplies one
    /// and never the other. Constructing a `HeldAuthority` is the kernel's job in the ring,
    /// and this asserts the fields the kernel has to fill.
    #[test]
    fn held_authority_carries_roots_grants_and_the_caller() {
        let held = HeldAuthority {
            roots: vec![RootRule {
                id: "docs".into(),
                path: PathBuf::from("/srv/docs"),
                permissions: [Permission::Read].into_iter().collect(),
            }],
            grants: BTreeSet::from([CapabilityGrant::new("read")]),
            agent_id: Some("agent-1".into()),
        };
        assert_eq!(held.roots.len(), 1);
        assert!(held.grants.contains(&CapabilityGrant::new("read")));
        assert_eq!(held.agent_id.as_deref(), Some("agent-1"));
    }
}
