//! The binding grant: proof that one resolution of one key was authorized.
//!
//! NMCP-SPEC-002 SB-15 and SB-A3, RATIFIED v1.0. The struct is frozen at ratification and
//! implemented as written.

use std::fmt;

use crate::name::{SecretName, Version};

/// The identifier of the binding rule that authorized a resolution, or refused one.
///
/// SB-8 requires a refusal to name the governing rule and SB-R5 requires the audit record to
/// carry it. It rides on the grant rather than being looked up again later, because policy can
/// hot reload between the decision and the record, and a record naming a rule that no longer
/// exists describes a decision nobody can reconstruct. NMCP-SPEC-002's G-1 records that the
/// wider version of that problem, pinning policy per request, is open and owned by I-036.
///
/// An opaque identifier rather than a structured type. What a rule *is* belongs to SB-6's
/// binding model, which is I-036's, and a shape guessed here would be a second owner of it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BindingRuleId(String);

impl BindingRuleId {
    /// Name a rule.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as text, for a message and an audit record.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BindingRuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Proof that binding evaluation authorized one resolution of one key.
///
/// Constructible only by the binding evaluator: the private fields make forging it `E0451` in
/// any other crate.
///
/// # The three properties, and how each is bought
///
/// **Single use.** [`SealedStore::resolve`](crate::SealedStore::resolve) takes it **by
/// value**. A shared reference resolves unboundedly many times, which makes SB-6's use budget
/// unenforceable at the point that consumes it. Taking it by value gives that budget a natural
/// decrement point; where the counter lives and whether it survives a restart is
/// NMCP-SPEC-002's G-2, open and owned by I-036.
///
/// **Bound to its subject.** The grant carries the name and the version, and `resolve` takes
/// no separate `SecretRef`. There is no parameter through which a grant issued for one key
/// could be pointed at another, which is the defect SB-15 records in the interface it
/// replaced.
///
/// **Carries its justification.** [`BindingGrant::rule`] is what a refusal names (SB-8) and
/// what the audit record carries (SB-R5).
///
/// # Where a grant comes from at I-033: nowhere, deliberately
///
/// The only constructor is `pub(crate)` and compiled only into this crate's test builds.
/// NMCP-SPEC-002 places the binding evaluator's production path at I-036, so at I-033 there
/// is no code anywhere that is entitled to mint one, and this crate does not invent a door
/// for a caller that does not exist: a public constructor taking a caller-supplied rule would
/// let anything holding the store authorize itself, which is the trust-boundary comment SB-A3
/// exists to replace, reintroduced as an API. In-crate tests construct grants directly, which
/// is what the test-scoped `pub(crate)` is for, and the crate documentation names the
/// dependency question I-036 has to answer before a production constructor can exist
/// (`nmcp-policy` cannot call into this crate without closing a cycle through
/// `nmcp-schema`).
///
/// The exemplar is NMCP-SPEC-003's `GrantedAuthority`, sealed and **consumed** by
/// `ToolProvider::call`, so the unauthorized call is not an expression that type-checks.
/// SB-15 names it as the correct precedent, and this type follows it rather than the advisory
/// `bool` predicate it corrects.
///
/// # The seal, proved out of band
///
/// Doc tests, which `rustdoc` builds as their own crates linking this one: exactly the
/// population the seal is aimed at. Each `compile_fail` block is paired with the positive
/// block below, which compiles the same path with the same names, because `rustdoc` passes a
/// `compile_fail` block on **any** compilation error and an unpaired one would stay green if
/// the type or method were renamed out from under it. The positive half is a function rather
/// than a run: with no public constructor there is no grant an external crate could construct
/// to call it with, and a function that takes one by value is precisely what dispatch at I-034
/// will be.
///
/// ```
/// use nmcp_secrets::{BindingGrant, ResolveError, Sealed, SealedStore};
///
/// fn resolve_once(
///     store: &SealedStore,
///     grant: BindingGrant,
/// ) -> Result<Sealed<Vec<u8>>, ResolveError> {
///     store.resolve(grant)
/// }
/// ```
///
/// Forging one is refused at the field, `E0451`:
///
/// ```compile_fail,E0451
/// let forged = nmcp_secrets::BindingGrant {
///     _seal: (),
///     name: nmcp_secrets::SecretName::parse("github.token").unwrap(),
///     version: nmcp_secrets::Version::first(),
///     rule: nmcp_secrets::BindingRuleId::new("forged"),
/// };
/// ```
///
/// Asking for a constructor finds none, `E0599`: outside this crate's own test builds the
/// constructor does not exist, so there is no door to be private.
///
/// ```compile_fail,E0599
/// let minted = nmcp_secrets::BindingGrant::issue(
///     nmcp_secrets::SecretName::parse("github.token").unwrap(),
///     nmcp_secrets::Version::first(),
///     nmcp_secrets::BindingRuleId::new("minted"),
/// );
/// ```
///
/// # Single use, proved the same way
///
/// `resolve` consumes the grant, so the second resolution below is a use of a moved value,
/// `E0382`. The positive block above is the paired half: identical shape, one resolution, and
/// it compiles.
///
/// ```compile_fail,E0382
/// use nmcp_secrets::{BindingGrant, SealedStore};
///
/// fn resolve_twice(store: &SealedStore, grant: BindingGrant) {
///     let _first = store.resolve(grant);
///     let _second = store.resolve(grant);
/// }
/// ```
///
/// # Bound to its subject, proved the same way
///
/// `resolve` takes the grant and nothing else, so there is no argument through which a caller
/// could redirect a grant at another key. Passing one is an arity error, `E0061`, rather than
/// a runtime refusal; the runtime half, that a grant for key A yields key A's value and not
/// key B's, is asserted in the store's tests.
///
/// ```compile_fail,E0061
/// use nmcp_secrets::{BindingGrant, SealedStore, SecretName};
///
/// fn redirect(store: &SealedStore, grant: BindingGrant, other: &SecretName) {
///     let _ = store.resolve(grant, other);
/// }
/// ```
#[derive(Debug)]
#[must_use = "a grant that is dropped is a resolution that was authorized and never happened"]
pub struct BindingGrant {
    _seal: (),
    name: SecretName,
    version: Version,
    rule: BindingRuleId,
}

impl BindingGrant {
    /// Issue a grant. Crate-private and compiled only into test builds: at I-033 no
    /// production caller is entitled to one, so in a release binary **no constructor for
    /// this type exists at all** and [`SealedStore::resolve`](crate::SealedStore::resolve)
    /// is unreachable, which is precisely the sequencing NMCP-SPEC-002 wants until I-034
    /// wires resolution and I-036 lands the evaluator. The crate documentation records the
    /// dependency question I-036 has to answer before a production constructor can live
    /// anywhere.
    #[cfg(test)]
    pub(crate) const fn issue(name: SecretName, version: Version, rule: BindingRuleId) -> Self {
        Self {
            _seal: (),
            name,
            version,
            rule,
        }
    }

    /// The key this grant authorizes, and the only key it authorizes.
    #[must_use]
    pub const fn name(&self) -> &SecretName {
        &self.name
    }

    /// The version this grant authorizes, chosen when the grant was issued rather than looked
    /// up again at resolution, so a rotation between the two does not silently redirect it.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// The rule that authorized it, which a refusal names (SB-8) and a record carries (SB-R5).
    #[must_use]
    pub const fn rule(&self) -> &BindingRuleId {
        &self.rule
    }

    /// Take the grant apart at the point that consumes it.
    ///
    /// `pub(crate)` and used by exactly one caller, `resolve`. It exists because taking the
    /// grant by value is the whole mechanism and a `resolve` that only borrowed the fields
    /// would leave the caller holding a grant it had already spent.
    pub(crate) fn into_parts(self) -> (SecretName, Version, BindingRuleId) {
        (self.name, self.version, self.rule)
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
    use super::{BindingGrant, BindingRuleId};
    use crate::name::{SecretName, Version};

    #[test]
    fn a_grant_reads_back_the_subject_it_was_issued_for() {
        let name = SecretName::parse("github.token").unwrap();
        let grant = BindingGrant::issue(
            name.clone(),
            Version::first(),
            BindingRuleId::new("operator.default"),
        );
        assert_eq!(grant.name(), &name);
        assert_eq!(grant.version(), Version::first());
        assert_eq!(grant.rule().as_str(), "operator.default");
    }

    #[test]
    fn the_parts_taken_out_are_the_parts_put_in() {
        let name = SecretName::parse("db.password").unwrap();
        let grant = BindingGrant::issue(
            name.clone(),
            Version::first().next(),
            BindingRuleId::new("policy.rule.7"),
        );
        let (out_name, out_version, out_rule) = grant.into_parts();
        assert_eq!(out_name, name);
        assert_eq!(out_version, Version::first().next());
        assert_eq!(out_rule.as_str(), "policy.rule.7");
    }

    #[test]
    fn the_debug_form_carries_no_material_because_a_grant_holds_none() {
        // A grant names a key; it never carries the value. Asserted so that a later field
        // addition that did carry one turns this red.
        let grant = BindingGrant::issue(
            SecretName::parse("github.token").unwrap(),
            Version::first(),
            BindingRuleId::new("operator.default"),
        );
        let rendered = format!("{grant:?}");
        assert!(rendered.contains("github.token"));
        assert!(rendered.contains("operator.default"));
        assert_eq!(
            rendered.matches("_seal").count(),
            1,
            "the seal field is the only structural member beyond the three named ones"
        );
    }

    #[test]
    fn a_rule_identifier_round_trips_through_its_text() {
        let rule = BindingRuleId::new("operator.policy.github");
        assert_eq!(rule.as_str(), "operator.policy.github");
        assert_eq!(rule.to_string(), "operator.policy.github");
        assert_eq!(rule, BindingRuleId::new("operator.policy.github"));
        assert_ne!(rule, BindingRuleId::new("operator.policy.gitlab"));
    }
}
