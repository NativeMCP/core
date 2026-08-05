//! The indexed tool registry.
//!
//! NMCP-SPEC-003 section 4.4, RATIFIED v1.1. The trait lives in `nmcp-schema` so every
//! provider can see it; the index lives here because the kernel owns dispatch and owns INV-1.
//!
//! RC-D6 is the shape: an index from public tool name to the provider that owns the tool, the
//! local name it is dispatched under, and the authority it declared. Built at registration,
//! rebuilt on refresh, never walked on dispatch. Duplicate detection falls out of insertion
//! rather than being a separate pass.
//!
//! Nothing in this module is wired into dispatch yet, and that is deliberate rather than
//! incomplete. `nmcp-router`'s ring still resolves through `ToolProvider::tool_names` and
//! still consults its own compiled-in policy table, so this PR changes no dispatch decision.
//! Wiring the ring through [`IndexedToolRegistry`] and [`nmcp_schema::authorize`] is one
//! atomic change, owner I-047d, because dispatch cannot hand a provider a
//! `GrantedAuthority` until it produces one and it cannot produce one until it reads the
//! declaration this index holds.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use nmcp_policy::{AbacAction, AbacRule, PolicyConfig};
use nmcp_schema::{
    CONTRACT_SCHEMA_VERSION, CatalogView, HeldAuthority, RegistrationError, ToolAuthority,
    ToolContract, ToolProvider, ToolRegistry, accepts_contract_version, authorize,
    contains_delete_intent, is_valid_public_tool_name, public_tool_name,
};
use parking_lot::RwLock;
use serde_json::{Value, json};

/// One tool, resolved.
///
/// Held behind an `Arc` so the several name forms a tool answers to share one record rather
/// than each carrying a copy that could drift from the others.
struct IndexEntry {
    provider: Arc<dyn ToolProvider>,
    local_name: String,
    public_name: String,
    authority: Arc<ToolAuthority>,
    list_entry: Value,
    /// Every index key this tool is reachable under, so removing a provider removes exactly
    /// what it added.
    keys: Vec<String>,
}

/// One provider's slice of the index, in the order it declared its tools.
#[derive(Clone)]
struct ProviderSlice {
    provider: Arc<dyn ToolProvider>,
    tools: Vec<Arc<IndexEntry>>,
}

/// The whole index: providers in registration order, and every name form they answer to.
#[derive(Default)]
struct Index {
    slices: Vec<ProviderSlice>,
    by_name: HashMap<String, Arc<IndexEntry>>,
}

/// The registry the kernel serves `tools/list` and `tools/call` from.
///
/// Every mutating method takes `&self` (RC-D7), so the registry is wired up after it is
/// already behind an `Arc` and an upstream admitted at runtime needs no special path.
/// Mutation goes through one `RwLock` and no guard is ever held across an `await`, because
/// nothing here is async: `parking_lot`'s guards are `!Send`, and a registry that made the
/// dispatch future `!Send` would not compile into an axum handler.
pub struct IndexedToolRegistry {
    policy: Arc<RwLock<PolicyConfig>>,
    index: RwLock<Index>,
}

impl std::fmt::Debug for IndexedToolRegistry {
    /// Counts, never contents. `ToolProvider` is a foreign trait object with no `Debug` bound
    /// and the entries hold caller-facing schemas; what an operator wants from a debug line is
    /// how much is registered, not a reprint of the catalogue.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let index = self.index.read();
        f.debug_struct("IndexedToolRegistry")
            .field("providers", &index.slices.len())
            .field("names", &index.by_name.len())
            .finish_non_exhaustive()
    }
}

impl IndexedToolRegistry {
    /// Build an empty registry reading `policy` for profile scoping and caller allowlists.
    ///
    /// The policy handle is shared rather than copied because `list_for` has to answer from
    /// the policy in force when it is asked, not the one in force when the registry was made.
    #[must_use]
    pub fn new(policy: Arc<RwLock<PolicyConfig>>) -> Self {
        Self {
            policy,
            index: RwLock::new(Index::default()),
        }
    }

    /// How many tools are indexed, counting each tool once however many names it answers to.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index
            .read()
            .slices
            .iter()
            .map(|slice| slice.tools.len())
            .sum()
    }

    /// Whether the index holds no tools. An empty registry is a legal state, not a broken one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Build one provider's slice, refusing rather than half-building it.
///
/// `retained` is every index key that survives this operation and does **not** belong to the
/// provider being built: for `register` that is the whole index, and for `refresh` it is the
/// index minus the slices being rebuilt. Nothing is written anywhere until this returns `Ok`,
/// which is how RC-D5's all-or-nothing rule is enforced rather than asserted.
///
/// Refusal order, per tool and in declaration order: an unaddressable public name, then the
/// INV-1 denylist, then a declared path argument the schema cannot receive, then a collision.
/// INV-1 sits above declaration integrity because a tool that could never legally be called
/// is a worse defect than one whose declaration is wrong, and a collision is checked last
/// because reporting one against a name that was never valid tells an operator to fix the
/// wrong provider.
fn build_slice(
    provider: &Arc<dyn ToolProvider>,
    retained: &HashMap<String, Arc<IndexEntry>>,
) -> Result<ProviderSlice, RegistrationError> {
    let provider_id = provider.provider_id().to_string();
    let found = provider.contract_version();
    if !accepts_contract_version(found) {
        return Err(RegistrationError::UnsupportedContractVersion {
            provider_id,
            found,
            accepted: CONTRACT_SCHEMA_VERSION,
        });
    }

    // Read once. RC-9 is the requirement: a provider whose catalogue is remote must not be
    // asked to produce it again on any path that is not `register` or `refresh`.
    let contracts = provider.contracts();
    let published = published_entries(provider, &provider_id);

    let mut claimed: HashMap<String, Arc<IndexEntry>> = HashMap::new();
    let mut tools: Vec<Arc<IndexEntry>> = Vec::with_capacity(contracts.len());

    for contract in &contracts {
        let public_name = public_tool_name(&provider_id, &contract.name);
        if !is_valid_public_tool_name(&public_name) {
            return Err(RegistrationError::InvalidToolName {
                provider_id,
                local: contract.name.clone(),
                public: public_name,
            });
        }

        let keys = name_forms(&provider_id, &contract.name, &public_name);
        // RC-A3 and RC-D4: INV-1 is kernel-owned and not delegable, so the denylist is
        // compared against every name the tool could actually be called by, and a provider's
        // opinion of its own destructiveness is not consulted. Refusing here means an operator
        // wiring the server learns it, instead of a caller being denied forever at stage 0.
        if let Some(denied) = keys.iter().find(|key| contains_delete_intent(key)) {
            return Err(RegistrationError::DeleteDeniedName {
                name: denied.clone(),
            });
        }

        // RC-5: a path argument the schema cannot receive is a root resolution that can never
        // fire, so it is refused at registration rather than discovered per call.
        if let Some(arg) = contract
            .authority
            .path_args
            .iter()
            .find(|arg| !schema_defines(&contract.input_schema, arg))
        {
            return Err(RegistrationError::UndeclaredPathArgument {
                name: public_name,
                arg: arg.clone(),
            });
        }

        let entry = Arc::new(IndexEntry {
            provider: Arc::clone(provider),
            local_name: contract.name.clone(),
            list_entry: list_entry_for(&provider_id, contract, &public_name, published.as_ref()),
            public_name,
            authority: Arc::new(contract.authority.clone()),
            keys,
        });

        for key in &entry.keys {
            // Both halves are checked: a name another provider already holds, and a name an
            // earlier tool of this same provider took, which is what a sanitization or
            // truncation collision looks like.
            if let Some(owner) = retained.get(key).or_else(|| claimed.get(key)) {
                return Err(RegistrationError::DuplicateToolName {
                    name: key.clone(),
                    owner: owner.provider.provider_id().to_string(),
                    claimant: provider_id,
                });
            }
            claimed.insert(key.clone(), Arc::clone(&entry));
        }
        tools.push(entry);
    }

    Ok(ProviderSlice {
        provider: Arc::clone(provider),
        tools,
    })
}

/// Every name form a tool answers to, in the order RC-D6 fixes.
///
/// The derived public name, always. The bare local name **only when `provider_id` is empty**,
/// which is the guard the base's `resolve` applies and which is load-bearing: without it every
/// upstream publishes its bare local names into the first-party namespace, and an upstream
/// exposing `execute` takes down its whole provider on a duplicate. And `provider_id::local`
/// for a non-empty id, which is the form the gateway has always accepted.
///
/// Deduplicated, because a first-party local name that is already sanitizer-clean derives
/// itself and a tool must not collide with itself.
fn name_forms(provider_id: &str, local_name: &str, public_name: &str) -> Vec<String> {
    let mut forms = vec![public_name.to_string()];
    let second = if provider_id.is_empty() {
        local_name.to_string()
    } else {
        format!("{provider_id}::{local_name}")
    };
    if second != *public_name {
        forms.push(second);
    }
    forms
}

/// Whether `arg` is a property of `schema`.
///
/// A schema that declares no properties at all defines no path argument, so a tool with one
/// is refused. That is the intended reading of RC-D5 and not an edge case: the declaration
/// says the kernel should resolve a root from an argument the tool cannot be sent.
fn schema_defines(schema: &Value, arg: &str) -> bool {
    schema
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| properties.contains_key(arg))
}

/// The entries an upstream published, keyed by local name, or `None` for a first-party
/// provider whose entries this server derives itself.
fn published_entries(
    provider: &Arc<dyn ToolProvider>,
    provider_id: &str,
) -> Option<HashMap<String, Value>> {
    if provider_id.is_empty() {
        return None;
    }
    Some(
        provider
            .tool_list()
            .into_iter()
            .filter_map(|entry| {
                let name = entry.get("name").and_then(Value::as_str)?.to_string();
                Some((name, entry))
            })
            .collect(),
    )
}

/// The `tools/list` entry for one tool, computed once at registration.
///
/// `ToolContract::to_list_entry` is called for **first-party providers only**. A proxied
/// upstream is somebody else's software: this server keeps whatever annotations the upstream
/// published and invents none, which is the existing rule in `nmcp-router`'s merged tool list
/// and stays the rule (RC-8).
///
/// Named gap, per INV-6. What an upstream published is read from `ToolProvider::tool_list`,
/// which I-047d deletes, and `ToolContract` has no field for a published annotation. So at
/// I-047d either the contract grows one or an upstream's annotations are lost. Owner I-047d,
/// flagged here rather than discovered there. The fallback below is what that world looks
/// like: name, description and schema, and no annotation invented on somebody else's behalf.
fn list_entry_for(
    provider_id: &str,
    contract: &ToolContract,
    public_name: &str,
    published: Option<&HashMap<String, Value>>,
) -> Value {
    if provider_id.is_empty() {
        return contract.to_list_entry(public_name);
    }
    match published.and_then(|entries| entries.get(&contract.name)) {
        Some(entry) => {
            let mut entry = entry.clone();
            if let Some(object) = entry.as_object_mut() {
                object.insert("name".into(), json!(public_name));
            }
            entry
        }
        None => json!({
            "name": public_name,
            "description": contract.description,
            "inputSchema": contract.input_schema,
        }),
    }
}

/// The tools one caller may reach, when policy restricts that caller to an explicit list.
///
/// `None` means unrestricted. RC-D8 makes this filtering unconditional: `CallerToolAllowlist`
/// is already policy and already a call-time deny, so applying it at list time is a pure
/// narrowing that makes the list agree with what a call would do.
///
/// Only `AbacAction::Deny` rules narrow the list. A rule whose action is `RequireApproval`
/// leaves the tool callable, behind a human, so hiding it would make the catalogue disagree
/// with the ring in the other direction. Several matching rules intersect, which is what the
/// ABAC stage does by evaluating all of them and letting any deny win.
fn caller_allowlist(policy: &PolicyConfig, agent_id: Option<&str>) -> Option<BTreeSet<String>> {
    let agent_id = agent_id?;
    let mut allowed: Option<BTreeSet<String>> = None;
    for rule in &policy.abac_rules {
        let AbacRule::CallerToolAllowlist {
            caller,
            allowed_tools,
            action: AbacAction::Deny,
        } = rule
        else {
            continue;
        };
        if caller != agent_id {
            continue;
        }
        let tools: BTreeSet<String> = allowed_tools.iter().cloned().collect();
        allowed = Some(match allowed {
            Some(existing) => existing.intersection(&tools).cloned().collect(),
            None => tools,
        });
    }
    allowed
}

/// Whether a holder satisfies a declaration, judged without a call to judge it against.
///
/// RC-D8's second part, and it is deliberately the same code the call path runs rather than a
/// second copy of the rule. The declaration is probed with its path arguments removed, because
/// at list time there is no call and therefore no path to resolve; every other check
/// [`authorize`] makes is made here unchanged. The result is exact rather than approximate: a
/// permission the holder has on no root can never be satisfied by any argument, and a grant is
/// held or not held regardless of arguments, so nothing is hidden that a call could have
/// reached.
fn holder_satisfies(authority: &ToolAuthority, held: &HeldAuthority) -> bool {
    let probe = ToolAuthority {
        permission: authority.permission,
        path_args: Vec::new(),
        grants: authority.grants.clone(),
        effect: authority.effect,
        reach: authority.reach,
    };
    authorize(&probe, held, &json!({})).is_ok()
}

/// Add every key a slice owns to `target`.
fn insert_keys(target: &mut HashMap<String, Arc<IndexEntry>>, slice: &ProviderSlice) {
    for tool in &slice.tools {
        for key in &tool.keys {
            target.insert(key.clone(), Arc::clone(tool));
        }
    }
}

impl ToolRegistry for IndexedToolRegistry {
    fn register(&self, provider: Arc<dyn ToolProvider>) -> Result<(), RegistrationError> {
        let mut index = self.index.write();
        let slice = build_slice(&provider, &index.by_name)?;
        insert_keys(&mut index.by_name, &slice);
        index.slices.push(slice);
        Ok(())
    }

    fn refresh(&self, provider_id: &str) -> Result<(), RegistrationError> {
        let mut index = self.index.write();

        // A first-party provider id is the empty string and is shared, so the argument selects
        // a set rather than one provider. The set is rebuilt as one unit or not at all, which
        // is the only reading of `refresh` that keeps RC-D5's all-or-nothing promise when the
        // id is `""`. An id no provider carries selects nothing and is a no-op: there is no
        // `RegistrationError` variant for "no such provider", and inventing one would be a
        // spec revision rather than an implementation choice.
        if !index
            .slices
            .iter()
            .any(|slice| slice.provider.provider_id() == provider_id)
        {
            return Ok(());
        }

        let mut retained: HashMap<String, Arc<IndexEntry>> = HashMap::new();
        for slice in index
            .slices
            .iter()
            .filter(|slice| slice.provider.provider_id() != provider_id)
        {
            insert_keys(&mut retained, slice);
        }

        let mut rebuilt: Vec<ProviderSlice> = Vec::with_capacity(index.slices.len());
        for slice in &index.slices {
            if slice.provider.provider_id() == provider_id {
                // The `?` is the all-or-nothing guarantee: `retained` and `rebuilt` are
                // scratch, and the live index is not touched until every rebuild succeeded.
                let fresh = build_slice(&slice.provider, &retained)?;
                insert_keys(&mut retained, &fresh);
                rebuilt.push(fresh);
            } else {
                rebuilt.push(slice.clone());
            }
        }

        index.slices = rebuilt;
        index.by_name = retained;
        Ok(())
    }

    fn unregister_provider(&self, provider_id: &str) -> bool {
        let mut index = self.index.write();
        let mut removed: Vec<String> = Vec::new();
        index.slices.retain(|slice| {
            if slice.provider.provider_id() == provider_id {
                for tool in &slice.tools {
                    removed.extend(tool.keys.iter().cloned());
                }
                false
            } else {
                true
            }
        });
        let present = !removed.is_empty();
        for key in removed {
            index.by_name.remove(&key);
        }
        present
    }

    fn resolve(&self, public_name: &str) -> Option<(Arc<dyn ToolProvider>, String)> {
        self.index
            .read()
            .by_name
            .get(public_name)
            .map(|entry| (Arc::clone(&entry.provider), entry.local_name.clone()))
    }

    fn authority_of(&self, public_name: &str) -> Option<Arc<ToolAuthority>> {
        self.index
            .read()
            .by_name
            .get(public_name)
            .map(|entry| Arc::clone(&entry.authority))
    }

    fn list_for(&self, view: &CatalogView) -> Vec<Value> {
        let policy = self.policy.read();
        let allowlist = caller_allowlist(&policy, view.agent_id.as_deref());
        self.index
            .read()
            .slices
            .iter()
            .filter(|slice| {
                policy.provider_visible_to_session(
                    view.profile.as_deref(),
                    slice.provider.provider_id(),
                )
            })
            .flat_map(|slice| slice.tools.iter())
            .filter(|tool| {
                allowlist
                    .as_ref()
                    .is_none_or(|allowed| allowed.contains(&tool.public_name))
            })
            .filter(|tool| {
                view.filter_by
                    .as_ref()
                    .is_none_or(|held| holder_satisfies(&tool.authority, held))
            })
            .map(|tool| tool.list_entry.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    // The test providers return `&str` because the trait says so; they cannot narrow to
    // `&'static str` one impl at a time.
    #![allow(clippy::unnecessary_literal_bound)]
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
    use async_trait::async_trait;
    use nmcp_policy::{Permission, RootRule};
    use nmcp_schema::{
        CONTRACT_SCHEMA_VERSION, CallContext, CapabilityGrant, ToolCallResult, ToolEffect,
        ToolReach,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    // - Fixtures -

    /// A contract declaring `path` as its only path argument, which its schema defines.
    fn contract(name: &str, permission: Option<Permission>) -> ToolContract {
        ToolContract {
            name: name.to_string(),
            description: format!("{name} description"),
            input_schema: json!({
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            }),
            authority: ToolAuthority {
                permission,
                path_args: if permission.is_some() {
                    vec!["path".to_string()]
                } else {
                    Vec::new()
                },
                grants: Vec::new(),
                effect: ToolEffect::Observe,
                reach: ToolReach::Local,
            },
        }
    }

    /// A provider that declares whatever it is told to and counts how often it is asked.
    ///
    /// It overrides nothing beyond the three methods NMCP-SPEC-003 section 4.3 requires, so
    /// `tool_names` and `tool_list` come from the trait's default bodies and this fixture also
    /// exercises them.
    struct TestProvider {
        id: String,
        version: u32,
        declared: RwLock<Vec<ToolContract>>,
        reads: AtomicUsize,
    }

    impl TestProvider {
        fn new(id: &str, contracts: Vec<ToolContract>) -> Arc<Self> {
            Arc::new(Self {
                id: id.to_string(),
                version: CONTRACT_SCHEMA_VERSION,
                declared: RwLock::new(contracts),
                reads: AtomicUsize::new(0),
            })
        }

        fn at_version(id: &str, version: u32, contracts: Vec<ToolContract>) -> Arc<Self> {
            let provider = Self::new(id, contracts);
            Arc::new(Self {
                id: provider.id.clone(),
                version,
                declared: RwLock::new(provider.declared.read().clone()),
                reads: AtomicUsize::new(0),
            })
        }

        fn redeclare(&self, contracts: Vec<ToolContract>) {
            *self.declared.write() = contracts;
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ToolProvider for TestProvider {
        fn contract_version(&self) -> u32 {
            self.version
        }
        fn provider_id(&self) -> &str {
            &self.id
        }
        fn contracts(&self) -> Vec<ToolContract> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.declared.read().clone()
        }
        async fn call(&self, _name: &str, args: Value, _ctx: &CallContext) -> ToolCallResult {
            ToolCallResult::ok(args)
        }
    }

    /// An upstream that publishes its own `tools/list` entries, annotations and all.
    ///
    /// This is the shape the gateway's `UpstreamProvider` has: the entries are somebody else's
    /// JSON, read off a remote server, and the contracts are what this workspace derived from
    /// them.
    struct PublishingProvider {
        id: String,
        declared: Vec<ToolContract>,
        published: Vec<Value>,
    }

    #[async_trait]
    impl ToolProvider for PublishingProvider {
        fn contract_version(&self) -> u32 {
            CONTRACT_SCHEMA_VERSION
        }
        fn provider_id(&self) -> &str {
            &self.id
        }
        fn contracts(&self) -> Vec<ToolContract> {
            self.declared.clone()
        }
        fn tool_list(&self) -> Vec<Value> {
            self.published.clone()
        }
        async fn call(&self, _name: &str, args: Value, _ctx: &CallContext) -> ToolCallResult {
            ToolCallResult::ok(args)
        }
    }

    fn registry() -> IndexedToolRegistry {
        IndexedToolRegistry::new(Arc::new(RwLock::new(PolicyConfig::default())))
    }

    fn registry_with(policy: PolicyConfig) -> IndexedToolRegistry {
        IndexedToolRegistry::new(Arc::new(RwLock::new(policy)))
    }

    fn names(entries: &[Value]) -> Vec<String> {
        entries
            .iter()
            .filter_map(|entry| entry["name"].as_str().map(String::from))
            .collect()
    }

    // - RC-4: registration refuses rather than shadows -

    /// RC-4. Two providers claiming one public name is a refusal naming both, and the second
    /// contributes nothing at all.
    ///
    /// The collision is the realistic one rather than a contrived one: a first-party tool
    /// named `dev.git_log` and an upstream with id `dev` exposing `git_log` both derive
    /// `dev_git_log`, because the sanitizer maps a dot and a prefix separator to the same
    /// character. That shape is also the reason the error names both contributors: the two
    /// providers have different ids, so an operator reading the message can tell which one to
    /// change.
    #[test]
    fn a_duplicate_public_name_refuses_the_provider_and_names_both_contributors() {
        let registry = registry();
        let first_party = TestProvider::new("", vec![contract("dev.git_log", None)]);
        registry
            .register(first_party)
            .expect("the first claim on a name succeeds");

        // Four tools, the third of which collides. RC-D5's example, exactly.
        let upstream = TestProvider::new(
            "dev",
            vec![
                contract("alpha", None),
                contract("beta", None),
                contract("git_log", None),
                contract("gamma", None),
            ],
        );
        let refused = registry
            .register(upstream)
            .expect_err("a duplicate public name is refused");

        match &refused {
            RegistrationError::DuplicateToolName {
                name,
                owner,
                claimant,
            } => {
                assert_eq!(name, "dev_git_log", "the contested name is reported");
                assert_eq!(owner, "", "the provider already holding the name");
                assert_eq!(claimant, "dev", "the provider that tried to take it");
            }
            other => panic!("expected DuplicateToolName, got {other:?}"),
        }

        // The second provider contributed NO tools, including the two that were valid and
        // came before the collision, and the one that came after.
        for name in ["dev_alpha", "dev_beta", "dev_gamma", "dev::alpha"] {
            assert!(
                registry.resolve(name).is_none(),
                "{name} must not resolve: a refused provider registers none of its tools"
            );
        }
        assert!(
            registry.resolve("dev_git_log").is_some(),
            "the provider that held the name keeps it"
        );
        assert_eq!(
            registry.len(),
            1,
            "only the first provider's tool is indexed"
        );
    }

    /// The same refusal between two first-party providers, which is the common shape and the
    /// one where both ids are empty. The message is weaker there and the registry does not
    /// pretend otherwise: `owner` and `claimant` are the only identifiers a provider has.
    #[test]
    fn two_first_party_providers_cannot_both_claim_one_name() {
        let registry = registry();
        registry
            .register(TestProvider::new("", vec![contract("echo", None)]))
            .expect("first");
        let refused = registry
            .register(TestProvider::new(
                "",
                vec![contract("echo", None), contract("other", None)],
            ))
            .expect_err("the second claim is refused");
        assert!(
            matches!(&refused, RegistrationError::DuplicateToolName { name, .. } if name == "echo"),
            "expected DuplicateToolName for echo, got {refused:?}"
        );
        assert!(registry.resolve("other").is_none());
    }

    /// RC-D6. `public_tool_name` truncates at 64 characters, so two distinct local names can
    /// derive one public name. That is a duplicate like any other, and the refusal names the
    /// derived name so an operator sees the collision rather than inferring it from two local
    /// names that look nothing alike at their tails.
    #[test]
    fn a_sanitization_collision_refuses_the_provider_and_names_the_derived_name() {
        let registry = registry();
        let prefix = "a".repeat(64);
        let refused = registry
            .register(TestProvider::new(
                "",
                vec![
                    contract(&format!("{prefix}_one"), None),
                    contract(&format!("{prefix}_two"), None),
                ],
            ))
            .expect_err("two local names deriving one public name collide");
        match &refused {
            RegistrationError::DuplicateToolName {
                name,
                owner,
                claimant,
            } => {
                assert_eq!(name, &prefix, "the derived name is what collided");
                assert_eq!(owner, "");
                assert_eq!(claimant, "");
            }
            other => panic!("expected DuplicateToolName, got {other:?}"),
        }
        assert!(registry.is_empty(), "neither tool was registered");
    }

    // - RC-5: declared path arguments exist in the schema -

    /// RC-5. A `path_args` entry the tool's own input schema does not define is a root
    /// resolution that can never fire, so it is refused at registration rather than
    /// discovered one denied call at a time.
    #[test]
    fn a_path_argument_the_schema_does_not_define_is_refused() {
        let registry = registry();
        let mut declared = contract("read_thing", Some(Permission::Read));
        declared.authority.path_args = vec!["path".to_string(), "repo_path".to_string()];

        let refused = registry
            .register(TestProvider::new("", vec![declared]))
            .expect_err("an undeclared path argument is refused");
        match &refused {
            RegistrationError::UndeclaredPathArgument { name, arg } => {
                assert_eq!(name, "read_thing");
                assert_eq!(
                    arg, "repo_path",
                    "the refusal names the argument the schema is missing, not the first one"
                );
            }
            other => panic!("expected UndeclaredPathArgument, got {other:?}"),
        }
        assert!(registry.is_empty());
    }

    /// The same tool with the argument added to its schema registers. Paired with the test
    /// above so the refusal is attributable to the schema and not to anything else about the
    /// declaration.
    #[test]
    fn the_same_declaration_registers_once_the_schema_defines_the_argument() {
        let registry = registry();
        let mut declared = contract("read_thing", Some(Permission::Read));
        declared.authority.path_args = vec!["path".to_string(), "repo_path".to_string()];
        declared.input_schema = json!({
            "type": "object",
            "properties": {"path": {"type": "string"}, "repo_path": {"type": "string"}},
        });
        registry
            .register(TestProvider::new("", vec![declared]))
            .expect("a declared path argument the schema defines is accepted");
        assert!(registry.resolve("read_thing").is_some());
    }

    /// A schema with no properties at all defines no path argument. Separated from the case
    /// above because an implementation that only compared against a present `properties` map
    /// would pass that one and let this through.
    #[test]
    fn a_schema_with_no_properties_defines_no_path_argument() {
        let registry = registry();
        let mut declared = contract("thing", Some(Permission::Read));
        declared.input_schema = json!({"type": "object"});
        let refused = registry
            .register(TestProvider::new("", vec![declared]))
            .expect_err("a schema with no properties cannot receive a path argument");
        assert!(matches!(
            refused,
            RegistrationError::UndeclaredPathArgument { .. }
        ));
    }

    /// NMCP-SPEC-003 v1.1: a call that supplies none of a tool's declared path arguments is
    /// `Denial::MissingPathArgument`, which is an authorization refusal and not a
    /// registration one. The tool registers, is listed, and is refused per call with a reason.
    #[test]
    fn a_missing_path_argument_is_not_a_registration_error() {
        let registry = registry();
        registry
            .register(TestProvider::new(
                "",
                vec![contract("read_thing", Some(Permission::Read))],
            ))
            .expect("declaring a path argument is not itself a refusal");
        let authority = registry
            .authority_of("read_thing")
            .expect("the declaration is indexed");
        assert_eq!(authority.path_args, vec!["path".to_string()]);
    }

    // - RC-9: dispatch does not enumerate -

    /// RC-9, and the reason it is written this way. A counting provider records how often it
    /// is asked to enumerate. One `register`, then ten thousand resolutions, and the count is
    /// exactly one: the index answers, the provider is never asked again.
    ///
    /// The version this replaces resolved a tail-registered tool and asserted it was found,
    /// which passes under a linear scan and therefore grades nothing.
    #[test]
    fn ten_thousand_resolutions_ask_the_provider_to_enumerate_exactly_once() {
        let registry = registry();
        let provider = TestProvider::new(
            "",
            vec![
                contract("first", None),
                contract("middle", None),
                contract("last", None),
            ],
        );
        registry
            .register(Arc::clone(&provider) as Arc<dyn ToolProvider>)
            .expect("register");
        assert_eq!(provider.reads(), 1, "registration reads the catalogue once");

        for _ in 0..10_000 {
            assert!(registry.resolve("last").is_some());
        }
        assert_eq!(
            provider.reads(),
            1,
            "ten thousand resolutions asked the provider to enumerate again"
        );

        // The declaration lookup is on the same path and must not enumerate either: it is
        // what authorization reads before every call.
        for _ in 0..10_000 {
            assert!(registry.authority_of("first").is_some());
        }
        assert_eq!(provider.reads(), 1);
    }

    /// The same property for an upstream, whose `contracts()` is the expensive one because it
    /// reads a cache filled from a remote server. The count after registration is not pinned,
    /// because a provider taking the default `tool_list` body legitimately enumerates twice
    /// while that method still exists; what is pinned is that no amount of resolving moves it.
    #[test]
    fn resolving_an_upstream_tool_never_re_reads_its_catalogue() {
        let registry = registry();
        let provider = TestProvider::new("gateway", vec![contract("ping", None)]);
        registry
            .register(Arc::clone(&provider) as Arc<dyn ToolProvider>)
            .expect("register");
        let after_registration = provider.reads();

        for _ in 0..10_000 {
            assert!(registry.resolve("gateway_ping").is_some());
            assert!(registry.authority_of("gateway_ping").is_some());
        }
        assert_eq!(provider.reads(), after_registration);
    }

    // - RC-18: the upstream refresh path -

    /// RC-18, the `UpstreamProvider` lifecycle end to end. A provider returning `vec![]`
    /// registers successfully, because an upstream legitimately declares nothing until its
    /// cache warms and refusing that would refuse every upstream (RC-D5). It then declares two
    /// tools, and `refresh` makes both resolvable and listable.
    #[test]
    fn an_upstream_registers_empty_and_becomes_resolvable_after_refresh() {
        let registry = registry();
        let provider = TestProvider::new("gateway", Vec::new());
        registry
            .register(Arc::clone(&provider) as Arc<dyn ToolProvider>)
            .expect("an empty provider registers: there is no EmptyProvider refusal");
        assert!(registry.is_empty());
        assert!(registry.list_for(&CatalogView::default()).is_empty());
        assert!(registry.resolve("gateway_ping").is_none());

        provider.redeclare(vec![contract("ping", None), contract("pong", None)]);
        // Nothing changes until refresh: the index is read at registration, not per call.
        assert!(registry.resolve("gateway_ping").is_none());

        registry.refresh("gateway").expect("refresh");

        for name in ["gateway_ping", "gateway_pong"] {
            let (owner, local) = registry.resolve(name).expect("resolves after refresh");
            assert_eq!(owner.provider_id(), "gateway");
            assert_eq!(name, format!("gateway_{local}"));
        }
        assert_eq!(
            names(&registry.list_for(&CatalogView::default())),
            ["gateway_ping", "gateway_pong"],
            "both tools are listable, under their public names"
        );

        // And the catalogue can shrink again, which is the other half of a remote catalogue.
        provider.redeclare(vec![contract("ping", None)]);
        registry.refresh("gateway").expect("refresh");
        assert!(registry.resolve("gateway_pong").is_none());
        assert_eq!(registry.len(), 1);
    }

    /// Refreshing an id no provider carries is a no-op rather than an error. There is no
    /// `RegistrationError` variant for "no such provider" and inventing one would be a spec
    /// revision; a caller that unregistered a provider and then polled it is not a caller
    /// doing anything wrong.
    #[test]
    fn refreshing_an_unknown_provider_id_changes_nothing() {
        let registry = registry();
        registry
            .register(TestProvider::new("", vec![contract("echo", None)]))
            .expect("register");
        registry.refresh("nobody").expect("no-op");
        assert!(registry.resolve("echo").is_some());
        assert_eq!(registry.len(), 1);
    }

    // - RC-D5: all-or-nothing, on both paths -

    /// A refresh that would introduce a duplicate leaves the previous index in place. The
    /// provider's own previous tools stay resolvable and the new ones do not appear, because a
    /// provider whose catalogue half-updated is a state no operator asked for.
    ///
    /// The collision arrives the way a real one would: the first-party catalogue holds
    /// `up.taken`, which sanitizes to `up_taken`, and an upstream with id `up` starts
    /// advertising a tool called `taken`. Nobody wrote either name to collide with the other,
    /// and after the refresh the upstream's own poll is what discovers it.
    #[test]
    fn a_refresh_that_would_collide_leaves_the_previous_index_in_place() {
        let registry = registry();
        registry
            .register(TestProvider::new("", vec![contract("up.taken", None)]))
            .expect("the first-party provider claims a name");

        let upstream = TestProvider::new("up", vec![contract("original", None)]);
        registry
            .register(Arc::clone(&upstream) as Arc<dyn ToolProvider>)
            .expect("register");
        assert!(registry.resolve("up_original").is_some());

        // The new catalogue collides on its second tool. `up_fresh` is valid and must not
        // survive the refusal.
        upstream.redeclare(vec![
            contract("fresh", None),
            contract("taken", None),
            contract("later", None),
        ]);
        let refused = registry
            .refresh("up")
            .expect_err("a refresh that collides is refused");
        assert!(matches!(
            refused,
            RegistrationError::DuplicateToolName { .. }
        ));

        assert!(
            registry.resolve("up_original").is_some(),
            "the previous index survives a refused refresh"
        );
        for name in ["up_fresh", "up_later"] {
            assert!(
                registry.resolve(name).is_none(),
                "{name} must not appear from a refused refresh"
            );
        }
        assert_eq!(registry.len(), 2);
    }

    /// A refresh may reclaim a name the same provider already held, which is what makes
    /// refresh different from registering a second time. Without excluding the provider's own
    /// slice from the duplicate check, every refresh of an unchanged catalogue would refuse
    /// itself.
    #[test]
    fn a_refresh_can_keep_the_names_the_provider_already_held() {
        let registry = registry();
        let provider = TestProvider::new("up", vec![contract("ping", None)]);
        registry
            .register(Arc::clone(&provider) as Arc<dyn ToolProvider>)
            .expect("register");
        registry
            .refresh("up")
            .expect("an unchanged refresh is fine");
        assert!(registry.resolve("up_ping").is_some());

        provider.redeclare(vec![contract("ping", None), contract("pong", None)]);
        registry.refresh("up").expect("a widened refresh is fine");
        assert_eq!(registry.len(), 2);
    }

    /// `refresh("")` selects every first-party provider, because a first-party id is shared.
    /// They are rebuilt as one unit, so a collision between two of them leaves both alone.
    #[test]
    fn refreshing_the_first_party_id_rebuilds_every_first_party_provider_as_one_unit() {
        let registry = registry();
        let one = TestProvider::new("", vec![contract("one", None)]);
        let two = TestProvider::new("", vec![contract("two", None)]);
        registry
            .register(Arc::clone(&one) as Arc<dyn ToolProvider>)
            .expect("register");
        registry
            .register(Arc::clone(&two) as Arc<dyn ToolProvider>)
            .expect("register");

        two.redeclare(vec![contract("three", None)]);
        registry.refresh("").expect("refresh");
        assert!(registry.resolve("one").is_some());
        assert!(registry.resolve("three").is_some());
        assert!(registry.resolve("two").is_none());

        // Now make them collide. Neither moves.
        two.redeclare(vec![contract("one", None)]);
        let refused = registry.refresh("").expect_err("a collision is refused");
        assert!(matches!(
            refused,
            RegistrationError::DuplicateToolName { .. }
        ));
        assert!(registry.resolve("one").is_some());
        assert!(registry.resolve("three").is_some());
        assert_eq!(registry.len(), 2);
    }

    // - RC-D6: the name forms, and the guard on the bare one -

    /// RC-D6, and the guard v0.1 dropped. A first-party tool answers to its bare local name.
    /// An upstream's tool does **not**: it answers to the derived public name and to
    /// `provider_id::local_name`, and nothing else. Without that guard every upstream
    /// publishes its bare local names into the first-party namespace, and an upstream exposing
    /// a common name takes down its whole provider on a duplicate.
    #[test]
    fn only_a_first_party_provider_publishes_its_bare_local_name() {
        let registry = registry();
        registry
            .register(TestProvider::new("", vec![contract("mem.write", None)]))
            .expect("first-party");
        registry
            .register(TestProvider::new("up", vec![contract("execute", None)]))
            .expect("upstream");

        // First-party: both the bare local name and the derived public name resolve.
        assert!(registry.resolve("mem.write").is_some());
        assert!(registry.resolve("mem_write").is_some());

        // Upstream: the public name and the namespaced form resolve, the bare one does not.
        assert!(registry.resolve("up_execute").is_some());
        assert!(registry.resolve("up::execute").is_some());
        assert!(
            registry.resolve("execute").is_none(),
            "an upstream must not publish its bare local name into the first-party namespace"
        );
    }

    /// The bare-name guard is what keeps two upstreams exposing the same local name apart.
    /// Both register, and each is reachable only under its own prefix.
    #[test]
    fn two_upstreams_may_expose_the_same_local_name() {
        let registry = registry();
        registry
            .register(TestProvider::new("alpha", vec![contract("run", None)]))
            .expect("alpha");
        registry
            .register(TestProvider::new("beta", vec![contract("run", None)]))
            .expect("beta: a shared local name is not a shared public name");

        assert_eq!(
            registry
                .resolve("alpha_run")
                .expect("alpha")
                .0
                .provider_id(),
            "alpha"
        );
        assert_eq!(
            registry.resolve("beta_run").expect("beta").0.provider_id(),
            "beta"
        );
        assert!(registry.resolve("run").is_none());
    }

    /// Validation applies to the derived public name and never to `ToolContract.name`. Local
    /// names legitimately contain dots and the validator rejects dots, so validating the local
    /// name would refuse the existing first-party catalogue.
    #[test]
    fn a_local_name_containing_dots_registers_under_a_sanitized_public_name() {
        let registry = registry();
        registry
            .register(TestProvider::new(
                "",
                vec![contract("win.eventlog_query", None)],
            ))
            .expect("a dotted local name is not an invalid tool name");
        let (_, local) = registry.resolve("win_eventlog_query").expect("resolves");
        assert_eq!(local, "win.eventlog_query", "dispatch gets the local name");
    }

    /// A local name that sanitizes to nothing derives an unaddressable public name, which is
    /// the case `InvalidToolName` exists for.
    #[test]
    fn a_name_that_sanitizes_to_nothing_is_refused_as_invalid() {
        let registry = registry();
        let refused = registry
            .register(TestProvider::new("", vec![contract("...", None)]))
            .expect_err("a name that derives nothing is refused");
        match &refused {
            RegistrationError::InvalidToolName {
                provider_id,
                local,
                public,
            } => {
                assert_eq!(provider_id, "");
                assert_eq!(local, "...", "the refusal names the local name as declared");
                assert!(public.is_empty(), "and the derived name that failed");
            }
            other => panic!("expected InvalidToolName, got {other:?}"),
        }
    }

    // - The remaining refusals -

    /// RC-D5. A provider built against a contract version this build does not understand is
    /// refused before its declarations are read at all: interpreting fields whose meaning may
    /// have changed is the failure the version exists to prevent.
    #[test]
    fn a_newer_contract_version_is_refused_rather_than_guessed_at() {
        let registry = registry();
        let refused = registry
            .register(TestProvider::at_version(
                "up",
                CONTRACT_SCHEMA_VERSION + 1,
                vec![contract("ping", None)],
            ))
            .expect_err("a newer contract version is refused");
        match &refused {
            RegistrationError::UnsupportedContractVersion {
                provider_id,
                found,
                accepted,
            } => {
                assert_eq!(provider_id, "up");
                assert_eq!(*found, CONTRACT_SCHEMA_VERSION + 1);
                assert_eq!(*accepted, CONTRACT_SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedContractVersion, got {other:?}"),
        }
        assert!(registry.is_empty());
    }

    /// RC-A3 and RC-D4. INV-1 is kernel-owned and not delegable: a provider declaring itself
    /// harmless is a provider grading its own homework, so a delete-denied name is refused at
    /// registration whatever the declaration says. Refusing here means the operator wiring the
    /// server learns it, rather than a caller being denied forever at stage 0.
    #[test]
    fn a_delete_denied_name_is_refused_however_it_is_declared() {
        for name in ["delete", "DROP_TABLE", "rm"] {
            let registry = registry();
            let mut declared = contract(name, None);
            declared.authority.effect = ToolEffect::Observe;
            let refused = registry
                .register(TestProvider::new("", vec![declared]))
                .expect_err("a delete-denied name is refused");
            assert!(
                matches!(&refused, RegistrationError::DeleteDeniedName { name: refused_name } if refused_name.eq_ignore_ascii_case(name)),
                "expected DeleteDeniedName for {name}, got {refused:?}"
            );
            assert!(registry.is_empty());
        }
    }

    /// The denylist is compared against the names a caller could actually dispatch, which is
    /// why an upstream tool named `delete` registers: it is reachable only as `up_delete` and
    /// `up::delete`, and neither is on the list. The guard that makes that true is the same
    /// `provider_id.is_empty()` guard as above, so this is that guard graded from the INV-1
    /// side.
    #[test]
    fn an_upstream_tool_whose_local_name_is_denied_is_reachable_only_under_its_prefix() {
        let registry = registry();
        registry
            .register(TestProvider::new("up", vec![contract("delete", None)]))
            .expect("the bare name is never published, so nothing on the denylist is reachable");
        assert!(registry.resolve("up_delete").is_some());
        assert!(registry.resolve("delete").is_none());
    }

    // - unregister -

    #[test]
    fn unregistering_removes_every_name_form_and_reports_whether_anything_went() {
        let registry = registry();
        registry
            .register(TestProvider::new("", vec![contract("mem.write", None)]))
            .expect("first-party");
        registry
            .register(TestProvider::new("up", vec![contract("ping", None)]))
            .expect("upstream");

        assert!(registry.unregister_provider("up"));
        for name in ["up_ping", "up::ping"] {
            assert!(registry.resolve(name).is_none(), "{name} still resolves");
        }
        assert!(
            registry.resolve("mem_write").is_some(),
            "the other provider is untouched"
        );

        assert!(
            !registry.unregister_provider("up"),
            "removing a provider that is not there reports false"
        );

        assert!(registry.unregister_provider(""));
        assert!(registry.resolve("mem.write").is_none());
        assert!(registry.is_empty());
    }

    /// A name freed by unregistering is available again, which is the property that makes an
    /// upstream replaceable at runtime without restarting the daemon.
    #[test]
    fn a_name_freed_by_unregistering_can_be_claimed_again() {
        let registry = registry();
        registry
            .register(TestProvider::new("", vec![contract("echo", None)]))
            .expect("register");
        assert!(
            registry
                .register(TestProvider::new("", vec![contract("echo", None)]))
                .is_err()
        );
        assert!(registry.unregister_provider(""));
        registry
            .register(TestProvider::new("", vec![contract("echo", None)]))
            .expect("the name is free again");
        assert_eq!(registry.len(), 1);
    }

    // - authority_of -

    /// The declaration is readable without obtaining the ability to call, which is why
    /// `authority_of` is a separate method from `resolve`. It hands back an owned handle
    /// rather than a reference because the index sits behind a lock (RC-D7) and a reference
    /// into it cannot outlive the guard.
    #[test]
    fn the_declaration_is_readable_without_obtaining_the_ability_to_call() {
        let registry = registry();
        let mut declared = contract("thing", Some(Permission::Read));
        declared.authority.grants = vec![CapabilityGrant::new(Permission::WindowsApi.as_str())];
        registry
            .register(TestProvider::new("", vec![declared]))
            .expect("register");

        let authority: Arc<ToolAuthority> = registry.authority_of("thing").expect("indexed");
        assert_eq!(authority.permission, Some(Permission::Read));
        assert_eq!(authority.path_args, vec!["path".to_string()]);
        assert_eq!(
            authority.grants,
            vec![CapabilityGrant::new(Permission::WindowsApi.as_str())]
        );
        assert!(registry.authority_of("not_a_tool").is_none());
    }

    // - list_for -

    fn root(id: &str, permissions: &[Permission]) -> RootRule {
        RootRule {
            id: id.to_string(),
            path: std::env::temp_dir().join(format!("nmcp-registry-{id}")),
            permissions: permissions.iter().copied().collect(),
        }
    }

    fn held(roots: Vec<RootRule>) -> HeldAuthority {
        let grants = roots
            .iter()
            .flat_map(|root| root.permissions.iter())
            .map(|permission| CapabilityGrant::new(permission.as_str()))
            .collect();
        HeldAuthority {
            roots,
            grants,
            agent_id: None,
        }
    }

    /// A first-party tool is listed through `ToolContract::to_list_entry`, so its annotations
    /// are read off the same declaration authorization consumes and the two cannot disagree
    /// (RC-A4). The entry carries the derived public name, not the local one.
    #[test]
    fn a_first_party_entry_is_derived_from_its_declaration() {
        let registry = registry();
        let mut declared = contract("dev.git_publish", None);
        declared.authority.effect = ToolEffect::Mutate;
        declared.authority.reach = ToolReach::Remote;
        registry
            .register(TestProvider::new("", vec![declared]))
            .expect("register");

        let listed = registry.list_for(&CatalogView::default());
        assert_eq!(listed.len(), 1);
        let entry = &listed[0];
        assert_eq!(entry["name"], "dev_git_publish");
        assert_eq!(entry["description"], "dev.git_publish description");
        assert_eq!(entry["annotations"]["readOnlyHint"], false);
        assert_eq!(entry["annotations"]["openWorldHint"], true);
        assert_eq!(entry["annotations"]["destructiveHint"], false);
    }

    /// An upstream keeps whatever annotations it published and gets none invented for it,
    /// which is the existing rule in the router's merged tool list and stays the rule (RC-8).
    /// Only the name is rewritten, because that is the one thing this server owns.
    #[test]
    fn an_upstream_entry_passes_through_what_the_upstream_published() {
        let registry = registry();
        registry
            .register(Arc::new(PublishingProvider {
                id: "up".to_string(),
                declared: vec![contract("ping", None)],
                published: vec![json!({
                    "name": "ping",
                    "description": "somebody else's description",
                    "inputSchema": {"type": "object"},
                    "annotations": {"readOnlyHint": false, "title": "Ping"},
                })],
            }))
            .expect("register");

        let listed = registry.list_for(&CatalogView::default());
        assert_eq!(listed.len(), 1);
        let entry = &listed[0];
        assert_eq!(entry["name"], "up_ping", "only the name is rewritten");
        assert_eq!(entry["description"], "somebody else's description");
        assert_eq!(entry["annotations"]["title"], "Ping");
        assert_eq!(entry["annotations"]["readOnlyHint"], false);
        assert!(
            entry["annotations"].get("destructiveHint").is_none(),
            "this server invents no annotation on somebody else's behalf"
        );
    }

    /// An upstream that published no annotations gets none. The other half of the rule above,
    /// separated because an implementation that fell back to `to_list_entry` would pass that
    /// one and fail this.
    #[test]
    fn an_upstream_that_published_no_annotations_is_given_none() {
        let registry = registry();
        registry
            .register(Arc::new(PublishingProvider {
                id: "up".to_string(),
                declared: vec![contract("ping", None)],
                published: vec![json!({
                    "name": "ping",
                    "description": "bare",
                    "inputSchema": {"type": "object"},
                })],
            }))
            .expect("register");
        let listed = registry.list_for(&CatalogView::default());
        assert!(listed[0].get("annotations").is_none());
    }

    /// G6-8. A session scoped to a gateway profile sees the upstreams that profile names and
    /// the first-party provider, which a profile never scopes away: a profile selects among
    /// proxied servers, and taking away the tools this service implements itself would be a
    /// different feature wearing the same word.
    #[test]
    fn listing_is_scoped_to_the_session_profile() {
        let mut policy = PolicyConfig::default();
        policy.gateway_profiles.insert(
            "reading".to_string(),
            nmcp_policy::GatewayProfile {
                label: "Reading".into(),
                servers: std::collections::BTreeMap::from([("up".to_string(), true)]),
            },
        );
        let registry = registry_with(policy);
        registry
            .register(TestProvider::new("", vec![contract("echo", None)]))
            .expect("first-party");
        registry
            .register(TestProvider::new("up", vec![contract("ping", None)]))
            .expect("upstream");
        registry
            .register(TestProvider::new("other", vec![contract("fetch", None)]))
            .expect("second upstream");

        assert_eq!(
            names(&registry.list_for(&CatalogView::default())),
            ["echo", "up_ping", "other_fetch"]
        );
        let scoped = CatalogView {
            profile: Some("reading".to_string()),
            ..CatalogView::default()
        };
        assert_eq!(names(&registry.list_for(&scoped)), ["echo", "up_ping"]);
    }

    /// RC-D8, first part. `CallerToolAllowlist` filtering is unconditional, because it is
    /// already policy and already a call-time deny: applying it at list time is a pure
    /// narrowing that makes the list agree with what a call would do.
    #[test]
    fn a_caller_restricted_by_policy_sees_only_the_tools_it_may_call() {
        let policy = PolicyConfig {
            abac_rules: vec![nmcp_policy::AbacRule::CallerToolAllowlist {
                caller: "third-party".into(),
                allowed_tools: vec!["echo".into()],
                action: nmcp_policy::AbacAction::Deny,
            }],
            ..PolicyConfig::default()
        };
        let registry = registry_with(policy);
        registry
            .register(TestProvider::new(
                "",
                vec![contract("echo", None), contract("mem.write", None)],
            ))
            .expect("register");

        let restricted = CatalogView {
            agent_id: Some("third-party".to_string()),
            ..CatalogView::default()
        };
        assert_eq!(names(&registry.list_for(&restricted)), ["echo"]);

        // The rule applies to exactly one caller. Everybody else, including an unauthenticated
        // local caller, sees everything.
        let other = CatalogView {
            agent_id: Some("operator".to_string()),
            ..CatalogView::default()
        };
        assert_eq!(names(&registry.list_for(&other)), ["echo", "mem_write"]);
        assert_eq!(
            names(&registry.list_for(&CatalogView::default())),
            ["echo", "mem_write"]
        );
    }

    /// A `RequireApproval` allowlist rule leaves the tool callable behind a human, so hiding
    /// it would make the catalogue disagree with the ring in the direction that produces a
    /// support question nobody can answer from the client side.
    #[test]
    fn an_allowlist_that_escalates_rather_than_denies_hides_nothing() {
        let policy = PolicyConfig {
            abac_rules: vec![nmcp_policy::AbacRule::CallerToolAllowlist {
                caller: "third-party".into(),
                allowed_tools: vec!["echo".into()],
                action: nmcp_policy::AbacAction::RequireApproval,
            }],
            ..PolicyConfig::default()
        };
        let registry = registry_with(policy);
        registry
            .register(TestProvider::new(
                "",
                vec![contract("echo", None), contract("mem.write", None)],
            ))
            .expect("register");
        let restricted = CatalogView {
            agent_id: Some("third-party".to_string()),
            ..CatalogView::default()
        };
        assert_eq!(
            names(&registry.list_for(&restricted)),
            ["echo", "mem_write"]
        );
    }

    /// RC-D8, second part. Permission filtering is available and off by default: a tool that
    /// vanishes is indistinguishable from a tool that does not exist, and the refusal path
    /// already gives a precise reason. With `filter_by` set, a tool whose declared permission
    /// the holder has on no root is omitted.
    #[test]
    fn permission_filtering_is_off_by_default_and_exact_when_switched_on() {
        let registry = registry();
        registry
            .register(TestProvider::new(
                "",
                vec![
                    contract("reader", Some(Permission::Read)),
                    contract("writer", Some(Permission::Write)),
                    contract("free", None),
                ],
            ))
            .expect("register");

        assert_eq!(
            names(&registry.list_for(&CatalogView::default())),
            ["reader", "writer", "free"],
            "the default lists everything and refuses at call time with a reason"
        );

        let read_only = CatalogView {
            filter_by: Some(held(vec![root("docs", &[Permission::Read])])),
            ..CatalogView::default()
        };
        assert_eq!(names(&registry.list_for(&read_only)), ["reader", "free"]);

        let nothing = CatalogView {
            filter_by: Some(held(Vec::new())),
            ..CatalogView::default()
        };
        assert_eq!(
            names(&registry.list_for(&nothing)),
            ["free"],
            "a tool needing no root-scoped authority is still listed"
        );
    }

    /// The filter is exact rather than approximate, which is the property that makes it safe
    /// to switch on. A tool declaring path arguments is judged on whether the holder could
    /// satisfy it at all, not on a call that does not exist: judging it against empty
    /// arguments would hide every path tool from every caller.
    #[test]
    fn permission_filtering_does_not_hide_a_tool_for_want_of_arguments() {
        let registry = registry();
        let mut declared = contract("reader", Some(Permission::Read));
        declared.authority.path_args = vec!["path".to_string()];
        registry
            .register(TestProvider::new("", vec![declared]))
            .expect("register");

        let holder = CatalogView {
            filter_by: Some(held(vec![root("docs", &[Permission::Read])])),
            ..CatalogView::default()
        };
        assert_eq!(names(&registry.list_for(&holder)), ["reader"]);
    }

    /// A declared grant the holder does not hold hides the tool, and one it does hold does
    /// not. Grants are checked by the same code the call path runs, so a tool listed under a
    /// grant filter is a tool the grant check would pass.
    #[test]
    fn permission_filtering_reads_declared_grants_too() {
        let registry = registry();
        let mut declared = contract("windows_thing", None);
        declared.authority.grants = vec![CapabilityGrant::new(Permission::WindowsApi.as_str())];
        registry
            .register(TestProvider::new("", vec![declared]))
            .expect("register");

        let without = CatalogView {
            filter_by: Some(held(vec![root("docs", &[Permission::Read])])),
            ..CatalogView::default()
        };
        assert!(names(&registry.list_for(&without)).is_empty());

        let with = CatalogView {
            filter_by: Some(held(vec![root("docs", &[Permission::WindowsApi])])),
            ..CatalogView::default()
        };
        assert_eq!(names(&registry.list_for(&with)), ["windows_thing"]);
    }

    /// Listing is in registration order, then declaration order within a provider. Not a
    /// requirement anybody wrote down, and pinned anyway: a catalogue whose order changes per
    /// call makes every client-side diff of `tools/list` noise.
    #[test]
    fn listing_is_stable_in_registration_then_declaration_order() {
        let registry = registry();
        registry
            .register(TestProvider::new(
                "",
                vec![contract("b", None), contract("a", None)],
            ))
            .expect("register");
        registry
            .register(TestProvider::new("up", vec![contract("z", None)]))
            .expect("register");
        for _ in 0..5 {
            assert_eq!(
                names(&registry.list_for(&CatalogView::default())),
                ["b", "a", "up_z"]
            );
        }
    }

    // - RC-D7: the mutability rule -

    /// RC-D7. Every wire-up method takes `&self`, so the registry is usable after it is behind
    /// an `Arc`, which is where the kernel keeps it. Asserted by doing it: this does not
    /// compile against a `&mut self` receiver, and a shared registry that cannot be registered
    /// into is the asymmetry the spec removed.
    #[test]
    fn every_wire_up_method_is_callable_through_a_shared_handle() {
        let registry: Arc<dyn ToolRegistry> = Arc::new(registry());
        let shared = Arc::clone(&registry);
        shared
            .register(TestProvider::new("up", vec![contract("ping", None)]))
            .expect("register through an Arc");
        shared.refresh("up").expect("refresh through an Arc");
        assert!(shared.resolve("up_ping").is_some());
        assert!(shared.unregister_provider("up"));
    }

    /// The registry crosses threads, which is what `Send + Sync` on the trait is for and what
    /// the axum handler that will hold it requires.
    #[test]
    fn the_registry_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IndexedToolRegistry>();
        assert_send_sync::<Arc<dyn ToolRegistry>>();
    }
}
