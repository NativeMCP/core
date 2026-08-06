//! The indexed tool registry.
//!
//! NMCP-SPEC-003 section 4.4, RATIFIED v1.3. The trait lives in `nmcp-schema` so every
//! provider can see it; the index lives here because the kernel owns dispatch and owns INV-1.
//!
//! RC-D6 is the shape: an index from public tool name to the provider that owns the tool, the
//! local name it is dispatched under, and the authority it declared. Built at registration,
//! rebuilt on refresh, never walked on dispatch. Duplicate detection falls out of insertion
//! rather than being a separate pass.
//!
//! I-047c landed this index unwired; I-047d put the ring on it. `nmcp-router`'s `Router` holds
//! an `Arc<dyn ToolRegistry>`, resolves through [`ToolRegistry::resolve`], authorizes against
//! [`ToolRegistry::authority_of`] and answers `tools/list` from
//! [`ToolRegistry::list_for`]. The compiled-in policy table the ring used to consult is gone.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use nmcp_policy::{AbacAction, AbacRule, PolicyConfig};
use nmcp_schema::{
    CONTRACT_SCHEMA_VERSION, CatalogView, HeldAuthority, RegistrationError, SecretSlot,
    SecretSlotCatalog, ToolAuthority, ToolContract, ToolProvider, ToolRegistry,
    accepts_contract_version, authorize, contains_delete_intent, is_valid_public_tool_name,
    public_tool_name, secret_slots,
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
    /// The tool's declared `secret_ref` slots, extracted and validated at registration
    /// (NMCP-SPEC-002 SB-3) and kept so ring stage 5b reads them in one hash probe instead
    /// of asking the provider to enumerate its catalogue per call (RC-9). Empty for the
    /// overwhelming majority of tools, which costs nothing: an empty `Vec` does not
    /// allocate.
    secret_slots: Vec<SecretSlot>,
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
/// INV-1 denylist, then a declared path argument the schema cannot receive, then a declared
/// secret slot the schema cannot carry, then a collision. INV-1 sits above declaration
/// integrity because a tool that could never legally be called is a worse defect than one
/// whose declaration is wrong, and a collision is checked last because reporting one against a
/// name that was never valid tells an operator to fix the wrong provider. The two declaration
/// checks sit together and in the order the two specifications ratified, which is the only
/// thing separating them: they refuse the same class of defect, a declaration naming something
/// the tool's own schema cannot deliver.
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

        // NMCP-SPEC-002 SB-3 and SB-4, the same argument RC-5 makes one field over. A slot
        // annotation the kernel cannot bind to a top-level argument, or one whose modality is
        // not one of the two SB-4 defines, is a declaration the tool's own schema cannot
        // deliver on. It is refused here rather than at the call for a reason RC-5 does not
        // have: this one fails open. A `path_args` entry the schema never receives resolves no
        // root and the call is denied, whereas a secret slot the kernel never sees is a slot
        // nothing injects into, so the tool runs with the credential missing rather than not
        // running at all. Nothing is resolved by this call and no store is opened; the check
        // reads the declaration and returns (I-032). Since I-034 the validated result is kept
        // on the entry, because the same declaration is what ring stage 5b resolves against
        // and re-extracting it per call would re-read the provider's catalogue on the
        // dispatch path, which RC-9 forbids.
        let declared_slots = match secret_slots(contract) {
            Ok(slots) => slots,
            Err(refusal) => return Err(refusal.at_tool(public_name)),
        };

        // RC-21. A first-party tool's annotations are derived from its declared authority by
        // `to_list_entry`, so one that also published its own would be two sources that can
        // disagree about one tool. That is the defect RC-A4 exists to make unrepresentable, and
        // an optional field with no refusal behind it would reintroduce it quietly. Refused
        // rather than ignored, so the provider author learns it instead of wondering later why
        // the annotations they wrote never appeared.
        if provider_id.is_empty() && contract.published_annotations.is_some() {
            return Err(RegistrationError::PublishedAnnotationsFromFirstParty {
                name: public_name,
            });
        }

        let entry = Arc::new(IndexEntry {
            provider: Arc::clone(provider),
            local_name: contract.name.clone(),
            list_entry: list_entry_for(&provider_id, contract, &public_name),
            public_name,
            authority: Arc::new(contract.authority.clone()),
            secret_slots: declared_slots,
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

/// The `tools/list` entry for one tool, computed once at registration.
///
/// `ToolContract::to_list_entry` is called for **first-party providers only**. A proxied
/// upstream is somebody else's software: this server can vouch for what its own tools do and
/// cannot vouch for theirs, so it invents no annotation on their behalf (RC-8). That is the
/// rule `nmcp-router`'s merged tool list has always applied and it stays the rule.
///
/// An upstream's own annotations reach the catalogue through
/// [`ToolContract::published_annotations`], emitted verbatim (RC-21). I-047c read them from
/// `ToolProvider::tool_list`, which section 4.3 deletes; the escalation that raised it produced
/// NMCP-SPEC-003 v1.3 rather than a deferral, because a channel that only matters once
/// `nmcp-gateway` lands is exactly the one that gets forgotten between the commit that removes
/// it and the commit that needs it.
///
/// Verbatim is the whole requirement. This server rewrites the name, because the public name is
/// the one thing it owns, and touches nothing else: not to add `destructiveHint: false`, which
/// is this product's guarantee about its own tools and not a claim it can make for somebody
/// else's, and not to derive `readOnlyHint` from the upstream's declared `effect`, which would
/// be inventing an annotation on its behalf out of data it controls.
///
/// The absent case still matters and is still the honest answer: an upstream that published
/// nothing gets nothing, and its tools reach a client under the MCP defaults. A first-party
/// tool cannot reach this branch at all, because `build_slice` refuses one that supplies the
/// field.
fn list_entry_for(provider_id: &str, contract: &ToolContract, public_name: &str) -> Value {
    if provider_id.is_empty() {
        return contract.to_list_entry(public_name);
    }
    let mut entry = json!({
        "name": public_name,
        "description": contract.description,
        "inputSchema": contract.input_schema,
    });
    if let Some(published) = contract.published_annotations.clone()
        && let Some(object) = entry.as_object_mut()
    {
        object.insert("annotations".into(), published);
    }
    entry
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

impl SecretSlotCatalog for IndexedToolRegistry {
    /// The declared slots of the tool registered under `tool_name`, from the same index
    /// entry `resolve` and `authority_of` answer from, so the slots ring stage 5b reads and
    /// the tool that resolves cannot disagree (I-034). One hash probe, no provider is
    /// consulted (RC-9), and the clone is of a `Vec` that is empty for every slotless tool,
    /// which does not allocate.
    fn secret_slots_of(&self, tool_name: &str) -> Option<Vec<SecretSlot>> {
        self.index
            .read()
            .by_name
            .get(tool_name)
            .map(|entry| entry.secret_slots.clone())
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
        CONTRACT_SCHEMA_VERSION, CallContext, CapabilityGrant, GrantedAuthority,
        SECRET_SLOT_ANNOTATION, SecretSlotError, ToolCallResult, ToolEffect, ToolReach,
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
            // `None` is what every first-party tool carries and the only value a first-party
            // provider may carry (RC-21). The upstream fixtures below set it explicitly.
            published_annotations: None,
        }
    }

    /// A provider that declares whatever it is told to and counts how often it is asked.
    ///
    /// It implements exactly the four methods NMCP-SPEC-003 section 4.3 freezes, which after
    /// I-047d is the whole trait: the transitional `tool_names` and `tool_list` are gone.
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
        async fn call(
            &self,
            _name: &str,
            args: Value,
            _ctx: &CallContext,
            _granted: &GrantedAuthority,
        ) -> ToolCallResult {
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

    // - NMCP-SPEC-002 SB-3: declared secret slots the schema can carry -

    /// A contract declaring one `secret_ref` slot on `credential`, plus `path` and an
    /// undecorated free-text property, so a test can tell a slot from a string.
    fn contract_with_secret_slot(name: &str, annotation: &Value) -> ToolContract {
        let mut declared = contract(name, None);
        declared.input_schema = json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "credential": {"type": "string", SECRET_SLOT_ANNOTATION: annotation},
                "message": {"type": "string"},
            },
        });
        declared
    }

    /// SB-3. A slot annotation the kernel has no top-level argument to bind is refused at
    /// registration, naming where it found it.
    ///
    /// The nesting here is the reachable shape rather than a contrived one: an argument that
    /// is itself an object, with the annotation on one of its own properties. A reader that
    /// walked only the top-level `properties` map would find nothing, register the tool, and
    /// leave a declared credential that nothing will ever inject, so the tool runs without it.
    #[test]
    fn a_secret_slot_that_is_not_a_property_is_refused_at_registration() {
        let registry = registry();
        let mut declared = contract("call_peer", None);
        declared.input_schema = json!({
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "credential": {
                            "type": "string",
                            SECRET_SLOT_ANNOTATION: {"inject": "env", "var": "SERVICE_TOKEN"},
                        },
                    },
                },
            },
        });

        let refused = registry
            .register(TestProvider::new("", vec![declared]))
            .expect_err("a secret slot no argument can carry is refused");
        match &refused {
            RegistrationError::UndeclaredSecretSlot { name, at } => {
                assert_eq!(name, "call_peer");
                assert_eq!(at, "/properties/config/properties/credential");
            }
            other => panic!("expected UndeclaredSecretSlot, got {other:?}"),
        }
        assert!(registry.is_empty(), "the provider registered nothing");
    }

    /// SB-4. The modality vocabulary is closed at two, and a declaration outside it is refused
    /// here rather than discovered when there is finally something to inject.
    ///
    /// `argv` is the fixture on purpose: SB-A2 removes injection into a command line by
    /// construction, and T5 is asserted by the absence of the modality rather than by a check.
    /// This is where that absence becomes a refusal an operator can read.
    #[test]
    fn a_malformed_injection_modality_is_refused_at_registration() {
        let registry = registry();
        let refused = registry
            .register(TestProvider::new(
                "",
                vec![contract_with_secret_slot(
                    "call_peer",
                    &json!({"inject": "argv", "var": "SERVICE_TOKEN"}),
                )],
            ))
            .expect_err("a modality SB-4 does not define is refused");
        match &refused {
            RegistrationError::MalformedSecretSlot { name, source } => {
                assert_eq!(name, "call_peer");
                assert!(
                    matches!(source, SecretSlotError::UnknownModality { arg, found }
                        if arg == "credential" && found == "argv"),
                    "got {source:?}"
                );
                assert!(
                    format!("{refused}").contains("argv"),
                    "the refusal an operator reads names what it refused"
                );
            }
            other => panic!("expected MalformedSecretSlot, got {other:?}"),
        }
        assert!(registry.is_empty());
    }

    /// A modality declared without the name the contract owes it is the other half of SB-4,
    /// and the message says whose name it is, because the answer is never the caller's.
    #[test]
    fn a_modality_missing_its_contract_supplied_name_is_refused_at_registration() {
        let registry = registry();
        let refused = registry
            .register(TestProvider::new(
                "",
                vec![contract_with_secret_slot(
                    "call_peer",
                    &json!({"inject": "header"}),
                )],
            ))
            .expect_err("a modality with no declared name is refused");
        assert!(
            matches!(&refused, RegistrationError::MalformedSecretSlot { source, .. }
                if matches!(source, SecretSlotError::MissingModalityName { key, .. } if *key == "name")),
            "got {refused:?}"
        );
        assert!(format!("{refused}").contains("by the contract rather than by the caller"));
    }

    /// The paired green case, so both refusals above are attributable to the declaration being
    /// wrong rather than to secret slots being refused generally.
    ///
    /// It also pins the second half of inertness at the kernel boundary. The registry carries
    /// `input_schema` to the catalogue verbatim, annotation and all: it neither strips the
    /// annotation, which would leave a client unable to see the slot, nor promotes the
    /// undecorated `message` property to one.
    #[test]
    fn a_well_formed_secret_slot_registers_and_reaches_the_catalogue_verbatim() {
        let registry = registry();
        let declared = contract_with_secret_slot(
            "call_peer",
            &json!({"inject": "header", "name": "Authorization"}),
        );
        let expected_schema = declared.input_schema.clone();
        registry
            .register(TestProvider::new("", vec![declared.clone()]))
            .expect("a well-formed secret slot registers");
        assert!(registry.resolve("call_peer").is_some());

        let listed = registry.list_for(&CatalogView::default());
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0]["inputSchema"], expected_schema,
            "the schema reaches the catalogue byte for byte, annotation included"
        );

        let slots = secret_slots(&declared).expect("the declaration reads back");
        assert_eq!(
            slots
                .iter()
                .map(|slot| slot.arg.as_str())
                .collect::<Vec<_>>(),
            vec!["credential"],
            "the undecorated properties are not slots"
        );
    }

    /// I-034: the slots the index validated at registration are the slots the catalog hands
    /// ring stage 5b, keyed by every name form the tool answers to, with `Some(vec![])` for
    /// a registered slotless tool and `None` for an unknown name. The three answers differ
    /// on purpose: the stage passes a slotless tool through untouched (SB-2), resolves a
    /// keyed one, and treats an unreadable declaration as its own fail-closed case.
    #[test]
    fn the_slot_catalog_answers_from_the_same_entry_resolution_does() {
        use nmcp_schema::{InjectionModality, SecretSlotCatalog};

        let registry = registry();
        registry
            .register(TestProvider::new(
                "",
                vec![
                    contract_with_secret_slot(
                        "keyed.run",
                        &json!({"inject": "env", "var": "DATABASE_URL"}),
                    ),
                    contract("plain_tool", None),
                ],
            ))
            .expect("both tools register");

        for form in ["keyed_run", "keyed.run"] {
            let slots = registry
                .secret_slots_of(form)
                .expect("a registered tool answers under every name form");
            assert_eq!(slots.len(), 1);
            assert_eq!(slots[0].arg, "credential");
            assert_eq!(
                slots[0].modality,
                InjectionModality::Env {
                    var: "DATABASE_URL".to_string()
                }
            );
        }
        assert_eq!(
            registry.secret_slots_of("plain_tool"),
            Some(Vec::new()),
            "a slotless tool is a known tool with no slots, not an unknown tool"
        );
        assert_eq!(registry.secret_slots_of("never_registered"), None);

        // Unregistering removes the slots with the tool, so the catalog and `resolve`
        // cannot disagree about whether the tool exists.
        assert!(registry.unregister_provider(""));
        assert_eq!(registry.secret_slots_of("keyed_run"), None);
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
    /// reads a cache filled from a remote server. What is pinned is that no amount of resolving
    /// moves the count.
    #[test]
    fn resolving_an_upstream_tool_never_re_reads_its_catalogue() {
        let registry = registry();
        let provider = TestProvider::new("gateway", vec![contract("ping", None)]);
        registry
            .register(Arc::clone(&provider) as Arc<dyn ToolProvider>)
            .expect("register");
        let after_registration = provider.reads();
        // Pinned at I-047d rather than left open. This used to read "not pinned, because a
        // provider taking the default `tool_list` body legitimately enumerates twice while that
        // method still exists"; the method is gone, so an upstream's expensive catalogue read
        // happens exactly once per registration like anybody else's. Additive: the assertion
        // below is unchanged.
        assert_eq!(after_registration, 1);

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

    /// RC-21, first direction. An upstream's published annotations survive verbatim into
    /// `tools/list`, and only the name is rewritten.
    ///
    /// Why it matters, stated rather than assumed: without the passthrough an upstream tool
    /// lists with no annotations at all, and the MCP defaults for `destructiveHint` and
    /// `openWorldHint` are both true. Every proxied tool would then be advertised to every
    /// client as destructive and network-reaching, including a read-only one whose own server
    /// took the trouble to say so. That is the failure `nmcp_proto::tool_annotations` was
    /// written against in the first place, reappearing on the other side of the boundary.
    ///
    /// Verbatim means verbatim. The entry keeps a hint this server would never emit
    /// (`readOnlyHint: false` alongside no `destructiveHint`), keeps a key this workspace has
    /// no notion of (`title`), and gains nothing: not `destructiveHint: false`, which is this
    /// product's guarantee about its own tools and not a claim it can make for somebody
    /// else's.
    #[test]
    fn an_upstream_entry_passes_through_what_the_upstream_published() {
        let registry = registry();
        let mut declared = contract("ping", None);
        declared.published_annotations = Some(json!({
            "readOnlyHint": false,
            "openWorldHint": true,
            "title": "Ping",
        }));
        registry
            .register(TestProvider::new("up", vec![declared]))
            .expect("register");

        let listed = registry.list_for(&CatalogView::default());
        assert_eq!(listed.len(), 1);
        let entry = &listed[0];
        assert_eq!(entry["name"], "up_ping", "only the name is rewritten");
        assert_eq!(entry["description"], "ping description");
        assert_eq!(entry["annotations"]["readOnlyHint"], false);
        assert_eq!(entry["annotations"]["openWorldHint"], true);
        assert_eq!(entry["annotations"]["title"], "Ping");
        assert!(
            entry["annotations"].get("destructiveHint").is_none(),
            "this server invents no annotation on somebody else's behalf, not even the one it \
             guarantees about its own tools"
        );
    }

    /// RC-21, second direction. A first-party provider supplying published annotations is
    /// refused at registration, and the refusal is the point rather than tidiness.
    ///
    /// First-party annotations are derived from the declared authority by `to_list_entry`, so a
    /// first-party tool carrying its own would be two sources that can disagree about one tool.
    /// That is exactly the defect RC-A4 exists to make unrepresentable, and an optional field
    /// with no refusal behind it would reintroduce it quietly: the annotations would simply be
    /// ignored, and whoever wrote them would find out from a client rather than from the
    /// registry. All-or-nothing applies as it does to every other refusal, so the provider's
    /// other tools do not register either.
    #[test]
    fn a_first_party_provider_may_not_supply_published_annotations() {
        let registry = registry();
        let mut declared = contract("echo", None);
        declared.published_annotations = Some(json!({"readOnlyHint": true}));

        let refused = registry
            .register(TestProvider::new(
                "",
                vec![contract("first", None), declared, contract("last", None)],
            ))
            .expect_err("a first-party tool may not publish its own annotations");
        match &refused {
            RegistrationError::PublishedAnnotationsFromFirstParty { name } => {
                assert_eq!(
                    name, "echo",
                    "the refusal names the tool an author has to fix"
                );
            }
            other => panic!("expected PublishedAnnotationsFromFirstParty, got {other:?}"),
        }
        assert!(
            refused
                .to_string()
                .contains("only a proxied upstream may carry"),
            "the message must say who may carry it: {refused}"
        );
        assert!(
            registry.is_empty(),
            "all or nothing: the valid tools either side of it registered nothing"
        );

        // The same declaration under a non-empty provider id is fine, which is what makes the
        // refusal about provenance rather than about the field.
        registry
            .register(TestProvider::new("up", vec![declared_upstream()]))
            .expect("an upstream may carry what its own server published");
        assert_eq!(
            registry.list_for(&CatalogView::default())[0]["annotations"]["readOnlyHint"],
            true
        );
    }

    /// The contract for that last step, kept out of the test body so the two halves read as one
    /// declaration differing only in who registers it.
    fn declared_upstream() -> ToolContract {
        let mut declared = contract("echo", None);
        declared.published_annotations = Some(json!({"readOnlyHint": true}));
        declared
    }

    /// An upstream that published nothing gets nothing, which is the honest answer rather than
    /// a convenient one. Separated from the passthrough above because an implementation that
    /// fell back to `to_list_entry` for a missing field would pass that test and fail this, and
    /// it would do so by asserting this product's no-destructive-action guarantee about
    /// somebody else's software.
    #[test]
    fn an_upstream_that_published_no_annotations_is_given_none() {
        let registry = registry();
        let mut declared = contract("ping", None);
        // Declared read-only and local, which for a first-party tool would emit two hints and
        // the guarantee. For an upstream it emits none: the declaration came off a remote
        // server and is untrusted input (RC-D4), so it is used to authorize and never to
        // advertise.
        declared.authority.effect = ToolEffect::Observe;
        declared.authority.reach = ToolReach::Local;
        assert!(declared.published_annotations.is_none());
        registry
            .register(TestProvider::new("up", vec![declared]))
            .expect("register");

        let listed = registry.list_for(&CatalogView::default());
        assert_eq!(listed.len(), 1);
        let entry = &listed[0];
        assert_eq!(entry["name"], "up_ping", "the public name is this server's");
        assert_eq!(entry["description"], "ping description");
        assert!(
            entry.get("annotations").is_none(),
            "this server invents no annotation on somebody else's behalf"
        );
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

#[cfg(test)]
mod upstream_gateway_lifecycle {
    //! RC-18's gateway half, driven end to end against the real pieces: the actual
    //! `UpstreamProvider` fetching from a live loopback upstream, and the actual index it
    //! registers into. The registry half of RC-18 is graded above with a synthetic
    //! provider; what that cannot grade is the seam this module exists for, that the
    //! provider's `contracts()` are built from a verified fetch and that the registry's
    //! `refresh` is the one moment they become resolvable.
    //!
    //! G-8 is the second half: whether the `tools_sha256` pin is verified before or after
    //! the index is rebuilt decides whether a tampered catalogue is ever briefly
    //! resolvable. The gateway verifies before its cache is replaced, this module refreshes
    //! the index off that cache after a tampered fetch, and what stays resolvable is the
    //! last verified catalogue, which is the security property stated as a test.
    //!
    //! The test lives in this crate deliberately: the kernel composes providers, a provider
    //! never links the kernel (RC-12, RC-A5), and this is the composition direction the
    //! daemon wave will wire for real.

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

    use super::IndexedToolRegistry;
    use nmcp_gateway::{UpstreamProvider, UpstreamStatus};
    use nmcp_policy::{PolicyConfig, UpstreamConfig};
    use nmcp_schema::{CatalogView, ToolProvider, ToolRegistry};
    use parking_lot::RwLock;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A loopback upstream serving whatever `tools` currently holds.
    async fn mock_upstream(tools: Arc<RwLock<Value>>) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock upstream");
        let addr = listener.local_addr().expect("mock addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let tools = Arc::clone(&tools);
                tokio::spawn(async move {
                    let mut data = Vec::new();
                    let mut tmp = [0u8; 2048];
                    for _ in 0..8 {
                        match socket.read(&mut tmp).await {
                            Ok(0) | Err(_) => break,
                            Ok(k) => {
                                data.extend_from_slice(&tmp[..k]);
                                if String::from_utf8_lossy(&data).contains("tools/list") {
                                    break;
                                }
                            }
                        }
                    }
                    let body = json!({
                        "jsonrpc": "2.0",
                        "id": "1",
                        "result": {"tools": tools.read().clone()}
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    let _ = socket.flush().await;
                });
            }
        });
        addr
    }

    fn test_audit() -> nmcp_audit::AuditSink {
        nmcp_audit::AuditSink::open(
            std::env::temp_dir().join(format!("nmcp-host-gateway-{}.jsonl", uuid::Uuid::new_v4())),
        )
        .expect("audit sink")
    }

    fn listed_names(registry: &IndexedToolRegistry) -> Vec<String> {
        registry
            .list_for(&CatalogView::default())
            .iter()
            .filter_map(|entry| entry.get("name").and_then(Value::as_str))
            .map(str::to_string)
            .collect()
    }

    /// The whole chain the plan names: fetch, pin verify, cache, registry refresh,
    /// resolvable; then the tampered fetch that must change none of it.
    #[tokio::test]
    async fn the_upstream_lifecycle_reaches_the_index_and_a_tampered_list_never_does() {
        let annotations = json!({"readOnlyHint": true, "customTier": 3});
        let pinned = json!([{
            "name": "echo",
            "description": "echo tool",
            "inputSchema": {"type": "object"},
            "annotations": annotations
        }]);
        let pin = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&pinned).expect("serialize"))
        );
        let tools = Arc::new(RwLock::new(pinned));
        let addr = mock_upstream(Arc::clone(&tools)).await;

        let mut config = UpstreamConfig::new("up", format!("http://{addr}"));
        config.tools_sha256 = Some(pin);
        let provider =
            UpstreamProvider::new(config, test_audit(), None, None).expect("provider builds");

        // RC-18: the provider registers EMPTY, before its cache warms, and that is a
        // successful registration rather than a refusal.
        let registry = IndexedToolRegistry::new(Arc::new(RwLock::new(PolicyConfig::default())));
        let as_provider: Arc<dyn ToolProvider> = provider.clone();
        registry
            .register(as_provider)
            .expect("an empty upstream registers");
        assert!(registry.resolve("up_echo").is_none());
        assert!(listed_names(&registry).is_empty());

        // The cache warms. Nothing becomes resolvable on its own: the index is read at
        // registration and refresh, never on dispatch (RC-9).
        for _ in 0..100 {
            if matches!(provider.status(), UpstreamStatus::Online) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(matches!(provider.status(), UpstreamStatus::Online));
        assert!(registry.resolve("up_echo").is_none());

        // The registry refresh picks up the warm, verified cache: resolvable under both
        // non-empty-id name forms, listable, and the upstream's own annotations ride the
        // listing verbatim (RC-21), never a first-party derivation.
        registry.refresh("up").expect("refresh");
        let (owner, local) = registry
            .resolve("up_echo")
            .expect("resolvable after refresh");
        assert_eq!(owner.provider_id(), "up");
        assert_eq!(local, "echo");
        assert!(registry.resolve("up::echo").is_some());
        let listed = registry.list_for(&CatalogView::default());
        let echo = listed
            .iter()
            .find(|entry| entry.get("name").and_then(Value::as_str) == Some("up_echo"))
            .expect("listed");
        assert_eq!(echo.get("annotations"), Some(&annotations));

        // The upstream turns hostile: same endpoint, a list the pin does not match. The
        // fetch is refused BEFORE the provider cache is replaced, so the registry refresh
        // that follows rebuilds from the last verified catalogue: the old tool stays
        // resolvable, the tampered one never resolves and never lists, even briefly (G-8).
        *tools.write() = json!([
            {"name": "echo", "description": "echo tool", "inputSchema": {"type": "object"},
             "annotations": {"readOnlyHint": true, "customTier": 3}},
            {"name": "exfiltrate", "description": "added after the pin was taken"}
        ]);
        provider.refresh();
        let mut refused = false;
        for _ in 0..100 {
            if let UpstreamStatus::Offline { reason } = provider.status() {
                assert!(reason.contains("tools_sha256 mismatch"), "{reason}");
                refused = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(refused, "the tampered fetch must be refused");

        registry
            .refresh("up")
            .expect("refresh after the refused fetch");
        assert!(
            registry.resolve("up_echo").is_some(),
            "the last verified catalogue must stay resolvable"
        );
        assert!(
            registry.resolve("up_exfiltrate").is_none(),
            "a tampered catalogue must never become resolvable"
        );
        assert!(!listed_names(&registry).contains(&"up_exfiltrate".to_string()));

        provider.shutdown();
    }
}
