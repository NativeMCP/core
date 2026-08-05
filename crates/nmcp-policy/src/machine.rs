//! Fleet policy from the machine's Group Policy registry key (G4-29, the ADMX leg of M4).
//!
//! One rule governs this entire module, and it is the reason the module can exist at all:
//! **a machine policy may only tighten.**
//!
//! The obvious design is a second policy file that overrides the first, field by field. That
//! design is wrong here, because the moment a fleet setting can widen, an attacker or a
//! mistaken GPO author gains a way to loosen a locally-hardened machine remotely, and the
//! local operator has no way to see it happened. So no setting in this module is a value to
//! apply. Every setting is a *restriction to enforce*, and the registry shape says so: each
//! one is present-or-absent, present meaning "enforce the tighter state", absent meaning "the
//! fleet has no opinion". `ForceAutoApproveOff` is expressible; `ForceAutoApproveOn` is not,
//! and cannot be written by any ADMX, any `reg add`, or any future field added here without
//! breaking the type.
//!
//! That makes the invariant checkable rather than merely intended, and
//! `no_machine_policy_can_widen_anything` checks it: for every combination of settings over
//! every fixture policy, the M5 diff planner must report zero newly-allowed verdicts and the
//! set of enabled upstreams afterwards must be a subset of the set before.
//!
//! What is deliberately NOT here: roots and permissions. A fleet path list merged with a local
//! path list is where "tighten" stops being well defined, since the same added root can narrow
//! one subtree and widen another depending on what it shadows. Until there is a shape that is
//! monotone by construction the way these seven are, roots stay local. `PolicyChangePlan`
//! already exists to review a root change on its own terms.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{PolicyConfig, PolicyError};

/// Where Group Policy writes, and where this reads. `HKLM` is implied.
///
/// Under `Policies` rather than the product's own key on purpose: that subtree is writable
/// only by administrators, is cleared and rewritten by the Group Policy engine on refresh, and
/// is where an auditor looks for a managed setting.
pub const MACHINE_POLICY_KEY: &str = r"SOFTWARE\Policies\NativeMCP";

/// Subkey holding the fleet's approved upstream ids, one per value, the id as the value data.
pub const ALLOWED_UPSTREAMS_SUBKEY: &str = "AllowedUpstreams";

/// Whether the allowlist is authoritative, stated separately from its contents.
///
/// The distinction between "the fleet approved no upstream" and "the fleet has not looked at
/// upstreams" is load bearing, and resting it on whether an empty subkey materializes would be
/// resting it on Group Policy client behaviour this code does not control. So the ADMX writes
/// this `REG_DWORD` on the same policy: absent is no opinion, 1 is authoritative whether or not
/// the list has entries, 0 is an administrator withdrawing the opinion.
pub const ALLOWED_UPSTREAMS_CONFIGURED_VALUE: &str = "AllowedUpstreamsConfigured";

/// What the fleet requires of this machine. Every field is a restriction, never a value.
///
/// `Default` is "the fleet has no opinion about anything", which is what an absent key means
/// and what every non-Windows build gets.
// Each bool is an independent fleet restriction with its own ADMX setting;
// packing them would make the "may only tighten" shape unexpressible.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachinePolicy {
    /// Human approval is required regardless of what the local policy file says.
    #[serde(default)]
    pub force_auto_approve_off: bool,
    /// The MCP endpoint requires a client credential, and fails closed without one.
    #[serde(default)]
    pub force_client_auth: bool,
    /// Every enabled upstream must pin the tool list it trusts.
    #[serde(default)]
    pub force_upstream_pinning: bool,
    /// The non-standard WebSocket lane is off (see ADR-0001).
    #[serde(default)]
    pub disable_ws_lane: bool,
    /// The SSE streaming lane is off.
    #[serde(default)]
    pub disable_sse_lane: bool,
    /// No upstream may be live on this machine. The gateway kill switch.
    #[serde(default)]
    pub disable_all_upstreams: bool,
    /// Only these upstream ids may be live.
    ///
    /// `None` and `Some(empty)` are different statements and both are meaningful. `None` is
    /// "the fleet has not reviewed upstreams". `Some(empty)` is "the fleet reviewed them and
    /// approved none", which is the same outcome as `disable_all_upstreams` but arrives by a
    /// different decision and reads differently in the audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_upstream_ids: Option<BTreeSet<String>>,
}

/// A source of fleet (machine-scoped) policy.
///
/// Core ships only [`NoFleetPolicy`], the no-op default. Platform daemons
/// inject a real reader: WinMCP reads Windows Group Policy at W3
/// (NMCP-SPEC-001 R-3). Keeping the reader behind this trait is what lets the
/// policy crate be platform-neutral while the fleet-policy source stays a
/// platform concern.
pub trait MachinePolicySource {
    /// The fleet policy in force, plus the names of any values that were
    /// present and unreadable (for `doctor` to surface).
    fn read(&self) -> (MachinePolicy, Vec<String>);
}

/// The portable default source: the fleet has no opinion.
///
/// This is core's only [`MachinePolicySource`]. It is what every build gets
/// until a platform daemon injects its own reader, and it is the exact
/// behaviour the base gave every non-Windows build.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoFleetPolicy;

impl MachinePolicySource for NoFleetPolicy {
    fn read(&self) -> (MachinePolicy, Vec<String>) {
        (MachinePolicy::default(), Vec::new())
    }
}

impl MachinePolicy {
    /// True when the fleet has no opinion at all, which is the overwhelmingly common case.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Read the fleet (machine-scoped) policy from the portable default source.
    ///
    /// Core has no registry: this delegates to [`NoFleetPolicy`], which reports
    /// no fleet opinion. The Windows Group Policy reader is a
    /// [`MachinePolicySource`] implemented by WinMCP (NMCP-SPEC-001 R-3) and
    /// injected via [`PolicyConfig::into_effective_from`]; it is not part of
    /// platform-neutral core.
    ///
    /// Never fails: an absent fleet policy is the normal state, not an error.
    #[must_use]
    pub fn from_registry() -> (Self, Vec<String>) {
        NoFleetPolicy.read()
    }

    /// What `policy` fails to honor about this machine policy, one line per gap.
    ///
    /// Empty for any policy that came out of [`PolicyConfig::with_machine_policy`] with the
    /// same machine policy, which the property test checks. A non-empty answer at runtime
    /// therefore means one thing: Group Policy changed after this process loaded its policy,
    /// and the running configuration is looser than the fleet now requires.
    #[must_use]
    pub fn unsatisfied(&self, policy: &PolicyConfig) -> Vec<String> {
        let mut gaps = Vec::new();
        if self.force_auto_approve_off && policy.auto_approve {
            gaps.push("ForceAutoApproveOff: auto_approve is on".to_string());
        }
        if self.force_client_auth && !policy.mcp_require_client_auth {
            gaps.push(
                "ForceClientAuth: the MCP endpoint accepts unauthenticated clients".to_string(),
            );
        }
        if self.force_upstream_pinning && !policy.require_upstream_pinning {
            gaps.push("ForceUpstreamPinning: upstream pinning is not required".to_string());
        }
        if self.disable_ws_lane && policy.enable_ws_lane {
            gaps.push("DisableWsLane: the WebSocket lane is on".to_string());
        }
        if self.disable_sse_lane && policy.enable_sse_lane {
            gaps.push("DisableSseLane: the SSE lane is on".to_string());
        }
        for upstream in policy.upstreams.iter().filter(|u| u.enabled) {
            if self.disable_all_upstreams {
                gaps.push(format!(
                    "DisableAllUpstreams: upstream '{}' is live",
                    upstream.id
                ));
            } else if self
                .allowed_upstream_ids
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&upstream.id))
            {
                gaps.push(format!(
                    "{ALLOWED_UPSTREAMS_SUBKEY}: upstream '{}' is live and not on the approved list",
                    upstream.id
                ));
            }
        }
        gaps
    }
}

/// One setting a machine policy changed, named for `doctor` and for the load audit record.
///
/// Recorded per change rather than per setting, so an allowlist that disables four upstreams
/// produces four lines naming four upstreams. A summary line would be shorter and would not
/// answer the question an operator actually asks, which is which one of theirs stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedOverride {
    /// The registry value that caused this, so the operator knows where to go to change it.
    pub setting: String,
    /// What the local policy file asked for.
    pub from: String,
    /// What the machine policy enforced instead.
    pub to: String,
}

impl AppliedOverride {
    fn new(setting: &str, from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            setting: setting.to_string(),
            from: from.into(),
            to: to.into(),
        }
    }
}

/// Applying a machine policy failed to leave a policy this server can serve.
///
/// Reachable in exactly one way today: `ForceClientAuth` on a machine whose local policy
/// configures no client credential. That is a real fleet instruction meeting a real local gap,
/// and the honest outcome is to refuse rather than to serve the untightened policy, which
/// would be a silent widening, or to serve an invalid one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachinePolicyConflict {
    /// The setting that caused this.
    pub setting: String,
    /// What was found.
    pub detail: String,
    /// How to resolve it.
    pub remediation: String,
}

impl std::fmt::Display for MachinePolicyConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "machine policy {} cannot be honored: {}. {}",
            self.setting, self.detail, self.remediation
        )
    }
}

impl PolicyConfig {
    /// Enforce a machine policy on top of a loaded policy file.
    ///
    /// Returns the tightened policy and every change it made. Never widens anything: see the
    /// module comment, and see `no_machine_policy_can_widen_anything`.
    #[must_use]
    pub fn with_machine_policy(mut self, machine: &MachinePolicy) -> (Self, Vec<AppliedOverride>) {
        let mut applied = Vec::new();

        if machine.force_auto_approve_off && self.auto_approve {
            self.auto_approve = false;
            applied.push(AppliedOverride::new("ForceAutoApproveOff", "true", "false"));
        }
        if machine.force_client_auth && !self.mcp_require_client_auth {
            self.mcp_require_client_auth = true;
            applied.push(AppliedOverride::new("ForceClientAuth", "false", "true"));
        }
        if machine.force_upstream_pinning && !self.require_upstream_pinning {
            self.require_upstream_pinning = true;
            applied.push(AppliedOverride::new(
                "ForceUpstreamPinning",
                "false",
                "true",
            ));
        }
        if machine.disable_ws_lane && self.enable_ws_lane {
            self.enable_ws_lane = false;
            applied.push(AppliedOverride::new("DisableWsLane", "true", "false"));
        }
        if machine.disable_sse_lane && self.enable_sse_lane {
            self.enable_sse_lane = false;
            applied.push(AppliedOverride::new("DisableSseLane", "true", "false"));
        }

        for upstream in self.upstreams.iter_mut().filter(|u| u.enabled) {
            let refused_by_kill_switch = machine.disable_all_upstreams;
            let refused_by_allowlist = machine
                .allowed_upstream_ids
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&upstream.id));
            if !refused_by_kill_switch && !refused_by_allowlist {
                continue;
            }
            upstream.enabled = false;
            let setting = if refused_by_kill_switch {
                "DisableAllUpstreams"
            } else {
                ALLOWED_UPSTREAMS_SUBKEY
            };
            applied.push(AppliedOverride::new(
                setting,
                format!("upstream '{}' enabled", upstream.id),
                format!("upstream '{}' disabled", upstream.id),
            ));
        }

        (self, applied)
    }

    /// Whether the tightened policy is still one this server can serve.
    ///
    /// Called after `with_machine_policy`. The local file already validated on its own, so any
    /// failure here was introduced by the fleet setting, and naming which one is the whole
    /// value of this function over calling `validate_semantics` directly.
    #[must_use]
    pub fn machine_policy_conflict(
        &self,
        machine: &MachinePolicy,
    ) -> Option<MachinePolicyConflict> {
        let error = self.validate_semantics().err()?;
        let (setting, remediation) = match &error {
            PolicyError::SemanticValidation(message)
                if machine.force_client_auth && message.contains("client") =>
            {
                (
                    "ForceClientAuth",
                    "Configure an mcp_clients credential on this machine, or clear \
                     ForceClientAuth in the Group Policy object that sets it.",
                )
            }
            _ => (
                "(unattributed)",
                "Compare the local policy file against the NativeMCP Group Policy settings \
                 on this machine.",
            ),
        };
        Some(MachinePolicyConflict {
            setting: setting.to_string(),
            detail: error.to_string(),
            remediation: remediation.to_string(),
        })
    }
}

/// A policy file plus the fleet policy in force, resolved into the one this machine serves.
///
/// Produced by [`PolicyConfig::into_effective`], which is the only supported way to load a
/// policy for service. Both load paths go through it so neither can forget a step, and so the
/// startup path and the hot-reload path cannot drift into applying different rules.
#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    /// The policy to serve: the file, tightened.
    pub policy: PolicyConfig,
    /// What the fleet required, kept so callers can report it without re-reading the registry.
    pub machine: MachinePolicy,
    /// Every change the fleet made, one per change.
    pub applied: Vec<AppliedOverride>,
    /// Registry values that were present and could not be read.
    pub unreadable: Vec<String>,
}

impl EffectivePolicy {
    /// One line per change, for the service log and for an operator reading it later.
    #[must_use]
    pub fn describe(&self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .applied
            .iter()
            .map(|change| {
                format!(
                    "machine policy {}: {} -> {}",
                    change.setting, change.from, change.to
                )
            })
            .collect();
        for name in &self.unreadable {
            lines.push(format!(
                "machine policy value {name} is set and could not be read; it was ignored"
            ));
        }
        lines
    }
}

impl PolicyConfig {
    /// Resolve this policy against the machine's Group Policy settings.
    ///
    /// Fails only when the fleet's requirements leave a policy this server cannot serve, which
    /// is a state worth refusing on rather than papering over: serving the untightened policy
    /// would be a silent widening, and serving the invalid one is not an option.
    ///
    /// # Errors
    ///
    /// Any failure from the injected source path; see [`PolicyConfig::into_effective_from`].
    pub fn into_effective(self) -> Result<EffectivePolicy, MachinePolicyConflict> {
        self.into_effective_from(&NoFleetPolicy)
    }

    /// Resolve this policy against a caller-supplied fleet-policy source.
    ///
    /// The injection seam for platform daemons: WinMCP passes its Group Policy
    /// registry reader here (NMCP-SPEC-001 R-3), core callers use
    /// [`PolicyConfig::into_effective`] which supplies [`NoFleetPolicy`].
    ///
    /// # Errors
    ///
    /// [`MachinePolicyConflict`] when the fleet's requirements leave a policy
    /// this server cannot serve. Serving the untightened policy would be a
    /// silent widening, and serving the invalid one is not an option.
    pub fn into_effective_from(
        self,
        source: &dyn MachinePolicySource,
    ) -> Result<EffectivePolicy, MachinePolicyConflict> {
        let (machine, unreadable) = source.read();
        let (policy, applied) = self.with_machine_policy(&machine);
        if !applied.is_empty() {
            // Only when the fleet changed something. A policy that was already invalid is not
            // the fleet's doing and must not be reported as though it were.
            if let Some(conflict) = policy.machine_policy_conflict(&machine) {
                return Err(conflict);
            }
        }
        Ok(EffectivePolicy {
            policy,
            machine,
            applied,
            unreadable,
        })
    }
}

#[cfg(test)]
mod tests {
    // Tests assert on shapes, plans and verdicts, where expect/indexing ARE
    // the assertion: a panic in a test is the failure signal, so the
    // production rationale for the workspace denies does not apply.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;
    use crate::{McpClientCredential, Permission, UpstreamConfig};

    fn upstream(id: &str, port: u16) -> UpstreamConfig {
        let mut config = UpstreamConfig::new(id, format!("http://127.0.0.1:{port}"));
        config.required_permission = Some(Permission::UpstreamCall);
        config
    }

    /// Deliberately loose: every lane on, approval off, nothing pinned, three live upstreams.
    /// A fixture already at the tight end would pass every assertion below by accident.
    fn loose_policy() -> PolicyConfig {
        PolicyConfig {
            auto_approve: true,
            mcp_require_client_auth: false,
            require_upstream_pinning: false,
            enable_sse_lane: true,
            enable_ws_lane: true,
            upstreams: vec![
                upstream("alpha", 9001),
                upstream("bravo", 9002),
                upstream("charlie", 9003),
            ],
            mcp_clients: vec![McpClientCredential {
                agent_id: "console".into(),
                token_sha256: "a".repeat(64),
                profile: None,
            }],
            ..PolicyConfig::default()
        }
    }

    /// A boolean that went from off to on. Every widening among the flags has this shape.
    fn turned_on(before: bool, after: bool) -> bool {
        after && !before
    }

    /// A boolean that went from on to off, which widens for the two settings that are
    /// restrictions in their own right.
    fn turned_off(before: bool, after: bool) -> bool {
        before && !after
    }

    fn enabled_ids(policy: &PolicyConfig) -> BTreeSet<String> {
        policy
            .upstreams
            .iter()
            .filter(|u| u.enabled)
            .map(|u| u.id.clone())
            .collect()
    }

    /// Every combination of the six flags crossed with four allowlist shapes. Small enough to
    /// enumerate exhaustively, which is the right way to test a claim of the form "no setting
    /// can ever".
    fn every_machine_policy() -> Vec<MachinePolicy> {
        let allowlists = [
            None,
            Some(BTreeSet::new()),
            Some(BTreeSet::from(["alpha".to_string()])),
            Some(BTreeSet::from([
                "alpha".to_string(),
                "bravo".to_string(),
                "charlie".to_string(),
                "not-configured-here".to_string(),
            ])),
        ];
        let mut all = Vec::new();
        for bits in 0u8..64 {
            for allowed in &allowlists {
                all.push(MachinePolicy {
                    force_auto_approve_off: bits & 1 != 0,
                    force_client_auth: bits & 2 != 0,
                    force_upstream_pinning: bits & 4 != 0,
                    disable_ws_lane: bits & 8 != 0,
                    disable_sse_lane: bits & 16 != 0,
                    disable_all_upstreams: bits & 32 != 0,
                    allowed_upstream_ids: allowed.clone(),
                });
            }
        }
        all
    }

    #[test]
    fn an_unmanaged_machine_changes_nothing() {
        // The common case, and the one where a bug would be least visible: no GPO anywhere.
        let before = loose_policy();
        let (after, applied) = before
            .clone()
            .with_machine_policy(&MachinePolicy::default());
        assert!(applied.is_empty(), "{applied:?}");
        assert!(
            crate::diff::plan(&before, &after).is_verdict_neutral(),
            "an unmanaged machine must be indistinguishable from no machine policy"
        );
        assert_eq!(enabled_ids(&after), enabled_ids(&before));
        assert!(MachinePolicy::default().is_empty());
    }

    #[test]
    fn forcing_approval_off_removes_auto_approve_and_names_the_setting() {
        let machine = MachinePolicy {
            force_auto_approve_off: true,
            ..MachinePolicy::default()
        };
        let (after, applied) = loose_policy().with_machine_policy(&machine);
        assert!(!after.auto_approve);
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].setting, "ForceAutoApproveOff");
        assert_eq!(
            (applied[0].from.as_str(), applied[0].to.as_str()),
            ("true", "false")
        );
    }

    #[test]
    fn a_setting_already_at_the_tighter_value_is_not_reported_as_a_change() {
        // An override list that lists settings which changed nothing is noise, and noise in a
        // governance surface is how a real override gets scrolled past.
        let mut policy = loose_policy();
        policy.auto_approve = false;
        policy.enable_ws_lane = false;
        let machine = MachinePolicy {
            force_auto_approve_off: true,
            disable_ws_lane: true,
            ..MachinePolicy::default()
        };
        let (after, applied) = policy.with_machine_policy(&machine);
        assert!(applied.is_empty(), "{applied:?}");
        assert!(!after.auto_approve && !after.enable_ws_lane);
    }

    #[test]
    fn the_kill_switch_disables_every_live_upstream_and_names_each_one() {
        let machine = MachinePolicy {
            disable_all_upstreams: true,
            ..MachinePolicy::default()
        };
        let (after, applied) = loose_policy().with_machine_policy(&machine);
        assert!(enabled_ids(&after).is_empty());
        assert_eq!(applied.len(), 3, "one line per upstream, not one summary");
        for id in ["alpha", "bravo", "charlie"] {
            assert!(
                applied.iter().any(|a| a.to.contains(id)),
                "the operator has to be able to find their own upstream: {applied:?}"
            );
        }
    }

    #[test]
    fn an_allowlist_disables_exactly_what_it_omits() {
        let machine = MachinePolicy {
            allowed_upstream_ids: Some(BTreeSet::from(["bravo".to_string()])),
            ..MachinePolicy::default()
        };
        let (after, applied) = loose_policy().with_machine_policy(&machine);
        assert_eq!(enabled_ids(&after), BTreeSet::from(["bravo".to_string()]));
        assert_eq!(applied.len(), 2);
        assert!(
            applied
                .iter()
                .all(|a| a.setting == ALLOWED_UPSTREAMS_SUBKEY)
        );
    }

    #[test]
    fn an_allowlist_naming_an_upstream_this_machine_does_not_have_is_not_an_error() {
        // A fleet allowlist is written once for the fleet. A machine that does not run one of
        // the approved servers is the normal case, not a misconfiguration.
        let machine = MachinePolicy {
            allowed_upstream_ids: Some(BTreeSet::from([
                "alpha".to_string(),
                "bravo".to_string(),
                "charlie".to_string(),
                "somebody-elses-server".to_string(),
            ])),
            ..MachinePolicy::default()
        };
        let (after, applied) = loose_policy().with_machine_policy(&machine);
        assert!(applied.is_empty(), "{applied:?}");
        assert_eq!(enabled_ids(&after).len(), 3);
    }

    #[test]
    fn an_empty_allowlist_is_a_statement_and_not_an_absence() {
        // Some(empty) means the fleet reviewed and approved none. None means it has not
        // looked. Collapsing the two would make "approve nothing" unexpressible.
        let reviewed = MachinePolicy {
            allowed_upstream_ids: Some(BTreeSet::new()),
            ..MachinePolicy::default()
        };
        let (after, applied) = loose_policy().with_machine_policy(&reviewed);
        assert!(enabled_ids(&after).is_empty());
        assert_eq!(applied.len(), 3);

        let unreviewed = MachinePolicy::default();
        let (after, applied) = loose_policy().with_machine_policy(&unreviewed);
        assert_eq!(enabled_ids(&after).len(), 3);
        assert!(applied.is_empty());
    }

    #[test]
    fn applying_a_machine_policy_twice_changes_nothing_the_second_time() {
        // The Group Policy engine re-applies on every refresh, and the daemon re-reads on
        // every hot reload, so a non-idempotent application would drift.
        for machine in every_machine_policy() {
            let (once, _) = loose_policy().with_machine_policy(&machine);
            let (twice, applied_again) = once.clone().with_machine_policy(&machine);
            assert!(
                applied_again.is_empty(),
                "second application changed something for {machine:?}: {applied_again:?}"
            );
            assert_eq!(enabled_ids(&once), enabled_ids(&twice));
        }
    }

    /// The invariant the whole module rests on, checked rather than asserted in prose.
    #[test]
    fn no_machine_policy_can_widen_anything() {
        let before = loose_policy();
        for machine in every_machine_policy() {
            let (after, _) = before.clone().with_machine_policy(&machine);

            let plan = crate::diff::plan(&before, &after);
            assert!(
                plan.newly_allowed.is_empty(),
                "{machine:?} newly allowed {:?}",
                plan.newly_allowed
            );
            for change in &plan.caller_tool_changes {
                assert!(
                    change.newly_allowed_tools.is_empty(),
                    "{machine:?} newly allowed tools for {}: {:?}",
                    change.caller,
                    change.newly_allowed_tools
                );
            }

            assert!(
                enabled_ids(&after).is_subset(&enabled_ids(&before)),
                "{machine:?} enabled an upstream that was not enabled"
            );
            assert!(
                !turned_on(before.auto_approve, after.auto_approve),
                "{machine:?} turned auto_approve on"
            );
            assert!(
                !turned_off(
                    before.mcp_require_client_auth,
                    after.mcp_require_client_auth
                ),
                "{machine:?} turned client auth off"
            );
            assert!(
                !turned_off(
                    before.require_upstream_pinning,
                    after.require_upstream_pinning
                ),
                "{machine:?} turned pinning off"
            );
            assert!(
                !turned_on(before.enable_ws_lane, after.enable_ws_lane),
                "{machine:?} turned the ws lane on"
            );
            assert!(
                !turned_on(before.enable_sse_lane, after.enable_sse_lane),
                "{machine:?} turned the sse lane on"
            );
            assert_eq!(
                after.roots.len(),
                before.roots.len(),
                "{machine:?} touched roots"
            );
        }
    }

    #[test]
    fn forcing_client_auth_without_a_credential_is_a_named_conflict() {
        // The fleet said no unauthenticated MCP access. The local file configures no
        // credential. Serving the untightened policy would be a silent widening, so the
        // conflict is reported, named, and left for the caller to refuse on.
        let mut policy = loose_policy();
        policy.mcp_clients.clear();
        policy
            .validate_semantics()
            .expect("the local file is legal on its own, which is what makes this the fleet's");

        let machine = MachinePolicy {
            force_client_auth: true,
            ..MachinePolicy::default()
        };
        let (after, applied) = policy.with_machine_policy(&machine);
        assert_eq!(applied.len(), 1);

        let conflict = after
            .machine_policy_conflict(&machine)
            .expect("a tightening that cannot be served must be reported");
        assert_eq!(conflict.setting, "ForceClientAuth");
        assert!(
            conflict.remediation.contains("mcp_clients"),
            "the remediation has to name the fix: {conflict}"
        );
    }

    #[test]
    fn a_tightening_that_can_be_served_reports_no_conflict() {
        let machine = MachinePolicy {
            force_auto_approve_off: true,
            force_client_auth: true,
            disable_ws_lane: true,
            ..MachinePolicy::default()
        };
        let (after, _) = loose_policy().with_machine_policy(&machine);
        assert!(after.machine_policy_conflict(&machine).is_none());
    }

    #[test]
    fn applying_a_machine_policy_leaves_nothing_unsatisfied() {
        // The pair that makes the doctor check meaningful. If applying could ever leave a gap,
        // a correctly-loaded machine would report drift it does not have, and the operator
        // would learn to ignore the check.
        for machine in every_machine_policy() {
            let (after, _) = loose_policy().with_machine_policy(&machine);
            assert!(
                machine.unsatisfied(&after).is_empty(),
                "{machine:?} left {:?}",
                machine.unsatisfied(&after)
            );
        }
    }

    #[test]
    fn unsatisfied_names_the_setting_and_what_is_wrong() {
        // The runtime case: the fleet tightened after this process loaded its policy.
        let machine = MachinePolicy {
            force_auto_approve_off: true,
            disable_all_upstreams: true,
            ..MachinePolicy::default()
        };
        let gaps = machine.unsatisfied(&loose_policy());
        assert_eq!(gaps.len(), 4, "{gaps:?}");
        assert!(gaps.iter().any(|g| g.starts_with("ForceAutoApproveOff")));
        assert_eq!(
            gaps.iter()
                .filter(|g| g.starts_with("DisableAllUpstreams"))
                .count(),
            3
        );
    }

    #[test]
    fn an_unmanaged_machine_is_never_unsatisfied() {
        assert!(
            MachinePolicy::default()
                .unsatisfied(&loose_policy())
                .is_empty()
        );
    }

    #[test]
    fn the_registry_read_is_infallible_on_an_unmanaged_machine() {
        // Nothing writes HKLM\SOFTWARE\Policies\NativeMCP in this suite, so this asserts
        // the absent-key path specifically: no panic, no error, no opinion.
        let (policy, unreadable) = MachinePolicy::from_registry();
        assert!(unreadable.is_empty(), "{unreadable:?}");
        assert!(
            policy.is_empty(),
            "a machine with no GPO must read as no opinion: {policy:?}"
        );
    }
}
