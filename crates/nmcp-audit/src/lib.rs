//! `nmcp-audit`
//!
//! The append-only, hash-chained audit trail for the NativeMCP server
//! family: record schema, canonical serialization, genesis and chain
//! verification, a live broadcast tap, and a [`PlatformMirror`] trait that
//! platform daemons bind to Event Log, journald or unified logging (R-2).
//! The chain and its write-before-effect ordering are INV-3; the invariants
//! in `docs/GOVERNANCE.md` are normative for every item here.

use anyhow::Context;
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

const MIRROR_ENABLED_ENV: &str = "NMCP_AUDIT_MIRROR_ENABLED";
const MIRROR_SOURCE_ENV: &str = "NMCP_AUDIT_MIRROR_SOURCE";
const DEFAULT_MIRROR_SOURCE: &str = "NativeMCP";
/// The Event ID a record whose class this build cannot name carries.
///
/// Deliberately the value every record used to carry, so a SIEM rule written against the old
/// single-ID mirror keeps matching something rather than silently matching nothing.
const UNCLASSIFIED_EVENT_ID: u16 = 1000;

/// The cap on one Event Log insertion string, in characters (M4-1).
const EVENT_LOG_MESSAGE_LIMIT: usize = 4096;

/// The cap on any single field inside that string.
///
/// Every field except `summary` is bounded by this, so the document minus its summary is
/// bounded by construction and the shrink loop below always terminates inside the cap.
const EVENT_LOG_FIELD_LIMIT: usize = 256;
use uuid::Uuid;

// ── AuditEvent ────────────────────────────────────────────────────────────────

/// The decision an effect record carries.
///
/// Not a verdict at all, which is the point: it marks the record as the other kind. See
/// [`AuditEvent`] for what the two kinds are and `docs/adr/ADR-0005` for why there are two.
pub const EFFECT_DECISION: &str = "effect";

/// The decision an authentication-attempt record carries (G3-13, AF-1).
///
/// Its own marker rather than a verdict string, because an authentication attempt is not a
/// governed call: there is no tool, no permission and no provider, so `is_authorization_decision`
/// must not count it. An operator asking "how many calls were denied" is asking about the ring,
/// and a refused credential never reached the ring.
pub const AUTH_REJECT_DECISION: &str = "auth_reject";

/// The action an authentication-attempt record carries.
pub const AUTH_REJECT_ACTION: &str = "auth.reject";

/// The verdict a call that the ring permitted carries.
pub const ALLOWED_DECISION: &str = "allowed";

/// The verdict a call the ring refused carries.
pub const DENIED_DECISION: &str = "denied";

/// The verdict an ABAC rule refused (Stage 1.5).
pub const ABAC_DENIED_DECISION: &str = "abac_denied";

/// The verdict a call awaiting a human carries.
pub const HITL_PENDING_DECISION: &str = "hitl_pending";

/// The verdict a call nobody approved in time carries.
pub const HITL_DENIED_TIMEOUT_DECISION: &str = "hitl_denied_timeout";

/// The decision [`AuditEvent::new`] starts with, meaning nobody set one.
///
/// Kept as the default rather than made an effect marker, so a caller that forgets to record a
/// verdict reads as unknown rather than silently claiming to be an effect.
pub const UNSPECIFIED_DECISION: &str = "unspecified";

/// Whether a decision string is a real authorization verdict rather than an effect marker.
///
/// One function rather than a comparison at each reader. There are two strings that mean "not a
/// verdict": `effect`, and `unspecified` from every record written before effect records were
/// named. The chain is append-only, so both stay true forever, and a reader that knows only one
/// of them miscounts without failing.
#[must_use]
pub fn is_authorization_decision(decision: &str) -> bool {
    let decision = decision.trim();
    !decision.is_empty()
        && decision != UNSPECIFIED_DECISION
        && decision != EFFECT_DECISION
        && decision != AUTH_REJECT_DECISION
}

/// One line in the audit chain.
///
/// A governed tool call writes two of these, and that is a decision rather than a defect
/// (ADR-0005).
///
/// An **effect record** is written by the code that performs the effect, where it happens. It
/// carries `path`, `normalized_path`, `before_hash` and `after_hash`, and no verdict and no
/// duration, because the code performing an effect knows neither: the verdict was reached
/// before it was called and the clock belongs to the ring. [`AuditEvent::effect`] builds one.
///
/// An **authorization record** is written by the router's audit ring after the call returns. It
/// carries the verdict, the duration the client actually waited, the caller and the session,
/// and not the content hashes, because the ring never sees the bytes.
///
/// They are separate because [`AuditSink::append`] syncs every write. An effect record is
/// durable at the moment the file changed, and a single record written on the way out would
/// lose that fact entirely if the process died in between. `mcp-fs` and `mcp-exec` are also
/// libraries usable without the router, and an effect performed outside the ring still has to
/// leave a record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique id of this record.
    pub id: Uuid,
    /// When the record was created.
    pub timestamp: DateTime<Utc>,
    /// Session identity of the caller; `local` when there is none.
    pub client: String,
    /// The action recorded, usually a tool name.
    pub action: String,
    /// Verdict or record-kind marker; see the decision constants above.
    pub decision: String,
    /// Path as the caller gave it, when the action names one.
    pub path: Option<String>,
    /// The canonicalized path the policy engine resolved.
    pub normalized_path: Option<String>,
    /// Redacted human-readable summary of the call.
    pub summary: String,
    /// Content hash before an effect, when measurable.
    pub before_hash: Option<String>,
    /// Content hash after an effect, when measurable.
    pub after_hash: Option<String>,
    /// Wall-clock duration of the tool call in milliseconds, if measured.
    /// Set by the middleware ring when timing is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Call ID that correlates this event to a specific tool invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<Uuid>,
    /// Upstream provider ID for proxied calls, `None` for local.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_id: Option<String>,
    /// Agent identity supplied by the transport, `None` for anonymous or local calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Position in the chain, assigned by the sink at append.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    /// Hash of the previous record, assigned by the sink at append.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_event_hash: Option<String>,
    /// What the client said it was, from the 2026-07-28 `_meta` block (G5-9).
    ///
    /// Self-reported and never an authorization input. It has a field of its own rather than
    /// reusing `client` or `agent_id`, because `client` carries the session id and session
    /// replay filters on it, and `agent_id` is the authenticated identity ABAC reads, so
    /// putting unauthenticated client-supplied text in either would break a reader or feed an
    /// access decision.
    ///
    /// Declared ahead of `event_hash` so `event_hash` stays the trailing member and the
    /// payload-recovery rule in the canonical serialization holds. Absent on every record
    /// written before it existed, and skipped when absent, so no existing record's bytes or
    /// hash change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_info: Option<String>,
    /// Where the call arrived from, already redacted (G3-13, AF-5).
    ///
    /// Never a full address. The truncation happens at the boundary, in `mcp-server`'s `peer`
    /// module, so a full address cannot reach this type at all rather than being trusted not
    /// to. `loopback` for a loopback caller, which is the local-or-remote distinction AF-7
    /// exists to make answerable.
    ///
    /// Same optional, skipped-when-absent discipline as `client_info` above, for the same
    /// reason: the chain is append-only and every record written before this field existed
    /// must keep verifying byte for byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// Which credential path authenticated this call, or attempted to (G3-13, AF-7).
    ///
    /// `static` or `oauth`. Without it an OAuth subject mapped to `agent_id: chatgpt` and a
    /// static credential using the same `agent_id` produce byte-identical records, so an
    /// operator asking whether a call came from the console or from the internet cannot
    /// answer it from the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_path: Option<String>,
    /// How many attempts this record stands for (G3-13, AF-2).
    ///
    /// Present only on a coalesced authentication-attempt record. One record per source per
    /// window carrying a count, rather than one record per attempt, because one per attempt
    /// hands an unauthenticated caller control of how fast this log grows, and therefore the
    /// ability to rotate a real event out of the retention window or bury it under noise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u64>,
    /// Whether the window this record covers was throttled (G3-13, AF-9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throttled: Option<bool>,
    /// The capability the policy ring required for this call (M4-1).
    ///
    /// The serialized `Permission` name: `read`, `execute`, `upstream.call` and so on, taken
    /// from the tool's policy spec rather than from anything a caller supplies. The Event Log
    /// mirror derives its Event ID class from this, so a SIEM rule can separate a read from a
    /// change from an execution from an egress without parsing a body, and an operator asking
    /// "who exercised Execute this week" can answer it from the chain, which was previously
    /// not answerable at all.
    ///
    /// Absent on an effect record, which is written by the code performing the effect and does
    /// not know what was required to authorize it, and on an authentication-attempt record,
    /// which never reached the ring.
    ///
    /// Same optional, skipped-when-absent discipline as the fields above, and declared before
    /// `event_hash` so `event_hash` stays the trailing member: the chain is append-only and
    /// every record written before this field existed must keep verifying byte for byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    /// This record's own chain hash; always the trailing member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<String>,
}

impl AuditEvent {
    /// A fresh record with an unspecified decision; see [`UNSPECIFIED_DECISION`].
    #[must_use]
    pub fn new(action: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            client: "local".into(),
            action: action.into(),
            decision: UNSPECIFIED_DECISION.into(),
            path: None,
            normalized_path: None,
            summary: summary.into(),
            before_hash: None,
            after_hash: None,
            duration_ms: None,
            call_id: None,
            upstream_id: None,
            agent_id: None,
            sequence: None,
            prev_event_hash: None,
            client_info: None,
            peer: None,
            credential_path: None,
            attempts: None,
            throttled: None,
            permission: None,
            event_hash: None,
        }
    }

    /// An effect record: what was actually done, written where it happened.
    ///
    /// Deliberately carries no verdict and no duration. See the type doc.
    #[must_use]
    pub fn effect(action: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            decision: EFFECT_DECISION.into(),
            ..Self::new(action, summary)
        }
    }

    /// A coalesced authentication-attempt record (G3-13, AF-1 through AF-6).
    ///
    /// One of these stands for every failed attempt from one source inside one window. The
    /// count is the whole point: see [`AuditEvent::attempts`].
    ///
    /// It carries no `agent_id` by construction, and that is AF-6 rather than an oversight. A
    /// failed attempt has no authenticated identity, and a claimed one is attacker-supplied
    /// text; putting that in the field an operator reads as identity is how a log becomes a
    /// place to plant evidence.
    ///
    /// `summary` must carry a reason CLASS from the closed set in the specification, never a
    /// rejection detail. An audit record is readable by anyone holding the log, and the
    /// fine-grained reason is exactly what tells an attacker which guess came closest.
    #[must_use]
    pub fn auth_reject(
        peer: impl Into<String>,
        credential_path: impl Into<String>,
        attempts: u64,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            decision: AUTH_REJECT_DECISION.into(),
            peer: Some(peer.into()),
            credential_path: Some(credential_path.into()),
            attempts: Some(attempts),
            ..Self::new(AUTH_REJECT_ACTION, summary)
        }
    }

    /// Mark the window this record covers as one in which the source was being throttled.
    #[must_use]
    pub fn throttled(mut self) -> Self {
        self.throttled = Some(true);
        self
    }
}

// ── Broadcast tap ─────────────────────────────────────────────────────────────

/// Capacity for the live audit broadcast channel.
/// Receivers that lag beyond this capacity will miss events (they will not block writers).
const BROADCAST_CAPACITY: usize = 512;
const AUDIT_CHAIN_TAIL_SCAN_BYTES: u64 = 1024 * 1024;

/// A live receiver of audit events.
/// Clone to create additional subscribers. Events are dropped if no receiver is active.
pub type AuditReceiver = tokio::sync::broadcast::Receiver<AuditEvent>;

// ── AuditSink ─────────────────────────────────────────────────────────────────

/// Write-side handle to the audit log. Clone-cheap via inner `Arc`.
///
/// Every `append()` call writes to the append-only JSONL file **and**
/// broadcasts to any active [`AuditReceiver`] subscribers.
/// If no subscribers are active the broadcast is a no-op (no allocation, no block).
#[derive(Clone)]
pub struct AuditSink {
    state: Arc<Mutex<AuditFileState>>,
    tx: Arc<tokio::sync::broadcast::Sender<AuditEvent>>,
    eventlog: Arc<RwLock<MirrorConfig>>,
    mirror: Arc<RwLock<Option<Arc<dyn PlatformMirror>>>>,
}

/// A platform-bound mirror of the audit chain: Event Log, journald, unified
/// logging (R-2). The chain in this crate is the record; a mirror is a copy
/// for the platform's own collection pipeline, and a mirror failure is
/// reported but never blocks or fails [`AuditSink::append`], because the
/// chain write already happened and INV-3 is about the chain.
pub trait PlatformMirror: Send + Sync {
    /// Deliver one record to the platform log.
    ///
    /// `message` is the rendered document from [`render_mirror_message`], so
    /// every platform mirror carries an identical body; the class and
    /// severity map to the platform's own filtering vocabulary.
    ///
    /// # Errors
    ///
    /// Any platform delivery failure; the sink logs it and continues.
    fn write(
        &self,
        config: &MirrorConfig,
        event: &AuditEvent,
        message: &str,
        class: EventLogClass,
        severity: EventLogSeverity,
    ) -> anyhow::Result<()>;
}

struct AuditFileState {
    file: File,
    sequence: u64,
    last_hash: String,
}

/// How the Windows Event Log mirror is configured.
///
/// Public and settable at runtime as of M4-1. It used to be read from the environment once,
/// at sink open, which meant the mirror could not be turned on from the admin console or the
/// policy file, could not be hot reloaded, and could not be reached by G4-29's ADMX fleet
/// floor, which operates on `PolicyConfig`. This codebase had already made that exact argument
/// about a different feature and not applied it here: `apply_upstream_auth` in `nmcp-gateway`
/// records that the environment route requires an operator to set a variable on a `LocalSystem`
/// service and restart it, which is a thing most operators cannot do, which is why the secret
/// store exists beside it. The audit mirror is the one feature whose entire purpose is being
/// turned on fleet-wide by somebody who administers a fleet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorConfig {
    /// Whether records are mirrored to the platform log at all.
    pub enabled: bool,
    /// The platform log source name records are written under.
    pub source: String,
}

impl MirrorConfig {
    /// The mirror off, which is what a sink opened without configuration gets.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            source: DEFAULT_MIRROR_SOURCE.into(),
        }
    }

    /// The legacy environment configuration.
    ///
    /// Still honoured, and still what [`AuditSink::open`] starts from, so an install that
    /// turned the mirror on with the legacy service switch keeps working
    /// unchanged. Policy overrides it when policy says anything at all; see
    /// [`AuditSink::configure_mirror`].
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// [`MirrorConfig::from_env`] with the environment read injected, so the
    /// parsing rules are testable without mutating process state (edition
    /// 2024 makes env mutation unsafe, and this workspace forbids unsafe).
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let enabled = lookup(MIRROR_ENABLED_ENV).is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        });
        let source = lookup(MIRROR_SOURCE_ENV)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MIRROR_SOURCE.into());
        Self { enabled, source }
    }
}

/// What kind of thing a record describes, for Event Log triage (M4-1).
///
/// Every record used to carry one Event ID, and SIEM rules key on Event ID, so no rule could
/// tell an execution from a read at the collector. The class comes from
/// [`AuditEvent::permission`], which is the capability the policy ring actually required,
/// rather than from parsing the tool name, so a tool added tomorrow classifies itself by
/// declaring its permission and nothing here has to learn about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLogClass {
    /// A record this build cannot place: no permission, and not an effect or an
    /// authentication attempt.
    Unclassified,
    /// Something was looked at.
    Read,
    /// Something on this host changed.
    Change,
    /// A program ran.
    Execute,
    /// Something left this host: Microsoft 365, a git publish, a gateway upstream.
    Egress,
    /// A credential was refused.
    Authentication,
}

impl EventLogClass {
    /// The Event ID a SIEM rule filters on.
    #[must_use]
    pub fn event_id(self) -> u16 {
        match self {
            Self::Unclassified => UNCLASSIFIED_EVENT_ID,
            Self::Read => 1010,
            Self::Change => 1020,
            Self::Execute => 1030,
            Self::Egress => 1040,
            Self::Authentication => 1050,
        }
    }

    /// The class name carried in the message body, for a rule that would rather read a word.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unclassified => "unclassified",
            Self::Read => "read",
            Self::Change => "change",
            Self::Execute => "execute",
            Self::Egress => "egress",
            Self::Authentication => "authentication",
        }
    }
}

/// Place a record in its Event Log class.
///
/// Order matters. An authentication attempt never reached the ring, so it has no permission
/// and must be recognised first. An effect record also has no permission, because the code
/// performing an effect is called after the verdict was reached and does not know what was
/// required, but it does know something on this host changed, which is the class that matters.
#[must_use]
pub fn event_log_class(event: &AuditEvent) -> EventLogClass {
    if event.decision == AUTH_REJECT_DECISION {
        return EventLogClass::Authentication;
    }
    if let Some(permission) = event.permission.as_deref() {
        // These are the serialized `Permission` names from `mcp-policy`. This crate cannot
        // depend on that one, so the pairing is asserted from `mcp-router`, which depends on
        // both, by an exhaustive wildcard-free match that stops compiling when a permission is
        // added. A name this build does not know falls through to Unclassified rather than
        // being guessed at.
        return match permission {
            "list" | "read" | "search" | "scan" | "report" | "memory.read" | "win.api" => {
                EventLogClass::Read
            }
            "create" | "write" | "modify" | "rename" | "move" | "backup" | "memory.write"
            | "win.api.write" => EventLogClass::Change,
            "execute" => EventLogClass::Execute,
            "m365" | "git.publish" | "upstream.call" => EventLogClass::Egress,
            _ => EventLogClass::Unclassified,
        };
    }
    if event.decision == EFFECT_DECISION {
        return EventLogClass::Change;
    }
    EventLogClass::Unclassified
}

/// The Event Log severity a record carries (M4-1).
///
/// Severity is a SIEM's first-line triage. Every record used to arrive as Information, so a
/// denial, a rejected credential and a successful directory listing were indistinguishable
/// without parsing the body, and `AuditEvent::decision` already carried what the severity
/// should be derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLogSeverity {
    /// Routine: permitted calls, effects, pending approvals.
    Information,
    /// A refusal or an unrecognised decision string.
    Warning,
    /// A throttled authentication window: the shape of an attack.
    Error,
}

/// Derive the severity from the record's decision.
///
/// A throttled authentication window is the one Error. It means a source kept presenting bad
/// credentials past the threshold, which is the shape of an attack in progress rather than a
/// fat-fingered token, and it is the record an operator wants to be paged on.
///
/// An unrecognised decision reads as a Warning rather than Information, deliberately. Success
/// has had one name since the beginning, so a decision string this build does not know is far
/// more likely to be a new refusal shape than a new success, and a security log should surface
/// what it cannot classify rather than bury it.
#[must_use]
pub fn event_log_severity(event: &AuditEvent) -> EventLogSeverity {
    match event.decision.as_str() {
        AUTH_REJECT_DECISION if event.throttled == Some(true) => EventLogSeverity::Error,
        AUTH_REJECT_DECISION
        | DENIED_DECISION
        | ABAC_DENIED_DECISION
        | HITL_DENIED_TIMEOUT_DECISION
        // Not written by anything today, and read by mcp-inspector out of historical chains.
        | "timed_out" => EventLogSeverity::Warning,
        ALLOWED_DECISION
        | HITL_PENDING_DECISION
        | EFFECT_DECISION
        | UNSPECIFIED_DECISION => EventLogSeverity::Information,
        _ => EventLogSeverity::Warning,
    }
}

impl AuditSink {
    /// Open (creating if needed) the append-only chain at `path`, resuming
    /// sequence and hash state from the existing tail.
    ///
    /// # Errors
    ///
    /// Directory creation or file open failure.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating audit directory {}", parent.display()))?;
        }
        let (sequence, last_hash) = audit_chain_tail(path.as_ref()).unwrap_or((0, genesis_hash()));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())?;
        let (tx, _) = tokio::sync::broadcast::channel(BROADCAST_CAPACITY);
        Ok(Self {
            state: Arc::new(Mutex::new(AuditFileState {
                file,
                sequence,
                last_hash,
            })),
            tx: Arc::new(tx),
            eventlog: Arc::new(RwLock::new(MirrorConfig::from_env())),
            mirror: Arc::new(RwLock::new(None)),
        })
    }

    /// Append an event to the file log and broadcast it to live subscribers.
    ///
    /// The record is durable (synced) before this returns: INV-3's
    /// write-before-effect ordering hangs off that property.
    ///
    /// # Errors
    ///
    /// Serialization or file write/sync failure. A platform-mirror failure
    /// is NOT an error here; the chain write already happened.
    pub fn append(&self, event: &AuditEvent) -> anyhow::Result<()> {
        let mut event = event.clone();
        let mut state = self.state.lock();
        event.sequence = Some(state.sequence + 1);
        event.prev_event_hash = Some(state.last_hash.clone());
        event.event_hash = None;
        let payload = serde_json::to_vec(&event)?;
        let event_hash = audit_event_hash(event.prev_event_hash.as_deref().unwrap_or(""), &payload);
        event.event_hash = Some(event_hash.clone());
        let line = serde_json::to_string(&event)?;
        writeln!(state.file, "{line}")?;
        state.file.sync_data()?;
        state.sequence += 1;
        state.last_hash = event_hash;
        drop(state);
        // Broadcast: ignore errors (no subscribers = RecvError::Closed, which is fine).
        let _ = self.tx.send(event.clone());
        self.try_mirror(&event);
        Ok(())
    }

    /// Whether platform mirroring is enabled for this sink.
    #[must_use]
    pub fn mirror_enabled(&self) -> bool {
        self.eventlog.read().enabled
    }

    /// The source name this sink writes under.
    #[must_use]
    pub fn mirror_source(&self) -> String {
        self.eventlog.read().source.clone()
    }

    /// Point the mirror at a new configuration (M4-1).
    ///
    /// Called once at startup with what policy says, and again on every accepted hot reload,
    /// so an operator can turn the mirror on from the admin console or a fleet floor can turn
    /// it on through ADMX without anybody restarting a `LocalSystem` service.
    ///
    /// Takes the whole configuration rather than a bool, because the source name and the
    /// enabled flag have to change together: turning the mirror on and pointing it at the
    /// wrong source is worse than leaving it off, since the events go somewhere nobody is
    /// collecting and the install looks compliant.
    pub fn configure_mirror(&self, config: MirrorConfig) {
        *self.eventlog.write() = config;
    }

    /// Install the platform mirror implementation for this build.
    ///
    /// Core installs none; a platform daemon installs its own (Event Log on
    /// Windows, journald on Linux, unified logging on macOS). Configuration
    /// stays separate on purpose: an installed mirror with `enabled: false`
    /// writes nothing.
    pub fn set_platform_mirror(&self, mirror: Arc<dyn PlatformMirror>) {
        *self.mirror.write() = Some(mirror);
    }

    fn try_mirror(&self, event: &AuditEvent) {
        let config = self.eventlog.read().clone();
        if !config.enabled {
            return;
        }
        let Some(mirror) = self.mirror.read().clone() else {
            return;
        };
        let message = render_mirror_message(event);
        let class = event_log_class(event);
        let severity = event_log_severity(event);
        if let Err(err) = mirror.write(&config, event, &message, class, severity) {
            eprintln!("audit mirror failed: {err}");
        }
    }

    /// Subscribe to the live audit broadcast.
    /// The returned receiver will receive all events appended *after* this call.
    #[must_use]
    pub fn subscribe(&self) -> AuditReceiver {
        self.tx.subscribe()
    }

    /// Number of currently active live subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

/// Clip a field to [`EVENT_LOG_FIELD_LIMIT`] characters.
///
/// Character-wise rather than byte-wise so a multi-byte value is never cut mid-character,
/// which would make the JSON encoder emit a replacement character where a name used to be.
fn clip(value: &str) -> String {
    value.chars().take(EVENT_LOG_FIELD_LIMIT).collect()
}

/// Build the Event Log document with the summary allowed `summary_budget` characters.
///
/// A budget of zero omits the summary entirely. Every other field is clipped, so the document
/// this returns with a zero budget is bounded by construction.
fn event_log_document(event: &AuditEvent, summary_budget: usize) -> serde_json::Value {
    let class = event_log_class(event);
    let mut document = serde_json::Map::new();
    document.insert("product".into(), serde_json::json!(DEFAULT_MIRROR_SOURCE));
    document.insert("id".into(), serde_json::json!(event.id));
    document.insert("timestamp".into(), serde_json::json!(event.timestamp));
    document.insert("action".into(), serde_json::json!(clip(&event.action)));
    document.insert("decision".into(), serde_json::json!(clip(&event.decision)));
    document.insert("client".into(), serde_json::json!(clip(&event.client)));
    document.insert("class".into(), serde_json::json!(class.as_str()));
    document.insert("event_id".into(), serde_json::json!(class.event_id()));
    if let Some(value) = &event.permission {
        document.insert("permission".into(), serde_json::json!(clip(value)));
    }
    if let Some(value) = &event.path {
        document.insert("path".into(), serde_json::json!(clip(value)));
    }
    if let Some(value) = event.call_id {
        document.insert("call_id".into(), serde_json::json!(value));
    }
    if let Some(value) = &event.agent_id {
        document.insert("agent_id".into(), serde_json::json!(clip(value)));
    }
    if let Some(value) = &event.peer {
        document.insert("peer".into(), serde_json::json!(clip(value)));
    }
    if let Some(value) = &event.credential_path {
        document.insert("credential_path".into(), serde_json::json!(clip(value)));
    }
    if let Some(value) = event.attempts {
        document.insert("attempts".into(), serde_json::json!(value));
    }
    if let Some(value) = event.throttled {
        document.insert("throttled".into(), serde_json::json!(value));
    }
    if let Some(value) = event.sequence {
        document.insert("sequence".into(), serde_json::json!(value));
    }
    if let Some(value) = &event.event_hash {
        document.insert("event_hash".into(), serde_json::json!(clip(value)));
    }
    if summary_budget > 0 {
        let summary: String = event.summary.chars().take(summary_budget).collect();
        document.insert("summary".into(), serde_json::json!(summary));
    }
    serde_json::Value::Object(document)
}

/// The Event Log insertion string: one JSON object, always (M4-1).
///
/// The old format was space-separated `key=value` with the free-text `summary` in the MIDDLE,
/// so `path`, `call_id` and `agent_id` followed it. An analyst's regex for `agent_id=(\S+)`
/// could match text inside a summary, and a tool call's arguments reach the summary through
/// redaction, which makes that attacker-influenceable rather than hypothetical. JSON has no
/// such ambiguity, Windows Event Forwarding carries the insertion string unchanged, and every
/// SIEM parses JSON natively.
///
/// The character cap stays, and truncation never emits invalid JSON. Every field except the
/// summary is clipped, so the summary is the only thing that can push the document over, and
/// it is halved until the document fits or it is gone. Truncating the serialized string
/// instead, which is what the old format did, produces a fragment no parser accepts: worse
/// than a shortened summary, because it loses the fields as well.
/// Render the mirror insertion document for one record (M4-1 shape).
///
/// Public so every platform mirror and its conformance tests render the
/// identical body the Event Log mirror shipped with.
#[must_use]
pub fn render_mirror_message(event: &AuditEvent) -> String {
    let mut budget = event.summary.chars().count();
    loop {
        let rendered = event_log_document(event, budget).to_string();
        if rendered.chars().count() <= EVENT_LOG_MESSAGE_LIMIT || budget == 0 {
            return rendered;
        }
        // Halving rather than computing an exact budget: JSON escaping makes the encoded
        // length of a string a function of its content, so an exact budget would be a guess
        // that is sometimes wrong. This is a few more iterations and always right.
        budget /= 2;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

fn genesis_hash() -> String {
    "0".repeat(64)
}

fn audit_event_hash(previous_hash: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(previous_hash.as_bytes());
    hasher.update(
        b"
",
    );
    hasher.update(payload);
    format!("{:x}", hasher.finalize())
}

fn audit_chain_tail(path: &Path) -> anyhow::Result<(u64, String)> {
    if !path.exists() {
        return Ok((0, genesis_hash()));
    }

    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok((0, genesis_hash()));
    }

    let start = len.saturating_sub(AUDIT_CHAIN_TAIL_SCAN_BYTES);
    file.seek(SeekFrom::Start(start))?;

    let mut tail = String::new();
    file.read_to_string(&mut tail)?;

    if start > 0
        && let Some(first_newline) = tail.find('\n')
    {
        tail = tail[first_newline + 1..].to_string();
    }

    for line in tail.lines().rev() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<AuditEvent>(line)
            && let (Some(seq), Some(hash)) = (event.sequence, event.event_hash)
        {
            return Ok((seq, hash));
        }
    }

    Ok((0, genesis_hash()))
}

/// Result of verifying the audit hash chain.
#[derive(Debug, Clone, Serialize)]
pub struct ChainVerification {
    /// True if every record's hash and prev-link are intact.
    pub ok: bool,
    /// Number of records checked.
    pub events: u64,
    /// Sequence of the first broken record, if any.
    pub broken_at_sequence: Option<u64>,
    /// Human-readable reason when `ok` is false.
    pub reason: Option<String>,
}

/// Re-walk the audit log and verify the tamper-evident hash chain. For each record,
/// `event_hash` must equal `sha256(prev_hash + "\n" + payload-without-hash)` and
/// `prev_event_hash` must equal the previous record's `event_hash`. This detects
/// edits, insertions, deletions, and reordering after the fact. A missing or empty
/// log verifies OK.
///
/// # Errors
///
/// I/O failure reading the log; a broken chain is NOT an error, it is an
/// `ok: false` report.
pub fn verify_chain(path: &Path) -> anyhow::Result<ChainVerification> {
    verify_chain_from(path, None)
}

/// Verify the tamper-evident hash chain, optionally starting at `from_sequence` so a log
/// with a legacy pre-chain head (records written before the chain feature) can still be
/// verified from its first chained record. When `from_sequence` is `None`, verification
/// starts from the genesis record as before.
///
/// # Errors
///
/// I/O failure reading the log; a broken chain is an `ok: false` report.
pub fn verify_chain_from(
    path: &Path,
    from_sequence: Option<u64>,
) -> anyhow::Result<ChainVerification> {
    if !path.exists() {
        return Ok(ChainVerification {
            ok: true,
            events: 0,
            broken_at_sequence: None,
            reason: None,
        });
    }
    let content = std::fs::read_to_string(path)?;
    let mut prev = genesis_hash();
    let mut count: u64 = 0;
    let mut started = from_sequence.is_none();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let report_seq = count + 1;
        let mut event: AuditEvent = match serde_json::from_str(line) {
            Ok(event) => event,
            Err(err) => {
                return Ok(ChainVerification {
                    ok: false,
                    events: count,
                    broken_at_sequence: Some(report_seq),
                    reason: Some(format!("record {report_seq} is not valid JSON: {err}")),
                });
            }
        };
        if !started {
            if event.sequence == from_sequence {
                prev = event.prev_event_hash.clone().unwrap_or_default();
                started = true;
            } else {
                continue;
            }
        }
        let Some(stored_hash) = event.event_hash.take() else {
            return Ok(ChainVerification {
                ok: false,
                events: count,
                broken_at_sequence: event.sequence.or(Some(report_seq)),
                reason: Some("record is missing event_hash".to_string()),
            });
        };
        let stored_prev = event.prev_event_hash.clone().unwrap_or_default();
        if stored_prev != prev {
            return Ok(ChainVerification {
                ok: false,
                events: count,
                broken_at_sequence: event.sequence.or(Some(report_seq)),
                reason: Some(
                    "prev_event_hash does not match the previous record (chain break)".to_string(),
                ),
            });
        }
        let payload = serde_json::to_vec(&event)?;
        let recomputed = audit_event_hash(&stored_prev, &payload);
        if recomputed != stored_hash {
            return Ok(ChainVerification {
                ok: false,
                events: count,
                broken_at_sequence: event.sequence.or(Some(report_seq)),
                reason: Some("event_hash mismatch (record modified after writing)".to_string()),
            });
        }
        prev = stored_hash;
        count += 1;
    }
    if !started {
        return Ok(ChainVerification {
            ok: false,
            events: 0,
            broken_at_sequence: from_sequence,
            reason: Some("from_sequence not found in the log".to_string()),
        });
    }
    Ok(ChainVerification {
        ok: true,
        events: count,
        broken_at_sequence: None,
        reason: None,
    })
}

#[cfg(test)]
mod verify_tests {
    // Tests assert on shapes, files and chains, where unwrap/expect/indexing
    // ARE the assertion: a panic in a test is the failure signal, so the
    // production rationale for the workspace denies does not apply.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;

    #[test]
    fn verify_chain_accepts_intact_log() {
        let dir = std::env::temp_dir().join(format!("nmcp-audit-verify-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let sink = AuditSink::open(&path).unwrap();
        for i in 0..3 {
            sink.append(&AuditEvent::new("tool", format!("event {i}")))
                .unwrap();
        }
        let report = verify_chain(&path).unwrap();
        assert!(report.ok, "reason: {:?}", report.reason);
        assert_eq!(report.events, 3);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// G5-9, fourth clause: a record written before `client_info` existed still hashes to
    /// the value stored alongside it.
    ///
    /// The line below is a verbatim production record, sequence 39220, written by the
    /// deployed binary on 2026-08-02 before the field was declared. Declaring a skipped
    /// `Option` must not move a byte of it, and the only proof of that is recomputing its
    /// stored hash with the current type rather than reasoning about serde attributes.
    #[test]
    fn a_record_written_before_client_info_existed_still_verifies() {
        const PRE_FIELD_RECORD: &str = r#"{"id":"cde7c1ad-abec-47bc-828f-16f55a8d07dd","timestamp":"2026-08-02T20:14:05.804117700Z","client":"local","action":"list_roots","decision":"allowed","path":null,"normalized_path":null,"summary":"{\"tool\":\"list_roots\"}","before_hash":null,"after_hash":null,"duration_ms":0,"agent_id":"claude-connector","sequence":39220,"prev_event_hash":"702e4f80d816b5689c843430eda3bd4380de896f6be7185d84ff5bfe9bb835af","event_hash":"a31e3b523931306a27405ca65276885338e6efaa4bd0e1b19a527d4068d27d0b"}"#;

        assert!(
            !PRE_FIELD_RECORD.contains("client_info"),
            "the fixture has to predate the field or this test proves nothing"
        );

        let dir = std::env::temp_dir().join(format!("nmcp-audit-pre-field-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        std::fs::write(&path, format!("{PRE_FIELD_RECORD}\n")).unwrap();

        let report = verify_chain_from(&path, Some(39220)).unwrap();
        assert!(report.ok, "reason: {:?}", report.reason);
        assert_eq!(report.events, 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// G3-13 AF-10. The same production record, against the four fields added for the
    /// authentication-attempt work.
    ///
    /// Separate from the `client_info` test above rather than folded into it, because the two
    /// prove the same property about different changes and a single test that grows a field
    /// per release stops naming what it is defending.
    #[test]
    fn a_record_written_before_the_auth_attempt_fields_existed_still_verifies() {
        const PRE_FIELD_RECORD: &str = r#"{"id":"cde7c1ad-abec-47bc-828f-16f55a8d07dd","timestamp":"2026-08-02T20:14:05.804117700Z","client":"local","action":"list_roots","decision":"allowed","path":null,"normalized_path":null,"summary":"{\"tool\":\"list_roots\"}","before_hash":null,"after_hash":null,"duration_ms":0,"agent_id":"claude-connector","sequence":39220,"prev_event_hash":"702e4f80d816b5689c843430eda3bd4380de896f6be7185d84ff5bfe9bb835af","event_hash":"a31e3b523931306a27405ca65276885338e6efaa4bd0e1b19a527d4068d27d0b"}"#;

        // `permission` (M4-1) is checked here too rather than in a test of its own: this
        // fixture predates it as well, and the property is the same one, that a record written
        // before a field existed keeps verifying byte for byte.
        for field in [
            "peer",
            "credential_path",
            "attempts",
            "throttled",
            "permission",
        ] {
            assert!(
                !PRE_FIELD_RECORD.contains(field),
                "the fixture has to predate {field} or this test proves nothing"
            );
        }

        let dir = std::env::temp_dir().join(format!("nmcp-audit-pre-auth-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        std::fs::write(&path, format!("{PRE_FIELD_RECORD}\n")).unwrap();

        let report = verify_chain_from(&path, Some(39220)).unwrap();
        assert!(report.ok, "reason: {:?}", report.reason);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// G3-13 AF-1 and AF-2. One record stands for a whole window of attempts, and says so.
    #[test]
    fn an_auth_reject_record_carries_the_count_it_stands_for() {
        let event =
            AuditEvent::auth_reject("203.0.113.0/24", "static", 10_000, "unknown_credential");
        assert_eq!(event.action, AUTH_REJECT_ACTION);
        assert_eq!(event.decision, AUTH_REJECT_DECISION);
        assert_eq!(event.attempts, Some(10_000));
        assert_eq!(event.peer.as_deref(), Some("203.0.113.0/24"));
        assert_eq!(event.credential_path.as_deref(), Some("static"));
        assert_eq!(event.throttled, None);
        assert_eq!(event.throttled().throttled, Some(true));
    }

    /// G3-13 AF-6. A failed attempt has no authenticated identity, and a claimed one is
    /// attacker-supplied text. There is no way to put one in this record.
    #[test]
    fn an_auth_reject_record_never_names_a_caller() {
        let event = AuditEvent::auth_reject("loopback", "oauth", 1, "unmapped_subject");
        assert_eq!(event.agent_id, None);
        assert_eq!(event.path, None);
        assert_eq!(event.call_id, None);
    }

    /// G3-13 AF-1. A refused credential never reached the ring, so counting it as an
    /// authorization verdict would answer "how many calls were denied" with the wrong number.
    #[test]
    fn an_auth_reject_is_not_counted_as_an_authorization_verdict() {
        assert!(!is_authorization_decision(AUTH_REJECT_DECISION));
        assert!(is_authorization_decision("denied"));
        assert!(is_authorization_decision("allowed"));
    }

    /// G3-13 AF-10. A record carrying the new fields still chains, which is the half the
    /// backward-compatibility test cannot cover.
    #[test]
    fn a_chain_of_auth_reject_records_verifies() {
        let dir = std::env::temp_dir().join(format!("nmcp-audit-auth-chain-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let sink = AuditSink::open(&path).unwrap();

        sink.append(&AuditEvent::new("tool", "an ordinary call"))
            .unwrap();
        sink.append(&AuditEvent::auth_reject(
            "198.51.100.0/24",
            "oauth",
            42,
            "expired",
        ))
        .unwrap();
        sink.append(&AuditEvent::auth_reject("loopback", "static", 3, "absent").throttled())
            .unwrap();

        let report = verify_chain_from(&path, None).unwrap();
        assert!(report.ok, "reason: {:?}", report.reason);
        assert_eq!(report.events, 3);

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            !written.contains("\"peer\":null"),
            "an absent field must be skipped rather than written as null: {written}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_chain_detects_tampering() {
        let dir = std::env::temp_dir().join(format!("nmcp-audit-tamper-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let sink = AuditSink::open(&path).unwrap();
        for i in 0..3 {
            sink.append(&AuditEvent::new("tool", format!("event {i}")))
                .unwrap();
        }
        let tampered = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| l.replace("event 1", "tampered"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, tampered + "\n").unwrap();
        let report = verify_chain(&path).unwrap();
        assert!(!report.ok);
        assert!(report.broken_at_sequence.is_some());
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod tests {
    // Tests assert on shapes, files and chains, where unwrap/expect/indexing
    // ARE the assertion: a panic in a test is the failure signal, so the
    // production rationale for the workspace denies does not apply.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn audit_records_capture_operation_type_and_canonical_path() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nmcp-audit-{stamp}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let audit_path = dir.join("audit.jsonl");
        let sink = AuditSink::open(&audit_path).expect("open");
        let mut evt = AuditEvent::new("rename_file", "ok");
        evt.normalized_path = Some(
            dir.canonicalize()
                .unwrap_or_else(|_| dir.clone())
                .display()
                .to_string(),
        );
        sink.append(&evt).expect("append");
        let content = std::fs::read_to_string(&audit_path).expect("read");
        assert!(content.contains("\"action\":\"rename_file\""));
        assert!(content.contains("normalized_path"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn audit_sink_broadcasts_to_subscriber() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nmcp-audit-bcast-{stamp}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let sink = AuditSink::open(dir.join("audit.jsonl")).expect("open");
        let mut rx = sink.subscribe();
        let evt = AuditEvent::new("test_tool", "broadcast test");
        sink.append(&evt).expect("append");
        let received = rx.try_recv().expect("broadcast delivered");
        assert_eq!(received.action, "test_tool");
        assert_eq!(sink.subscriber_count(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mirror_defaults_off_and_lookup_parses_the_legacy_toggles() {
        // No environment mutation: edition 2024 makes set_var/remove_var
        // unsafe and this workspace forbids unsafe. The parsing rules are
        // proven through the injected lookup instead.
        let absent = MirrorConfig::from_lookup(|_| None);
        assert!(!absent.enabled);
        assert_eq!(absent.source, DEFAULT_MIRROR_SOURCE);

        for on in ["1", "true", "YES", "On"] {
            let config = MirrorConfig::from_lookup(|name| {
                (name == MIRROR_ENABLED_ENV).then(|| on.to_string())
            });
            assert!(config.enabled, "{on} should enable the mirror");
        }
        let off = MirrorConfig::from_lookup(|name| {
            (name == MIRROR_ENABLED_ENV).then(|| "off".to_string())
        });
        assert!(!off.enabled);

        let named = MirrorConfig::from_lookup(|name| {
            (name == MIRROR_SOURCE_ENV).then(|| "FleetSource".to_string())
        });
        assert_eq!(named.source, "FleetSource");

        // A sink explicitly configured off reports off, and stays off with
        // no platform mirror installed.
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nmcp-audit-mirror-default-{stamp}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let sink = AuditSink::open(dir.join("audit.jsonl")).expect("open");
        sink.configure_mirror(MirrorConfig::disabled());
        assert!(!sink.mirror_enabled());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn render_mirror_message_is_bounded_and_informative() {
        let mut evt = AuditEvent::new("inspect_file_integrity", "returned file integrity report");
        evt.path = Some(r"D:\projects\nativemcp-core\docs\file.md".into());
        evt.permission = Some("read".into());
        let message = render_mirror_message(&evt);
        let document: serde_json::Value = serde_json::from_str(&message).expect("valid JSON");
        assert_eq!(document["product"], "NativeMCP");
        assert_eq!(document["action"], "inspect_file_integrity");
        assert_eq!(document["decision"], "unspecified");
        assert_eq!(document["class"], "read");
        assert_eq!(document["event_id"], 1010);
        assert_eq!(document["path"], r"D:\projects\nativemcp-core\docs\file.md");
        assert!(message.chars().count() <= EVENT_LOG_MESSAGE_LIMIT);
    }

    /// M4-1, the fourth defect. The old format put the free-text summary in the MIDDLE of a
    /// space-separated key=value string, so `path`, `call_id` and `agent_id` followed it and an
    /// analyst's regex for `agent_id=(\S+)` could match text inside a summary. A tool call's
    /// arguments reach the summary through redaction, so that was attacker-influenceable rather
    /// than hypothetical. This drives exactly that attack and reads the fields back.
    #[test]
    fn a_summary_cannot_impersonate_the_fields_that_follow_it() {
        let mut evt = AuditEvent::new(
            "write_text_file",
            r#"{"tool":"write_text_file","content":"agent_id=administrator path=C:\\Windows call_id=00000000-0000-0000-0000-000000000000"}"#,
        );
        evt.agent_id = Some("claude-connector".into());
        evt.path = Some(r"D:\projects\notes.md".into());
        evt.permission = Some("write".into());

        let message = render_mirror_message(&evt);
        let document: serde_json::Value = serde_json::from_str(&message).expect("valid JSON");

        assert_eq!(
            document["agent_id"], "claude-connector",
            "the caller-supplied text must not be able to become the agent_id"
        );
        assert_eq!(document["path"], r"D:\projects\notes.md");
        assert_eq!(document["class"], "change");
        assert_eq!(document["event_id"], 1020);
        assert!(
            document["summary"]
                .as_str()
                .expect("summary")
                .contains("agent_id=administrator"),
            "the summary keeps its text; it just cannot be mistaken for a field"
        );
    }

    /// M4-1. The cap holds and truncation still parses, which the old string-slicing format
    /// could not promise: cutting a serialized document mid-token leaves a fragment no SIEM
    /// accepts, and loses the fields as well as the summary.
    #[test]
    fn an_enormous_summary_is_shortened_rather_than_the_document_being_cut() {
        let mut evt = AuditEvent::new("execute", "x".repeat(64 * 1024));
        evt.permission = Some("execute".into());
        evt.agent_id = Some("y".repeat(4096));

        let message = render_mirror_message(&evt);
        assert!(
            message.chars().count() <= EVENT_LOG_MESSAGE_LIMIT,
            "message was {} characters",
            message.chars().count()
        );
        let document: serde_json::Value =
            serde_json::from_str(&message).expect("truncated output must still be valid JSON");
        assert_eq!(document["action"], "execute");
        assert_eq!(document["event_id"], 1030);
        assert_eq!(
            document["agent_id"].as_str().expect("agent_id").len(),
            EVENT_LOG_FIELD_LIMIT,
            "every field except the summary is clipped, so the summary is the only thing that \
             can push the document over the cap"
        );
    }

    /// M4-1, the second defect. A denial, a rejected credential and a successful listing all
    /// arrived as Information, so severity, which is a SIEM's first-line triage, carried no
    /// information at all.
    #[test]
    fn severity_comes_from_the_decision_rather_than_being_fixed() {
        fn severity_of(decision: &str) -> EventLogSeverity {
            let mut event = AuditEvent::new("tool", "s");
            event.decision = decision.into();
            event_log_severity(&event)
        }

        assert_eq!(severity_of(ALLOWED_DECISION), EventLogSeverity::Information);
        assert_eq!(severity_of(EFFECT_DECISION), EventLogSeverity::Information);
        assert_eq!(
            severity_of(UNSPECIFIED_DECISION),
            EventLogSeverity::Information
        );
        assert_eq!(
            severity_of(HITL_PENDING_DECISION),
            EventLogSeverity::Information,
            "waiting on a human is not a failure"
        );

        assert_eq!(severity_of(DENIED_DECISION), EventLogSeverity::Warning);
        assert_eq!(severity_of(ABAC_DENIED_DECISION), EventLogSeverity::Warning);
        assert_eq!(
            severity_of(HITL_DENIED_TIMEOUT_DECISION),
            EventLogSeverity::Warning
        );
        assert_eq!(severity_of(AUTH_REJECT_DECISION), EventLogSeverity::Warning);
        assert_eq!(
            severity_of("something_this_build_has_never_heard_of"),
            EventLogSeverity::Warning,
            "success has had one name since the beginning, so an unknown decision is far more \
             likely to be a new refusal, and a security log surfaces what it cannot classify"
        );

        // The one Error: a source that kept presenting bad credentials past the threshold.
        // That is an attack in progress rather than a fat-fingered token.
        let throttled =
            AuditEvent::auth_reject("203.0.113.0/24", "static", 10_000, "expired").throttled();
        assert_eq!(event_log_severity(&throttled), EventLogSeverity::Error);
    }

    /// M4-1, the third defect. Every record carried one Event ID, and SIEM rules key on Event
    /// ID, so no rule could tell an execution from a read at the collector.
    #[test]
    fn the_event_id_separates_the_classes_a_soc_triages_on() {
        fn class_for_permission(permission: &str) -> EventLogClass {
            let mut event = AuditEvent::new("tool", "s");
            event.decision = ALLOWED_DECISION.into();
            event.permission = Some(permission.into());
            event_log_class(&event)
        }

        assert_eq!(class_for_permission("read"), EventLogClass::Read);
        assert_eq!(class_for_permission("win.api"), EventLogClass::Read);
        assert_eq!(class_for_permission("write"), EventLogClass::Change);
        assert_eq!(class_for_permission("memory.write"), EventLogClass::Change);
        assert_eq!(class_for_permission("execute"), EventLogClass::Execute);
        assert_eq!(class_for_permission("m365"), EventLogClass::Egress);
        assert_eq!(class_for_permission("upstream.call"), EventLogClass::Egress);

        // An effect record carries no permission, because the code performing the effect was
        // called after the verdict was reached. It does know something on this host changed.
        let mut effect = AuditEvent::new("write_text_file", "wrote");
        effect.decision = EFFECT_DECISION.into();
        assert_eq!(event_log_class(&effect), EventLogClass::Change);

        let rejected = AuditEvent::auth_reject("loopback", "oauth", 1, "expired");
        assert_eq!(event_log_class(&rejected), EventLogClass::Authentication);

        // Every class has its own id, and the legacy id still means unclassified so a rule
        // written against the old single-id mirror keeps matching something.
        let ids: Vec<u16> = [
            EventLogClass::Unclassified,
            EventLogClass::Read,
            EventLogClass::Change,
            EventLogClass::Execute,
            EventLogClass::Egress,
            EventLogClass::Authentication,
        ]
        .iter()
        .map(|class| class.event_id())
        .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), ids.len(), "two classes share an Event ID");
        assert_eq!(
            EventLogClass::Unclassified.event_id(),
            UNCLASSIFIED_EVENT_ID
        );
    }

    /// M4-1, the first defect. The mirror was read from the environment once, at sink open, so
    /// it could not be turned on from the console, could not be hot reloaded, and could not be
    /// reached by the ADMX fleet floor, which acts on `PolicyConfig`.
    #[test]
    fn the_mirror_can_be_reconfigured_on_a_running_sink() {
        let dir = std::env::temp_dir().join(format!("nmcp-audit-mirror-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let sink = AuditSink::open(dir.join("audit.jsonl")).expect("open");

        assert!(
            !sink.mirror_enabled(),
            "the environment in this test sets nothing, so the mirror starts off"
        );

        sink.configure_mirror(MirrorConfig {
            enabled: true,
            source: "FleetCollector".into(),
        });
        assert!(sink.mirror_enabled());
        assert_eq!(sink.mirror_source(), "FleetCollector");

        // And back off again, because a fleet floor that can only turn things on is half a
        // control.
        sink.configure_mirror(MirrorConfig::disabled());
        assert!(!sink.mirror_enabled());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn audit_append_writes_hash_chain_and_unspecified_default() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nmcp-audit-chain-{stamp}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let audit_path = dir.join("audit.jsonl");
        let sink = AuditSink::open(&audit_path).expect("open");
        sink.append(&AuditEvent::new("first", "one"))
            .expect("append first");
        sink.append(&AuditEvent::new("second", "two"))
            .expect("append second");
        let lines: Vec<String> = std::fs::read_to_string(&audit_path)
            .expect("read")
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(lines.len(), 2);
        let first: AuditEvent = serde_json::from_str(&lines[0]).expect("first json");
        let second: AuditEvent = serde_json::from_str(&lines[1]).expect("second json");
        assert_eq!(first.sequence, Some(1));
        assert_eq!(second.sequence, Some(2));
        assert_eq!(second.prev_event_hash, first.event_hash);
        assert_eq!(first.decision, "unspecified");
        assert_eq!(second.event_hash.as_deref().unwrap_or_default().len(), 64);
        let _ = std::fs::remove_dir_all(dir);
    }
    #[test]
    fn an_effect_record_says_so_rather_than_saying_nothing() {
        let effect = AuditEvent::effect("write_text_file", "wrote 5 bytes");
        assert_eq!(effect.decision, EFFECT_DECISION);
        assert!(
            effect.duration_ms.is_none(),
            "an effect record is never timed"
        );
        // The default stays "unspecified", so a caller that forgets a verdict reads as unknown
        // rather than quietly claiming to be an effect.
        assert_eq!(AuditEvent::new("x", "y").decision, UNSPECIFIED_DECISION);
    }

    #[test]
    fn both_markers_for_not_a_verdict_classify_the_same_way() {
        // The chain is append-only: every record written before effect records were named says
        // "unspecified" and will keep saying it, so both have to stay non-verdicts forever.
        for marker in [UNSPECIFIED_DECISION, EFFECT_DECISION, "", "   "] {
            assert!(
                !is_authorization_decision(marker),
                "{marker:?} is not a verdict"
            );
        }
        for verdict in ["allowed", "denied", "escalated"] {
            assert!(is_authorization_decision(verdict), "{verdict} is a verdict");
        }
    }

    #[test]
    fn client_info_sits_ahead_of_event_hash_and_changes_nothing_when_absent() {
        // The canonical serialization is a published contract, so this pins the two claims the
        // doc makes about adding a field: an absent one changes no existing record's bytes, and
        // event_hash stays the trailing member so the payload-recovery rule still works.
        let mut event = AuditEvent::new("write_text_file", "wrote 5 bytes");
        event.id = "00000000-0000-4000-8000-000000000000"
            .parse()
            .expect("uuid");
        event.timestamp = "2026-08-02T09:00:00Z".parse().expect("timestamp");
        event.sequence = Some(1);
        event.prev_event_hash = Some("0".repeat(64));

        let without = serde_json::to_string(&event).expect("serialize");
        assert!(
            !without.contains("client_info"),
            "an absent field must not appear at all: {without}"
        );
        let tail = format!(r#""prev_event_hash":"{}"}}"#, "0".repeat(64));
        assert!(
            without.ends_with(&tail),
            "prev_event_hash is last while event_hash is None: {without}"
        );

        event.client_info = Some("claude-desktop/1.4.2".into());
        event.event_hash = Some("a".repeat(64));
        let with = serde_json::to_string(&event).expect("serialize");
        let client_at = with.find("client_info").expect("client_info present");
        let hash_at = with.find(r#""event_hash""#).expect("event_hash present");
        let prev_at = with
            .find("prev_event_hash")
            .expect("prev_event_hash present");
        assert!(
            prev_at < client_at && client_at < hash_at,
            "client_info goes after prev_event_hash and ahead of event_hash: {with}"
        );
    }

    #[test]
    fn a_record_that_sets_client_info_hashes_differently_from_one_that_does_not() {
        // The doc calls a field addition a chain-format boundary for the records that set it.
        // This is that claim, stated as a test rather than left as prose.
        let base = AuditEvent::new("tools/call", "x");
        let mut named = base.clone();
        named.client_info = Some("claude-desktop/1.4.2".into());
        assert_ne!(
            serde_json::to_vec(&base).expect("bytes"),
            serde_json::to_vec(&named).expect("bytes")
        );
    }

    #[test]
    fn audit_event_duration_ms_skipped_when_none() {
        let evt = AuditEvent::new("tool", "summary");
        let json = serde_json::to_string(&evt).unwrap();
        assert!(
            !json.contains("duration_ms"),
            "duration_ms must be omitted when None"
        );
    }
}
