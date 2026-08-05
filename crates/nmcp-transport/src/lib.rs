//! `nmcp-transport`
//!
//! Streaming transport state for the NativeMCP server family: bounded
//! sessions, streams, event queues and replay journals, the redaction
//! pipeline events pass through before they are queued or journaled, and
//! cancellation routing. The governance invariants in `docs/GOVERNANCE.md`
//! are normative for every item in this crate; the bounds here are INV-5
//! made structural, and every ceiling is a named constant rather than a
//! magic number.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

/// Ceiling on concurrent sessions (DEC-001 holds this at 128).
pub const DEFAULT_MAX_SESSIONS: usize = 128;
/// Ceiling on concurrent streams within one session.
pub const DEFAULT_MAX_STREAMS_PER_SESSION: usize = 16;
/// Capacity of a session's aggregate event queue.
pub const DEFAULT_MAX_EVENTS_PER_SESSION: usize = 4096;
/// Capacity of one stream's queue and replay journal, in events.
pub const DEFAULT_MAX_EVENTS_PER_STREAM: usize = 1024;
/// Largest event payload carried verbatim; larger payloads truncate.
pub const DEFAULT_MAX_EVENT_PAYLOAD_BYTES: usize = 65_536;
/// Aggregate byte cap on one stream's replay journal.
pub const DEFAULT_MAX_JOURNAL_BYTES: usize = 1024 * 1024;
/// Idle time after which a session is eligible for expiry.
pub const DEFAULT_SESSION_IDLE_TTL: Duration = Duration::from_mins(30);

#[derive(Debug, Error, PartialEq, Eq)]
/// Why a transport operation was refused. Refusals are decisions, not
/// transient failures: retrying an identical call yields an identical
/// refusal.
pub enum TransportError {
    /// A configured bound was zero.
    #[error("transport config must use non-zero bounds")]
    InvalidConfig,
    /// The session ceiling is reached; also counted in capacity rejections.
    #[error("session limit exceeded")]
    SessionLimitExceeded,
    /// No such session, or not the caller's session; deliberately the same
    /// error either way (see `SessionRegistry::owns_session`).
    #[error("session not found: {0}")]
    SessionNotFound(SessionId),
    /// The per-session stream ceiling is reached.
    #[error("stream limit exceeded for session: {0}")]
    StreamLimitExceeded(SessionId),
    /// The session exists but the stream does not.
    #[error("stream not found for session {session_id}: {stream_id}")]
    StreamNotFound {
        /// The session the caller addressed.
        session_id: SessionId,
        /// The stream that was not found in it.
        stream_id: StreamId,
    },
    /// A journal was constructed with zero capacity.
    #[error("event journal capacity must be non-zero")]
    EmptyEventJournal,
}

/// Shorthand result type for every fallible operation in this crate.
pub type TransportResult<T> = Result<T, TransportError>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
/// Opaque identifier of one transport session.
pub struct SessionId(String);

impl SessionId {
    /// A fresh random id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4().hyphenated().to_string())
    }

    /// Wrap an id received off the wire.
    #[must_use]
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The id as sent on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
/// Opaque identifier of one stream within a session.
pub struct StreamId(String);

impl StreamId {
    /// A fresh random id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4().hyphenated().to_string())
    }

    /// Wrap an id received off the wire.
    #[must_use]
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The id as sent on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for StreamId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
/// Monotonic per-stream event sequence number, starting at 1.
pub struct EventId(u64);

impl EventId {
    /// Wrap a raw sequence number.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw sequence number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The successor id.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Where a resuming client left off: replay everything after this point.
// The three ids ARE the content: this struct addresses a position.
#[allow(clippy::struct_field_names)]
pub struct ResumeCursor {
    /// The session being resumed.
    pub session_id: SessionId,
    /// The stream being resumed.
    pub stream_id: StreamId,
    /// The last event id the client already holds.
    pub after_event_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// One event as queued, journaled and delivered.
pub struct TransportEvent {
    /// The session it belongs to.
    pub session_id: SessionId,
    /// The stream it was emitted on.
    pub stream_id: StreamId,
    /// Monotonic per-stream sequence number.
    pub event_id: EventId,
    /// Application event type tag.
    #[serde(rename = "type")]
    pub event_type: String,
    /// Redacted, possibly truncated payload.
    pub payload: Value,
    /// True when the payload was replaced by a truncation notice.
    pub payload_truncated: bool,
    /// Wall-clock emission time, unix milliseconds.
    pub emitted_unix_ms: u64,
}

#[derive(Debug, Clone)]
/// Bounds for one registry. Every field must be non-zero; see `validate`.
pub struct TransportConfig {
    /// Ceiling on concurrent sessions.
    pub max_sessions: usize,
    /// Ceiling on streams per session.
    pub max_streams_per_session: usize,
    /// Session aggregate queue capacity, in events.
    pub max_events_per_session: usize,
    /// Per-stream queue and journal capacity, in events.
    pub max_events_per_stream: usize,
    /// Largest payload carried verbatim.
    pub max_event_payload_bytes: usize,
    /// Per-stream journal byte cap.
    pub max_journal_bytes: usize,
    /// Idle time before a session may be expired.
    pub session_idle_ttl: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_streams_per_session: DEFAULT_MAX_STREAMS_PER_SESSION,
            max_events_per_session: DEFAULT_MAX_EVENTS_PER_SESSION,
            max_events_per_stream: DEFAULT_MAX_EVENTS_PER_STREAM,
            max_event_payload_bytes: DEFAULT_MAX_EVENT_PAYLOAD_BYTES,
            max_journal_bytes: DEFAULT_MAX_JOURNAL_BYTES,
            session_idle_ttl: DEFAULT_SESSION_IDLE_TTL,
        }
    }
}

impl TransportConfig {
    /// Check every bound is non-zero.
    ///
    /// # Errors
    ///
    /// [`TransportError::InvalidConfig`] when any bound is zero.
    pub fn validate(&self) -> TransportResult<()> {
        if self.max_sessions == 0
            || self.max_streams_per_session == 0
            || self.max_events_per_session == 0
            || self.max_events_per_stream == 0
            || self.max_event_payload_bytes == 0
            || self.max_journal_bytes == 0
            || self.session_idle_ttl.is_zero()
        {
            return Err(TransportError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// What this transport build offers, advertised to clients verbatim.
// The advertisement is a wire shape: each bool is an independent published
// capability flag, not packed state.
#[allow(clippy::struct_excessive_bools)]
pub struct TransportCapabilities {
    /// The streaming core is compiled in.
    pub core_available: bool,
    /// Replay from the in-memory journal is available.
    pub in_memory_replay: bool,
    /// Replay across a process restart; not offered by this build.
    pub cross_process_replay: bool,
    /// Payloads pass a redaction pipeline before queueing.
    pub redaction_pipeline: bool,
    /// Cancellation routing is available.
    pub cancellation_routing: bool,
    /// Configured session ceiling.
    pub max_sessions: usize,
    /// Configured per-session stream ceiling.
    pub max_streams_per_session: usize,
    /// Configured session queue capacity.
    pub max_events_per_session: usize,
    /// Configured per-stream capacity.
    pub max_events_per_stream: usize,
    /// Configured payload ceiling.
    pub max_event_payload_bytes: usize,
    /// Configured journal byte cap.
    pub max_journal_bytes: usize,
    /// Configured idle TTL, in seconds.
    pub session_idle_ttl_secs: u64,
}

impl TransportCapabilities {
    /// Derive the advertisement from a validated config.
    #[must_use]
    pub fn from_config(config: &TransportConfig) -> Self {
        Self {
            core_available: true,
            in_memory_replay: true,
            cross_process_replay: false,
            redaction_pipeline: true,
            cancellation_routing: true,
            max_sessions: config.max_sessions,
            max_streams_per_session: config.max_streams_per_session,
            max_events_per_session: config.max_events_per_session,
            max_events_per_stream: config.max_events_per_stream,
            max_event_payload_bytes: config.max_event_payload_bytes,
            max_journal_bytes: config.max_journal_bytes,
            session_idle_ttl_secs: config.session_idle_ttl.as_secs(),
        }
    }
}

/// One redaction hook applied to every payload before it is retained.
pub trait Redactor: Send + Sync {
    /// Return the payload with sensitive material removed.
    fn redact(&self, event_type: &str, payload: Value) -> Value;
}

/// Ordered chain of [`Redactor`] hooks; every payload passes through all.
#[derive(Clone, Default)]
pub struct RedactionPipeline {
    hooks: Arc<Vec<Arc<dyn Redactor>>>,
}

impl RedactionPipeline {
    /// An empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// This pipeline with `hook` appended.
    #[must_use]
    pub fn with_hook<R>(self, hook: R) -> Self
    where
        R: Redactor + 'static,
    {
        let mut hooks = self.hooks.as_ref().clone();
        hooks.push(Arc::new(hook));
        Self {
            hooks: Arc::new(hooks),
        }
    }

    /// Run every hook over `payload`, in registration order.
    #[must_use]
    pub fn redact(&self, event_type: &str, payload: Value) -> Value {
        self.hooks
            .iter()
            .fold(payload, |payload, hook| hook.redact(event_type, payload))
    }
}

/// Production redactor: replaces common secret-bearing fields with a placeholder
/// before payloads are queued or journaled for replay.
#[derive(Clone, Default)]
pub struct DefaultSecretRedactor;

impl Redactor for DefaultSecretRedactor {
    fn redact(&self, _event_type: &str, payload: Value) -> Value {
        redact_secret_values(payload)
    }
}

fn redact_secret_values(payload: Value) -> Value {
    const SENSITIVE: &[&str] = &[
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "secret",
        "client_secret",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "bearer",
    ];
    match payload {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    let lower = key.to_ascii_lowercase();
                    if SENSITIVE.iter().any(|needle| lower.contains(needle)) {
                        (key, Value::String("[REDACTED]".to_string()))
                    } else {
                        (key, redact_secret_values(value))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(redact_secret_values).collect()),
        other => other,
    }
}

impl RedactionPipeline {
    /// A pipeline preloaded with the default production secret redactor.
    #[must_use]
    pub fn with_default_redactors() -> Self {
        Self::new().with_hook(DefaultSecretRedactor)
    }
}

fn event_byte_cost(event: &TransportEvent) -> usize {
    serde_json::to_string(&event.payload).map_or(0, |s| s.len()) + 64
}

/// Bounded replay journal for one stream: capped in events and in bytes.
#[derive(Debug, Clone)]
pub struct EventJournal {
    capacity: usize,
    max_bytes: usize,
    byte_len: usize,
    events: VecDeque<TransportEvent>,
    dropped_events: u64,
}

impl EventJournal {
    /// A journal bounded to `capacity` events and `max_bytes` payload bytes.
    ///
    /// # Errors
    ///
    /// [`TransportError::EmptyEventJournal`] when `capacity` is zero.
    pub fn new(capacity: usize, max_bytes: usize) -> TransportResult<Self> {
        if capacity == 0 {
            return Err(TransportError::EmptyEventJournal);
        }
        Ok(Self {
            capacity,
            max_bytes,
            byte_len: 0,
            events: VecDeque::with_capacity(capacity),
            dropped_events: 0,
        })
    }

    fn evict_oldest(&mut self) {
        if let Some(old) = self.events.pop_front() {
            self.byte_len = self.byte_len.saturating_sub(event_byte_cost(&old));
            self.dropped_events += 1;
        }
    }

    /// Append `event`, evicting oldest entries to hold both bounds.
    pub fn append(&mut self, event: TransportEvent) {
        let cost = event_byte_cost(&event);
        if self.events.len() == self.capacity {
            self.evict_oldest();
        }
        self.events.push_back(event);
        self.byte_len += cost;
        // Bound aggregate journal memory: evict oldest until under the byte cap,
        // always retaining at least the most recent event.
        while self.byte_len > self.max_bytes && self.events.len() > 1 {
            self.evict_oldest();
        }
    }

    /// Bytes currently retained.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.byte_len
    }

    /// Every retained event with an id greater than `after_event_id`.
    #[must_use]
    pub fn replay_after(&self, after_event_id: EventId) -> Vec<TransportEvent> {
        self.events
            .iter()
            .filter(|event| event.event_id > after_event_id)
            .cloned()
            .collect()
    }

    /// Events currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// True when nothing is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Events evicted to hold the bounds since creation.
    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// Id of the newest retained event, if any.
    #[must_use]
    pub fn last_event_id(&self) -> Option<EventId> {
        self.events.back().map(|event| event.event_id)
    }
}

/// The streams of one session, keyed by id, bounded per config.
#[derive(Debug, Clone)]
pub struct StreamRegistry {
    streams: BTreeMap<StreamId, StreamState>,
    max_streams: usize,
    max_events_per_stream: usize,
    max_journal_bytes: usize,
}

impl StreamRegistry {
    /// An empty registry bounded by `config`.
    ///
    /// # Errors
    ///
    /// [`TransportError::InvalidConfig`] when the config fails validation.
    pub fn new(config: &TransportConfig) -> TransportResult<Self> {
        config.validate()?;
        Ok(Self {
            streams: BTreeMap::new(),
            max_streams: config.max_streams_per_session,
            max_events_per_stream: config.max_events_per_stream,
            max_journal_bytes: config.max_journal_bytes,
        })
    }

    fn create_stream_at(&mut self, now: Instant) -> TransportResult<StreamId> {
        if self.streams.len() >= self.max_streams {
            return Err(TransportError::StreamLimitExceeded(SessionId(
                "<unbound>".into(),
            )));
        }
        let stream_id = StreamId::new();
        let state = StreamState::new(self.max_events_per_stream, self.max_journal_bytes, now)?;
        self.streams.insert(stream_id.clone(), state);
        Ok(stream_id)
    }

    /// Streams currently registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// True when no stream is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Whether `stream_id` is registered.
    #[must_use]
    pub fn contains_stream(&self, stream_id: &StreamId) -> bool {
        self.streams.contains_key(stream_id)
    }
}

#[derive(Debug, Clone)]
struct StreamState {
    last_seen: Instant,
    next_event_id: EventId,
    queue: BoundedEventQueue,
    journal: EventJournal,
}

impl StreamState {
    fn new(max_events: usize, max_journal_bytes: usize, now: Instant) -> TransportResult<Self> {
        Ok(Self {
            last_seen: now,
            next_event_id: EventId::new(1),
            queue: BoundedEventQueue::new(max_events),
            journal: EventJournal::new(max_events, max_journal_bytes)?,
        })
    }
}

/// Who a session belongs to (G3-16).
///
/// The authenticated `agent_id`, or [`SessionOwner::Anonymous`] on an install that configures
/// no client credentials.
///
/// Anonymous is a real owner rather than a wildcard, and it compares equal only to itself. On
/// an install with no credentials configured every caller is anonymous, so anonymous callers
/// can resume each other's sessions; that is not a hole this type can close, because there is
/// no identity to separate them by. It is the posture of an install that authenticates
/// nobody, and it is documented rather than papered over. What this type does close is the
/// case that matters: an authenticated caller cannot resume a session belonging to a
/// different authenticated caller, or to an anonymous one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOwner {
    /// No authenticated identity; equal only to itself.
    Anonymous,
    /// The authenticated `agent_id`.
    Agent(String),
}

impl SessionOwner {
    /// The owner an authenticated caller has, or `Anonymous` when there is no identity.
    #[must_use]
    pub fn from_agent(agent_id: Option<&str>) -> Self {
        match agent_id {
            Some(agent) => Self::Agent(agent.to_string()),
            None => Self::Anonymous,
        }
    }
}

#[derive(Debug, Clone)]
struct SessionState {
    last_seen: Instant,
    streams: StreamRegistry,
    queue: BoundedEventQueue,
    /// G3-16. Set once at creation and never changed: a session does not change hands.
    owner: SessionOwner,
}

impl SessionState {
    fn new(config: &TransportConfig, now: Instant, owner: SessionOwner) -> TransportResult<Self> {
        Ok(Self {
            last_seen: now,
            streams: StreamRegistry::new(config)?,
            queue: BoundedEventQueue::new(config.max_events_per_session),
            owner,
        })
    }
}

#[derive(Debug, Clone)]
struct BoundedEventQueue {
    capacity: usize,
    events: VecDeque<TransportEvent>,
    dropped_events: u64,
}

impl BoundedEventQueue {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            events: VecDeque::with_capacity(capacity),
            dropped_events: 0,
        }
    }

    fn push(&mut self, event: TransportEvent) {
        if self.events.len() == self.capacity {
            self.events.pop_front();
            self.dropped_events += 1;
        }
        self.events.push_back(event);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Point-in-time view of one session, for diagnostics.
pub struct SessionSnapshot {
    /// The session observed.
    pub session_id: SessionId,
    /// Streams currently open.
    pub stream_count: usize,
    /// Events in the session aggregate queue.
    pub queued_events: usize,
    /// Events dropped from that queue since creation.
    pub dropped_events: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Point-in-time view of one stream, for diagnostics.
pub struct StreamSnapshot {
    /// The stream observed.
    pub stream_id: StreamId,
    /// Events waiting in the delivery queue.
    pub queued_events: usize,
    /// Events retained in the replay journal.
    pub journaled_events: usize,
    /// Queue evictions since creation.
    pub queue_dropped_events: u64,
    /// Journal evictions since creation.
    pub journal_dropped_events: u64,
    /// Newest journaled event id, if any.
    pub last_event_id: Option<EventId>,
}

/// The transport's root object: bounded sessions with owner checks,
/// redaction, replay and backpressure counters. Cheap to clone; clones
/// share state.
#[derive(Clone)]
pub struct SessionRegistry {
    config: TransportConfig,
    redaction: RedactionPipeline,
    sessions: Arc<Mutex<BTreeMap<SessionId, SessionState>>>,
    rejections: Arc<AtomicU64>,
}

impl SessionRegistry {
    /// A registry bounded by `config`, redacting through `redaction`.
    ///
    /// # Errors
    ///
    /// [`TransportError::InvalidConfig`] when the config fails validation.
    pub fn new(config: TransportConfig, redaction: RedactionPipeline) -> TransportResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            redaction,
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            rejections: Arc::new(AtomicU64::new(0)),
        })
    }

    /// The advertisement for this build and configuration.
    #[must_use]
    pub fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities::from_config(&self.config)
    }

    /// Create a session owned by a caller (G3-16).
    ///
    /// There is deliberately no owner-less constructor. A session with no owner is one anybody
    /// can resume, which is the defect this exists to prevent, so the caller has to say who it
    /// is even if the answer is [`SessionOwner::Anonymous`].
    ///
    /// # Errors
    ///
    /// [`TransportError::SessionLimitExceeded`] at the session ceiling.
    pub fn create_session(&self, owner: SessionOwner) -> TransportResult<SessionId> {
        self.create_session_at(Instant::now(), owner)
    }

    /// [`SessionRegistry::create_session`] with an injected clock, for tests.
    ///
    /// # Errors
    ///
    /// [`TransportError::SessionLimitExceeded`] at the session ceiling.
    pub fn create_session_at(
        &self,
        now: Instant,
        owner: SessionOwner,
    ) -> TransportResult<SessionId> {
        let mut sessions = self.sessions.lock();
        if sessions.len() >= self.config.max_sessions {
            self.rejections.fetch_add(1, Ordering::Relaxed);
            return Err(TransportError::SessionLimitExceeded);
        }
        let session_id = SessionId::new();
        let state = SessionState::new(&self.config, now, owner)?;
        sessions.insert(session_id.clone(), state);
        Ok(session_id)
    }

    /// Whether this caller owns this session, without saying whether it exists (G3-16).
    ///
    /// Returns the same answer for "no such session" and "not yours" ON PURPOSE. Telling the
    /// two apart hands an attacker a session-id oracle: they could enumerate live sessions by
    /// the error they get back, which is most of the work of the attack this closes.
    #[must_use]
    pub fn owns_session(&self, session_id: &SessionId, owner: &SessionOwner) -> bool {
        self.sessions
            .lock()
            .get(session_id)
            .is_some_and(|session| &session.owner == owner)
    }

    /// Open a stream on an existing session.
    ///
    /// # Errors
    ///
    /// [`TransportError::SessionNotFound`] or
    /// [`TransportError::StreamLimitExceeded`].
    pub fn create_stream(&self, session_id: &SessionId) -> TransportResult<StreamId> {
        self.create_stream_at(session_id, Instant::now())
    }

    /// [`SessionRegistry::create_stream`] with an injected clock, for tests.
    ///
    /// # Errors
    ///
    /// [`TransportError::SessionNotFound`] or
    /// [`TransportError::StreamLimitExceeded`].
    pub fn create_stream_at(
        &self,
        session_id: &SessionId,
        now: Instant,
    ) -> TransportResult<StreamId> {
        let mut sessions = self.sessions.lock();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| TransportError::SessionNotFound(session_id.clone()))?;
        if session.streams.len() >= self.config.max_streams_per_session {
            self.rejections.fetch_add(1, Ordering::Relaxed);
            return Err(TransportError::StreamLimitExceeded(session_id.clone()));
        }
        session.last_seen = now;
        session.streams.create_stream_at(now)
    }

    /// Emit an event: redact, truncate to the payload bound, stamp the next
    /// id, then queue and journal it.
    ///
    /// # Errors
    ///
    /// [`TransportError::SessionNotFound`] or
    /// [`TransportError::StreamNotFound`].
    pub fn emit(
        &self,
        session_id: &SessionId,
        stream_id: &StreamId,
        event_type: impl Into<String>,
        payload: Value,
    ) -> TransportResult<TransportEvent> {
        let mut sessions = self.sessions.lock();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| TransportError::SessionNotFound(session_id.clone()))?;
        let stream = session.streams.streams.get_mut(stream_id).ok_or_else(|| {
            TransportError::StreamNotFound {
                session_id: session_id.clone(),
                stream_id: stream_id.clone(),
            }
        })?;
        let event_type = event_type.into();
        let payload = self.redaction.redact(&event_type, payload);
        let (payload, payload_truncated) =
            limit_payload(payload, self.config.max_event_payload_bytes);
        let event = TransportEvent {
            session_id: session_id.clone(),
            stream_id: stream_id.clone(),
            event_id: stream.next_event_id,
            event_type,
            payload,
            payload_truncated,
            emitted_unix_ms: now_unix_ms(),
        };
        stream.next_event_id = stream.next_event_id.next();
        stream.last_seen = Instant::now();
        stream.queue.push(event.clone());
        stream.journal.append(event.clone());
        session.last_seen = stream.last_seen;
        session.queue.push(event.clone());
        Ok(event)
    }

    /// Replay a stream's journal to the caller that owns it (G3-16).
    ///
    /// A caller who does not own the session gets `SessionNotFound`, the identical error a
    /// caller gets for a session that does not exist. See [`SessionRegistry::owns_session`]
    /// for why the two must not be distinguishable.
    ///
    /// # Errors
    ///
    /// [`TransportError::SessionNotFound`] for a missing OR not-owned
    /// session; [`TransportError::StreamNotFound`] for a missing stream.
    pub fn replay(
        &self,
        cursor: &ResumeCursor,
        owner: &SessionOwner,
    ) -> TransportResult<Vec<TransportEvent>> {
        let sessions = self.sessions.lock();
        let session = sessions
            .get(&cursor.session_id)
            .filter(|session| &session.owner == owner)
            .ok_or_else(|| TransportError::SessionNotFound(cursor.session_id.clone()))?;
        let stream = session
            .streams
            .streams
            .get(&cursor.stream_id)
            .ok_or_else(|| TransportError::StreamNotFound {
                session_id: cursor.session_id.clone(),
                stream_id: cursor.stream_id.clone(),
            })?;
        Ok(stream.journal.replay_after(cursor.after_event_id))
    }

    /// Drop sessions idle past the TTL as of `now`; returns how many.
    #[must_use = "the count says whether anything expired"]
    pub fn expire_idle_at(&self, now: Instant) -> usize {
        let mut sessions = self.sessions.lock();
        let before = sessions.len();
        let ttl = self.config.session_idle_ttl;
        sessions.retain(|_, session| now.duration_since(session.last_seen) <= ttl);
        before - sessions.len()
    }

    /// Sessions currently live.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.lock().len()
    }

    /// Total number of session/stream creations rejected because a capacity
    /// limit was reached. Backpressure observability for the 128-session ceiling.
    #[must_use]
    pub fn capacity_rejections(&self) -> u64 {
        self.rejections.load(Ordering::Relaxed)
    }

    /// Aggregate bytes currently retained across all stream replay journals.
    /// Hard-bounded by `max_journal_bytes` per stream times the active stream count.
    #[must_use]
    pub fn total_journal_bytes(&self) -> usize {
        self.sessions
            .lock()
            .values()
            .flat_map(|session| session.streams.streams.values())
            .map(|stream| stream.journal.byte_len())
            .sum()
    }

    /// Diagnostic view of one session.
    ///
    /// # Errors
    ///
    /// [`TransportError::SessionNotFound`].
    pub fn session_snapshot(&self, session_id: &SessionId) -> TransportResult<SessionSnapshot> {
        let sessions = self.sessions.lock();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| TransportError::SessionNotFound(session_id.clone()))?;
        Ok(SessionSnapshot {
            session_id: session_id.clone(),
            stream_count: session.streams.len(),
            queued_events: session.queue.events.len(),
            dropped_events: session.queue.dropped_events,
        })
    }

    /// Diagnostic view of one stream.
    ///
    /// # Errors
    ///
    /// [`TransportError::SessionNotFound`] or
    /// [`TransportError::StreamNotFound`].
    pub fn stream_snapshot(
        &self,
        session_id: &SessionId,
        stream_id: &StreamId,
    ) -> TransportResult<StreamSnapshot> {
        let sessions = self.sessions.lock();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| TransportError::SessionNotFound(session_id.clone()))?;
        let stream = session.streams.streams.get(stream_id).ok_or_else(|| {
            TransportError::StreamNotFound {
                session_id: session_id.clone(),
                stream_id: stream_id.clone(),
            }
        })?;
        Ok(StreamSnapshot {
            stream_id: stream_id.clone(),
            queued_events: stream.queue.events.len(),
            journaled_events: stream.journal.len(),
            queue_dropped_events: stream.queue.dropped_events,
            journal_dropped_events: stream.journal.dropped_events(),
            last_event_id: stream.journal.last_event_id(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
/// What a cancellation addresses: one request within one session.
pub struct CancellationKey {
    /// The session the request belongs to.
    pub session_id: SessionId,
    /// The request id as the client sent it.
    pub request_id: String,
}

/// Shared flag a long-running handler polls to honour cancellation.
#[derive(Debug, Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Routes `notifications/cancelled` to the token of the addressed request.
#[derive(Clone, Default)]
pub struct CancellationRegistry {
    inner: Arc<Mutex<BTreeMap<CancellationKey, CancellationToken>>>,
}

impl CancellationRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a request and get the token its handler polls.
    pub fn register(
        &self,
        session_id: SessionId,
        request_id: impl Into<String>,
    ) -> CancellationToken {
        let key = CancellationKey {
            session_id,
            request_id: request_id.into(),
        };
        let token = CancellationToken {
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        self.inner.lock().insert(key, token.clone());
        token
    }

    /// Request cancellation; true when the request was registered.
    #[must_use = "false means nothing was cancelled"]
    pub fn cancel(&self, session_id: &SessionId, request_id: &str) -> bool {
        let key = CancellationKey {
            session_id: session_id.clone(),
            request_id: request_id.to_string(),
        };
        if let Some(token) = self.inner.lock().get(&key) {
            token.cancelled.store(true, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    /// Remove a finished request; true when it was registered.
    #[must_use = "false means nothing was removed"]
    pub fn unregister(&self, session_id: &SessionId, request_id: &str) -> bool {
        let key = CancellationKey {
            session_id: session_id.clone(),
            request_id: request_id.to_string(),
        };
        self.inner.lock().remove(&key).is_some()
    }

    /// Requests currently registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// True when no request is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

fn limit_payload(payload: Value, max_bytes: usize) -> (Value, bool) {
    let Ok(bytes) = serde_json::to_vec(&payload) else {
        return (
            json!({
                "truncated": true,
                "reason": "payload serialization failed"
            }),
            true,
        );
    };
    if bytes.len() <= max_bytes {
        return (payload, false);
    }
    (
        json!({
            "truncated": true,
            "original_bytes": bytes.len(),
            "max_bytes": max_bytes,
            "summary": "event payload exceeded transport limit"
        }),
        true,
    )
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    // Tests assert on shapes and sequences, where unwrap/expect/indexing ARE
    // the assertion: a panic in a test is the failure signal, so the
    // production rationale for the workspace denies does not apply.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;

    fn registry(config: TransportConfig) -> SessionRegistry {
        SessionRegistry::new(config, RedactionPipeline::new()).expect("registry")
    }

    #[test]
    fn event_ids_are_monotonic_and_replay_is_ordered() {
        let registry = registry(TransportConfig::default());
        let session_id = registry
            .create_session(SessionOwner::Anonymous)
            .expect("session");
        let stream_id = registry.create_stream(&session_id).expect("stream");

        let first = registry
            .emit(&session_id, &stream_id, "message", json!({"n": 1}))
            .expect("emit first");
        let second = registry
            .emit(&session_id, &stream_id, "message", json!({"n": 2}))
            .expect("emit second");

        assert_eq!(first.event_id, EventId::new(1));
        assert_eq!(second.event_id, EventId::new(2));

        let replayed = registry
            .replay(
                &ResumeCursor {
                    session_id,
                    stream_id,
                    after_event_id: EventId::new(0),
                },
                &SessionOwner::Anonymous,
            )
            .expect("replay");
        let ids: Vec<EventId> = replayed.iter().map(|event| event.event_id).collect();
        assert_eq!(ids, vec![EventId::new(1), EventId::new(2)]);
    }

    #[test]
    fn queues_and_journals_are_bounded() {
        let registry = registry(TransportConfig {
            max_events_per_session: 3,
            max_events_per_stream: 2,
            ..TransportConfig::default()
        });
        let session_id = registry
            .create_session(SessionOwner::Anonymous)
            .expect("session");
        let stream_id = registry.create_stream(&session_id).expect("stream");

        for n in 1..=4 {
            registry
                .emit(&session_id, &stream_id, "message", json!({"n": n}))
                .expect("emit");
        }

        let session = registry
            .session_snapshot(&session_id)
            .expect("session stats");
        let stream = registry
            .stream_snapshot(&session_id, &stream_id)
            .expect("stream stats");
        assert_eq!(session.queued_events, 3);
        assert_eq!(session.dropped_events, 1);
        assert_eq!(stream.queued_events, 2);
        assert_eq!(stream.journaled_events, 2);
        assert_eq!(stream.queue_dropped_events, 2);
        assert_eq!(stream.journal_dropped_events, 2);

        let replayed = registry
            .replay(
                &ResumeCursor {
                    session_id,
                    stream_id,
                    after_event_id: EventId::new(0),
                },
                &SessionOwner::Anonymous,
            )
            .expect("replay");
        let ids: Vec<EventId> = replayed.iter().map(|event| event.event_id).collect();
        assert_eq!(ids, vec![EventId::new(3), EventId::new(4)]);
    }

    #[test]
    fn session_expiry_removes_idle_sessions() {
        let registry = registry(TransportConfig {
            session_idle_ttl: Duration::from_secs(1),
            ..TransportConfig::default()
        });
        let now = Instant::now();
        let session_id = registry
            .create_session_at(now, SessionOwner::Anonymous)
            .expect("session");

        let expired = registry.expire_idle_at(now + Duration::from_secs(2));

        assert_eq!(expired, 1);
        assert_eq!(registry.session_count(), 0);
        assert_eq!(
            registry.create_stream(&session_id),
            Err(TransportError::SessionNotFound(session_id))
        );
    }

    /// G3-16, the acceptance criterion. A caller with a valid credential of their own, holding
    /// another caller's session and stream ids, must not be able to read that stream's
    /// replayed tool results.
    #[test]
    fn one_caller_cannot_replay_another_callers_stream() {
        let registry = registry(TransportConfig::default());
        let alice = SessionOwner::Agent("alice".into());
        let mallory = SessionOwner::Agent("mallory".into());

        let session_id = registry
            .create_session(alice.clone())
            .expect("alice's session");
        let stream_id = registry.create_stream(&session_id).expect("alice's stream");
        registry
            .emit(
                &session_id,
                &stream_id,
                "message",
                json!({"tool_result": 1}),
            )
            .expect("an event alice's client would receive");

        let cursor = ResumeCursor {
            session_id: session_id.clone(),
            stream_id: stream_id.clone(),
            after_event_id: EventId::new(0),
        };

        assert!(
            !registry.replay(&cursor, &alice).unwrap().is_empty(),
            "alice can replay her own stream"
        );

        let refused = registry.replay(&cursor, &mallory);
        assert!(
            matches!(refused, Err(TransportError::SessionNotFound(_))),
            "mallory must be refused, and told nothing that distinguishes \
             'not yours' from 'no such session': {refused:?}"
        );
    }

    /// G3-16. The refusal for a session somebody else owns is byte-identical to the refusal
    /// for a session that does not exist, so an attacker cannot enumerate live sessions by
    /// the error they get back.
    #[test]
    fn a_foreign_session_is_indistinguishable_from_a_missing_one() {
        let registry = registry(TransportConfig::default());
        let alice = SessionOwner::Agent("alice".into());
        let mallory = SessionOwner::Agent("mallory".into());

        let real = registry.create_session(alice).expect("alice's session");
        let invented = SessionId::from_string("00000000-0000-4000-8000-000000000000");

        assert!(!registry.owns_session(&real, &mallory), "not mallory's");
        assert!(
            !registry.owns_session(&invented, &mallory),
            "does not exist"
        );

        let stream_id = registry.create_stream(&real).expect("stream");
        let foreign = registry.replay(
            &ResumeCursor {
                session_id: real,
                stream_id: stream_id.clone(),
                after_event_id: EventId::new(0),
            },
            &mallory,
        );
        let missing = registry.replay(
            &ResumeCursor {
                session_id: invented,
                stream_id,
                after_event_id: EventId::new(0),
            },
            &mallory,
        );
        assert_eq!(
            std::mem::discriminant(&foreign.unwrap_err()),
            std::mem::discriminant(&missing.unwrap_err()),
            "the two refusals must be the same kind of refusal"
        );
    }

    /// G3-16. Anonymous is a real owner that compares equal only to itself, so an
    /// authenticated caller cannot resume a session created before credentials existed, and
    /// an anonymous caller cannot resume an authenticated one's.
    #[test]
    fn anonymous_and_authenticated_sessions_do_not_cross() {
        let registry = registry(TransportConfig::default());
        let anonymous = SessionOwner::Anonymous;
        let agent = SessionOwner::Agent("alice".into());

        let anon_session = registry
            .create_session(anonymous.clone())
            .expect("anonymous session");
        let agent_session = registry
            .create_session(agent.clone())
            .expect("agent session");

        assert!(registry.owns_session(&anon_session, &anonymous));
        assert!(!registry.owns_session(&anon_session, &agent));
        assert!(registry.owns_session(&agent_session, &agent));
        assert!(!registry.owns_session(&agent_session, &anonymous));
    }

    /// G3-16. `from_agent` is the only way the server builds an owner, so this pins the
    /// mapping rather than leaving it to each call site.
    #[test]
    fn an_absent_agent_id_is_anonymous_rather_than_a_wildcard() {
        assert_eq!(SessionOwner::from_agent(None), SessionOwner::Anonymous);
        assert_eq!(
            SessionOwner::from_agent(Some("alice")),
            SessionOwner::Agent("alice".into())
        );
        assert_ne!(
            SessionOwner::from_agent(Some("alice")),
            SessionOwner::from_agent(Some("mallory"))
        );
    }

    #[test]
    fn replay_does_not_cross_stream_identity() {
        let registry = registry(TransportConfig::default());
        let first_session = registry
            .create_session(SessionOwner::Anonymous)
            .expect("first session");
        let first_stream = registry
            .create_stream(&first_session)
            .expect("first stream");
        let second_session = registry
            .create_session(SessionOwner::Anonymous)
            .expect("second session");

        registry
            .emit(
                &first_session,
                &first_stream,
                "message",
                json!({"ok": true}),
            )
            .expect("emit");

        let result = registry.replay(
            &ResumeCursor {
                session_id: second_session.clone(),
                stream_id: first_stream.clone(),
                after_event_id: EventId::new(0),
            },
            &SessionOwner::Anonymous,
        );

        assert_eq!(
            result,
            Err(TransportError::StreamNotFound {
                session_id: second_session,
                stream_id: first_stream,
            })
        );
    }

    #[test]
    fn stream_limit_is_enforced_per_session() {
        let registry = registry(TransportConfig {
            max_streams_per_session: 1,
            ..TransportConfig::default()
        });
        let session_id = registry
            .create_session(SessionOwner::Anonymous)
            .expect("session");
        registry.create_stream(&session_id).expect("stream");

        assert_eq!(
            registry.create_stream(&session_id),
            Err(TransportError::StreamLimitExceeded(session_id))
        );
    }

    #[derive(Clone)]
    struct SecretRedactor;

    impl Redactor for SecretRedactor {
        fn redact(&self, _event_type: &str, mut payload: Value) -> Value {
            if let Value::Object(map) = &mut payload
                && map.get("token").is_some()
            {
                map.insert("token".into(), json!("[REDACTED]"));
            }
            payload
        }
    }

    #[test]
    fn redaction_hook_runs_before_queue_and_replay_storage() {
        let redaction = RedactionPipeline::new().with_hook(SecretRedactor);
        let registry =
            SessionRegistry::new(TransportConfig::default(), redaction).expect("registry");
        let session_id = registry
            .create_session(SessionOwner::Anonymous)
            .expect("session");
        let stream_id = registry.create_stream(&session_id).expect("stream");

        let event = registry
            .emit(
                &session_id,
                &stream_id,
                "stdout",
                json!({"token": "raw-secret", "visible": "ok"}),
            )
            .expect("emit");
        let replayed = registry
            .replay(
                &ResumeCursor {
                    session_id,
                    stream_id,
                    after_event_id: EventId::new(0),
                },
                &SessionOwner::Anonymous,
            )
            .expect("replay");
        let replay_json = serde_json::to_string(&replayed).expect("event json");

        assert_eq!(event.payload["token"], "[REDACTED]");
        assert!(!replay_json.contains("raw-secret"));
        assert!(replay_json.contains("[REDACTED]"));
    }

    #[test]
    fn redaction_runs_before_payload_size_limiting() {
        let redaction = RedactionPipeline::new().with_hook(SecretRedactor);
        let registry = SessionRegistry::new(
            TransportConfig {
                max_event_payload_bytes: 40,
                ..TransportConfig::default()
            },
            redaction,
        )
        .expect("registry");
        let session_id = registry
            .create_session(SessionOwner::Anonymous)
            .expect("session");
        let stream_id = registry.create_stream(&session_id).expect("stream");

        let event = registry
            .emit(
                &session_id,
                &stream_id,
                "stdout",
                json!({"token": "x".repeat(500)}),
            )
            .expect("emit");

        assert!(!event.payload_truncated);
        assert_eq!(event.payload["token"], "[REDACTED]");
    }

    #[test]
    fn oversized_payloads_are_replaced_with_truncation_marker() {
        let registry = registry(TransportConfig {
            max_event_payload_bytes: 32,
            ..TransportConfig::default()
        });
        let session_id = registry
            .create_session(SessionOwner::Anonymous)
            .expect("session");
        let stream_id = registry.create_stream(&session_id).expect("stream");

        let event = registry
            .emit(
                &session_id,
                &stream_id,
                "stdout",
                json!({"line": "x".repeat(200)}),
            )
            .expect("emit");

        assert!(event.payload_truncated);
        assert_eq!(event.payload["truncated"], true);
        assert_eq!(event.payload["max_bytes"], 32);
    }

    #[test]
    fn cancellation_registry_routes_by_session_and_request() {
        let registry = CancellationRegistry::new();
        let session_id = SessionId::new();
        let other_session = SessionId::new();
        let token = registry.register(session_id.clone(), "request-1");

        assert!(!token.is_cancelled());
        assert!(!registry.cancel(&other_session, "request-1"));
        assert!(registry.cancel(&session_id, "request-1"));
        assert!(token.is_cancelled());
        assert!(registry.unregister(&session_id, "request-1"));
        assert!(registry.is_empty());
    }

    #[test]
    fn capabilities_report_bounded_in_memory_core() {
        let config = TransportConfig::default();
        let registry = registry(config.clone());
        let capabilities = registry.capabilities();

        assert!(capabilities.core_available);
        assert!(capabilities.in_memory_replay);
        assert!(!capabilities.cross_process_replay);
        assert_eq!(capabilities.max_sessions, config.max_sessions);
        assert_eq!(
            capabilities.max_events_per_stream,
            config.max_events_per_stream
        );
    }
}

#[cfg(test)]
mod backpressure_tests {
    // Tests assert on shapes and sequences, where unwrap/expect/indexing ARE
    // the assertion: a panic in a test is the failure signal, so the
    // production rationale for the workspace denies does not apply.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;

    #[test]
    fn session_limit_increments_capacity_rejections() {
        let config = TransportConfig {
            max_sessions: 1,
            ..TransportConfig::default()
        };
        let registry = SessionRegistry::new(config, RedactionPipeline::new()).unwrap();
        let _first = registry.create_session(SessionOwner::Anonymous).unwrap();
        assert_eq!(registry.capacity_rejections(), 0);
        let second = registry.create_session(SessionOwner::Anonymous);
        assert!(matches!(second, Err(TransportError::SessionLimitExceeded)));
        assert_eq!(registry.capacity_rejections(), 1);
    }

    #[test]
    fn journal_evicts_under_byte_pressure() {
        let config = TransportConfig {
            max_journal_bytes: 16 * 1024,
            ..TransportConfig::default()
        };
        let registry = SessionRegistry::new(config, RedactionPipeline::new()).unwrap();
        let sid = registry.create_session(SessionOwner::Anonymous).unwrap();
        let stream = registry.create_stream(&sid).unwrap();
        let payload = serde_json::json!({ "blob": "x".repeat(4096) });
        for _ in 0..50 {
            registry
                .emit(&sid, &stream, "load", payload.clone())
                .unwrap();
        }
        assert!(registry.total_journal_bytes() <= 16 * 1024);
        assert!(registry.total_journal_bytes() > 0);
    }
}
