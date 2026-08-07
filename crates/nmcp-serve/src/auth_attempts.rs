//! Coalescing failed authentication attempts into bounded audit records (G3-13, AF-2).
//!
//! The obvious implementation of "record a failed authentication" is to append a record per
//! attempt. That hands an unauthenticated caller a write primitive against a hash-chained,
//! append-only, permanently retained log: they control how fast it grows, so they can rotate a
//! real event out of the retention window and bury the record of a successful intrusion under
//! millions of their own. The log that exists to make an intrusion visible becomes the thing an
//! intruder uses to hide it.
//!
//! So attempts are coalesced. One record per source per window, carrying the count. Ten thousand
//! individual "bad token" records answer no question that "10,000 attempts from this source
//! between these two times, all `unknown_credential`" does not answer better.
//!
//! # The second unbounded thing
//!
//! Coalescing by source bounds the writes and moves the problem: the ledger itself is now a map
//! an attacker grows by varying source, which is free with IPv6 and cheap with a botnet. A cap on
//! tracked sources is therefore not a nicety, it is the same requirement one level down, and
//! [`MAX_TRACKED_SOURCES`] enforces it with an overflow bucket so the attempts are still counted
//! rather than dropped silently.
//!
//! This is a deviation from the frozen specification, which specifies the disk bound in AF-2 and
//! does not name the memory one. Recorded here rather than fixed silently; the specification
//! wants an AF-12 saying it.

// Every caller of this module outside its own tests is a lane's authentication path, and
// the lanes are I-075. Its own test module uses all of it, so `expect` cannot express this:
// the lint fires in the lib target and not in the lib-test target, and an unfulfilled
// expectation in one of them is an error either way. The self-clearing enforcement point is
// the single `expect(dead_code)` on `AppState::auth_attempts`, which is dead in both
// targets and stops applying the moment a lane calls it. Removing that one removes the
// reason for these.
#![allow(
    dead_code,
    reason = "the ledger's consumers are the three lanes, which land in I-075"
)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use nmcp_audit::AuditEvent;
use parking_lot::Mutex;

use crate::peer::PeerSource;

/// How long one coalescing window stays open.
///
/// Long enough that a sustained attack collapses into few records, short enough that an operator
/// watching a live incident sees movement rather than waiting on a flush.
const WINDOW: Duration = Duration::from_mins(1);

/// The attempt count that forces a flush before the window closes.
///
/// Without it, a burst inside one window is invisible until the window ends, which is exactly
/// when an operator most wants to know. With it, the write rate is still bounded, because the
/// bound is per source per window and a source that reaches it has its window restarted.
const FLUSH_AT_ATTEMPTS: u64 = 1_000;

/// The most distinct sources tracked at once. See the module doc.
const MAX_TRACKED_SOURCES: usize = 1_024;

/// The label used for every attempt beyond [`MAX_TRACKED_SOURCES`].
///
/// A named bucket rather than a dropped attempt, because "we stopped counting" is itself the
/// finding an operator needs, and a silent cap would read as an attack having stopped.
const OVERFLOW_SOURCE: &str = "overflow (source cap reached)";

/// The label for an attempt that arrived without connect info.
const UNKNOWN_SOURCE: &str = "unknown";

/// What one window is counted under.
///
/// The whole of finding F-3 is here. The base used one `String` for two jobs `peer.rs`'s module
/// doc says must not be conflated: the identity the throttle counts by, and the label the record
/// carries. That string was `PeerSource::redacted()`, so the throttle counted by /24 and /64.
/// One attacker behind an office NAT refused everyone behind it, which is the exact failure the
/// doc says the design exists to avoid.
///
/// Splitting them costs one enum. [`Self::Peer`] holds the full address and is never written;
/// [`Self::label`] is the redacted form and is the only thing that reaches an [`AuditEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SourceKey {
    /// A caller that arrived over the listener, at full resolution.
    Peer(PeerSource),
    /// A caller with no connect info, which today is only a test driving a handler directly.
    ///
    /// Named rather than guessed at: recording it as loopback would be a claim about the
    /// network this code cannot support.
    Unknown,
    /// Every source beyond the cap, sharing one window.
    Overflow,
}

impl SourceKey {
    /// The form that may be written down. Never the full address.
    ///
    /// Two distinct keys can share a label, which is the point: two hosts in one /24 are two
    /// throttle buckets and one line in the record, and neither of those is a compromise on the
    /// other.
    fn label(self) -> String {
        match self {
            Self::Peer(peer) => peer.redacted(),
            Self::Unknown => UNKNOWN_SOURCE.to_string(),
            Self::Overflow => OVERFLOW_SOURCE.to_string(),
        }
    }
}

/// One source's open window.
#[derive(Debug, Clone)]
struct Window {
    opened_at: Instant,
    attempts: u64,
    /// The reason classes seen, deduplicated and ordered so a record reads the same way twice.
    reasons: std::collections::BTreeSet<&'static str>,
    /// The credential paths attempted. A source may try both.
    paths: std::collections::BTreeSet<&'static str>,
    throttled: bool,
}

impl Window {
    fn open(now: Instant) -> Self {
        Self {
            opened_at: now,
            attempts: 0,
            reasons: std::collections::BTreeSet::default(),
            paths: std::collections::BTreeSet::default(),
            throttled: false,
        }
    }

    /// Turn this window into the one record that stands for it.
    ///
    /// The summary carries reason CLASSES only. An audit record is readable by anyone holding
    /// the log, and a fine-grained reason is what tells an attacker which guess came closest.
    fn into_record(self, peer: &str) -> AuditEvent {
        let summary = format!(
            "{} failed authentication attempt(s) over {}s; reasons: {}",
            self.attempts,
            self.opened_at.elapsed().as_secs(),
            if self.reasons.is_empty() {
                "none recorded".to_string()
            } else {
                self.reasons.iter().copied().collect::<Vec<_>>().join(", ")
            }
        );
        let paths = if self.paths.is_empty() {
            "none".to_string()
        } else {
            self.paths.iter().copied().collect::<Vec<_>>().join(", ")
        };
        let record = AuditEvent::auth_reject(peer, paths, self.attempts, summary);
        if self.throttled {
            record.throttled()
        } else {
            record
        }
    }
}

/// The coalescing ledger.
///
/// Holds no credential and nothing derived from one: an attempt reaches it as a source, a
/// credential path and a reason class, and the reason class comes from a closed set of
/// `&'static str` rather than from a formatted string, so there is no way for attacker-supplied
/// bytes to arrive here at all rather than being trusted not to.
#[derive(Default)]
pub(crate) struct AuthAttemptLedger {
    inner: Mutex<BTreeMap<SourceKey, Window>>,
}

impl AuthAttemptLedger {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record one failed attempt, returning a record to append if a window closed.
    ///
    /// `reason` and `credential_path` are `&'static str` by design. See the type doc.
    pub(crate) fn record(
        &self,
        peer: Option<&PeerSource>,
        credential_path: &'static str,
        reason: &'static str,
        now: Instant,
    ) -> Option<AuditEvent> {
        let mut guard = self.inner.lock();
        let key = Self::key_for(&guard, peer);

        // A window that has already outlived WINDOW is flushed and replaced, so this attempt is
        // counted in a fresh one rather than extending an old one indefinitely.
        let expired = guard
            .get(&key)
            .is_some_and(|window| now.duration_since(window.opened_at) >= WINDOW);
        let mut flushed = None;
        if expired && let Some(window) = guard.remove(&key) {
            flushed = Some(window.into_record(&key.label()));
        }

        let attempts = {
            let window = guard.entry(key).or_insert_with(|| Window::open(now));
            window.attempts += 1;
            window.reasons.insert(reason);
            window.paths.insert(credential_path);
            window.attempts
        };

        if attempts >= FLUSH_AT_ATTEMPTS {
            // A forced flush wins over a window rollover, because they cannot both happen on
            // one attempt and the full window is the more urgent thing to report.
            //
            // The base wrote this as `.expect("just inserted")`, and the claim is true: the
            // entry above found or inserted this key and the guard has not been released since.
            // It is still the wrong shape, and the workspace denying `expect_used` is what
            // surfaced it. That panic fires on an unauthenticated caller's thousandth attempt,
            // which is exactly the moment the listener must not go down, and it would take the
            // coalescing ledger down with it. A miss that cannot happen costs nothing to handle.
            if let Some(full) = guard.remove(&key) {
                return Some(full.into_record(&key.label()));
            }
        }
        flushed
    }

    /// Whether this source has already failed enough times inside its window to be refused
    /// without its credential being evaluated (G3-14, AF-8).
    ///
    /// Reads the open window rather than a counter of its own, so the throttle and the record
    /// cannot disagree about how many attempts there were.
    ///
    /// A window older than the configured span is treated as no attempts: it is about to be
    /// flushed and replaced, and counting a stale window would extend a throttle past the span
    /// an operator configured.
    pub(crate) fn should_throttle(
        &self,
        peer: Option<&PeerSource>,
        threshold: u32,
        window: Duration,
        now: Instant,
    ) -> bool {
        let guard = self.inner.lock();
        let key = Self::key_for(&guard, peer);
        guard.get(&key).is_some_and(|open| {
            now.duration_since(open.opened_at) < window && open.attempts >= u64::from(threshold)
        })
    }

    /// Mark the current window for a source as one in which it was being throttled (AF-9).
    pub(crate) fn mark_throttled(&self, peer: Option<&PeerSource>, now: Instant) {
        let mut guard = self.inner.lock();
        let key = Self::key_for(&guard, peer);
        guard
            .entry(key)
            .or_insert_with(|| Window::open(now))
            .throttled = true;
    }

    /// Flush every window that has outlived the coalescing window.
    ///
    /// Called on a timer rather than only on the next attempt, so an attack that stops does not
    /// leave its last window unreported until something else happens to arrive.
    pub(crate) fn flush_expired(&self, now: Instant) -> Vec<AuditEvent> {
        let mut guard = self.inner.lock();
        let expired: Vec<SourceKey> = guard
            .iter()
            .filter(|(_, window)| now.duration_since(window.opened_at) >= WINDOW)
            .map(|(key, _)| *key)
            .collect();
        expired
            .into_iter()
            .filter_map(|key| {
                guard
                    .remove(&key)
                    .map(|window| window.into_record(&key.label()))
            })
            .collect()
    }

    /// The key a source is counted under, honouring the source cap.
    ///
    /// A source already being tracked keeps its own key whatever the map size, so reaching the
    /// cap cannot evict or merge an attacker already being counted.
    fn key_for(tracked: &BTreeMap<SourceKey, Window>, peer: Option<&PeerSource>) -> SourceKey {
        let Some(peer) = peer else {
            return SourceKey::Unknown;
        };
        let key = SourceKey::Peer(*peer);
        // A source already being tracked keeps its own key whatever the map size, so reaching
        // the cap cannot evict or merge an attacker already being counted.
        if tracked.contains_key(&key) || tracked.len() < MAX_TRACKED_SOURCES {
            key
        } else {
            SourceKey::Overflow
        }
    }

    #[cfg(test)]
    fn tracked_sources(&self) -> usize {
        self.inner.lock().len()
    }
}

#[cfg(test)]
mod tests {
    // Tests assert on shapes, counts and JSON, where expect/indexing ARE the assertion: a
    // panic in a test is the failure signal, so the production rationale for the workspace
    // denies (availability plus an audit gap) does not apply. Scoped to the test module,
    // named in the PR.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::cast_possible_truncation
    )]

    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn source(last_octet: u8) -> PeerSource {
        PeerSource::new(IpAddr::V4(Ipv4Addr::new(203, 0, last_octet, 1)))
    }

    /// AF-2, the acceptance criterion. A thousand attempts are one record, not a thousand.
    #[test]
    fn a_burst_from_one_source_becomes_one_record_carrying_its_count() {
        let ledger = AuthAttemptLedger::new();
        let peer = source(113);
        let now = Instant::now();

        let mut records = Vec::new();
        for _ in 0..FLUSH_AT_ATTEMPTS {
            if let Some(record) = ledger.record(Some(&peer), "static", "unknown_credential", now) {
                records.push(record);
            }
        }

        assert_eq!(
            records.len(),
            1,
            "{} attempts must not produce {} records",
            FLUSH_AT_ATTEMPTS,
            records.len()
        );
        assert_eq!(records[0].attempts, Some(FLUSH_AT_ATTEMPTS));
        assert_eq!(records[0].peer.as_deref(), Some("203.0.113.0/24"));
    }

    /// AF-2. Below the flush bound nothing is written at all, so an ordinary typo does not
    /// append to a permanent chain.
    #[test]
    fn a_handful_of_attempts_writes_nothing_until_the_window_closes() {
        let ledger = AuthAttemptLedger::new();
        let peer = source(113);
        let now = Instant::now();

        for _ in 0..5 {
            assert!(
                ledger
                    .record(Some(&peer), "oauth", "expired", now)
                    .is_none()
            );
        }

        // The window closing is what produces the record.
        let flushed = ledger.flush_expired(now + WINDOW);
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].attempts, Some(5));
        assert!(
            flushed[0].summary.contains("expired"),
            "{}",
            flushed[0].summary
        );
    }

    /// AF-3. Reason classes are deduplicated and ordered, so the same attack reads the same way
    /// twice and a record does not grow with repetition.
    #[test]
    fn reason_classes_are_deduplicated_and_ordered() {
        let ledger = AuthAttemptLedger::new();
        let peer = source(113);
        let now = Instant::now();

        for reason in ["expired", "absent", "expired", "absent", "expired"] {
            ledger.record(Some(&peer), "oauth", reason, now);
        }
        let flushed = ledger.flush_expired(now + WINDOW);
        assert_eq!(flushed[0].attempts, Some(5));
        assert!(
            flushed[0].summary.contains("absent, expired"),
            "{}",
            flushed[0].summary
        );
    }

    /// The module doc's second unbounded thing. Varying source is free with IPv6 and cheap with
    /// a botnet, so the ledger needs the same bound the log has.
    #[test]
    fn varying_the_source_cannot_grow_the_ledger_without_bound() {
        let ledger = AuthAttemptLedger::new();
        let now = Instant::now();

        // Far more distinct /24s than the cap allows. Records returned mid-loop are a forced
        // flush of the overflow bucket reaching FLUSH_AT_ATTEMPTS, and are part of the
        // accounting: dropping them here would make this test claim attempts were lost when
        // they were reported.
        let mut records = Vec::new();
        for a in 0..=255u8 {
            for b in 0..=63u8 {
                let peer = PeerSource::new(IpAddr::V4(Ipv4Addr::new(a, b, 0, 1)));
                if let Some(record) =
                    ledger.record(Some(&peer), "static", "unknown_credential", now)
                {
                    records.push(record);
                }
            }
        }

        assert!(
            ledger.tracked_sources() <= MAX_TRACKED_SOURCES + 1,
            "ledger grew to {}",
            ledger.tracked_sources()
        );

        records.extend(ledger.flush_expired(now + WINDOW));
        let total: u64 = records.iter().filter_map(|record| record.attempts).sum();
        assert_eq!(
            total,
            256 * 64,
            "every attempt must be counted somewhere, not dropped at the cap"
        );
        assert!(
            records
                .iter()
                .any(|record| record.peer.as_deref() == Some(OVERFLOW_SOURCE)),
            "the cap must be visible in the record rather than silent"
        );
        // The point of the cap. Record count is bounded by the source cap plus the forced
        // flushes of the overflow bucket, and NOT by the number of distinct sources an
        // attacker invents. A capped source legitimately gets its own record per window, so
        // the ceiling is the cap rather than a small constant; what matters is that inventing
        // ten times as many sources does not produce ten times as many records.
        let ceiling = MAX_TRACKED_SOURCES + (total as usize / FLUSH_AT_ATTEMPTS as usize) + 2;
        assert!(
            records.len() <= ceiling,
            "{} records exceeds the ceiling of {ceiling}",
            records.len()
        );
        assert!(
            records.len() < 256 * 64,
            "{} records for {} sources means the cap did nothing",
            records.len(),
            256 * 64
        );
    }

    /// A source already being counted keeps its own key, so reaching the cap cannot hide an
    /// attacker who was being tracked before the flood started.
    #[test]
    fn reaching_the_cap_does_not_merge_a_source_already_being_counted() {
        let ledger = AuthAttemptLedger::new();
        let now = Instant::now();
        let known = source(113);

        ledger.record(Some(&known), "static", "unknown_credential", now);
        for a in 0..=255u8 {
            for b in 0..=63u8 {
                let peer = PeerSource::new(IpAddr::V4(Ipv4Addr::new(a, b, 9, 1)));
                ledger.record(Some(&peer), "static", "unknown_credential", now);
            }
        }
        ledger.record(Some(&known), "static", "unknown_credential", now);

        let flushed = ledger.flush_expired(now + WINDOW);
        let known_record = flushed
            .iter()
            .find(|record| record.peer.as_deref() == Some("203.0.113.0/24"))
            .expect("the known source keeps its own window");
        assert_eq!(known_record.attempts, Some(2));
    }

    /// AF-9. A throttled window says so, and does not become a record per refused request.
    #[test]
    fn a_throttled_window_is_marked_once_rather_than_recorded_per_request() {
        let ledger = AuthAttemptLedger::new();
        let peer = source(113);
        let now = Instant::now();

        ledger.record(Some(&peer), "static", "unknown_credential", now);
        for _ in 0..100 {
            ledger.mark_throttled(Some(&peer), now);
        }

        let flushed = ledger.flush_expired(now + WINDOW);
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].throttled, Some(true));
        assert_eq!(
            flushed[0].attempts,
            Some(1),
            "marking throttled is not an attempt"
        );
    }

    /// AF-8, the acceptance criterion. One attacker must not get a legitimate client refused.
    #[test]
    fn throttling_one_source_leaves_every_other_source_untouched() {
        let ledger = AuthAttemptLedger::new();
        let now = Instant::now();
        let attacker = source(113);
        let legitimate = source(114);

        for _ in 0..20 {
            ledger.record(Some(&attacker), "static", "unknown_credential", now);
        }

        assert!(ledger.should_throttle(Some(&attacker), 20, WINDOW, now));
        assert!(
            !ledger.should_throttle(Some(&legitimate), 20, WINDOW, now),
            "a second source must be unaffected by the first one's failures"
        );
        // And a caller with no connect info is not swept into the attacker's window.
        assert!(!ledger.should_throttle(None, 20, WINDOW, now));
    }

    /// AF-8, the case its own acceptance test did not construct. Finding F-3.
    ///
    /// `throttling_one_source_leaves_every_other_source_untouched` is the criterion AF-8 names,
    /// and in the base it compares `source(113)` against `source(114)`. That helper is
    /// `Ipv4Addr::new(203, 0, last_octet, 1)`, so it varies the **third** octet: those are two
    /// different /24s, and under prefix keying two different buckets. The test written to prove
    /// one attacker cannot lock out a legitimate client never put them in the same bucket.
    ///
    /// Two hosts on one network is not an edge case. It is every office behind one NAT, every
    /// pair of containers on one host, every pod in one subnet. Under the base's keying, one
    /// user mistyping a token twenty times refused their whole building.
    #[test]
    fn one_attacker_does_not_throttle_a_second_host_on_the_same_network() {
        let ledger = AuthAttemptLedger::new();
        let now = Instant::now();
        let attacker = PeerSource::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)));
        let neighbour = PeerSource::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 43)));
        assert_eq!(
            attacker.redacted(),
            neighbour.redacted(),
            "the premise: these two share a redacted label, which is what the base keyed on"
        );

        for _ in 0..20 {
            ledger.record(Some(&attacker), "static", "unknown_credential", now);
        }

        assert!(ledger.should_throttle(Some(&attacker), 20, WINDOW, now));
        assert!(
            !ledger.should_throttle(Some(&neighbour), 20, WINDOW, now),
            "a second host behind the same prefix must reach the credential check. Keying the \
             throttle on the redacted form is what refused it, and peer.rs's module doc says \
             in as many words that throttling coarsely is the failure mode that matters."
        );
    }

    /// The other half of F-3, and the reason the fix is a separation rather than a widening.
    ///
    /// The two hosts above are two throttle buckets and one label in the record. Precision
    /// belongs to the throttle, which holds it in memory and never writes it; truncation belongs
    /// to the record, which is permanent and widely readable. Asserting only the throttle half
    /// would leave a future change free to reach precision by writing the address down.
    #[test]
    fn two_hosts_on_one_network_are_two_buckets_and_one_label_in_the_record() {
        let ledger = AuthAttemptLedger::new();
        let now = Instant::now();
        let first = PeerSource::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)));
        let second = PeerSource::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 43)));

        ledger.record(Some(&first), "static", "unknown_credential", now);
        ledger.record(Some(&second), "static", "unknown_credential", now);
        assert_eq!(
            ledger.tracked_sources(),
            2,
            "two hosts are two windows, which is the throttle keeping its precision"
        );

        let flushed = ledger.flush_expired(now + WINDOW);
        assert_eq!(flushed.len(), 2);
        // A FLAKY ASSERTION, fixed. This read `for host in [".42", ".43"]` and scanned the whole
        // serialized document. `AuditEvent.timestamp` is a `DateTime<Utc>`, which serialises with
        // fractional seconds, so `.42` matched any record whose fraction happened to begin with
        // those two digits. Two records and two patterns is roughly a four percent failure rate
        // per run, which is exactly often enough to red a CI job occasionally and never often
        // enough to be reproduced by whoever sees it.
        //
        // Third instance of one shape in this port, after `crates/nmcp-serve` matching
        // `crates/nmcp-serve-assets` and `Instant` matching a doc comment about removing
        // `Instant`. A substring assertion is only as precise as the shortest thing that
        // satisfies it, and a two-character suffix satisfies almost anything.
        //
        // The full address is what must not appear, and naming it is both stronger and immune to
        // whatever else the record carries.
        let rendered = serde_json::to_string(&flushed).expect("serialize");
        for host in ["203.0.113.42", "203.0.113.43"] {
            assert!(
                !rendered.contains(host),
                "the record keeps the network and never the host: {rendered}"
            );
        }
        assert!(
            flushed
                .iter()
                .all(|record| record.peer.as_deref() == Some("203.0.113.0/24")),
            "both records carry the same redacted label, which is the record's job"
        );
    }

    /// AF-8. The throttle lasts the window an operator configured and not a moment longer, so
    /// a source that stops is not held past its span.
    #[test]
    fn a_throttle_expires_with_its_window() {
        let ledger = AuthAttemptLedger::new();
        let now = Instant::now();
        let peer = source(113);

        for _ in 0..20 {
            ledger.record(Some(&peer), "static", "unknown_credential", now);
        }
        assert!(ledger.should_throttle(Some(&peer), 20, WINDOW, now));
        assert!(
            !ledger.should_throttle(Some(&peer), 20, WINDOW, now + WINDOW),
            "a stale window must not extend a throttle past its configured span"
        );
    }

    /// AF-8. Below the threshold nothing is throttled, so an ordinary run of typos still
    /// reaches the credential check.
    #[test]
    fn attempts_below_the_threshold_are_not_throttled() {
        let ledger = AuthAttemptLedger::new();
        let now = Instant::now();
        let peer = source(113);

        for _ in 0..19 {
            ledger.record(Some(&peer), "static", "unknown_credential", now);
        }
        assert!(!ledger.should_throttle(Some(&peer), 20, WINDOW, now));
    }

    /// AF-4. There is no way to get attacker bytes into a record, because the reason and the
    /// credential path are `&'static str` and the source is redacted before it arrives.
    #[test]
    fn nothing_a_caller_controls_reaches_the_record() {
        let ledger = AuthAttemptLedger::new();
        let peer = PeerSource::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)));
        let now = Instant::now();

        ledger.record(Some(&peer), "oauth", "malformed", now);
        let flushed = ledger.flush_expired(now + WINDOW);
        let rendered = serde_json::to_string(&flushed[0]).expect("serialize");

        assert!(!rendered.contains("203.0.113.42"), "{rendered}");
        assert!(rendered.contains("203.0.113.0/24"), "{rendered}");
        assert!(!rendered.contains("agent_id"), "{rendered}");
    }
}
