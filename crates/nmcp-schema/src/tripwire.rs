//! The exfiltration tripwire: literal detection of an injected value in a byte surface, and
//! the redacted form that replaces it.
//!
//! NMCP-SPEC-002 SB-9, RATIFIED v1.1. A detector, not the boundary: the boundary is SB-6
//! bindings, and this is the post-effect scan that catches an armed value that reached an
//! agent-visible surface anyway. What it does is narrow and stated plainly: given the set of
//! active injected values for one request and a byte surface, it finds **literal** occurrences
//! of each value and produces the redacted surface, replacing every occurrence with
//! [`redaction_marker`]'s `[nmcp:redacted/<name>]`.
//!
//! ## Why the scanner lives in `nmcp-schema`
//!
//! Two crates scan for a request's injected values, and they are the ring at NMCP-SPEC-003
//! stage 8 ([`nmcp-router`]) and the `env` modality's output path ([`nmcp-exec`]). The scanner
//! has to be reachable from both without a new heavy edge, and `nmcp-schema` is the one crate
//! both already depend on: `nmcp-router -> nmcp-schema` and `nmcp-exec -> nmcp-schema` are
//! established edges (I-034). It also needs the sealed carrier's scoped exposure, and
//! [`SealedSecret`] with its `with_exposed` closure lives here, so the scanner compares against
//! material without ever copying the plaintext into a field of its own: every needle is read
//! transiently inside `with_exposed` and never outlives the comparison. Putting the scanner in
//! `nmcp-secrets` instead would force `nmcp-exec -> nmcp-secrets`, a new edge to a crate
//! `nmcp-exec` deliberately does not depend on (it takes only the carrier from `nmcp-schema`),
//! and `nmcp-secrets` cannot be reached from the ring's `nmcp-exec` sibling at all. The arming
//! floor's home stays in `nmcp-secrets` store configuration (SB-9, section 8 item 2); this
//! module applies the floor it is handed and does not own it, which keeps the configured policy
//! value and the mechanism that reads it in separate crates on purpose.
//!
//! No heavy dependencies: the search is a literal byte scan over `std` and `serde_json`, both
//! of which this crate already carries.
//!
//! ## Literal match only, and what that concedes (SB-A5)
//!
//! The scan is byte-for-byte. It does not decode base64, url-encoding, JSON string escapes,
//! gzip or any other transform, and it does not reassemble a value split across two surfaces or
//! two reads. SB-A5 concedes the encoding class by design and SB-9 names the specific evasions:
//! an agent that base64s a value defeats the scan, a value straddling a stream read boundary is
//! not seen, and the process exit code is a one-bit channel this never touches. The detector's
//! job is the direct leak, the value appearing verbatim in output, which is the case an
//! allowlisted echo produces; the encoded cases are the residual SB-A5 accepts and section 7
//! G-4 names. One consequence worth stating where the scanner lives: when the surface is JSON,
//! the ring redacts the **unescaped** string leaves (see [`SecretTripwire::redact_json`]), so a
//! value carrying a quote, which JSON would escape in its serialized form, is still caught in
//! the leaf rather than missed for its escaping; the literal-only limit bites on transforms the
//! value itself underwent, not on the container's own encoding of an unaltered value.
//!
//! ## The confirmation oracle (SB-A5, T13)
//!
//! The redaction marker is agent-visible, so a miss and a hit are distinguishable: an agent
//! that can make an allowlisted program emit attacker-chosen bytes learns whether the secret is
//! exactly those bytes, and the marker names the key. A miss costs nothing observable; a hit is
//! one-shot, because the ring's on-trip policy suspends the key (SB-9, section 8 item 1), so a
//! low-entropy value is recoverable in at most one confirmed guess. That is the argument for the
//! arming floor and for auto-suspend being the default, and it is a cost of detection rather than
//! a defect in it (T13). This module supplies the marker and the arming; the one-shot bound is
//! the ring's, where the suspension is applied.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::secrets::SealedSecret;

/// The default arming floor, in bytes (NMCP-SPEC-002 section 8 item 2).
///
/// A value shorter than the floor does not arm the tripwire for that key: it still resolves and
/// injects, but detection is off, because a short or common value trips on unrelated output and,
/// under the auto-suspend default, would suspend the operator's own credential on a false
/// positive (T14). Sixteen sits above the range where accidental collisions live and below every
/// real credential format in use. The floor's home is store configuration, not this constant;
/// this is the default the store starts at, quoted here so a caller with no store can arm the
/// scanner the same way the store would.
pub const DEFAULT_TRIPWIRE_FLOOR: usize = 16;

/// The leading bytes of every redaction marker, for a reader that wants to recognise one.
pub const REDACTION_MARKER_PREFIX: &str = "[nmcp:redacted/";

/// The marker one occurrence of an injected value is replaced with (SB-9).
///
/// `[nmcp:redacted/<name>]`, where `<name>` is what the scanning surface calls the value: the
/// key name at the ring, the injected variable name at the exec output path. Every character is
/// ASCII and none needs JSON escaping, so replacing a value inside a serialized JSON string with
/// this keeps the JSON valid, which is what lets the ring redact a serialized result in place.
#[must_use]
pub fn redaction_marker(name: &str) -> String {
    format!("{REDACTION_MARKER_PREFIX}{name}]")
}

/// One value the tripwire watches for, paired with the name its marker carries.
struct Target {
    /// What `[nmcp:redacted/<name>]` names for this value.
    name: String,
    /// The sealed material, read transiently through `with_exposed` and never copied out.
    value: SealedSecret,
}

/// A request's armed injected values and the literal scan over a byte surface.
///
/// Built from the set of active injected values for one request and an arming floor
/// ([`SecretTripwire::armed`]); a value below the floor is dropped at construction, which is
/// where "detection is off for a short value" becomes a property of the type rather than a check
/// each scan repeats. The material never leaves a [`SealedSecret`]: each needle is read inside
/// `with_exposed` for the duration of one scan and is gone when the scan returns.
pub struct SecretTripwire {
    targets: Vec<Target>,
}

impl SecretTripwire {
    /// Arm the tripwire over `values`, keeping only those at or above `floor` bytes.
    ///
    /// A value shorter than `floor`, or empty, is not armed: it is dropped here, so nothing
    /// downstream scans for it and a short value passes through every surface unredacted, which
    /// is SB-9's "false positives do not suspend" made structural (T14). `floor` is the store's
    /// configured value, handed in rather than read here; the module documentation argues why
    /// the floor's home is `nmcp-secrets` and the mechanism is here.
    ///
    /// Each pair is `(marker name, value)`. The marker name is what the caller wants
    /// `[nmcp:redacted/<name>]` to read for this value: the ring passes the key name, the exec
    /// output path passes the injected variable name.
    #[must_use]
    pub fn armed(floor: usize, values: impl IntoIterator<Item = (String, SealedSecret)>) -> Self {
        let targets = values
            .into_iter()
            .filter(|(_, value)| {
                let len = value.with_exposed(<[u8]>::len);
                len >= floor && len > 0
            })
            .map(|(name, value)| Target { name, value })
            .collect();
        Self { targets }
    }

    /// Whether nothing is armed, so a scan is a guaranteed pass-through.
    ///
    /// `true` for a request whose tool declared no slot, and for one all of whose injected
    /// values fell below the floor. A caller checks this to skip the scan entirely rather than
    /// walk a surface for no targets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Scan a text surface, returning the redacted text and the marker names that occurred.
    ///
    /// A value that is not valid UTF-8 cannot appear in a `&str` and so never matches here and
    /// never hits; a value that is valid UTF-8 is replaced at every occurrence. This is the
    /// surface a JSON string leaf presents, which is why [`SecretTripwire::redact_json`] is
    /// built on it.
    #[must_use]
    pub fn scan_text(&self, surface: &str) -> TripwireScan<String> {
        let mut redacted = surface.to_string();
        let mut hits = BTreeSet::new();
        for target in &self.targets {
            target.value.with_exposed(|needle| {
                if let Ok(needle) = std::str::from_utf8(needle)
                    && !needle.is_empty()
                    && redacted.contains(needle)
                {
                    redacted = redacted.replace(needle, &redaction_marker(&target.name));
                    hits.insert(target.name.clone());
                }
            });
        }
        TripwireScan { redacted, hits }
    }

    /// Scan a raw byte surface, returning the redacted bytes and the marker names that occurred.
    ///
    /// The surface the exec output path presents: captured stdout and stderr are bytes, and a
    /// persisted log is bytes, neither guaranteed to be valid UTF-8. A value is matched and
    /// replaced byte for byte, so a non-UTF-8 value is caught here where [`scan_text`] would not
    /// see it.
    ///
    /// [`scan_text`]: SecretTripwire::scan_text
    #[must_use]
    pub fn scan_bytes(&self, surface: &[u8]) -> TripwireScan<Vec<u8>> {
        let mut redacted = surface.to_vec();
        let mut hits = BTreeSet::new();
        for target in &self.targets {
            target.value.with_exposed(|needle| {
                let (next, hit) =
                    replace_all(&redacted, needle, redaction_marker(&target.name).as_bytes());
                if hit {
                    redacted = next;
                    hits.insert(target.name.clone());
                }
            });
        }
        TripwireScan { redacted, hits }
    }

    /// Redact every string leaf of a JSON value in place, returning the marker names that hit.
    ///
    /// The ring's surface: the full serialized tool result is a JSON tree, and a value can only
    /// reach a caller through a string leaf. Walking the leaves and applying [`scan_text`] to
    /// each redacts the whole payload, not one stdout field, which is SB-9's scope correction.
    /// It also catches a value the container would have escaped in its serialized form, because
    /// a leaf is the unescaped string; the module documentation states why that is the right
    /// reading of "literal match" for a JSON container.
    ///
    /// [`scan_text`]: SecretTripwire::scan_text
    pub fn redact_json(&self, value: &mut Value) -> BTreeSet<String> {
        let mut hits = BTreeSet::new();
        self.redact_value(value, &mut hits);
        hits
    }

    /// The recursion behind [`SecretTripwire::redact_json`].
    fn redact_value(&self, value: &mut Value, hits: &mut BTreeSet<String>) {
        match value {
            Value::String(text) => {
                let scan = self.scan_text(text);
                if !scan.hits.is_empty() {
                    *text = scan.redacted;
                    hits.extend(scan.hits);
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.redact_value(item, hits);
                }
            }
            Value::Object(entries) => {
                for entry in entries.values_mut() {
                    self.redact_value(entry, hits);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
}

/// A scan's result: the redacted surface, and the marker names that occurred in it.
///
/// `hits` is a set because one value can appear many times but names its key once, and because
/// the caller acts once per key: the ring audits and applies the on-trip policy per hit name,
/// not per occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TripwireScan<T> {
    /// The surface with every occurrence replaced by its marker.
    pub redacted: T,
    /// The marker names whose value occurred at least once.
    pub hits: BTreeSet<String>,
}

/// Replace every non-overlapping occurrence of `needle` in `haystack` with `repl`.
///
/// Returns the rewritten bytes and whether anything was replaced. An empty needle matches
/// nothing, which is the guard that keeps an unarmed-length value (impossible past
/// [`SecretTripwire::armed`], belt and braces here) from looping.
fn replace_all(haystack: &[u8], needle: &[u8], repl: &[u8]) -> (Vec<u8>, bool) {
    if needle.is_empty() {
        return (haystack.to_vec(), false);
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut rest = haystack;
    let mut hit = false;
    while let Some(at) = find_subslice(rest, needle) {
        let (before, from_match) = rest.split_at(at);
        out.extend_from_slice(before);
        out.extend_from_slice(repl);
        rest = from_match.get(needle.len()..).unwrap_or(&[]);
        hit = true;
    }
    out.extend_from_slice(rest);
    (out, hit)
}

/// The first index at which `needle` occurs in `haystack`, or `None`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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
    use super::{DEFAULT_TRIPWIRE_FLOOR, SecretTripwire, redaction_marker};
    use crate::secrets::SealedSecret;
    use serde_json::json;

    /// Distinctive material with no English substring, above the default floor, so the leak
    /// assertions cannot collide with legitimate prose.
    const MATERIAL: &[u8] = b"qx7ve-2wkzn-8rjt4-pm9hd";

    fn armed(name: &str, value: &[u8]) -> SecretTripwire {
        SecretTripwire::armed(
            DEFAULT_TRIPWIRE_FLOOR,
            [(name.to_string(), SealedSecret::new(value.to_vec()))],
        )
    }

    #[test]
    fn a_value_at_or_above_the_floor_arms_and_a_short_one_does_not() {
        assert!(!armed("deploy.db", MATERIAL).is_empty());
        // Fifteen bytes, one below the default floor: not armed, so every scan is a
        // pass-through and the short value is never redacted (T14).
        let short = SecretTripwire::armed(
            DEFAULT_TRIPWIRE_FLOOR,
            [(
                "pin".to_string(),
                SealedSecret::new(b"012345678901234".to_vec()),
            )],
        );
        assert!(short.is_empty());
        let scan = short.scan_text("the value 012345678901234 is here");
        assert_eq!(scan.redacted, "the value 012345678901234 is here");
        assert!(scan.hits.is_empty());
    }

    #[test]
    fn a_text_hit_is_redacted_and_named() {
        let tripwire = armed("deploy.db", MATERIAL);
        let surface = format!("prefix {} suffix", String::from_utf8_lossy(MATERIAL));
        let scan = tripwire.scan_text(&surface);
        assert_eq!(scan.redacted, "prefix [nmcp:redacted/deploy.db] suffix");
        assert!(scan.hits.contains("deploy.db"));
        // The measurement discipline: no byte window of the material survives (SB-1).
        let material = String::from_utf8_lossy(MATERIAL);
        assert!(!scan.redacted.contains(material.as_ref()));
    }

    #[test]
    fn a_miss_costs_nothing_and_the_surface_is_unchanged() {
        let tripwire = armed("deploy.db", MATERIAL);
        let scan = tripwire.scan_text("nothing to see here");
        assert_eq!(scan.redacted, "nothing to see here");
        assert!(scan.hits.is_empty());
    }

    #[test]
    fn every_occurrence_is_replaced_in_bytes() {
        let tripwire = armed("deploy.db", MATERIAL);
        let mut surface = Vec::new();
        surface.extend_from_slice(MATERIAL);
        surface.extend_from_slice(b" and again ");
        surface.extend_from_slice(MATERIAL);
        let scan = tripwire.scan_bytes(&surface);
        let expected = format!(
            "{marker} and again {marker}",
            marker = redaction_marker("deploy.db")
        );
        assert_eq!(scan.redacted, expected.into_bytes());
        assert!(scan.hits.contains("deploy.db"));
        // No byte window of the material survives in the redacted bytes.
        assert!(
            !scan
                .redacted
                .windows(MATERIAL.len())
                .any(|window| window == MATERIAL)
        );
    }

    #[test]
    fn json_leaves_are_redacted_in_place_including_escaped_values() {
        // A value carrying a quote, which JSON would escape in its serialized form. Walking
        // the unescaped leaf catches it where a scan of the serialized bytes would miss it.
        let value = b"ab\"cd-2wkzn-8rjt4-pm9hd";
        let tripwire = armed("deploy.db", value);
        let mut result = json!({
            "content": [{"type": "text", "text": format!("secret is {}", String::from_utf8_lossy(value))}],
            "nested": {"redacted_env": {"DATABASE_URL": "<redacted>"}},
        });
        let hits = tripwire.redact_json(&mut result);
        assert!(hits.contains("deploy.db"));
        let rendered = serde_json::to_string(&result).unwrap();
        assert!(rendered.contains("[nmcp:redacted/deploy.db]"));
        assert!(!rendered.contains("ab\\\"cd-2wkzn-8rjt4-pm9hd"));
        assert!(!rendered.contains("ab\"cd-2wkzn-8rjt4-pm9hd"));
    }

    #[test]
    fn a_non_utf8_value_hits_bytes_but_not_text() {
        // Eighteen bytes, above the floor, and not valid UTF-8 (the leading 0xFF/0xFE).
        let value: &[u8] = &[
            0xFF, 0xFE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            0x0D, 0x0E, 0x0F, 0x10,
        ];
        let tripwire = armed("blob.key", value);
        let mut surface = b"lead ".to_vec();
        surface.extend_from_slice(value);
        let scan = tripwire.scan_bytes(&surface);
        assert!(scan.hits.contains("blob.key"));
        // The same bytes as a lossy string never match, because the value is not UTF-8.
        let text = String::from_utf8_lossy(&surface).to_string();
        let text_scan = tripwire.scan_text(&text);
        assert!(text_scan.hits.is_empty());
    }

    #[test]
    fn two_values_redact_independently_and_only_the_present_one_hits() {
        let tripwire = SecretTripwire::armed(
            DEFAULT_TRIPWIRE_FLOOR,
            [
                (
                    "deploy.db".to_string(),
                    SealedSecret::new(MATERIAL.to_vec()),
                ),
                (
                    "other.key".to_string(),
                    SealedSecret::new(b"absent-9qz2-vk7x-value".to_vec()),
                ),
            ],
        );
        let surface = format!("only {} appears", String::from_utf8_lossy(MATERIAL));
        let scan = tripwire.scan_text(&surface);
        assert_eq!(scan.redacted, "only [nmcp:redacted/deploy.db] appears");
        assert!(scan.hits.contains("deploy.db"));
        assert!(!scan.hits.contains("other.key"));
    }
}
