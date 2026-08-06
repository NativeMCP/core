//! Where a request came from, at two different resolutions (G3-13, AF-5).
//!
//! The throttle and the audit record want the same input for different jobs with different
//! bounds, and conflating them gets one of them wrong.
//!
//! Throttling needs to distinguish sources precisely. Throttling coarsely means one attacker
//! behind a shared prefix locks out every legitimate client behind it, which is the failure
//! mode that matters, because an attacker being slowed is the point and a paying customer
//! being locked out is an outage. So [`PeerSource`] holds the full address, in memory, and is
//! never written anywhere.
//!
//! The base said all of that and then keyed the throttle on the redacted form anyway, so
//! `PeerSource`'s full-precision `Eq` and `Hash` had no reader. Finding F-3. Every client
//! behind one office NAT shared a throttle bucket, which means one user mistyping a token
//! enough times refused their whole building. `auth_attempts::SourceKey` is the separation:
//! it is the identity, and its `label` is the only thing that reaches a record.
//!
//! The audit record needs enough to investigate and no more. A peer address is personal data,
//! this service keeps its records permanently by design, and the record is readable by anyone
//! with the log. So [`PeerSource::redacted`] truncates: three octets of IPv4, the first 64
//! bits of IPv6, and the literal `loopback` for a loopback caller.
//!
//! That truncation is also what makes the local-or-remote question answerable at all, which is
//! AF-7. `loopback` versus anything else is exactly that question.

// Every caller of this module outside its own tests is a lane's authentication path, and
// the lanes are I-075. Its own test module uses all of it, so `expect` cannot express this:
// the lint fires in the lib target and not in the lib-test target, and an unfulfilled
// expectation in one of them is an error either way. The self-clearing enforcement point is
// the single `expect(dead_code)` on `AppState::auth_attempts`, which is dead in both
// targets and stops applying the moment a lane calls it. Removing that one removes the
// reason for these.
#![allow(
    dead_code,
    reason = "the peer resolution's consumers are the three lanes, which land in I-075"
)]

use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// A caller's network origin, at full resolution.
///
/// Compared and hashed by address only, never by port: a port changes per connection and
/// keying a throttle on it would mean an attacker escapes the throttle by reconnecting, which
/// is the one thing every attacker does anyway.
///
/// `Ord` so this can be the throttle's map key directly. It is derived from `IpAddr`'s own
/// ordering and carries no meaning beyond giving the map a total order; nothing reads the
/// relation. Before I-073 the key was the redacted string and this full-precision identity
/// had no reader at all, which is finding F-3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PeerSource(IpAddr);

impl PeerSource {
    /// Test-only. Production builds one from a `SocketAddr` through [`From`], because that is
    /// the only place a peer address legitimately comes from: a connection.
    #[cfg(test)]
    pub(crate) fn new(addr: IpAddr) -> Self {
        Self(addr)
    }

    /// Whether this caller reached the daemon over loopback.
    ///
    /// The one distinction an operator most needs from a record, and the reason the redacted
    /// form keeps it as a name rather than as a truncated address.
    pub(crate) fn is_loopback(&self) -> bool {
        self.0.is_loopback()
    }

    /// The form that may be written down.
    ///
    /// Never the full address. See the module doc: this goes into a permanent, widely readable
    /// record, and the investigative value of "which network" survives truncation while the
    /// ability to identify one person's machine does not.
    pub(crate) fn redacted(&self) -> String {
        if self.is_loopback() {
            return "loopback".to_string();
        }
        match self.0 {
            // Three octets. Enough to say which network, not which host.
            IpAddr::V4(v4) => {
                let [a, b, c, _] = v4.octets();
                format!("{a}.{b}.{c}.0/24")
            }
            // The routing prefix. A v6 interface identifier is frequently derived from a MAC
            // address or is a stable per-host value, so the low 64 bits are the identifying
            // half and are exactly what must not be kept.
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                format!(
                    "{:x}:{:x}:{:x}:{:x}::/64",
                    segments[0], segments[1], segments[2], segments[3]
                )
            }
        }
    }
}

impl From<SocketAddr> for PeerSource {
    fn from(addr: SocketAddr) -> Self {
        Self(addr.ip())
    }
}

impl fmt::Display for PeerSource {
    /// Deliberately the redacted form.
    ///
    /// `Display` is what a format string reaches for, and a format string is how the full
    /// address would end up in a log by accident. The full address is reachable only through
    /// the field, which nothing outside the throttle reads.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// AF-5. The record keeps which network, never which host.
    #[test]
    fn a_v4_source_is_truncated_to_its_network() {
        let peer = PeerSource::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)));
        assert_eq!(peer.redacted(), "203.0.113.0/24");
        assert!(!peer.redacted().contains("42"));
    }

    /// AF-5. A v6 interface identifier is often derived from a MAC address or is otherwise a
    /// stable per-host value, so the low 64 bits are the identifying half.
    #[test]
    fn a_v6_source_keeps_the_routing_prefix_and_drops_the_interface_identifier() {
        let peer = PeerSource::new(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0xdead, 0xbeef, 0xfeed, 0xface, 0xcafe, 0xf00d,
        )));
        assert_eq!(peer.redacted(), "2001:db8:dead:beef::/64");
        for identifying in ["feed", "face", "cafe", "f00d"] {
            assert!(
                !peer.redacted().contains(identifying),
                "the interface identifier must not survive: {}",
                peer.redacted()
            );
        }
    }

    /// AF-5 and AF-7. Local or remote is the question an operator asks first, and it survives
    /// redaction as a name rather than as an address.
    #[test]
    fn a_loopback_caller_is_named_rather_than_truncated() {
        for addr in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let peer = PeerSource::new(addr);
            assert!(peer.is_loopback());
            assert_eq!(peer.redacted(), "loopback");
        }
    }

    /// AF-5. `Display` is what a format string reaches for, so it has to be the safe form or
    /// the full address reaches a log the first time somebody interpolates one.
    #[test]
    fn display_is_the_redacted_form_so_a_format_string_cannot_leak_the_address() {
        let peer = PeerSource::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
        assert_eq!(format!("{peer}"), "198.51.100.0/24");
        assert!(!format!("{peer}").ends_with(".7"));
    }

    /// The throttle keys on this, and a port changes per connection. Keying on the port would
    /// mean an attacker leaves the throttle behind by reconnecting.
    #[test]
    fn two_connections_from_one_host_are_one_source_whatever_their_ports() {
        let first: PeerSource = "203.0.113.42:51000".parse::<SocketAddr>().unwrap().into();
        let second: PeerSource = "203.0.113.42:51001".parse::<SocketAddr>().unwrap().into();
        assert_eq!(first, second);

        let other: PeerSource = "203.0.113.43:51000".parse::<SocketAddr>().unwrap().into();
        assert_ne!(first, other, "a different host is a different source");
    }
}
