//! Link-change monitor — detect a host network-path change (Wi-Fi switch, sleep/wake, an IP or
//! interface coming/going) and tell the engine to re-bind (Go `tailscaled`'s `net/netmon` link
//! monitor → magicsock `Rebind`).
//!
//! ## Why poll, not netlink/route-socket
//!
//! Go subscribes to OS link events (`RTMGRP_LINK` on Linux, `PF_ROUTE` on macOS). We deliberately
//! use a **periodic interface-address poll** instead: it is portable across Linux/macOS with no
//! platform-specific socket code, and a network change that matters to magicsock (a different set of
//! usable local addresses) is exactly what an address snapshot captures. The cost is up to one
//! [`POLL_INTERVAL`] of latency before a rebind — fine for the "laptop changed networks" case, where
//! the connection was already disrupted and a few seconds to re-home is acceptable.
//!
//! ## What is (and isn't) the signal
//!
//! The signal is the set of the host's **non-loopback, non-link-local** interface IPs (a
//! [`LinkSnapshot`]). When that set changes between polls — a new Wi-Fi IP appears, the old one goes
//! away, an interface drops — [`LinkSnapshot::changed`] is true and the daemon calls
//! [`Device::rebind`](tailscale::Device::rebind). Loopback and IPv6 link-local (`fe80::/10`) are
//! filtered out: they are present on every interface state and would add noise without signalling a
//! real path change. The pure [`changed`](LinkSnapshot::changed) decision is unit-tested; the live
//! rebind it drives is exercised by the gated e2e.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

/// How often the monitor re-snapshots the host's interface addresses. A change is acted on within
/// one interval. 5s balances responsiveness (re-home a few seconds after a network switch) against
/// the cost of an `if-addrs` enumeration (cheap, but not free to do in a tight loop).
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// A canonical snapshot of the host's usable local interface addresses — the signal the monitor
/// diffs to decide whether the network path changed. A [`BTreeSet`] so equality/comparison is
/// order-independent and cheap, and so the snapshot is deterministic regardless of enumeration order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkSnapshot {
    addrs: BTreeSet<IpAddr>,
}

impl LinkSnapshot {
    /// Build a snapshot from an iterator of interface IPs, applying the same noise filter the live
    /// [`snapshot`] uses: drop loopback and IPv6 link-local (`fe80::/10`) addresses, which are
    /// present in every interface state and do not signal a real path change. Pure → unit-testable
    /// without touching the OS.
    pub fn from_addrs(addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        let addrs = addrs.into_iter().filter(is_path_relevant).collect();
        Self { addrs }
    }

    /// Whether the network path changed since `self` — i.e. the usable-address set differs. The
    /// monitor rebinds exactly when this is true. Pure.
    pub fn changed(&self, other: &LinkSnapshot) -> bool {
        self.addrs != other.addrs
    }
}

/// Whether an interface address is a real *underlay* network-path signal: not loopback, not IPv6
/// link-local, and **not our own tailnet address**. (IPv4 link-local `169.254/16` is left in — a
/// DHCP-failure APIPA address is still a host-path state worth reacting to.)
///
/// The tailnet address (CGNAT `100.64.0.0/10`, ULA `fd7a:115c:a1e0::/48`) is excluded deliberately:
/// it is the engine's OWN overlay address, which comes/goes as a *consequence* of the engine's state
/// (bring-up, the engine's own rebind), not a cause of a host network change. Including it would let
/// a tailnet-IP flap drive a spurious (though non-disruptive) rebind and muddy the "host path changed"
/// log signal. We want only the underlay — the physical interfaces the engine binds its sockets to.
fn is_path_relevant(addr: &IpAddr) -> bool {
    if addr.is_loopback() {
        return false;
    }
    match addr {
        // IPv6 link-local (`fe80::/10`) is per-interface housekeeping, not a routable path signal.
        IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80 => false,
        // Our own tailnet overlay address — a consequence of engine state, not a host-path change.
        // CGNAT 100.64.0.0/10: first octet 100, second octet's top 2 bits == 0b01 (64..=127).
        IpAddr::V4(v4) if v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40 => false,
        // Tailscale ULA fd7a:115c:a1e0::/48.
        IpAddr::V6(v6) if v6.segments()[0] == 0xfd7a && v6.segments()[1] == 0x115c => false,
        _ => true,
    }
}

/// Snapshot the host's current interface addresses (the live [`LinkSnapshot::from_addrs`] source).
/// On a failure to enumerate interfaces, returns an empty snapshot + logs — an enumeration error
/// must not crash the monitor; the next poll retries, and an empty-vs-nonempty transition simply
/// reads as a change (a conservative rebind, not a missed one).
pub fn snapshot() -> LinkSnapshot {
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => LinkSnapshot::from_addrs(ifaces.into_iter().map(|i| i.ip())),
        Err(e) => {
            tracing::warn!(error = %e, "linkmon: failed to enumerate interfaces; treating as empty snapshot");
            LinkSnapshot::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn identical_snapshots_do_not_change() {
        let a = LinkSnapshot::from_addrs([v4(192, 168, 1, 5), v4(10, 0, 0, 2)]);
        let b = LinkSnapshot::from_addrs([v4(10, 0, 0, 2), v4(192, 168, 1, 5)]); // different order
        assert!(
            !a.changed(&b),
            "same addr set (any order) must not be a change"
        );
    }

    #[test]
    fn added_removed_or_changed_addr_is_a_change() {
        let base = LinkSnapshot::from_addrs([v4(192, 168, 1, 5)]);
        // Added.
        assert!(base.changed(&LinkSnapshot::from_addrs([
            v4(192, 168, 1, 5),
            v4(10, 0, 0, 9)
        ])));
        // Removed (→ empty).
        assert!(base.changed(&LinkSnapshot::default()));
        // Changed (the Wi-Fi IP moved).
        assert!(base.changed(&LinkSnapshot::from_addrs([v4(192, 168, 1, 6)])));
    }

    #[test]
    fn loopback_and_v6_link_local_are_filtered_noise() {
        // A snapshot that differs ONLY by loopback / v6-link-local entries is NOT a change.
        let real = LinkSnapshot::from_addrs([v4(192, 168, 1, 5)]);
        let with_noise = LinkSnapshot::from_addrs([
            v4(192, 168, 1, 5),
            v4(127, 0, 0, 1),                                       // loopback
            IpAddr::V6(Ipv6Addr::LOCALHOST),                        // ::1 loopback
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), // link-local
        ]);
        assert!(
            !real.changed(&with_noise),
            "loopback + v6 link-local must be filtered, so they don't trigger a spurious rebind"
        );
    }

    #[test]
    fn own_tailnet_address_is_filtered() {
        // The node's own overlay address (100.64/10 CGNAT, fd7a:115c:a1e0::/48 ULA) is a consequence
        // of engine state, not an underlay path change — so it must not be in the snapshot, and a
        // tailnet-IP-only difference must not be a change.
        let underlay = LinkSnapshot::from_addrs([v4(192, 168, 1, 5)]);
        let with_tailnet = LinkSnapshot::from_addrs([
            v4(192, 168, 1, 5),
            v4(100, 64, 0, 7),  // CGNAT tailnet IP
            v4(100, 127, 0, 1), // still 100.64/10 (second octet 127 → top bits 0b01)
            IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1)), // tailnet ULA
        ]);
        assert!(
            !underlay.changed(&with_tailnet),
            "the node's own tailnet address must be filtered from the path signal"
        );
        // But a real public/private underlay IP at 100.x that is NOT in 100.64/10 is kept (e.g.
        // 100.128.0.1 → second octet's top bits 0b10, outside CGNAT).
        let with_real_100 = LinkSnapshot::from_addrs([v4(192, 168, 1, 5), v4(100, 128, 0, 1)]);
        assert!(
            underlay.changed(&with_real_100),
            "a non-CGNAT 100.x address is a real underlay addr and must count"
        );
    }

    #[test]
    fn empty_to_nonempty_is_a_change() {
        let empty = LinkSnapshot::default();
        assert!(empty.changed(&LinkSnapshot::from_addrs([v4(192, 168, 1, 5)])));
        assert!(LinkSnapshot::from_addrs([v4(192, 168, 1, 5)]).changed(&empty));
    }

    #[test]
    fn live_snapshot_does_not_panic() {
        // Smoke test: enumerating the test host's interfaces returns a snapshot without panicking
        // (the result content is host-dependent, so only the no-panic + total-fn contract is asserted).
        let _ = snapshot();
    }
}
