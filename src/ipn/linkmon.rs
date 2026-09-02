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

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Duration;

/// How often the monitor re-snapshots the host's interface addresses. A change is acted on within
/// one interval. 5s balances responsiveness (re-home a few seconds after a network switch) against
/// the cost of an `if-addrs` enumeration (cheap, but not free to do in a tight loop).
pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// A canonical snapshot of the host's usable local interface addresses — the signal the monitor
/// diffs to decide whether the network path changed. A [`BTreeSet`] so equality/comparison is
/// order-independent and cheap, and so the snapshot is deterministic regardless of enumeration order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct LinkSnapshot {
    addrs: BTreeSet<IpAddr>,
}

impl LinkSnapshot {
    /// Build a snapshot from an iterator of interface IPs, applying the same noise filter the live
    /// [`snapshot`] uses: drop loopback and IPv6 link-local (`fe80::/10`) addresses, which are
    /// present in every interface state and do not signal a real path change. Pure → unit-testable
    /// without touching the OS.
    pub(super) fn from_addrs(addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        let addrs = addrs.into_iter().filter(is_path_relevant).collect();
        Self { addrs }
    }

    /// Whether the network path changed since `self` — i.e. the usable-address set differs. The
    /// monitor rebinds exactly when this is true. Pure.
    pub(super) fn changed(&self, other: &LinkSnapshot) -> bool {
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
        // Tailscale ULA fd7a:115c:a1e0::/48 — match the full /48 prefix (all three leading
        // segments), not just /32, so an unrelated underlay ULA in fd7a:115c::/32 isn't over-filtered.
        IpAddr::V6(v6)
            if v6.segments()[0] == 0xfd7a
                && v6.segments()[1] == 0x115c
                && v6.segments()[2] == 0xa1e0 =>
        {
            false
        }
        _ => true,
    }
}

/// Snapshot the host's current interface addresses (the live [`LinkSnapshot::from_addrs`] source).
/// On a failure to enumerate interfaces, returns an empty snapshot + logs — an enumeration error
/// must not crash the monitor; the next poll retries, and an empty-vs-nonempty transition simply
/// reads as a change (a conservative rebind, not a missed one).
pub(super) fn snapshot() -> LinkSnapshot {
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => LinkSnapshot::from_addrs(ifaces.into_iter().map(|i| i.ip())),
        Err(e) => {
            tracing::warn!(error = %e, "linkmon: failed to enumerate interfaces; treating as empty snapshot");
            LinkSnapshot::default()
        }
    }
}

// ---------------------------------------------------------------------------------------------
// `tailnetd debug --ifconfig` / `--monitor`: rendering the host's network state.
//
// Go's daemon-side debug subcommand (`cmd/tailscaled/debug.go`, `runMonitor`) dumps a
// `net/netmon.State` as indented JSON and — with `--monitor` — re-dumps it on every link change.
// `netmon.State` is the *whole* interface picture, not the filtered path signal the monitor diffs,
// so the two are rendered together here: `InterfaceIPs`/`Interface` are every address the host has,
// while `PathRelevantIPs` is the subset [`is_path_relevant`] keeps — i.e. exactly what a rebind
// decision is made on. Seeing both at once is the point of the dump: "the address is there but it
// was filtered out" and "the address is not there at all" are different faults.
// ---------------------------------------------------------------------------------------------

/// One interface address as [`NetworkState::from_interfaces`] consumes it: the OS facts the renderer
/// needs, decoupled from `if_addrs` so the renderer stays pure (and therefore unit-testable on a
/// host whose real interfaces are unknown).
#[derive(Debug, Clone)]
pub(crate) struct InterfaceAddr {
    /// Interface name (`en0`, `eth0`, `lo`).
    pub(crate) name: String,
    /// The address itself.
    pub(crate) ip: IpAddr,
    /// CIDR prefix length of the address on that interface.
    pub(crate) prefix_len: u8,
    /// Kernel interface index, when the platform reports one.
    pub(crate) index: Option<u32>,
    /// Whether the interface is operationally up (RFC 2863 `IfOperStatus::Up`).
    pub(crate) oper_up: bool,
    /// Whether the interface is point-to-point (a tunnel/PPP link).
    pub(crate) point_to_point: bool,
}

/// Per-interface metadata in the dump — the analogue of the `Interface` map in Go's `netmon.State`,
/// whose values embed a `net.Interface` (`Index`, `MTU`, `Name`, `HardwareAddr`, `Flags`).
///
/// Only the fields this fork can actually observe are emitted: `if_addrs` reports the name, the
/// index, the operational state and the point-to-point bit, and loopback is a property of the
/// address. MTU and the hardware address are NOT enumerated by `if_addrs`, and `broadcast`/
/// `multicast` are not either — so they are absent rather than guessed. Go serialises `Flags` as the
/// integer `net.Flags` bitmask; here it is the readable list of the flags we can vouch for, which is
/// why this dump is Go-*shaped* rather than byte-identical to Go's.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct InterfaceInfo {
    #[serde(rename = "Index", skip_serializing_if = "Option::is_none")]
    index: Option<u32>,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Flags")]
    flags: Vec<&'static str>,
}

/// The host's network state as `tailnetd debug --ifconfig`/`--monitor` prints it — the port of the
/// `netmon.State` value Go's `runMonitor` dumps.
///
/// Go's field names are kept (`InterfaceIPs`, `Interface`, `HaveV4`, `HaveV6`) so a dump from either
/// daemon reads the same way. Four Go fields are deliberately ABSENT rather than emitted empty:
/// `IsExpensive` (metered-link detection), `DefaultRouteInterface` (a route-table query),
/// `HTTPProxy` and `PAC` (system proxy configuration). This daemon probes none of those, and a
/// present-but-empty `HTTPProxy` would read as "no proxy is configured" — a claim it cannot make.
///
/// `PathRelevantIPs` is the one key with no Go counterpart: the filtered address set the link
/// monitor actually diffs ([`LinkSnapshot`]), included because `--monitor`'s whole job is to explain
/// why a link change did or did not fire.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct NetworkState {
    /// Every address of every interface, `"ip/prefixlen"`, keyed by interface name (Go's
    /// `InterfaceIPs map[string][]netip.Prefix`). Unfiltered — loopback and link-local included.
    #[serde(rename = "InterfaceIPs")]
    interface_ips: BTreeMap<String, Vec<String>>,
    /// Per-interface metadata, keyed by interface name (Go's `Interface map[string]Interface`).
    #[serde(rename = "Interface")]
    interfaces: BTreeMap<String, InterfaceInfo>,
    /// Whether the host has a usable IPv4 path — computed over the FILTERED set, like Go's, so the
    /// node's own tailnet address never makes an offline host look v4-connected.
    #[serde(rename = "HaveV4")]
    have_v4: bool,
    /// Whether the host has a usable IPv6 path (filtered set, as `HaveV4`).
    #[serde(rename = "HaveV6")]
    have_v6: bool,
    /// The path signal the monitor diffs. Not a Go field — see the type docs.
    #[serde(rename = "PathRelevantIPs", serialize_with = "serialize_snapshot")]
    path: LinkSnapshot,
}

/// Serialize a [`LinkSnapshot`] as a plain array of its addresses (it is a newtype over a
/// [`BTreeSet`], so the order is deterministic and a dump diffs cleanly against the previous one).
fn serialize_snapshot<S: serde::Serializer>(
    snapshot: &LinkSnapshot,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(&snapshot.addrs)
}

impl NetworkState {
    /// Render the state from an interface-address list. Pure: the OS is not touched, so a test can
    /// hand it a fabricated host and assert the whole dump.
    ///
    /// Addresses are grouped by interface name. Per-interface facts (index, flags) arrive once per
    /// *address*, so they are MERGED across an interface's addresses — an interface whose second
    /// address happens to be reported without an index must not lose the index its first address
    /// carried, and `loopback` is set when any of the interface's addresses is a loopback address.
    pub(crate) fn from_interfaces(addrs: impl IntoIterator<Item = InterfaceAddr>) -> Self {
        /// Accumulated per-interface flags, materialised into [`InterfaceInfo`] at the end.
        #[derive(Default)]
        struct Acc {
            index: Option<u32>,
            up: bool,
            loopback: bool,
            point_to_point: bool,
        }

        let mut interface_ips: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
        let mut all: Vec<IpAddr> = Vec::new();

        for addr in addrs {
            interface_ips
                .entry(addr.name.clone())
                .or_default()
                .push(format!("{}/{}", addr.ip, addr.prefix_len));
            let entry = acc.entry(addr.name).or_default();
            entry.index = entry.index.or(addr.index);
            entry.up |= addr.oper_up;
            entry.loopback |= addr.ip.is_loopback();
            entry.point_to_point |= addr.point_to_point;
            all.push(addr.ip);
        }

        let interfaces = acc
            .into_iter()
            .map(|(name, a)| {
                let mut flags = Vec::new();
                if a.up {
                    flags.push("up");
                }
                if a.loopback {
                    flags.push("loopback");
                }
                if a.point_to_point {
                    flags.push("pointtopoint");
                }
                (
                    name.clone(),
                    InterfaceInfo {
                        index: a.index,
                        name,
                        flags,
                    },
                )
            })
            .collect();

        // The SAME filter the rebind decision uses — the dump must not disagree with the monitor.
        let path = LinkSnapshot::from_addrs(all);
        Self {
            interface_ips,
            interfaces,
            have_v4: path.addrs.iter().any(IpAddr::is_ipv4),
            have_v6: path.addrs.iter().any(IpAddr::is_ipv6),
            path,
        }
    }

    /// Snapshot the live host (the `--ifconfig`/`--monitor` source). An enumeration failure yields an
    /// EMPTY state plus a warning rather than an error, exactly as [`snapshot`] does: a debug dump
    /// that says "no interfaces" is a usable diagnosis; a monitor that exits on one bad poll is not.
    pub(crate) fn current() -> Self {
        match if_addrs::get_if_addrs() {
            Ok(ifaces) => Self::from_interfaces(ifaces.into_iter().map(|i| InterfaceAddr {
                prefix_len: match &i.addr {
                    if_addrs::IfAddr::V4(v4) => v4.prefixlen,
                    if_addrs::IfAddr::V6(v6) => v6.prefixlen,
                },
                ip: i.ip(),
                index: i.index,
                oper_up: i.is_oper_up(),
                point_to_point: i.is_p2p(),
                name: i.name,
            })),
            Err(e) => {
                tracing::warn!(error = %e, "linkmon: failed to enumerate interfaces; reporting an empty network state");
                Self::from_interfaces([])
            }
        }
    }

    /// The names of the interfaces that reported at least one address, in deterministic order.
    ///
    /// The compact half of the dump: `bugreport --diagnose` prints one line naming the interfaces
    /// and whether the host has a usable path, where `tailnetd debug --ifconfig` prints the whole
    /// JSON state. Both read the same snapshot, so they can never disagree about what the host has.
    pub(crate) fn interface_names(&self) -> Vec<&str> {
        self.interfaces.keys().map(String::as_str).collect()
    }

    /// Whether the host has a usable IPv4 underlay path — the FILTERED answer (see the field docs),
    /// so the node's own overlay address never makes an offline host look connected.
    pub(crate) fn have_v4(&self) -> bool {
        self.have_v4
    }

    /// Whether the host has a usable IPv6 underlay path (filtered, as [`have_v4`](Self::have_v4)).
    pub(crate) fn have_v6(&self) -> bool {
        self.have_v6
    }

    /// Whether the *path signal* differs between two states — the same decision
    /// [`LinkSnapshot::changed`] drives the rebind with, so `--monitor` prints a new state exactly
    /// when the running daemon would have rebound.
    pub(crate) fn path_changed(&self, other: &NetworkState) -> bool {
        self.path.changed(&other.path)
    }

    /// The dump as JSON, indented with FOUR spaces — Go's `json.MarshalIndent(st, "", "    ")`.
    /// Serialization of a plain in-memory tree cannot fail, but a formatter error is still surfaced
    /// as an error string rather than a panic in a diagnostic tool.
    pub(crate) fn to_json(&self) -> String {
        let mut out = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let mut ser = serde_json::Serializer::with_formatter(&mut out, formatter);
        match serde::Serialize::serialize(self, &mut ser) {
            Ok(()) => String::from_utf8_lossy(&out).into_owned(),
            Err(e) => format!("{{\"error\": \"failed to render network state: {e}\"}}"),
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
        // The ULA filter is /48 (fd7a:115c:a1e0::), NOT /32: an unrelated underlay ULA sharing only
        // fd7a:115c::/32 must be KEPT (it's not the tailnet's overlay range).
        let with_other_ula = LinkSnapshot::from_addrs([
            v4(192, 168, 1, 5),
            IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xbeef, 0, 0, 0, 0, 1)),
        ]);
        assert!(
            underlay.changed(&with_other_ula),
            "a /32-but-not-/48 ULA is a real underlay addr and must count (not over-filtered)"
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

    // --- the `tailnetd debug --ifconfig` / `--monitor` renderer -------------------------------
    //
    // `NetworkState` is what Go's `runMonitor` dumps (`netmon.State`), so the properties worth
    // pinning are the ones a diagnosis is read off: every address appears unfiltered, the path
    // signal is the FILTERED set, and the two disagree exactly where the filter says they should.

    fn iface(name: &str, ip: IpAddr, prefix_len: u8) -> InterfaceAddr {
        InterfaceAddr {
            name: name.to_string(),
            ip,
            prefix_len,
            index: Some(3),
            oper_up: true,
            point_to_point: false,
        }
    }

    #[test]
    fn network_state_renders_every_address_but_filters_the_path_signal() {
        let state = NetworkState::from_interfaces([
            iface("en0", v4(192, 0, 2, 5), 24),
            iface(
                "en0",
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                64,
            ),
            iface("lo0", v4(127, 0, 0, 1), 8),
            // The node's own tailnet address: present on the host, filtered from the path signal.
            iface("utun3", v4(100, 64, 0, 7), 32),
        ]);
        let json = state.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

        // Unfiltered: loopback, link-local and the tailnet address are all in `InterfaceIPs`, as
        // `ip/prefixlen` strings keyed by interface (Go's `map[string][]netip.Prefix`).
        assert_eq!(
            parsed["InterfaceIPs"]["en0"],
            serde_json::json!(["192.0.2.5/24", "fe80::1/64"])
        );
        assert_eq!(
            parsed["InterfaceIPs"]["lo0"],
            serde_json::json!(["127.0.0.1/8"])
        );
        assert_eq!(
            parsed["InterfaceIPs"]["utun3"],
            serde_json::json!(["100.64.0.7/32"])
        );

        // Filtered: only the underlay address the monitor would rebind on.
        assert_eq!(parsed["PathRelevantIPs"], serde_json::json!(["192.0.2.5"]));
        // …which is also what HaveV4/HaveV6 are computed over: the v6 link-local does not make this
        // host v6-capable, and the tailnet address does not make an offline host look connected.
        assert_eq!(parsed["HaveV4"], serde_json::json!(true));
        assert_eq!(parsed["HaveV6"], serde_json::json!(false));

        // Per-interface metadata: the index and the flags this fork can actually vouch for.
        assert_eq!(parsed["Interface"]["lo0"]["Name"], serde_json::json!("lo0"));
        assert_eq!(parsed["Interface"]["lo0"]["Index"], serde_json::json!(3));
        assert_eq!(
            parsed["Interface"]["lo0"]["Flags"],
            serde_json::json!(["up", "loopback"]),
            "loopback is a property of the address, so it lands on the interface carrying it"
        );
        assert_eq!(
            parsed["Interface"]["en0"]["Flags"],
            serde_json::json!(["up"])
        );

        // Go indents with four spaces (`json.MarshalIndent(st, "", "    ")`).
        assert!(
            json.contains("\n    \"InterfaceIPs\""),
            "four-space indent, as Go's dump; got:\n{json}"
        );
    }

    #[test]
    fn network_state_merges_per_interface_facts_across_addresses() {
        // Index and flags arrive once per ADDRESS; an interface's second address must not be able to
        // drop what the first one established (nor the other way round).
        let state = NetworkState::from_interfaces([
            InterfaceAddr {
                index: None,
                oper_up: false,
                ..iface("ppp0", v4(192, 0, 2, 8), 32)
            },
            InterfaceAddr {
                index: Some(9),
                oper_up: true,
                point_to_point: true,
                ..iface("ppp0", v4(198, 51, 100, 8), 32)
            },
        ]);
        let parsed: serde_json::Value = serde_json::from_str(&state.to_json()).expect("valid JSON");
        assert_eq!(
            parsed["Interface"]["ppp0"]["Index"],
            serde_json::json!(9),
            "an index reported by any address of the interface is kept"
        );
        assert_eq!(
            parsed["Interface"]["ppp0"]["Flags"],
            serde_json::json!(["up", "pointtopoint"])
        );
        assert_eq!(
            parsed["InterfaceIPs"]["ppp0"],
            serde_json::json!(["192.0.2.8/32", "198.51.100.8/32"]),
            "both addresses are listed, in the order the OS reported them"
        );
    }

    #[test]
    fn network_state_change_follows_the_path_signal_not_the_dump() {
        // `--monitor` re-dumps exactly when the daemon would rebind, so the comparison is the path
        // signal's — a difference confined to the filtered-out addresses is NOT a change.
        let base = NetworkState::from_interfaces([iface("en0", v4(192, 0, 2, 5), 24)]);
        let plus_noise = NetworkState::from_interfaces([
            iface("en0", v4(192, 0, 2, 5), 24),
            iface("lo0", v4(127, 0, 0, 1), 8),
            iface("utun3", v4(100, 64, 0, 7), 32),
        ]);
        assert!(
            !base.path_changed(&plus_noise),
            "loopback + the node's own tailnet address are not a path change"
        );
        assert_ne!(
            base.to_json(),
            plus_noise.to_json(),
            "…even though the dumps differ, which is why the dump is not the comparison"
        );
        // A real underlay address appearing IS a change.
        let moved = NetworkState::from_interfaces([iface("en0", v4(198, 51, 100, 5), 24)]);
        assert!(base.path_changed(&moved));
    }

    #[test]
    fn network_state_of_a_host_with_no_interfaces_is_still_a_valid_dump() {
        // The enumeration-failure arm of `current()` renders this, and a monitor must survive it.
        let empty = NetworkState::from_interfaces([]);
        let parsed: serde_json::Value = serde_json::from_str(&empty.to_json()).expect("valid JSON");
        assert_eq!(parsed["InterfaceIPs"], serde_json::json!({}));
        assert_eq!(parsed["Interface"], serde_json::json!({}));
        assert_eq!(parsed["HaveV4"], serde_json::json!(false));
        assert_eq!(parsed["HaveV6"], serde_json::json!(false));
        assert_eq!(parsed["PathRelevantIPs"], serde_json::json!([]));
        // An empty host differs from a host with an address — the "interfaces vanished" transition
        // a monitor has to notice.
        assert!(empty.path_changed(&NetworkState::from_interfaces([iface(
            "en0",
            v4(192, 0, 2, 5),
            24
        )])));
    }

    #[test]
    fn live_network_state_does_not_panic() {
        // Smoke test, as for `snapshot`: the content is host-dependent, so only the total-function
        // contract and the JSON validity are asserted.
        let state = NetworkState::current();
        serde_json::from_str::<serde_json::Value>(&state.to_json()).expect("valid JSON");
    }
}
