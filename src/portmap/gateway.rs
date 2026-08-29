//! Finding the LAN gateway (and this host's address on that LAN) — the port of Go's
//! `netmon.LikelyHomeRouterIP` (`net/netmon/state.go`, `net/netmon/interfaces_linux.go` and
//! `net/netmon/interfaces_bsd.go`, tailscale v1.100.0).
//!
//! Every one of the three port-mapping protocols is addressed to the *default gateway*: NAT-PMP and
//! PCP send UDP to `gateway:5351`, and the UPnP unicast SSDP probe goes to `gateway:1900`. PCP
//! additionally needs to state this host's own LAN address in its request header. So before any
//! protocol runs, we need the pair `(gateway, self)`.
//!
//! As Go's naming ("likely *home* router") admits, this is a heuristic aimed squarely at the
//! residential-NAT case that port mapping exists to solve: the gateway must be an RFC 1918 address,
//! and self must be an RFC 1918 address on a prefix that contains that gateway.
//!
//! ## Deviation from Go: how the default route is read
//!
//! On Linux this parses `/proc/net/route`, exactly as Go does. On macOS/BSD Go reads the kernel
//! routing table directly over `PF_ROUTE` (`golang.org/x/net/route`'s `FetchRIB`); this port instead
//! runs `route -n get default` and parses its output, which needs no route-socket bindings and is
//! available on a stock macOS/BSD install. Both platforms' *parsers* are pure functions over text,
//! so both are unit-tested against real-world output without touching the host.

use std::net::Ipv4Addr;

/// Go's `maxProcNetRouteRead`: stop after this many lines of `/proc/net/route`.
///
/// A big Linux router can have an enormous routing table, and this lookup exists only to find a home
/// gateway — if the answer is not near the top, it is not coming (Go: "we're unlikely to ever find one
/// in the future"). The cap keeps a pathological table from turning a 250 ms probe into a long scan.
pub const MAX_PROC_NET_ROUTE_READ: usize = 1000;

/// `RTF_UP` — the route is usable.
const RTF_UP: u32 = 0x0001;
/// `RTF_GATEWAY` — the route's destination is reached via a gateway (i.e. it *has* a next hop).
const RTF_GATEWAY: u32 = 0x0002;

/// One IPv4 interface address of this host, reduced to what the self-address choice needs.
///
/// Constructed from `if_addrs` in [`host_interface_addrs`], or by hand in tests — which is the point:
/// the selection rule is a pure function over this, so it is testable without any host state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceAddr {
    /// Interface name (`eth0`, `en0`, …).
    pub name: String,
    /// Whether the interface is operationally up. A down interface is skipped, as in Go.
    pub up: bool,
    /// The address itself.
    pub ip: Ipv4Addr,
    /// The address's prefix length, used to decide whether the gateway is on this interface's subnet.
    pub prefix_len: u8,
}

impl InterfaceAddr {
    /// Whether this address's subnet contains `addr` — Go's `pfx.Contains(gateway)`.
    fn prefix_contains(&self, addr: Ipv4Addr) -> bool {
        if self.prefix_len > 32 {
            return false;
        }
        // A /0 shifts by 32, which is UB-adjacent in Rust (it panics in debug); treat it as "matches
        // everything", which is what a zero-length prefix means.
        if self.prefix_len == 0 {
            return true;
        }
        let mask = u32::MAX << (32 - self.prefix_len);
        (u32::from(self.ip) & mask) == (u32::from(addr) & mask)
    }
}

/// Choose this host's address on the gateway's LAN (the second half of Go's `LikelyHomeRouterIP`).
///
/// The rules, in Go's order: skip interfaces that are not up; consider IPv4 only; the interface's
/// prefix must contain the gateway (this is what stops a second, unrelated interface from supplying
/// an address that the gateway would never answer); and both the gateway and the address must be
/// private. The first address that satisfies all of it wins, so the result is stable for a given
/// interface enumeration order.
pub fn select_self_ip(gateway: Ipv4Addr, addrs: &[InterfaceAddr]) -> Option<Ipv4Addr> {
    if !gateway.is_private() {
        return None;
    }
    addrs
        .iter()
        .find(|a| a.up && a.ip.is_private() && a.prefix_contains(gateway))
        .map(|a| a.ip)
}

/// The first IPv4 address of the named interface — Go's Linux short-circuit, which uses the route's
/// own interface rather than re-scanning every interface. Unlike [`select_self_ip`] this applies no
/// private/prefix filter: the kernel already told us this interface is the one carrying the default
/// route.
pub fn self_ip_on_interface(iface: &str, addrs: &[InterfaceAddr]) -> Option<Ipv4Addr> {
    addrs.iter().find(|a| a.name == iface).map(|a| a.ip)
}

/// Parse `/proc/net/route` for the default gateway (Go: `likelyHomeRouterIPLinux`).
///
/// Returns the gateway and the name of the interface the route is on. Only routes that are both `UP`
/// and `GATEWAY` are considered, and only a *private* next hop is accepted — a public next hop means
/// this host is not behind the kind of consumer NAT that offers port mapping, so there is nothing to
/// ask.
///
/// Malformed lines are skipped rather than failing the whole parse, matching Go ("ignore error, skip
/// line and keep going"): `/proc/net/route` is also written to by anything that can add a route, and
/// one odd line must not hide a perfectly good default route below it.
pub fn parse_proc_net_route(contents: &str) -> Option<(Ipv4Addr, String)> {
    for (line_num, line) in contents.lines().enumerate() {
        // Line 1 is the header (`Iface Destination Gateway ...`).
        if line_num == 0 {
            continue;
        }
        if line_num >= MAX_PROC_NET_ROUTE_READ {
            break;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let (gw_hex, flags_hex) = (fields[2], fields[3]);
        let Ok(flags) = u32::from_str_radix(flags_hex, 16) else {
            continue;
        };
        if flags & (RTF_UP | RTF_GATEWAY) != RTF_UP | RTF_GATEWAY {
            continue;
        }
        let Ok(raw) = u32::from_str_radix(gw_hex, 16) else {
            continue;
        };
        // The kernel writes the address in host byte order, i.e. little-endian on every platform
        // that has /proc/net/route, so the low byte is the FIRST octet: 0102A8C0 is 192.168.2.1.
        let ip = Ipv4Addr::new(
            raw as u8,
            (raw >> 8) as u8,
            (raw >> 16) as u8,
            (raw >> 24) as u8,
        );
        if ip.is_private() {
            return Some((ip, fields[0].to_string()));
        }
    }
    None
}

/// Parse the output of `route -n get default` (macOS/BSD) for the gateway and its interface.
///
/// The output is a small block of `label: value` lines; we want `gateway:` and `interface:`. A
/// gateway that is not a private IPv4 address is rejected for the same reason as in
/// [`parse_proc_net_route`]. If the default route has no `gateway:` line at all (a point-to-point
/// link, e.g. a VPN default route), there is no LAN gateway to ask and this returns `None`.
pub fn parse_route_get_default(output: &str) -> Option<(Ipv4Addr, String)> {
    let mut gateway = None;
    let mut iface = String::new();
    for line in output.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        match label.trim() {
            "gateway" => gateway = value.trim().parse::<Ipv4Addr>().ok(),
            "interface" => iface = value.trim().to_string(),
            _ => {}
        }
    }
    let gateway = gateway?;
    if !gateway.is_private() {
        return None;
    }
    Some((gateway, iface))
}

/// This host's IPv4 interface addresses, for the self-address choice.
///
/// An enumeration failure is not fatal: it yields an empty list, which simply means no self address
/// is found and the port-map attempt reports "no gateway or self IP" — the same outcome Go reports
/// when the interface state has nothing usable.
pub fn host_interface_addrs() -> Vec<InterfaceAddr> {
    #[cfg(unix)]
    {
        match if_addrs::get_if_addrs() {
            Ok(ifaces) => ifaces
                .into_iter()
                .filter_map(|i| {
                    let up = i.oper_status == if_addrs::IfOperStatus::Up;
                    match i.addr {
                        if_addrs::IfAddr::V4(v4) if !v4.ip.is_loopback() => Some(InterfaceAddr {
                            name: i.name,
                            up,
                            ip: v4.ip,
                            prefix_len: v4.prefixlen,
                        }),
                        _ => None,
                    }
                })
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "portmap: failed to enumerate interfaces");
                Vec::new()
            }
        }
    }
    #[cfg(not(unix))]
    {
        Vec::new()
    }
}

/// The gateway and this host's address on the gateway's LAN, or `None` if either cannot be found —
/// Go's `LikelyHomeRouterIP`, whose `ok` is likewise false unless BOTH are valid.
///
/// A `None` here is what makes the caller report Go's `ErrGatewayRange` ("skipping portmap; gateway
/// range likely lacks support"): with no private gateway there is nothing on this network that could
/// answer a port-mapping request.
pub fn gateway_and_self_ip() -> Option<(Ipv4Addr, Ipv4Addr)> {
    let (gateway, iface) = default_route()?;
    let addrs = host_interface_addrs();
    // Prefer the interface the default route itself is on (Go's platform short-circuit), then fall
    // back to scanning every interface for one whose prefix contains the gateway.
    let self_ip =
        self_ip_on_interface(&iface, &addrs).or_else(|| select_self_ip(gateway, &addrs))?;
    Some((gateway, self_ip))
}

/// Read the host's default route: `/proc/net/route` on Linux, `route -n get default` elsewhere on
/// unix. Returns the gateway plus the interface name the route uses.
fn default_route() -> Option<(Ipv4Addr, String)> {
    #[cfg(target_os = "linux")]
    {
        let contents = std::fs::read_to_string("/proc/net/route")
            .map_err(|e| {
                tracing::warn!(error = %e, "portmap: failed to read /proc/net/route");
            })
            .ok()?;
        parse_proc_net_route(&contents)
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let out = std::process::Command::new("/sbin/route")
            .args(["-n", "get", "default"])
            .output()
            .map_err(|e| {
                tracing::warn!(error = %e, "portmap: failed to run `route -n get default`");
            })
            .ok()?;
        parse_route_get_default(&String::from_utf8_lossy(&out.stdout))
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `/proc/net/route`, as a Linux host with one default route via 192.168.2.1 writes it.
    const PROC_NET_ROUTE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    #[test]
    fn reads_the_default_gateway_from_proc_net_route() {
        assert_eq!(
            parse_proc_net_route(PROC_NET_ROUTE),
            Some((Ipv4Addr::new(192, 168, 2, 1), "eth0".to_string())),
            "the little-endian hex 0102A8C0 is 192.168.2.1, on eth0"
        );
    }

    #[test]
    fn skips_routes_that_are_not_up_gateway_routes() {
        // Flags 0x0001 is UP without GATEWAY (the on-link subnet route): not a next hop.
        let only_onlink = "Iface\tDestination\tGateway\tFlags\n\
eth0\t0002A8C0\t0102A8C0\t0001\t0\t0\t100\n";
        assert_eq!(parse_proc_net_route(only_onlink), None);
    }

    #[test]
    fn skips_a_public_next_hop() {
        // A public next hop: the little-endian hex 017100CB is 203.0.113.1 — not private, so not a
        // home NAT, so not an answer.
        let public = "Iface\tDestination\tGateway\tFlags\n\
eth0\t00000000\t017100CB\t0003\t0\t0\t100\n";
        assert_eq!(parse_proc_net_route(public), None);
    }

    #[test]
    fn malformed_lines_do_not_hide_a_good_route_below_them() {
        let messy = "Iface\tDestination\tGateway\tFlags\n\
short\tline\n\
eth0\t00000000\tZZZZZZZZ\t0003\n\
eth0\t00000000\t0102A8C0\tnothex\n\
eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\n";
        assert_eq!(
            parse_proc_net_route(messy),
            Some((Ipv4Addr::new(192, 168, 2, 1), "eth0".to_string()))
        );
    }

    #[test]
    fn stops_after_the_line_cap() {
        // A pathological table: the good route sits past the cap, so it is deliberately not found.
        let mut big = String::from("Iface\tDestination\tGateway\tFlags\n");
        for _ in 0..MAX_PROC_NET_ROUTE_READ {
            big.push_str("eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\n");
        }
        big.push_str("eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\n");
        assert_eq!(parse_proc_net_route(&big), None);
    }

    /// Real `route -n get default` output from macOS.
    const ROUTE_GET_DEFAULT: &str = "   route to: default
destination: default
       mask: default
    gateway: 192.168.2.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";

    #[test]
    fn reads_the_default_gateway_from_route_get_default() {
        assert_eq!(
            parse_route_get_default(ROUTE_GET_DEFAULT),
            Some((Ipv4Addr::new(192, 168, 2, 1), "en0".to_string()))
        );
    }

    #[test]
    fn route_get_default_without_a_gateway_is_no_answer() {
        // A point-to-point default route (a VPN tunnel) has no `gateway:` line — there is no LAN
        // router to ask for a mapping.
        let ptp = "   route to: default
destination: default
  interface: utun4
      flags: <UP,DONE,STATIC>
";
        assert_eq!(parse_route_get_default(ptp), None);
    }

    #[test]
    fn route_get_default_rejects_a_public_gateway() {
        let public = "    gateway: 203.0.113.1\n  interface: en0\n";
        assert_eq!(parse_route_get_default(public), None);
    }

    fn addr(name: &str, ip: [u8; 4], prefix_len: u8, up: bool) -> InterfaceAddr {
        InterfaceAddr {
            name: name.to_string(),
            up,
            ip: Ipv4Addr::from(ip),
            prefix_len,
        }
    }

    #[test]
    fn self_ip_is_the_address_on_the_gateways_subnet() {
        let addrs = vec![
            // An unrelated, running interface whose subnet does NOT contain the gateway. Go skips it
            // precisely so that interface ordering can't hand back an address the gateway will never
            // answer.
            addr("eth1", [10, 9, 9, 5], 24, true),
            addr("eth0", [192, 168, 2, 30], 24, true),
        ];
        assert_eq!(
            select_self_ip(Ipv4Addr::new(192, 168, 2, 1), &addrs),
            Some(Ipv4Addr::new(192, 168, 2, 30))
        );
    }

    #[test]
    fn self_ip_skips_interfaces_that_are_down() {
        let addrs = vec![
            addr("eth0", [192, 168, 2, 30], 24, false),
            addr("eth2", [192, 168, 2, 31], 24, true),
        ];
        assert_eq!(
            select_self_ip(Ipv4Addr::new(192, 168, 2, 1), &addrs),
            Some(Ipv4Addr::new(192, 168, 2, 31))
        );
    }

    #[test]
    fn a_public_gateway_never_gets_a_self_ip() {
        let addrs = vec![addr("eth0", [192, 168, 2, 30], 24, true)];
        assert_eq!(select_self_ip(Ipv4Addr::new(203, 0, 113, 1), &addrs), None);
    }

    #[test]
    fn no_interface_on_the_gateways_subnet_is_no_self_ip() {
        let addrs = vec![addr("eth1", [10, 9, 9, 5], 24, true)];
        assert_eq!(select_self_ip(Ipv4Addr::new(192, 168, 2, 1), &addrs), None);
    }

    #[test]
    fn a_wider_prefix_still_contains_the_gateway() {
        // A /16 on 192.168.x.x contains a gateway in a different /24 of the same /16.
        let addrs = vec![addr("eth0", [192, 168, 9, 30], 16, true)];
        assert_eq!(
            select_self_ip(Ipv4Addr::new(192, 168, 2, 1), &addrs),
            Some(Ipv4Addr::new(192, 168, 9, 30))
        );
    }

    #[test]
    fn the_route_interface_short_circuit_picks_that_interface() {
        let addrs = vec![
            addr("eth1", [10, 9, 9, 5], 24, true),
            addr("eth0", [192, 168, 2, 30], 24, true),
        ];
        assert_eq!(
            self_ip_on_interface("eth0", &addrs),
            Some(Ipv4Addr::new(192, 168, 2, 30))
        );
        assert_eq!(self_ip_on_interface("wlan7", &addrs), None);
    }
}
