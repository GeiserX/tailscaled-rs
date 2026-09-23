//! OS IP-forwarding readiness check (the `check-ip-forwarding` LocalAPI / Go
//! `netutil.CheckIPForwarding`).
//!
//! A subnet router / exit node only works if the host kernel forwards IP traffic. This module
//! reproduces the *parity-meaningful* slice of Go's check:
//!
//! - **Netstack mode** (this daemon's default — userspace routing, no kernel TUN): there is nothing
//!   to check, because the kernel never forwards our traffic — the userspace netstack does. Go
//!   short-circuits the same way (`LocalBackend.CheckIPForwarding` returns `nil` when
//!   `IsNetstackRouter()`), so the warning is always empty here.
//! - **Linux + kernel TUN**: read the global forwarding sysctls directly from `/proc/sys` (Go reads
//!   the proc files, not the `sysctl` binary) and warn with Go's verbatim strings if disabled.
//! - **macOS / other non-Linux**: a no-op returning an empty warning — faithful to Go, whose
//!   `netutil.CheckIPForwarding` falls through to `return nil, nil` on darwin/windows (subnet-router
//!   forwarding there needs manual config Go does not probe).
//!
//! The result is a single human-readable `warning` string; empty means "OK / not applicable".

/// Go's KB link, appended to every forwarding warning so a Tailscale-compatible client renders the
/// identical help pointer (`net/netutil/ip_forward.go`). Only the Linux path emits warnings (the
/// netstack short-circuit and the non-Linux no-op never warn), so it is Linux-gated to avoid a
/// dead-const lint on other platforms.
#[cfg(target_os = "linux")]
const KB_LINK: &str = "\nSee https://tailscale.com/s/ip-forwarding";

/// Compute the IP-forwarding warning for the current host.
///
/// `tun_enabled` is the daemon's transport mode: `false` = userspace netstack (nothing to check),
/// `true` = a kernel TUN whose traffic the kernel must forward. Returns an empty string when
/// forwarding is fine or the check does not apply (netstack, macOS, non-Linux).
pub fn forwarding_warning(tun_enabled: bool) -> String {
    // Netstack mode: the kernel does not forward our traffic, so kernel IP forwarding is irrelevant
    // — mirror Go's `IsNetstackRouter()` short-circuit.
    if !tun_enabled {
        return String::new();
    }
    forwarding_warning_os()
}

#[cfg(target_os = "linux")]
fn forwarding_warning_os() -> String {
    // Read the two GLOBAL forwarding sysctls Go checks, straight from /proc/sys (Go does the same —
    // it does not shell out to `sysctl`). A read error is itself a (soft) warning, matching Go's
    // "couldn't check" path.
    let v4 = read_proc_forwarding("/proc/sys/net/ipv4/ip_forward");
    let v6 = read_proc_forwarding("/proc/sys/net/ipv6/conf/all/forwarding");

    match (v4, v6) {
        // Both readable + enabled → all good.
        (Ok(true), Ok(true)) => String::new(),
        // Both readable, at least one disabled → the "fully off" vs "v6 only" Go distinction.
        (Ok(false), Ok(false)) => {
            format!("IP forwarding is disabled, subnet routing/exit nodes will not work.{KB_LINK}")
        }
        (Ok(true), Ok(false)) => {
            format!("IPv6 forwarding is disabled, subnet routing/exit nodes may not work.{KB_LINK}")
        }
        (Ok(false), Ok(true)) => {
            format!("IP forwarding is disabled, subnet routing/exit nodes will not work.{KB_LINK}")
        }
        // Couldn't read a sysctl → Go's "couldn't check" warning, naming the cause.
        (Err(e), _) | (_, Err(e)) => {
            format!(
                "Couldn't check system's IP forwarding configuration, subnet routing/exit nodes may \
                 not work: {e}{KB_LINK}"
            )
        }
    }
}

/// Read a `/proc/sys/.../forwarding`-style file and interpret it as a forwarding flag. Go accepts
/// `0` (disabled), `1`/`2` (enabled); anything else is an error.
#[cfg(target_os = "linux")]
fn read_proc_forwarding(path: &str) -> Result<bool, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    match raw.trim() {
        "0" => Ok(false),
        "1" | "2" => Ok(true),
        other => Err(format!("{path}: unexpected value {other:?}")),
    }
}

#[cfg(not(target_os = "linux"))]
fn forwarding_warning_os() -> String {
    // macOS / other non-Linux: Go's `netutil.CheckIPForwarding` returns `nil` (no warning) — subnet
    // routing there needs manual OS config Go does not probe. Faithful no-op.
    String::new()
}

/// Which forwarding sysctl family to read (Go `netutil.protocol`: `ipv4`, `ipv6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    V4,
    V6,
}

/// Whether Go's `ip-forwarding-off` health warnable would be unhealthy on this node.
///
/// Go installs that check in `LocalBackend.applyPrefsToHostinfoLocked` (`ipn/ipnlocal/local.go`):
/// only when the node advertises routes (`len(hi.RoutableIPs) > 0`) and is not a netstack router,
/// and then calls it `warn != nil` from `netutil.CheckIPForwarding(routes, netMon.InterfaceState())`.
/// A check *error* is healthy there — `return false // don't want false positives` — so every
/// failure path here answers `false` as well.
///
/// `routes` is the advertised set ([`crate::routes::calc_advertise_routes`], Go's `RoutableIPs`).
/// `interface_ips` enumerates the host's `(interface name, address)` pairs; it is only called where
/// the check can say anything, and an enumeration failure is Go's `state == nil` error — healthy.
///
/// This is deliberately not [`forwarding_warning`]: that one serves the `check-ip-forwarding`
/// LocalAPI, reads only the global sysctls and ignores `routes`. The health warnable must not fire
/// on a TUN node that routes nothing.
pub fn ip_forwarding_broken(
    tun_enabled: bool,
    routes: &[ipnet::IpNet],
    interface_ips: impl FnOnce() -> std::io::Result<Vec<(String, std::net::IpAddr)>>,
) -> bool {
    // Go: `len(hi.RoutableIPs) > 0 && ... && !b.sys.IsNetstackRouter()`, else
    // `SetIPForwardingCheck(nil)`, which leaves the warnable healthy.
    if !tun_enabled || routes.is_empty() {
        return false;
    }
    ip_forwarding_broken_os(routes, interface_ips)
}

#[cfg(target_os = "linux")]
fn ip_forwarding_broken_os(
    routes: &[ipnet::IpNet],
    interface_ips: impl FnOnce() -> std::io::Result<Vec<(String, std::net::IpAddr)>>,
) -> bool {
    match interface_ips() {
        Ok(ips) => ip_forwarding_broken_linux(routes, &ips, ip_forwarding_enabled_linux),
        Err(e) => {
            tracing::debug!(error = %e, "ipforward: no interface state; forwarding health unknown");
            false
        }
    }
}

/// The BSDs: Go returns a *warning* (not an error) saying subnet routing needs manual
/// configuration there and is not officially supported, so the warnable is unhealthy.
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
fn ip_forwarding_broken_os(
    _routes: &[ipnet::IpNet],
    _interface_ips: impl FnOnce() -> std::io::Result<Vec<(String, std::net::IpAddr)>>,
) -> bool {
    true
}

/// Everything else (macOS, Windows, illumos, ...): Go's `CheckIPForwarding` returns no warning.
#[cfg(not(any(
    target_os = "linux",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
)))]
fn ip_forwarding_broken_os(
    _routes: &[ipnet::IpNet],
    _interface_ips: impl FnOnce() -> std::io::Result<Vec<(String, std::net::IpAddr)>>,
) -> bool {
    false
}

/// Go `netutil.CheckIPForwarding`'s Linux path, reduced to its `warn != nil` verdict with every
/// error read as "not broken". `read(p, iface)` is Go `ipForwardingEnabledLinux` (`""` = the global
/// sysctl), taken as an argument so the decision is testable on any host.
///
/// `interface_ips` stands in for Go's `netmon.State`: its addresses are `InterfaceIPs` and its names
/// are the `Interface` keys. The enumeration only reports interfaces that carry an address, where
/// Go's state also lists address-less ones, so an address-less interface with forwarding off is not
/// seen here — a missed warning, never an invented one.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn ip_forwarding_broken_linux(
    routes: &[ipnet::IpNet],
    interface_ips: &[(String, std::net::IpAddr)],
    read: impl Fn(Protocol, &str) -> Result<bool, String>,
) -> bool {
    let (want_v4, want_v6) = protocols_required_for_forwarding(routes, interface_ips);
    if !want_v4 && !want_v6 {
        return false;
    }
    let (Ok(v4e), Ok(v6e)) = (read(Protocol::V4, ""), read(Protocol::V6, "")) else {
        return false;
    };
    if v4e && v6e {
        return false;
    }
    // Go: with no IPv4 route, a disabled IPv6 sysctl is returned as the ERROR value, not the warning,
    // so the health check reads it as healthy.
    if !want_v4 {
        return false;
    }

    let mut any_enabled = false;
    let mut warnings = want_v6 && !v6e;
    let names: std::collections::BTreeSet<&str> = interface_ips
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    for name in names {
        if name == "lo" {
            continue;
        }
        match read(Protocol::V4, name) {
            Err(_) => return false,
            Ok(false) => warnings = true,
            Ok(true) => any_enabled = true,
        }
    }
    !any_enabled || warnings
}

/// Go `netutil.protocolsRequiredForForwarding`: which families the advertised routes need forwarded.
/// A single-IP route naming one of this host's own addresses needs no forwarding at all.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn protocols_required_for_forwarding(
    routes: &[ipnet::IpNet],
    interface_ips: &[(String, std::net::IpAddr)],
) -> (bool, bool) {
    let (mut v4, mut v6) = (false, false);
    for r in routes {
        let single_ip = r.prefix_len() == r.max_prefix_len();
        if single_ip && interface_ips.iter().any(|(_, ip)| *ip == r.addr()) {
            continue;
        }
        if r.addr().is_ipv4() {
            v4 = true;
        } else {
            v6 = true;
        }
    }
    (v4, v6)
}

/// Go `ipForwardSysctlKey(slashFormat, p, iface)`: the path under `/proc/sys` for a forwarding flag,
/// global when `iface` is empty.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn ip_forward_sysctl_key(p: Protocol, iface: &str) -> String {
    match (p, iface) {
        (Protocol::V4, "") => "net/ipv4/ip_forward".to_string(),
        (Protocol::V6, "") => "net/ipv6/conf/all/forwarding".to_string(),
        (Protocol::V4, _) => format!("net/ipv4/conf/{iface}/forwarding"),
        (Protocol::V6, _) => format!("net/ipv6/conf/{iface}/forwarding"),
    }
}

/// Go `ipForwardingEnabledLinux`: read one forwarding flag from `/proc/sys`. A missing key is
/// `false` (IPv6 disabled removes its keys) once `/proc/sys` itself is confirmed to be a directory;
/// values outside `0..=2` are errors (`2` is enabled, see tailscale/tailscale#8375).
#[cfg(target_os = "linux")]
fn ip_forwarding_enabled_linux(p: Protocol, iface: &str) -> Result<bool, String> {
    let key = ip_forward_sysctl_key(p, iface);
    // Go opens the key with `os.OpenInRoot("/proc/sys", k)` so an interface name cannot walk out of
    // `/proc/sys`. The kernel never names an interface `.`/`..` or with a `/`, so refusing those is
    // the same guarantee.
    if iface.contains('/') || iface == "." || iface == ".." {
        return Err(format!("invalid interface name {iface:?}"));
    }
    let bytes = match std::fs::read(format!("/proc/sys/{key}")) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return match std::fs::metadata("/proc/sys") {
                Err(e) => Err(format!("failed to check sysctl {key}; no procfs? {e}")),
                Ok(m) if !m.is_dir() => Err(format!(
                    "failed to check sysctl {key}; /proc/sys isn't a directory"
                )),
                Ok(_) => Ok(false),
            };
        }
        Err(e) => return Err(e.to_string()),
    };
    let val: i32 = String::from_utf8_lossy(&bytes)
        .trim()
        .parse()
        .map_err(|e| format!("couldn't parse {key}: {e}"))?;
    if !(0..=2).contains(&val) {
        return Err(format!("unexpected value {val} for {key}"));
    }
    Ok(val == 1 || val == 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netstack_mode_never_warns() {
        // The default (netstack) transport: nothing to check, always empty — regardless of host OS.
        assert_eq!(forwarding_warning(false), "");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_tun_is_a_noop() {
        // On macOS/other, even TUN mode yields an empty warning (Go is a no-op off Linux/BSD).
        assert_eq!(forwarding_warning(true), "");
    }

    fn nets(routes: &[&str]) -> Vec<ipnet::IpNet> {
        routes.iter().map(|r| r.parse().unwrap()).collect()
    }

    fn ifaces(pairs: &[(&str, &str)]) -> Vec<(String, std::net::IpAddr)> {
        pairs
            .iter()
            .map(|(n, ip)| (n.to_string(), ip.parse().unwrap()))
            .collect()
    }

    /// A fake `/proc/sys`: global v4/v6 flags plus per-interface v4 flags; an unlisted interface is a
    /// read error.
    fn sysctls(
        v4: bool,
        v6: bool,
        per_iface: &'static [(&'static str, bool)],
    ) -> impl Fn(Protocol, &str) -> Result<bool, String> {
        move |p, iface| match (p, iface) {
            (Protocol::V4, "") => Ok(v4),
            (Protocol::V6, "") => Ok(v6),
            (Protocol::V4, name) => per_iface
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, on)| *on)
                .ok_or_else(|| format!("no sysctl for {name}")),
            (Protocol::V6, name) => Err(format!("Go never reads the v6 flag of {name}")),
        }
    }

    #[test]
    fn netstack_or_no_routes_never_installs_the_health_check() {
        // Go `applyPrefsToHostinfoLocked`: the check exists only for a non-netstack node with
        // routes; otherwise `SetIPForwardingCheck(nil)` and the interface state is never read.
        let routes = nets(&["192.0.2.0/24"]);
        let must_not_enumerate = || -> std::io::Result<Vec<(String, std::net::IpAddr)>> {
            panic!("the interface state must not be read when the check does not apply")
        };
        assert!(!ip_forwarding_broken(false, &routes, must_not_enumerate));
        assert!(!ip_forwarding_broken(true, &[], must_not_enumerate));
    }

    #[test]
    fn broken_verdict_matches_go_check_ip_forwarding() {
        let eth = ifaces(&[("lo", "127.0.0.1"), ("eth0", "203.0.113.10")]);
        let v4 = nets(&["192.0.2.0/24"]);

        // Both global flags on: healthy without looking at any interface.
        assert!(!ip_forwarding_broken_linux(
            &v4,
            &eth,
            sysctls(true, true, &[])
        ));
        // Forwarding off everywhere (loopback is skipped): Go's "IP forwarding is disabled".
        assert!(ip_forwarding_broken_linux(
            &v4,
            &eth,
            sysctls(false, true, &[("eth0", false)])
        ));
        // Global v4 off but the interface forwards, and v6 is not wanted: no warning.
        assert!(!ip_forwarding_broken_linux(
            &v4,
            &eth,
            sysctls(false, false, &[("eth0", true)])
        ));
        // One interface of two will not forward: Go's partial "won't be forwarded" warning.
        let two = ifaces(&[("eth0", "203.0.113.10"), ("eth1", "198.51.100.10")]);
        assert!(ip_forwarding_broken_linux(
            &v4,
            &two,
            sysctls(false, true, &[("eth0", true), ("eth1", false)])
        ));
        // An exit node wants v6 too, and v6 forwarding is off.
        let exit = nets(&["0.0.0.0/0", "::/0"]);
        assert!(ip_forwarding_broken_linux(
            &exit,
            &eth,
            sysctls(true, false, &[("eth0", true)])
        ));
    }

    #[test]
    fn go_error_paths_are_never_broken() {
        let eth = ifaces(&[("eth0", "203.0.113.10")]);
        // A v6-only router with v6 forwarding off: Go returns that as the error value, not the
        // warning, and the health check discards errors.
        assert!(!ip_forwarding_broken_linux(
            &nets(&["2001:db8::/32"]),
            &eth,
            sysctls(false, false, &[])
        ));
        // An unreadable interface flag is Go's "Couldn't check" error: healthy.
        assert!(!ip_forwarding_broken_linux(
            &nets(&["192.0.2.0/24"]),
            &eth,
            sysctls(false, true, &[])
        ));
        // An unreadable global flag, likewise.
        assert!(!ip_forwarding_broken_linux(
            &nets(&["192.0.2.0/24"]),
            &eth,
            |_, _| Err("no procfs".to_string())
        ));
        // Routes that only name this host's own address need no forwarding.
        assert!(!ip_forwarding_broken_linux(
            &nets(&["203.0.113.10/32"]),
            &eth,
            sysctls(false, false, &[("eth0", false)])
        ));
    }

    #[test]
    fn sysctl_keys_match_go_slash_format() {
        assert_eq!(
            ip_forward_sysctl_key(Protocol::V4, ""),
            "net/ipv4/ip_forward"
        );
        assert_eq!(
            ip_forward_sysctl_key(Protocol::V6, ""),
            "net/ipv6/conf/all/forwarding"
        );
        assert_eq!(
            ip_forward_sysctl_key(Protocol::V4, "eth0.100"),
            "net/ipv4/conf/eth0.100/forwarding"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_warning_carries_the_kb_link_when_disabled() {
        // We can't control the host sysctls in a unit test, but whatever the result, a non-empty
        // warning must carry the Go KB link (the client renders it), and an empty one means enabled.
        let w = forwarding_warning(true);
        if !w.is_empty() {
            assert!(
                w.contains("tailscale.com/s/ip-forwarding"),
                "a forwarding warning must carry the KB link: {w:?}"
            );
        }
    }
}
