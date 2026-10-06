//! `bugreport --diagnose` — the "additional in-depth checks" pass.
//!
//! Upstream: `cmd/tailscale/cli/bugreport.go` (`--diagnose` → `ipn.BugReportOpts.Diagnose`, which
//! the LocalAPI carries to `serveBugReport` → `LocalBackend.Doctor`) @
//! `53a0d659afa51835dd7a9283873cca44261454f8`.
//!
//! ## Why the checks are RETURNED, not logged
//!
//! Go's `Doctor` writes its findings into the daemon's log stream, and `bugreport` has just uploaded
//! that stream to logtail: the marker is the receipt support quotes to *fetch* those lines later. So
//! upstream, "in-depth checks" means "extra lines in the upload".
//!
//! This fork uploads nothing — the marker is a purely local identifier (see
//! [`Backend::bugreport`](super::Backend::bugreport)) — so a pass that only logged would be a pass
//! nobody ever reads: the support engineer has no stream to fetch, and the operator would have to be
//! told to go dig in the daemon's journal. The checks are therefore returned alongside the marker
//! and printed by `tnet bugreport --diagnose`, so what the operator pastes into the issue *is* the
//! diagnostic. That is the one adaptation this fork's no-upload posture forces; everything else
//! about the flag (its name, its help text, that it changes nothing about the marker) is Go's.
//!
//! ## Which of Go's checks are here
//!
//! | Go check | here |
//! |---|---|
//! | `permissions` (`doctor/permissions`) | ported — effective uid + whether the state dir is writable |
//! | `dns-resolvers` (the inline `CheckFunc` in `Doctor`) | ported — control-pushed resolvers that are tailnet IPs |
//! | `routetable` (`doctor/routetable`) | **no analogue** — this daemon has no route-table reader |
//! | `ethtool` (`doctor/ethtool`) | **no analogue** — no NIC-level introspection here |
//! | goroutine dump | **no analogue** |
//!
//! Where Go has no analogue the pass says so by name ([`checks`] emits a `not-checked:` line) rather
//! than quietly reporting a clean bill of health for something it never looked at. In their place it
//! adds the local context Go's `serveBugReport` logs next to the marker (hostinfo, the current
//! profile): the IPN state and intent, the profile, and the prefs that explain most breakage. Those
//! are free — the marker builder already holds them — and they are the first thing anyone reading a
//! report asks for.
//!
//! ## Where the work happens
//!
//! [`Probe::gather`] does everything that touches the OS or the engine (uid, interface enumeration,
//! the DNS-config round-trip) and is called **off** the backend lock by the LocalAPI dispatch;
//! [`checks`] is then a pure render over those facts plus what only the backend can supply
//! ([`LocalFacts`]). That split keeps `bugreport`'s promise — the marker is built under a brief lock
//! with no engine round-trip — intact with `--diagnose` on, and makes every verdict unit-testable
//! against fabricated facts.

use std::net::IpAddr;
use std::path::Path;

use super::linkmon::NetworkState;
use crate::localapi::Response;
use crate::prefs::Prefs;

/// The facts only [`Backend`](super::Backend) can supply, borrowed for one [`checks`] render.
///
/// A struct rather than a dozen positional arguments so a new fact cannot silently shift an existing
/// one, and so a test can fabricate a whole daemon posture without a `Backend`.
pub struct LocalFacts<'a> {
    /// The IPN state name (`Running`, `Stopped`, …) — [`State::as_str`](super::State::as_str).
    pub state: &'a str,
    /// A terminal registration failure the engine reported, if any (`StatusReport::error`).
    pub error: Option<&'a str>,
    /// The persisted `want_running` intent.
    pub want_running: bool,
    /// The persisted `logged_out` flag.
    pub logged_out: bool,
    /// Whether an engine is actually up right now.
    pub node_up: bool,
    /// The active profile id.
    pub profile: &'a str,
    /// Whether a node key is persisted for the active profile.
    pub have_node_key: bool,
    /// The daemon's state directory.
    pub state_dir: &'a Path,
    /// Whether the daemon can actually WRITE that directory ([`dir_writable`]).
    pub state_dir_writable: bool,
    /// The active profile's prefs, for the posture lines.
    pub prefs: &'a Prefs,
}

/// What the `dns-resolvers` check had to work with — the control-pushed DNS configuration, or the
/// reason there is none to judge.
///
/// Modelled as an enum, not an empty `Vec`, because "no resolvers are tailnet IPs" and "we never got
/// to look" must not print the same line: the second is not a clean result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsProbe {
    /// The node is not up, so there is no engine to ask and no control-pushed config to judge.
    NodeDown,
    /// The engine refused the query; the message is kept verbatim.
    Failed(String),
    /// The control-pushed resolver set, each entry an `addr:port` string.
    Config {
        /// Global upstream resolvers, in preference order (Go `nm.DNS.Resolvers`).
        resolvers: Vec<String>,
        /// Fallback resolvers (Go `nm.DNS.FallbackResolvers`).
        fallback_resolvers: Vec<String>,
    },
}

/// Everything the pass learns from outside the backend: the process's identity, the host's network
/// state, and the engine's DNS configuration.
///
/// Gathered by [`gather`](Probe::gather) **off** the backend lock — it makes syscalls and (when the
/// node is up) one engine round-trip, neither of which may run under the lock the marker is built
/// under.
pub struct Probe {
    /// The daemon process's effective uid.
    euid: u32,
    /// The host's interface state, as the link monitor sees it.
    net: NetworkState,
    /// The control-pushed DNS configuration, or why there is none.
    dns: DnsProbe,
}

impl Probe {
    /// Run the out-of-backend probes. `dev` is the engine handle when the node is up (cloned by the
    /// dispatch under a brief lock and passed in here), `None` when it is down.
    ///
    /// Every probe is best-effort and infallible: a diagnostic pass that fails is worse than one
    /// that reports what it could not learn, so an engine error becomes [`DnsProbe::Failed`] and a
    /// failed interface enumeration becomes an empty [`NetworkState`] (its own documented
    /// behaviour), not an error reply that costs the operator their marker.
    pub async fn gather(dev: Option<&tailscale::Device>) -> Self {
        let dns = match dev {
            None => DnsProbe::NodeDown,
            // Reuse the `dns status` mapping rather than re-decoding the engine's config here, so
            // the resolvers this check judges are exactly the ones `tnet dns status` shows.
            Some(dev) => match super::diag::dns_status(dev).await {
                Response::DnsStatus(report) => DnsProbe::Config {
                    resolvers: report.resolvers,
                    fallback_resolvers: report.fallback_resolvers,
                },
                Response::Error { message } => DnsProbe::Failed(message),
                other => {
                    DnsProbe::Failed(format!("unexpected reply to dns config query: {other:?}"))
                }
            },
        };
        Self {
            euid: crate::auth::current_euid(),
            net: NetworkState::current(),
            dns,
        }
    }

    /// Build a probe from fabricated facts, for tests of [`checks`] that must not depend on the
    /// machine they run on.
    #[cfg(test)]
    fn for_test(euid: u32, net: NetworkState, dns: DnsProbe) -> Self {
        Self { euid, net, dns }
    }
}

/// Whether an address is in the tailnet's own ranges — the port of Go's `tsaddr.IsTailscaleIP`,
/// which the `dns-resolvers` check uses to spot a resolver that lives *inside* the overlay.
///
/// CGNAT `100.64.0.0/10` and the Tailscale ULA `fd7a:115c:a1e0::/48`. (The link monitor's
/// `is_path_relevant` embeds the same two ranges for an unrelated decision — filtering the node's
/// own overlay address out of the host-path signal — and is deliberately left alone: sharing one
/// predicate between a path filter and a resolver classifier would couple two things that only look
/// alike.)
fn is_tailnet_ip(addr: IpAddr) -> bool {
    match addr {
        // 100.64.0.0/10: first octet 100, second octet's top two bits 0b01 (64..=127).
        IpAddr::V4(v4) => v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40,
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
        }
    }
}

/// The address half of an `addr:port` resolver string, when it parses as one.
///
/// The engine renders resolvers via `DnsResolver::udp_addr`, so the normal shape is a
/// [`SocketAddr`](std::net::SocketAddr) (`192.0.2.1:53`, `[2001:db8::1]:53`); a bare address is
/// accepted too so the check does not go blind if that rendering ever changes. Anything else yields
/// `None` and is reported as unparsed rather than silently treated as safe.
fn resolver_addr(resolver: &str) -> Option<IpAddr> {
    if let Ok(sock) = resolver.parse::<std::net::SocketAddr>() {
        return Some(sock.ip());
    }
    resolver.parse::<IpAddr>().ok()
}

/// Whether the daemon can write `dir` — the port of the question Go's `doctor/permissions` check
/// answers for the whole process (it prints uid/gid and, on Linux, capabilities; the operative fact
/// for *this* daemon is whether its state directory is writable, because a node whose prefs and node
/// key cannot be persisted fails in ways that look like anything but a permissions problem).
///
/// Uses `faccessat(…, W_OK, AT_EACCESS)` — the kernel's own answer for the **effective** uid,
/// including group membership and ACLs — rather than inferring from the mode bits, which would call
/// a root-owned `0755` directory writable for every user on the box. A path that cannot be encoded
/// as a C string, or that does not exist, is reported as not writable (which is the truth for the
/// daemon's purposes either way).
pub fn dir_writable(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(c_path) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c_path` is a valid NUL-terminated C string that outlives the call, `AT_FDCWD` is the
    // documented "resolve relative to cwd" sentinel (the path here is absolute anyway), and
    // `faccessat` only reads the arguments it is given. It returns 0 on success and -1 on any denial
    // or error, which is the whole result we consume.
    unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            libc::W_OK,
            libc::AT_EACCESS,
        ) == 0
    }
}

/// Render the pass: one `name: detail` line per check, in a fixed order, ready to print.
///
/// Pure — every fact arrives in `facts`/`probe`, so the whole output is unit-testable against a
/// fabricated daemon. Each finished line is run through the marker-note sanitizer
/// ([`sanitize_marker_note`](super::sanitize_marker_note)): the values interpolated here include
/// operator-supplied text (a control URL, a hostname, an exit-node selector) and control-supplied
/// text (resolver strings), and a diagnostic block is copy-pasted by definition — a stray newline or
/// escape must not be able to split a line or repaint the reader's terminal.
pub fn checks(facts: &LocalFacts<'_>, probe: &Probe) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    // ---- local context (Go logs its hostinfo + profile next to the marker) -------------------
    out.push(format!(
        "state: {} (want_running={}, logged_out={}, engine_up={})",
        facts.state, facts.want_running, facts.logged_out, facts.node_up
    ));
    if let Some(error) = facts.error {
        out.push(format!("state: terminal registration failure: {error}"));
    }
    // The one inconsistency worth calling out by name: intent says up, the node is not.
    if facts.want_running && !facts.node_up {
        out.push(
            "state: WARNING want_running=true but no engine is up — the node is not connected"
                .to_string(),
        );
    }
    out.push(format!(
        "profile: {} (node key persisted: {})",
        facts.profile, facts.have_node_key
    ));

    let p = facts.prefs;
    out.push(format!(
        "prefs: control_url={} hostname={} operator={} ephemeral={}",
        p.control_url.as_deref().unwrap_or("<default>"),
        p.hostname.as_deref().unwrap_or("<default>"),
        p.operator_user.as_deref().unwrap_or("<none>"),
        p.ephemeral,
    ));
    out.push(format!(
        "prefs: exit_node={} advertise_exit_node={} advertise_routes=[{}] accept_routes={} \
         accept_dns={} shields_up={} ssh={} tun={}",
        p.exit_node.as_deref().unwrap_or("<none>"),
        p.advertise_exit_node,
        p.advertise_routes.join(","),
        p.accept_routes,
        p.accept_dns,
        p.shields_up,
        p.ssh_enabled,
        p.tun_enabled,
    ));

    // ---- permissions (Go `doctor/permissions`) ------------------------------------------------
    out.push(format!(
        "permissions: euid={} (root={}) state_dir={} writable={}",
        probe.euid,
        probe.euid == 0,
        facts.state_dir.display(),
        facts.state_dir_writable,
    ));
    if !facts.state_dir_writable {
        out.push(
            "permissions: WARNING the state directory is not writable — prefs and the node key \
             cannot be persisted"
                .to_string(),
        );
    }

    // ---- dns-resolvers (Go's inline `CheckFunc` in `Doctor`) ----------------------------------
    match &probe.dns {
        DnsProbe::NodeDown => {
            out.push("dns-resolvers: not checked — the node is not up, so control has pushed no DNS configuration".to_string());
        }
        DnsProbe::Failed(message) => {
            out.push(format!("dns-resolvers: query failed: {message}"));
        }
        DnsProbe::Config {
            resolvers,
            fallback_resolvers,
        } => {
            out.push(format!(
                "dns-resolvers: {} global, {} fallback",
                resolvers.len(),
                fallback_resolvers.len()
            ));
            // Go logs one line per offending resolver, naming which list and which index it is in;
            // the reason is the same in both lists — a resolver inside the overlay can only be
            // reached once the overlay is up, so depending on it can keep the node from reaching
            // control at all.
            for (label, list) in [
                ("resolver", resolvers),
                ("fallback resolver", fallback_resolvers),
            ] {
                for (i, resolver) in list.iter().enumerate() {
                    match resolver_addr(resolver) {
                        Some(addr) if is_tailnet_ip(addr) => out.push(format!(
                            "dns-resolvers: WARNING {label} {i} is a tailnet address: {resolver}"
                        )),
                        Some(_) => {}
                        None => out.push(format!(
                            "dns-resolvers: {label} {i} could not be parsed as an address: {resolver}"
                        )),
                    }
                }
            }
        }
    }

    // ---- interfaces (this fork's stand-in for the host-level Go checks) -----------------------
    let names = probe.net.interface_names();
    out.push(format!(
        "interfaces: {} with addresses ({}) have_v4={} have_v6={}",
        names.len(),
        if names.is_empty() {
            "none".to_string()
        } else {
            names.join(", ")
        },
        probe.net.have_v4(),
        probe.net.have_v6(),
    ));
    if !probe.net.have_v4() && !probe.net.have_v6() {
        out.push(
            "interfaces: WARNING no usable underlay address — the host has no network path to \
             control or to any peer"
                .to_string(),
        );
    }

    // ---- what was NOT checked ------------------------------------------------------------------
    out.push(
        "not-checked: route table and NIC (ethtool) details — this daemon has no route-table or \
         link-layer reader; `tailnetd debug --ifconfig` dumps the full interface state"
            .to_string(),
    );

    out.into_iter()
        .map(|line| super::sanitize_marker_note(&line))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    /// A `NetworkState` for a host with one loopback and one Ethernet address — enough for the
    /// interfaces line to have something true to say without consulting the test machine.
    fn net_state() -> NetworkState {
        use super::super::linkmon::InterfaceAddr;
        NetworkState::from_interfaces([
            InterfaceAddr {
                name: "lo0".into(),
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                prefix_len: 8,
                index: Some(1),
                oper_up: true,
                point_to_point: false,
            },
            InterfaceAddr {
                name: "eth0".into(),
                ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 15)),
                prefix_len: 24,
                index: Some(2),
                oper_up: true,
                point_to_point: false,
            },
        ])
    }

    fn prefs() -> Prefs {
        Prefs::default()
    }

    fn facts<'a>(prefs: &'a Prefs, state_dir: &'a Path) -> LocalFacts<'a> {
        LocalFacts {
            state: "Running",
            error: None,
            want_running: true,
            logged_out: false,
            node_up: true,
            profile: "default",
            have_node_key: true,
            state_dir,
            state_dir_writable: true,
            prefs,
        }
    }

    /// Every check reports, in order, and the healthy posture warns about nothing.
    #[test]
    fn checks_cover_every_section_of_the_pass() {
        let prefs = prefs();
        let dir = PathBuf::from("/var/lib/tailnetd");
        let probe = Probe::for_test(
            501,
            net_state(),
            DnsProbe::Config {
                resolvers: vec!["192.0.2.53:53".into()],
                fallback_resolvers: vec![],
            },
        );
        let lines = checks(&facts(&prefs, &dir), &probe);

        for expected in [
            "state: ",
            "profile: default",
            "prefs: control_url=",
            "prefs: exit_node=",
            "permissions: euid=501 (root=false)",
            "dns-resolvers: 1 global, 0 fallback",
            "interfaces: 2 with addresses",
            "not-checked: ",
        ] {
            assert!(
                lines.iter().any(|l| l.starts_with(expected)),
                "the pass should report {expected:?}; got:\n{}",
                lines.join("\n")
            );
        }
        assert!(
            !lines.iter().any(|l| l.contains("WARNING")),
            "a healthy posture warns about nothing; got:\n{}",
            lines.join("\n")
        );
        // The interfaces line is derived from the fabricated host, not the test machine: only the
        // non-loopback address counts towards a usable path.
        assert!(
            lines
                .iter()
                .any(|l| l.contains("have_v4=true") && l.contains("have_v6=false")),
            "the fabricated host has a v4 path and no v6 path; got:\n{}",
            lines.join("\n")
        );
    }

    /// Go's `dns-resolvers` check exists to name a resolver that lives inside the overlay, in either
    /// list — that is the whole finding, so it must be unmissable in the output.
    #[test]
    fn dns_resolvers_check_names_tailnet_resolvers_in_both_lists() {
        let prefs = prefs();
        let dir = PathBuf::from("/var/lib/tailnetd");
        let probe = Probe::for_test(
            0,
            net_state(),
            DnsProbe::Config {
                resolvers: vec!["100.100.100.100:53".into(), "192.0.2.53:53".into()],
                fallback_resolvers: vec![
                    format!(
                        "[{}]:53",
                        Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1)
                    ),
                    "not-an-address".into(),
                ],
            },
        );
        let lines = checks(&facts(&prefs, &dir), &probe);
        let joined = lines.join("\n");

        assert!(
            joined.contains("WARNING resolver 0 is a tailnet address: 100.100.100.100:53"),
            "the CGNAT resolver must be named by list and index; got:\n{joined}"
        );
        assert!(
            joined.contains("WARNING fallback resolver 0 is a tailnet address"),
            "the ULA fallback resolver must be named too; got:\n{joined}"
        );
        assert!(
            !joined.contains("192.0.2.53:53"),
            "a public resolver is not a finding; got:\n{joined}"
        );
        assert!(
            joined.contains("could not be parsed as an address: not-an-address"),
            "an unparsable resolver is reported, not assumed safe; got:\n{joined}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("permissions: euid=0 (root=true)")),
            "root is reported as root; got:\n{joined}"
        );
    }

    /// The states that must not read as healthy: an engine that is down against `want_running`, a
    /// state dir the daemon cannot write, a host with no underlay, and a node that is not up at all
    /// (so the DNS check has nothing to judge and says so).
    #[test]
    fn checks_warn_on_each_broken_posture() {
        let prefs = prefs();
        let dir = PathBuf::from("/var/lib/tailnetd");
        let mut facts = facts(&prefs, &dir);
        facts.node_up = false;
        facts.state = "Stopped";
        facts.error = Some("bad auth key");
        facts.state_dir_writable = false;
        let probe = Probe::for_test(501, NetworkState::from_interfaces([]), DnsProbe::NodeDown);
        let joined = checks(&facts, &probe).join("\n");

        assert!(
            joined.contains("WARNING want_running=true but no engine is up"),
            "intent-vs-reality mismatch must be named; got:\n{joined}"
        );
        assert!(
            joined.contains("terminal registration failure: bad auth key"),
            "a terminal failure must be reported; got:\n{joined}"
        );
        assert!(
            joined.contains("WARNING the state directory is not writable"),
            "an unwritable state dir must be named; got:\n{joined}"
        );
        assert!(
            joined.contains("WARNING no usable underlay address"),
            "a host with no addresses must be named; got:\n{joined}"
        );
        assert!(
            joined.contains("dns-resolvers: not checked — the node is not up"),
            "a down node must say why DNS was not judged, not report it clean; got:\n{joined}"
        );
    }

    /// A hostile pref value cannot split a line or repaint the terminal of whoever reads the report.
    #[test]
    fn checks_sanitize_control_characters_out_of_every_line() {
        let mut prefs = prefs();
        prefs.hostname = Some("evil\nprofile: fake\x1b[2J".into());
        let dir = PathBuf::from("/var/lib/tailnetd");
        let probe = Probe::for_test(501, net_state(), DnsProbe::NodeDown);
        let lines = checks(&facts(&prefs, &dir), &probe);

        assert!(
            lines
                .iter()
                .all(|l| !l.contains('\n') && !l.contains('\x1b')),
            "no line may carry a newline or an escape; got:\n{}",
            lines.join("\n")
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("hostname=evil_profile: fake_[2J")),
            "the value is kept, with its control characters replaced; got:\n{}",
            lines.join("\n")
        );
    }

    /// The tailnet-range predicate is the port of `tsaddr.IsTailscaleIP`: the two overlay ranges and
    /// nothing else.
    #[test]
    fn is_tailnet_ip_matches_the_two_overlay_ranges() {
        assert!(is_tailnet_ip(IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100))));
        assert!(is_tailnet_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_tailnet_ip(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 255))));
        assert!(is_tailnet_ip(IpAddr::V6(Ipv6Addr::new(
            0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1
        ))));
        // Just outside 100.64.0.0/10 on either side, and a public resolver.
        assert!(!is_tailnet_ip(IpAddr::V4(Ipv4Addr::new(100, 63, 255, 255))));
        assert!(!is_tailnet_ip(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 0))));
        assert!(!is_tailnet_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        // Same ULA /32, different /48 — not the tailnet's range.
        assert!(!is_tailnet_ip(IpAddr::V6(Ipv6Addr::new(
            0xfd7a, 0x115c, 0xbeef, 0, 0, 0, 0, 1
        ))));
    }

    /// `dir_writable` answers for the real filesystem: a temp dir the test owns is writable, a path
    /// that does not exist is not.
    #[test]
    fn dir_writable_answers_for_the_real_filesystem() {
        let dir = std::env::temp_dir();
        assert!(
            dir_writable(&dir),
            "the temp dir must be writable by the test process"
        );
        assert!(
            !dir_writable(&dir.join(format!("tailnetd-absent-{}", std::process::id()))),
            "a path that does not exist is not writable"
        );
    }
}
