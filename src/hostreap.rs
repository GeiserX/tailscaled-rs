//! Startup reaper for **stale host network state** left behind by a hard kill (macOS).
//!
//! ## Why this exists
//!
//! The engine's macOS host-net backend programs two things into the *host* when the kernel-TUN data
//! path comes up: point-to-point IPv4 routes via the `utunN` device (`route(8) … -interface utunN`),
//! and a scoped MagicDNS resolver as an SCDynamicStore dictionary (`scutil(8)`, the key
//! `DNS_KEY`). Both are reversed on a **graceful** shutdown, by the engine's own RAII teardown.
//!
//! A **hard** kill is the gap. `SIGKILL`, a panic-abort, or a power loss never runs `Drop`, so:
//!
//! - the `scutil` dictionary **survives the process** — SCDynamicStore keys written with `set` are
//!   not session-scoped, so the key outlives `tailnetd` and keeps pointing the resolver at a
//!   MagicDNS server that is no longer listening, until it is removed or the host reboots;
//! - any route the kernel did not purge with the vanished `utunN` keeps **blackholing** its CIDR
//!   into a dead interface.
//!
//! Neither self-heals until something re-converges the host, so a crashed node can leave the
//! operator's DNS and a slice of their route table broken *after tailnetd is gone*.
//!
//! This module is the daemon-lane fix: on startup, **before the engine is brought up**, remove the
//! leftovers of a previous life. Go's `tailscaled` does the equivalent on Linux and Windows (its
//! `router.CleanUp` runs at startup); on darwin Go's `Close()` is a no-op and there is no
//! `HookCleanUp`, so it merely re-converges on the next `Set` — which never happens if the node is
//! not brought up again. This reaper is therefore deliberately *beyond* Go's macOS behaviour.
//!
//! ## Engine coupling: none
//!
//! The engine's macOS backend is a private module; nothing here calls into it. The reaper matches
//! leftovers by their **stable, externally observable markers** — the scutil key string, and the
//! shape a `route add … -interface utunN` entry has in the host FIB. Those markers are the contract;
//! they are asserted against real `netstat`/`scutil` output in the tests below, and the module fails
//! *safe* (reaps nothing) whenever the observed output does not match them.
//!
//! ## What it will and will not touch
//!
//! A route is reaped only when **all** of these hold (see `is_interface_scoped_utun_route` and
//! `stale_utun_routes`):
//!
//! 1. it is an IPv4 route (the engine's macOS host-net path is IPv4-only — `route … -inet`);
//! 2. its output interface is a `utun*` device (the macOS TUN naming the engine uses);
//! 3. its gateway *is* that interface name — the exact form `route add -interface <if>` produces,
//!    as opposed to an IP gateway or a kernel `link#N` cloning route;
//! 4. its flags carry `S` (`RTF_STATIC`) — added by an explicit `route add`, not kernel-generated;
//! 5. **that interface no longer exists on the host.** This is the safety interlock: a route whose
//!    output interface is gone can only blackhole, so removing it cannot break a working path. Its
//!    converse is equally deliberate — if some *other* VPN has since taken the recycled `utunN`
//!    name, its live routes are indistinguishable from ours, so we leave them alone.
//!
//! The `scutil` key needs no such interlock: `DNS_KEY` is namespaced to this fork, and at daemon
//! startup no engine of ours has installed it yet, so its presence is by definition a leftover. (The
//! engine writes one host-global key, so two `tailnetd` instances on one host already contend for
//! it; the second to start wins here, as it would anyway on the first DNS apply.)
//!
//! Everything is **best-effort and non-fatal**: a missing binary, an unparsable table or a failed
//! delete is logged and the daemon starts anyway. Losing the cleanup is never a reason to refuse to
//! bring the node up. The whole pass can be skipped with `TAILNETD_NO_REAP=1`.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

/// Env var that, when set to `1`, skips the entire reap pass. Intended for debugging, and for the
/// operator who deliberately keeps hand-made static routes on a `utun` device and wants them left
/// strictly alone.
pub const NO_REAP_VAR: &str = "TAILNETD_NO_REAP";

/// The SCDynamicStore DNS key the engine's macOS host-net backend writes for the MagicDNS resolver.
///
/// This is the **stable marker** the reaper matches on, not an import: the engine's macOS module is
/// private, so the daemon restates the key here. It is namespaced to this fork (`tailscale-rs`), so
/// it can never collide with a real Tailscale install's `State:/Network/Service/<serviceID>/DNS`.
/// If the engine ever renames it, the reaper degrades to "reaps nothing" — never to reaping
/// somebody else's key.
const DNS_KEY: &str = "State:/Network/Service/tailscale-rs/DNS";

/// `route(8)`. On macOS it lives in `/sbin` (`/usr/sbin/route` is the Linux path and does not exist).
const ROUTE_BIN: &str = "/sbin/route";
/// `scutil(8)`.
const SCUTIL_BIN: &str = "/usr/sbin/scutil";
/// `netstat(8)`, used read-only to dump the IPv4 FIB.
const NETSTAT_BIN: &str = "/usr/sbin/netstat";
/// Interface-name prefix of a macOS TUN device (the engine's `tun_name` default on darwin).
const TUN_IF_PREFIX: &str = "utun";

/// One IPv4 entry of the host FIB, as printed by `netstat -rn -f inet`.
///
/// Only the four columns the reaper decides on are kept; `Expire` is ignored. `destination` is
/// canonicalised out of netstat's abbreviated form (`100.64/10`, `default`, a bare host address)
/// into a real [`Ipv4Net`] by [`parse_destination`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct FibEntry {
    /// Destination prefix, canonicalised (netstat prints it abbreviated).
    destination: Ipv4Net,
    /// Gateway column verbatim: an IP, a `link#N`, or — for an `-interface` route — the interface name.
    gateway: String,
    /// Flags column verbatim (e.g. `USc`); `S` is `RTF_STATIC`.
    flags: String,
    /// Output interface (`Netif` column).
    netif: String,
}

/// What [`reap_stale_host_state`] actually did, so the caller can log one line and tests can assert
/// the decision without inspecting kernel state.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReapReport {
    /// The pass did not run: opted out via [`NO_REAP_VAR`], not macOS, or not root.
    pub skipped: bool,
    /// Rendered `<cidr> via <ifname>` for each stale route successfully deleted.
    pub routes_reaped: Vec<String>,
    /// Rendered `<cidr> via <ifname>` for each stale route that could not be deleted (best-effort).
    pub routes_failed: Vec<String>,
    /// A leftover `DNS_KEY` dictionary was found and removed.
    pub dns_key_reaped: bool,
}

impl ReapReport {
    /// Whether anything was actually removed — the "this host was left dirty" signal the daemon logs
    /// at `info` (a clean host reaps nothing and stays quiet).
    pub fn reaped_anything(&self) -> bool {
        self.dns_key_reaped || !self.routes_reaped.is_empty()
    }
}

/// Remove host network state left behind by a previous, hard-killed `tailnetd`.
///
/// Call this **once at daemon startup, before the engine is brought up** — after logging is
/// initialised (so its outcome is visible) and before any `Device::new`, so the reap can never race
/// the fresh `utun` device and its routes.
///
/// A no-op off macOS (Go's `router.CleanUp` already covers Linux/Windows and the engine's Linux
/// backend is not part of this bead's scope), a no-op when not root (every mutation here needs it),
/// and a no-op under [`NO_REAP_VAR`]. Never fails: the return value is a report, not a `Result`.
pub fn reap_stale_host_state() -> ReapReport {
    if reap_disabled(std::env::var(NO_REAP_VAR).ok().as_deref()) {
        tracing::info!(
            "host-reap: {NO_REAP_VAR}=1; not reaping stale routes/DNS from a previous hard kill"
        );
        return ReapReport {
            skipped: true,
            ..ReapReport::default()
        };
    }

    // Platform gate. `cfg!` (a runtime constant), NOT `#[cfg]`: the whole module — the marker
    // matching, the argv builders, the `scutil` scripts — is then compiled, linted and unit-tested
    // on **every** target, including the Linux CI runner, instead of rotting behind a macOS-only
    // attribute nothing in CI ever type-checks. Only a macOS host reaches the shell-outs. Off macOS
    // there is nothing to do anyway: Go's `router.CleanUp` already covers the Linux/Windows startup
    // cleanup, and the crash-safety gap this closes is specific to the macOS host-net path.
    if !cfg!(target_os = "macos") {
        tracing::debug!("host-reap: stale host-state reaping is macOS-only; nothing to do");
        return ReapReport {
            skipped: true,
            ..ReapReport::default()
        };
    }

    let mut report = ReapReport::default();

    // Every mutation below (`route delete`, `scutil remove` of a `State:` key) requires root, and
    // the read side is pointless without it. A non-root daemon runs in userspace-netstack mode and
    // never programmed the host in the first place. SAFETY: `geteuid` takes no arguments,
    // dereferences no pointers and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        tracing::debug!("host-reap: not root; skipping stale route/DNS reap");
        report.skipped = true;
        return report;
    }

    reap_routes(&mut report);
    reap_dns_key(&mut report);

    if report.reaped_anything() {
        tracing::info!(
            routes = ?report.routes_reaped,
            dns_key_reaped = report.dns_key_reaped,
            "host-reap: removed host network state left by a previous hard kill (SIGKILL/abort \
             skips the engine's graceful teardown)"
        );
    } else {
        tracing::debug!("host-reap: no stale routes or DNS key found");
    }
    if !report.routes_failed.is_empty() {
        tracing::warn!(
            routes = ?report.routes_failed,
            "host-reap: could not delete some stale routes; they still blackhole into a dead \
             interface (delete them by hand with `route -n delete -inet <cidr>`)"
        );
    }
    report
}

/// Pure predicate for the opt-out so it is unit-testable without touching the real environment: the
/// pass is skipped only when [`NO_REAP_VAR`] is exactly `"1"`. Unset, empty, or any other value
/// leaves the reaper **on** — the conservative default is to clean up after a crash.
fn reap_disabled(value: Option<&str>) -> bool {
    value == Some("1")
}

/// Scan the IPv4 FIB and delete every stale, `utun`-scoped static route (see the module docs for the
/// five-part match). Best-effort throughout: an unavailable `netstat` just means nothing is reaped.
fn reap_routes(report: &mut ReapReport) {
    let table = match std::process::Command::new(NETSTAT_BIN)
        .args(["-rn", "-f", "inet"])
        .output()
    {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
        Ok(out) => {
            tracing::warn!(
                status = %out.status,
                "host-reap: {NETSTAT_BIN} -rn -f inet failed; not reaping routes"
            );
            return;
        }
        Err(e) => {
            tracing::warn!(error = %e, "host-reap: cannot run {NETSTAT_BIN}; not reaping routes");
            return;
        }
    };

    for entry in stale_utun_routes(&parse_netstat_inet(&table), interface_exists) {
        let rendered = format!("{} via {}", entry.destination, entry.netif);
        if delete_route(&entry) {
            report.routes_reaped.push(rendered);
        } else {
            report.routes_failed.push(rendered);
        }
    }
}

/// Delete one stale route, returning whether it is gone.
///
/// Tries the exact inverse of the install first (`… delete -inet <cidr> -interface <if>`), then
/// falls back to a destination-only delete. The fallback is what makes this work for the case that
/// *defines* a stale route: the interface named in the entry no longer exists, so `route(8)` may
/// refuse to resolve it as a link-level gateway. A destination-only delete is unambiguous here —
/// macOS holds at most one FIB entry per destination/netmask, and we only issue it for an entry we
/// positively matched in the scan above.
fn delete_route(entry: &FibEntry) -> bool {
    if run_route(&route_delete_argv(&entry.netif, &entry.destination)) {
        return true;
    }
    tracing::debug!(
        destination = %entry.destination,
        netif = %entry.netif,
        "host-reap: interface-scoped delete failed (the interface is gone); retrying by destination"
    );
    run_route(&route_delete_dest_argv(&entry.destination))
}

/// Run `route(8)` with `argv`, returning whether it exited successfully.
fn run_route(argv: &[String]) -> bool {
    match std::process::Command::new(ROUTE_BIN).args(argv).status() {
        Ok(status) => status.success(),
        Err(e) => {
            tracing::debug!(error = %e, "host-reap: cannot run {ROUTE_BIN}");
            false
        }
    }
}

/// Probe for a leftover [`DNS_KEY`] dictionary and remove it if present.
fn reap_dns_key(report: &mut ReapReport) {
    match run_scutil(&scutil_show_script()) {
        Some(stdout) => match scutil_key_state(&stdout) {
            KeyState::Absent => {}
            KeyState::Present => {
                if run_scutil(&scutil_remove_script()).is_some() {
                    report.dns_key_reaped = true;
                } else {
                    tracing::warn!(
                        "host-reap: found the leftover {DNS_KEY} resolver dictionary but could not \
                         remove it; host DNS may still point at a dead MagicDNS server"
                    );
                }
            }
            KeyState::Unknown => {
                // Fail safe: `scutil` said something we do not recognise, so we do not guess and we
                // do not remove. A leftover key costs DNS resolution for the tailnet suffixes; a
                // wrong removal could take out state we do not own.
                tracing::debug!("host-reap: unrecognised `scutil show` output; leaving DNS alone");
            }
        },
        None => tracing::debug!("host-reap: cannot probe {DNS_KEY} via {SCUTIL_BIN}"),
    }
}

/// Feed `script` to `scutil` on stdin, returning its stdout on a successful exit (`None` otherwise).
fn run_scutil(script: &str) -> Option<String> {
    use std::io::Write as _;

    let mut child = std::process::Command::new(SCUTIL_BIN)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .inspect_err(|e| tracing::debug!(error = %e, "host-reap: cannot spawn {SCUTIL_BIN}"))
        .ok()?;
    child.stdin.take()?.write_all(script.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Whether `name` is currently a real interface on this host — the staleness interlock.
///
/// `if_nametoindex` returns 0 for an unknown name, which is exactly the "the `utun` this route
/// points at is gone" signal the reaper keys on.
fn interface_exists(name: &str) -> bool {
    let Ok(c_name) = std::ffi::CString::new(name) else {
        // A NUL in an interface name cannot come from `netstat`; treat it as "exists" so the
        // unparsable case never leads to a delete.
        return true;
    };
    // SAFETY: `if_nametoindex` reads a single NUL-terminated C string through the pointer and
    // retains nothing. `c_name` is a valid `CString` that outlives the call.
    unsafe { libc::if_nametoindex(c_name.as_ptr()) != 0 }
}

/// Parse the IPv4 routing table as printed by `netstat -rn -f inet`.
///
/// Lines that are not FIB rows (the banner, the blank line, the `Internet:` heading, the column
/// header) are dropped simply by failing to parse — the destination column of a real row is always
/// an address, `default`, or an abbreviated prefix. Robust to the trailing `Expire` column being
/// present, absent, or `!`.
fn parse_netstat_inet(output: &str) -> Vec<FibEntry> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let (Some(dest), Some(gateway), Some(flags), Some(netif)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Some(destination) = parse_destination(dest) else {
            continue;
        };
        entries.push(FibEntry {
            destination,
            gateway: gateway.to_owned(),
            flags: flags.to_owned(),
            netif: netif.to_owned(),
        });
    }
    entries
}

/// Canonicalise netstat's abbreviated destination column into an [`Ipv4Net`].
///
/// macOS prints `default` for the default route, drops trailing zero octets (`100.64/10`,
/// `192.0.2` = `192.0.2.0/24`), and omits the prefix length when it equals the printed octet count
/// times eight (so a bare `192.0.2` is a `/24` and a bare host address is a `/32`). Anything that is
/// not an IPv4 destination in that grammar — a column header, an IPv6 address, a `link#N` — returns
/// `None` and is skipped by the caller.
fn parse_destination(token: &str) -> Option<Ipv4Net> {
    if token == "default" {
        return Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).ok();
    }
    let (addr_part, explicit_prefix) = match token.split_once('/') {
        Some((addr, len)) => (addr, Some(len.parse::<u8>().ok()?)),
        None => (token, None),
    };

    let mut octets = [0u8; 4];
    let mut count = 0usize;
    for part in addr_part.split('.') {
        if count == 4 || part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        octets[count] = part.parse::<u8>().ok()?;
        count += 1;
    }
    if count == 0 {
        return None;
    }

    // No explicit `/len` ⇒ netstat elided it because it equals the printed octet count × 8.
    let prefix_len = explicit_prefix.unwrap_or((count * 8) as u8);
    Ipv4Net::new(Ipv4Addr::from(octets), prefix_len).ok()
}

/// Whether this FIB entry has the shape the engine's `route add … -inet <net> -interface <utunN>`
/// leaves behind: a static route out of a `utun` device whose gateway *is* that device.
///
/// This is marker-matching, not ownership proof — the staleness interlock in [`stale_utun_routes`]
/// is what makes acting on it safe.
fn is_interface_scoped_utun_route(entry: &FibEntry) -> bool {
    entry.netif.starts_with(TUN_IF_PREFIX)
        && entry.gateway == entry.netif
        && entry.flags.contains('S')
}

/// Select the entries the reaper may delete: engine-shaped `utun` routes whose output interface no
/// longer exists on the host.
///
/// `iface_exists` is injected so the whole decision is testable off a live FIB (and off macOS).
fn stale_utun_routes(entries: &[FibEntry], iface_exists: impl Fn(&str) -> bool) -> Vec<FibEntry> {
    entries
        .iter()
        .filter(|e| is_interface_scoped_utun_route(e) && !iface_exists(&e.netif))
        .cloned()
        .collect()
}

/// Argv deleting `net` as a point-to-point route via `if_name` — the exact inverse of the install.
fn route_delete_argv(if_name: &str, net: &Ipv4Net) -> Vec<String> {
    vec![
        "-n".to_owned(),
        "-q".to_owned(),
        "delete".to_owned(),
        "-inet".to_owned(),
        net.to_string(),
        "-interface".to_owned(),
        if_name.to_owned(),
    ]
}

/// Argv deleting `net` by destination only — the fallback for when the interface named in the FIB
/// entry no longer exists and `route(8)` will not resolve it as a link-level gateway.
fn route_delete_dest_argv(net: &Ipv4Net) -> Vec<String> {
    vec![
        "-n".to_owned(),
        "-q".to_owned(),
        "delete".to_owned(),
        "-inet".to_owned(),
        net.to_string(),
    ]
}

/// The `scutil` script that *probes* for the leftover resolver dictionary (read-only).
fn scutil_show_script() -> String {
    format!("open\nshow {DNS_KEY}\nquit\n")
}

/// The `scutil` script that removes the leftover resolver dictionary.
fn scutil_remove_script() -> String {
    format!("open\nremove {DNS_KEY}\nquit\n")
}

/// What a `scutil show <key>` said about the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyState {
    /// `scutil` printed a dictionary — the key is there.
    Present,
    /// `scutil` printed `No such key` — nothing to reap.
    Absent,
    /// Neither: do not guess, do not remove (see [`reap_dns_key`]).
    Unknown,
}

/// Classify `scutil show` stdout. Deliberately three-state and fail-safe: only an explicit
/// dictionary counts as present, so a future `scutil` output change degrades to "leave it alone"
/// rather than to a blind removal.
fn scutil_key_state(stdout: &str) -> KeyState {
    if stdout.contains("No such key") {
        KeyState::Absent
    } else if stdout.contains("<dictionary>") {
        KeyState::Present
    } else {
        KeyState::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic `netstat -rn -f inet` capture, in the exact column layout macOS prints (verified
    /// against a live Darwin 25 host). `utun7` is the crashed run's device — gone from the host —
    /// and carries the full engine-shaped set: the split default an exit node installs (`0/1` +
    /// `128/1`), the CGNAT range, a MagicDNS host route and a subnet route. `utun3` belongs to some
    /// *other*, still-running VPN and must be left strictly alone. Addresses are documentation
    /// (RFC 5737), RFC 1918, loopback and Tailscale CGNAT ranges only.
    const NETSTAT_FIXTURE: &str = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.10.1       UGScg                 en0       
0/1                utun7              USc                 utun7
100.64/10          utun7              USc                 utun7
100.100.100.100    utun7              UHS                 utun7
128/1              utun7              USc                 utun7
192.0.2            utun7              USc                 utun7
203.0.113/24       utun7              USc                 utun7
127                127.0.0.1          UCS                   lo0
127.0.0.1          127.0.0.1          UH                    lo0
192.168.10         link#11            UCS                   en0      !
192.168.10.1/32    link#11            UCS                   en0      !
198.51.100.9       192.168.10.1       UGHS                  en0
100.64/10          utun3              USc                 utun3
100.115.92.0/23    link#12            UCS                 utun3
";

    /// Interface predicate for the fixture: `utun7` is the dangling device of the killed run,
    /// everything else in the capture is live.
    fn fixture_iface_exists(name: &str) -> bool {
        name != "utun7"
    }

    #[test]
    fn reap_disabled_only_on_exact_one() {
        // On by default: unset and empty must NOT disable the reaper.
        assert!(!reap_disabled(None));
        assert!(!reap_disabled(Some("")));
        // Only the exact opt-out value disables it; near-misses leave the reaper on.
        assert!(!reap_disabled(Some("0")));
        assert!(!reap_disabled(Some("true")));
        assert!(!reap_disabled(Some("yes")));
        assert!(!reap_disabled(Some(" 1")));
        assert!(reap_disabled(Some("1")));
    }

    #[test]
    fn parse_destination_handles_every_netstat_abbreviation() {
        // `default` is the only non-numeric destination netstat prints.
        assert_eq!(
            parse_destination("default"),
            Some("0.0.0.0/0".parse().unwrap())
        );
        // Trailing zero octets are dropped and the prefix length elided when it is octets × 8.
        assert_eq!(
            parse_destination("127"),
            Some("127.0.0.0/8".parse().unwrap())
        );
        assert_eq!(
            parse_destination("192.0.2"),
            Some("192.0.2.0/24".parse().unwrap())
        );
        // An explicit `/len` wins over the octet-count rule (the abbreviated CGNAT case).
        assert_eq!(
            parse_destination("100.64/10"),
            Some("100.64.0.0/10".parse().unwrap())
        );
        assert_eq!(parse_destination("0/1"), Some("0.0.0.0/1".parse().unwrap()));
        assert_eq!(
            parse_destination("128/1"),
            Some("128.0.0.0/1".parse().unwrap())
        );
        // A bare host address is a /32; a spelled-out net route keeps its printed length.
        assert_eq!(
            parse_destination("100.100.100.100"),
            Some("100.100.100.100/32".parse().unwrap())
        );
        assert_eq!(
            parse_destination("203.0.113.0/24"),
            Some("203.0.113.0/24".parse().unwrap())
        );
    }

    #[test]
    fn parse_destination_rejects_everything_that_is_not_an_ipv4_destination() {
        // Header/banner tokens — this is what keeps non-row lines out of the parse.
        assert_eq!(parse_destination("Destination"), None);
        assert_eq!(parse_destination("Internet:"), None);
        // Gateway-column shapes must never be mistaken for a destination.
        assert_eq!(parse_destination("link#11"), None);
        assert_eq!(parse_destination("utun7"), None);
        assert_eq!(parse_destination("aa:bb:cc:dd:ee:ff"), None);
        // IPv6 (only reachable if someone drops `-f inet`) and malformed input.
        assert_eq!(parse_destination("fe80::%utun3/64"), None);
        assert_eq!(parse_destination(""), None);
        assert_eq!(parse_destination("192.0.2."), None);
        assert_eq!(parse_destination("192.0.2.1.5"), None);
        assert_eq!(parse_destination("192.0.2.999"), None);
        assert_eq!(parse_destination("192.0.2.0/33"), None);
        assert_eq!(parse_destination("192.0.2.0/x"), None);
    }

    #[test]
    fn parse_netstat_inet_reads_rows_and_drops_the_banner() {
        let entries = parse_netstat_inet(NETSTAT_FIXTURE);
        // The banner, blank line, `Internet:` heading and column header must all fall out.
        assert!(
            !entries.iter().any(|e| e.gateway == "Gateway"),
            "the column header parsed as a FIB row: {entries:?}"
        );
        assert_eq!(entries.len(), 14, "{entries:?}");

        // Spot-check the shape the reaper decides on, including the trailing `!` Expire column.
        let cgnat = entries
            .iter()
            .find(|e| e.netif == "utun7" && e.destination.to_string() == "100.64.0.0/10")
            .expect("the CGNAT route must parse");
        assert_eq!(cgnat.gateway, "utun7");
        assert_eq!(cgnat.flags, "USc");
        let lan = entries
            .iter()
            .find(|e| e.destination.to_string() == "192.168.10.0/24" && e.gateway == "link#11")
            .expect("the LAN cloning route must parse despite the trailing `!`");
        assert_eq!(lan.netif, "en0");
    }

    #[test]
    fn stale_utun_routes_reaps_the_dead_devices_routes_and_nothing_else() {
        let entries = parse_netstat_inet(NETSTAT_FIXTURE);
        let stale = stale_utun_routes(&entries, fixture_iface_exists);

        let mut reaped: Vec<String> = stale.iter().map(|e| e.destination.to_string()).collect();
        reaped.sort();
        assert_eq!(
            reaped,
            vec![
                "0.0.0.0/1",
                "100.100.100.100/32",
                "100.64.0.0/10",
                "128.0.0.0/1",
                "192.0.2.0/24",
                "203.0.113.0/24",
            ],
            "exactly the dead device's engine-shaped routes — including the split default an exit \
             node leaves behind — must be reaped"
        );
        assert!(
            stale.iter().all(|e| e.netif == "utun7"),
            "nothing outside the dead device may be touched: {stale:?}"
        );
    }

    #[test]
    fn stale_utun_routes_leaves_a_live_devices_identical_routes_alone() {
        // The interlock: `utun3` carries a byte-identical `100.64/10` route, but its interface is
        // live, so it is indistinguishable from another VPN's and must survive. Prove it by flipping
        // *only* the interface predicate — the FIB rows are unchanged.
        let entries = parse_netstat_inet(NETSTAT_FIXTURE);
        assert!(
            !stale_utun_routes(&entries, fixture_iface_exists)
                .iter()
                .any(|e| e.netif == "utun3"),
            "a live utun's routes must never be reaped"
        );
        // …and with every interface live, the reaper does nothing at all.
        assert!(stale_utun_routes(&entries, |_| true).is_empty());
    }

    #[test]
    fn stale_utun_routes_requires_every_marker() {
        // Each case is the engine-shaped row with exactly ONE marker broken; none may be reaped even
        // though the interface is (in every case) gone.
        let cases: Vec<(&str, FibEntry)> = vec![
            (
                "gateway is an IP, not the interface (a routed next-hop, not `-interface`)",
                FibEntry {
                    destination: "192.0.2.0/24".parse().unwrap(),
                    gateway: "192.168.10.1".to_owned(),
                    flags: "UGSc".to_owned(),
                    netif: "utun7".to_owned(),
                },
            ),
            (
                "gateway is a kernel `link#N` cloning route, not an explicit `route add`",
                FibEntry {
                    destination: "192.0.2.0/24".parse().unwrap(),
                    gateway: "link#12".to_owned(),
                    flags: "UCS".to_owned(),
                    netif: "utun7".to_owned(),
                },
            ),
            (
                "not RTF_STATIC — kernel-generated, e.g. the device's own on-link entry",
                FibEntry {
                    destination: "192.0.2.0/24".parse().unwrap(),
                    gateway: "utun7".to_owned(),
                    flags: "UHc".to_owned(),
                    netif: "utun7".to_owned(),
                },
            ),
            (
                "not a utun device — the engine never programs the host through one",
                FibEntry {
                    destination: "192.0.2.0/24".parse().unwrap(),
                    gateway: "en0".to_owned(),
                    flags: "USc".to_owned(),
                    netif: "en0".to_owned(),
                },
            ),
        ];
        for (why, entry) in cases {
            assert!(
                stale_utun_routes(std::slice::from_ref(&entry), |_| false).is_empty(),
                "must not reap: {why}"
            );
        }

        // Control: the same row with every marker intact and a dead interface IS reaped, so the
        // cases above fail for the stated reason and not because the fixture is inert.
        let engine_shaped = FibEntry {
            destination: "192.0.2.0/24".parse().unwrap(),
            gateway: "utun7".to_owned(),
            flags: "USc".to_owned(),
            netif: "utun7".to_owned(),
        };
        assert_eq!(
            stale_utun_routes(std::slice::from_ref(&engine_shaped), |_| false).len(),
            1
        );
    }

    #[test]
    fn route_delete_argv_is_the_exact_inverse_of_the_install() {
        // The engine installs with `route -n -q add -inet <net> -interface <if>`; the reaper's
        // primary delete must be that argv with `add` → `delete` and nothing else changed.
        let net: Ipv4Net = "100.64.0.0/10".parse().unwrap();
        assert_eq!(
            route_delete_argv("utun7", &net),
            vec![
                "-n",
                "-q",
                "delete",
                "-inet",
                "100.64.0.0/10",
                "-interface",
                "utun7"
            ]
        );
        // The fallback drops the (by definition non-existent) interface and matches on destination
        // alone — macOS holds at most one entry per destination/netmask, so this stays unambiguous.
        assert_eq!(
            route_delete_dest_argv(&net),
            vec!["-n", "-q", "delete", "-inet", "100.64.0.0/10"]
        );
        // Both forms are IPv4-only and quiet/numeric: never a name lookup, never a v6 family.
        for argv in [
            route_delete_argv("utun7", &net),
            route_delete_dest_argv(&net),
        ] {
            assert_eq!(argv.iter().filter(|a| a.as_str() == "-inet").count(), 1);
            assert!(argv.contains(&"-n".to_owned()) && argv.contains(&"-q".to_owned()));
        }
    }

    #[test]
    fn scutil_scripts_target_only_this_forks_key() {
        // Pin both scripts byte-for-byte: the key is the marker the whole DNS half rests on, and the
        // probe must stay read-only (`show`), never a `set`/`d.add` that could install anything.
        assert_eq!(
            scutil_show_script(),
            "open\nshow State:/Network/Service/tailscale-rs/DNS\nquit\n"
        );
        assert_eq!(
            scutil_remove_script(),
            "open\nremove State:/Network/Service/tailscale-rs/DNS\nquit\n"
        );
        assert!(!scutil_show_script().contains("set "));
        assert!(!scutil_show_script().contains("d.add"));
        // The key is namespaced to this fork, so it can never name a real Tailscale service's key.
        assert!(DNS_KEY.contains("tailscale-rs"));
    }

    #[test]
    fn scutil_key_state_is_fail_safe() {
        // The literal `scutil` says for a missing key (verified live on Darwin 25).
        assert_eq!(scutil_key_state("  No such key\n"), KeyState::Absent);
        // A real dictionary — the only thing that authorises a removal.
        assert_eq!(
            scutil_key_state(
                "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 100.100.100.100\n  }\n}\n"
            ),
            KeyState::Present
        );
        // Anything else must NOT be read as "present": no output, or a shape we do not recognise,
        // leaves the key alone rather than guessing.
        assert_eq!(scutil_key_state(""), KeyState::Unknown);
        assert_eq!(scutil_key_state("something new\n"), KeyState::Unknown);
    }

    #[test]
    fn reaped_anything_reflects_only_actual_removals() {
        assert!(!ReapReport::default().reaped_anything());
        // A failed delete is not a removal.
        assert!(
            !ReapReport {
                routes_failed: vec!["192.0.2.0/24 via utun7".to_owned()],
                ..ReapReport::default()
            }
            .reaped_anything()
        );
        assert!(
            ReapReport {
                routes_reaped: vec!["192.0.2.0/24 via utun7".to_owned()],
                ..ReapReport::default()
            }
            .reaped_anything()
        );
        assert!(
            ReapReport {
                dns_key_reaped: true,
                ..ReapReport::default()
            }
            .reaped_anything()
        );
    }

    /// Off macOS the whole pass is a no-op, so calling it here is free of side effects. It is NOT
    /// called on macOS: under `sudo cargo test` that would reap the developer's live host state.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn reap_is_a_skipped_no_op_off_macos() {
        let report = reap_stale_host_state();
        assert!(report.skipped);
        assert!(!report.reaped_anything());
        assert!(report.routes_failed.is_empty());
    }

    /// **Live format contract (macOS).** The parser is only as good as its assumption about what
    /// `netstat -rn -f inet` prints, so assert that against the real binary on the real host.
    /// Read-only and root-free: it parses the table and checks the shape, and deletes nothing.
    #[cfg(target_os = "macos")]
    #[test]
    fn live_netstat_output_parses_into_the_expected_shape() {
        let Ok(out) = std::process::Command::new(NETSTAT_BIN)
            .args(["-rn", "-f", "inet"])
            .output()
        else {
            return; // No netstat: nothing to pin (the reaper itself degrades the same way).
        };
        if !out.status.success() {
            return;
        }
        let table = String::from_utf8_lossy(&out.stdout);
        let entries = parse_netstat_inet(&table);
        assert!(
            !entries.is_empty(),
            "a live macOS host always has IPv4 routes; the parser matched none:\n{table}"
        );
        // Loopback is present on every host and is the cheapest invariant to pin.
        assert!(
            entries.iter().any(|e| e.netif == "lo0"),
            "expected a loopback route in the live table: {entries:?}"
        );
        // Every parsed row must have come from a real data line, never the header.
        assert!(entries.iter().all(|e| !e.flags.is_empty()));
        // And the live host's own interfaces must read back as existing — the interlock's other half.
        assert!(interface_exists("lo0"));
        assert!(!interface_exists("utun-nonexistent"));
    }

    /// **Live probe contract (macOS).** The DNS half hinges on being able to tell "key present" from
    /// "key absent" out of real `scutil` output. Read-only (`show`), root-free, mutates nothing.
    #[cfg(target_os = "macos")]
    #[test]
    fn live_scutil_probe_is_classifiable() {
        let Some(stdout) = run_scutil(&scutil_show_script()) else {
            return; // No scutil / it failed: the reaper degrades to "leave DNS alone" too.
        };
        assert_ne!(
            scutil_key_state(&stdout),
            KeyState::Unknown,
            "the live `scutil show` output must be classifiable as Present or Absent, otherwise the \
             reaper silently stops removing leftover DNS keys:\n{stdout}"
        );
    }
}
