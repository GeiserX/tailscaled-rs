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
//! Two callers read the result. The `check-ip-forwarding` LocalAPI wants a single human-readable
//! string ([`forwarding_warning`]; empty means "OK / not applicable"). The captive-portal trigger
//! wants Go's `isIPForwardingBroken` predicate ([`forwarding_broken`]) — the closure
//! `ipn/ipnlocal/local.go` installs via `health.Tracker.SetIPForwardingCheck`, which drives the
//! `ip-forwarding-off` health warnable. They agree on everything but one case: a check that could
//! not be *run* is worth printing to a human, yet Go deliberately reports it to the warnable as
//! **not** broken (*"don't want false positives"*). So both share one OS check and render it
//! differently.

/// Go's KB link, appended to every forwarding warning so a Tailscale-compatible client renders the
/// identical help pointer (`net/netutil/ip_forward.go`). Only the Linux path emits warnings (the
/// netstack short-circuit and the non-Linux no-op never warn), so it is Linux-gated to avoid a
/// dead-const lint on other platforms.
#[cfg(target_os = "linux")]
const KB_LINK: &str = "\nSee https://tailscale.com/s/ip-forwarding";

/// The OS check's outcome, before it is rendered for a caller.
///
/// - `Ok("")` — forwarding is fine, or there is nothing to check (Go `netutil.CheckIPForwarding`
///   returning a nil warning).
/// - `Ok(warning)` — forwarding is off, carrying Go's verbatim text.
/// - `Err(warning)` — the check itself could not be run, carrying the text Go's LocalAPI shows.
///
/// The split exists only because Go's two consumers disagree about that last case.
type ForwardingCheck = Result<String, String>;

/// Compute the IP-forwarding warning for the current host (the `check-ip-forwarding` LocalAPI).
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
    // Both arms are a warning to a human — "forwarding is off" and "I could not tell" are equally
    // worth printing, which is what Go's `LocalBackend.CheckIPForwarding` does by returning either
    // the warning or the error it hit.
    match forwarding_check_os() {
        Ok(warning) => warning,
        Err(warning) => warning,
    }
}

/// Go's `isIPForwardingBroken` predicate — the closure `LocalBackend.applyPrefsToHostinfoLocked`
/// installs via `health.Tracker.SetIPForwardingCheck` (`ipn/ipnlocal/local.go`), which is what
/// drives the `ip-forwarding-off` warnable (`health/warnings.go`, `ImpactsConnectivity: true`).
///
/// - `Some(true)` — forwarding is off, so nothing this node routes can work.
/// - `Some(false)` — forwarding is fine, or the check does not apply: netstack (Go gates the whole
///   check on `!b.sys.IsNetstackRouter()`) or a non-Linux host (Go's check is a no-op there).
/// - `None` — the check could not be run. Go collapses that into "not broken" for the reason its own
///   comment gives — `return false // don't want false positives` — and an unknown signal never
///   raises a warnable on this side either, so the two behave identically; `None` merely keeps
///   "could not read" distinguishable from "read it, it is fine" for the caller's log.
///
/// Go's *other* gate is not here: the check is installed only for a node that advertises at least
/// one route (`len(hi.RoutableIPs) > 0`), and otherwise `SetIPForwardingCheck(nil)` leaves the
/// warnable healthy. That gate needs the prefs, so it lives with its caller
/// (`Backend::ip_forwarding_health`).
pub fn forwarding_broken(tun_enabled: bool) -> Option<bool> {
    if !tun_enabled {
        // Go's `IsNetstackRouter()` gate: the check is never installed, and an uninstalled check is
        // healthy rather than unknown (`SetIPForwardingCheck(nil)` → `setHealthyLocked`).
        return Some(false);
    }
    match forwarding_check_os() {
        Ok(warning) => Some(!warning.is_empty()),
        Err(_) => None,
    }
}

#[cfg(target_os = "linux")]
fn forwarding_check_os() -> ForwardingCheck {
    // Read the two GLOBAL forwarding sysctls Go checks, straight from /proc/sys (Go does the same —
    // it does not shell out to `sysctl`). A read error is itself a (soft) warning, matching Go's
    // "couldn't check" path.
    let v4 = read_proc_forwarding("/proc/sys/net/ipv4/ip_forward");
    let v6 = read_proc_forwarding("/proc/sys/net/ipv6/conf/all/forwarding");

    match (v4, v6) {
        // Both readable + enabled → all good.
        (Ok(true), Ok(true)) => Ok(String::new()),
        // Both readable, at least one disabled → the "fully off" vs "v6 only" Go distinction.
        (Ok(false), Ok(false)) => Ok(format!(
            "IP forwarding is disabled, subnet routing/exit nodes will not work.{KB_LINK}"
        )),
        (Ok(true), Ok(false)) => Ok(format!(
            "IPv6 forwarding is disabled, subnet routing/exit nodes may not work.{KB_LINK}"
        )),
        (Ok(false), Ok(true)) => Ok(format!(
            "IP forwarding is disabled, subnet routing/exit nodes will not work.{KB_LINK}"
        )),
        // Couldn't read a sysctl → Go's "couldn't check" warning, naming the cause. `Err` and not
        // `Ok`: this is the one case the health warnable must not read as broken.
        (Err(e), _) | (_, Err(e)) => Err(format!(
            "Couldn't check system's IP forwarding configuration, subnet routing/exit nodes may \
             not work: {e}{KB_LINK}"
        )),
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
fn forwarding_check_os() -> ForwardingCheck {
    // macOS / other non-Linux: Go's `netutil.CheckIPForwarding` returns `nil` (no warning) — subnet
    // routing there needs manual OS config Go does not probe. Faithful no-op.
    Ok(String::new())
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

    #[test]
    fn netstack_mode_is_healthy_not_unknown_to_the_warnable() {
        // Go gates the whole check on `!b.sys.IsNetstackRouter()` and otherwise calls
        // `SetIPForwardingCheck(nil)`, which sets the warnable HEALTHY. A netstack node must
        // therefore report "not broken", not "cannot tell" — the difference matters because only a
        // definite `Some(true)` may ever raise `ip-forwarding-off`.
        assert_eq!(forwarding_broken(false), Some(false));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_tun_is_healthy_to_the_warnable() {
        // Go's `netutil.CheckIPForwarding` is a no-op off Linux, so it returns a nil warning and the
        // closure reports "not broken".
        assert_eq!(forwarding_broken(true), Some(false));
    }

    #[test]
    fn the_predicate_and_the_warning_agree_about_this_host() {
        // The two renderings come from one OS check, so they can never disagree about whether
        // forwarding is off: a `Some(true)` verdict must have a non-empty warning behind it. (The
        // converse is not asserted — a "couldn't check" warning is `None` to the predicate, which is
        // exactly the case Go keeps apart.)
        for tun in [false, true] {
            if forwarding_broken(tun) == Some(true) {
                assert!(
                    !forwarding_warning(tun).is_empty(),
                    "forwarding reported broken but no warning to show the operator"
                );
            }
        }
    }
}
