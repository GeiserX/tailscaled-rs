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
//! ## Two callers, one check
//!
//! Go's `CheckIPForwarding` has a two-slot return, `(warn, err error)`, and its two consumers read
//! those slots differently:
//!
//! - `LocalBackend.CheckIPForwarding` (the `check-ip-forwarding` LocalAPI) shows the operator
//!   whichever of the two is non-nil — "forwarding is off" and "I could not tell" are equally worth
//!   printing. That is [`forwarding_warning`]; empty means "OK / not applicable".
//! - The closure `applyPrefsToHostinfoLocked` installs with `health.Tracker.SetIPForwardingCheck`
//!   (`ipn/ipnlocal/local.go`) drives the `ip-forwarding-off` health warnable, and it reads only the
//!   warning slot: `if err != nil { return false // don't want false positives }; return warn != nil`.
//!   That is [`forwarding_broken`].
//!
//! So the OS check runs once and is rendered twice, and the shape that keeps the two apart is
//! [`ForwardingCheck`]: `Err` is Go's `err` slot, which the warnable must never read as broken.
//!
//! **Honest reduced scope.** Go decides *which* families it needs forwarded from the advertised
//! routes (`protocolsRequiredForForwarding`) and then re-checks per interface. This module reads the
//! two global sysctls only, so "IPv4 on, IPv6 off" always renders Go's `wantV4` wording (a warning,
//! and therefore broken) rather than the different sentence Go emits for a node advertising IPv6
//! routes alone. That pre-dates the health warnable and is not changed here.

/// Go's KB link, appended to every forwarding warning so a Tailscale-compatible client renders the
/// identical help pointer (`net/netutil/ip_forward.go`'s `kbLink`). Only Linux ever emits a warning
/// — the netstack short-circuit and the non-Linux no-op never do — so outside Linux this and
/// [`render_forwarding`] exist for the tests alone, which is what the `test` arm is for: the mapping
/// they pin is platform-independent even though the sysctls it reads are not.
#[cfg(any(target_os = "linux", test))]
const KB_LINK: &str = "\nSee https://tailscale.com/s/ip-forwarding";

/// One run of the OS check, before it is rendered for a caller — Go `CheckIPForwarding`'s
/// `(warn, err)` pair, as the one-of-two-slots it actually is.
///
/// - `Ok("")` — forwarding is fine, or there is nothing to check (Go's `return nil, nil`).
/// - `Ok(warning)` — forwarding is off, carrying Go's verbatim warning text.
/// - `Err(warning)` — the check itself could not be run, carrying the text Go puts in its `err`.
///
/// The split exists only because Go's two consumers disagree about that last case: the LocalAPI
/// prints it, the health warnable ignores it.
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
    // Both slots are a warning to a human — "forwarding is off" and "I could not tell" are equally
    // worth printing, which is what Go's `LocalBackend.CheckIPForwarding` does by surfacing whichever
    // of `warn`/`err` came back non-nil.
    match forwarding_check_os() {
        Ok(warning) => warning,
        Err(warning) => warning,
    }
}

/// Go's IP-forwarding-broken predicate — the closure `LocalBackend.applyPrefsToHostinfoLocked`
/// installs via `health.Tracker.SetIPForwardingCheck` (`ipn/ipnlocal/local.go`), which is what
/// drives the `ip-forwarding-off` warnable (`health/warnings.go`, `ImpactsConnectivity: true`).
///
/// - `Some(true)` — forwarding is off, so nothing this node routes can work.
/// - `Some(false)` — forwarding is fine, or the check does not apply: netstack (Go gates the whole
///   install on `!b.sys.IsNetstackRouter()`) or a non-Linux host (Go's check is a no-op there).
/// - `None` — the check could not be run. Go collapses that into "not broken" (`return false // don't
///   want false positives`), and an unknown signal never raises a warnable on this side either, so
///   the two behave identically; `None` merely keeps "could not read" distinguishable from "read it,
///   it is fine" for the caller's log.
///
/// Go's *other* install gate is not here: the check is installed only for a node that advertises at
/// least one route (`len(hi.RoutableIPs) > 0`), and otherwise `SetIPForwardingCheck(nil)` leaves the
/// warnable healthy. That gate needs the prefs, so it lives with its caller
/// (`Backend::ip_forwarding_health`). Go's third condition, `b.NetMon() != nil`, has no analogue: it
/// guards the `*netmon.State` argument this fork's check does not take.
pub fn forwarding_broken(tun_enabled: bool) -> Option<bool> {
    if !tun_enabled {
        // Go's `IsNetstackRouter()` gate: the check is never installed, and an uninstalled check is
        // healthy rather than unknown (`SetIPForwardingCheck(nil)` → `setHealthyLocked`).
        return Some(false);
    }
    broken_from(&forwarding_check_os())
}

/// Read a [`ForwardingCheck`] the way Go's health closure reads `(warn, err)`: `warn != nil` is
/// broken, and an `err` is deliberately *not*.
fn broken_from(check: &ForwardingCheck) -> Option<bool> {
    match check {
        Ok(warning) => Some(!warning.is_empty()),
        // Go's `if err != nil { return false // don't want false positives }`. `None` here, because
        // an unknown signal and a healthy one reach the warnable identically but read differently in
        // a log — what must never happen is this arm becoming `Some(true)`.
        Err(_) => None,
    }
}

/// Render the two global forwarding sysctls into Go's `(warn, err)` pair.
///
/// Pure and platform-independent on purpose: the reading is Linux-only, but the *mapping* — in
/// particular which combination lands in the `err` slot the health warnable ignores — is the part
/// worth testing, and it should be tested everywhere the daemon builds rather than only on a
/// misconfigured Linux host.
#[cfg(any(target_os = "linux", test))]
fn render_forwarding(v4: Result<bool, String>, v6: Result<bool, String>) -> ForwardingCheck {
    match (v4, v6) {
        // Both readable + enabled → all good (Go's `if v4e && v6e { return nil, nil }`).
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
        // Couldn't read a sysctl → Go's "couldn't check" text, naming the cause. `Err` and not `Ok`:
        // this is the one case the health warnable must not read as broken, and Go puts it in the
        // slot that closure discards.
        (Err(e), _) | (_, Err(e)) => Err(format!(
            "Couldn't check system's IP forwarding configuration, subnet routing/exit nodes may \
             not work: {e}{KB_LINK}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn forwarding_check_os() -> ForwardingCheck {
    // Read the two GLOBAL forwarding sysctls Go checks, straight from /proc/sys (Go does the same —
    // it does not shell out to `sysctl`). A read error is itself a (soft) warning, matching Go's
    // "couldn't check" path.
    let v4 = read_proc_forwarding("/proc/sys/net/ipv4/ip_forward");
    let v6 = read_proc_forwarding("/proc/sys/net/ipv6/conf/all/forwarding");
    render_forwarding(v4, v6)
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
    fn every_sysctl_combination_renders_gos_slot() {
        // All five shapes of Go's `(warn, err)` return, driven through the production renderer. The
        // `Ok`/`Err` split is the whole point: `Ok` is the slot the health warnable reads, `Err` is
        // the slot it discards.
        assert_eq!(
            render_forwarding(Ok(true), Ok(true)),
            Ok(String::new()),
            "both enabled is Go's `return nil, nil`"
        );
        assert_eq!(
            render_forwarding(Ok(false), Ok(false)),
            Ok(format!(
                "IP forwarding is disabled, subnet routing/exit nodes will not work.{KB_LINK}"
            ))
        );
        assert_eq!(
            render_forwarding(Ok(false), Ok(true)),
            Ok(format!(
                "IP forwarding is disabled, subnet routing/exit nodes will not work.{KB_LINK}"
            )),
            "v4 off is Go's `!anyEnabled` sentence, whatever v6 says"
        );
        assert_eq!(
            render_forwarding(Ok(true), Ok(false)),
            Ok(format!(
                "IPv6 forwarding is disabled, subnet routing/exit nodes may not work.{KB_LINK}"
            ))
        );
        let unreadable = render_forwarding(Err("/proc/sys/x: nope".to_string()), Ok(true));
        assert_eq!(
            unreadable,
            Err(format!(
                "Couldn't check system's IP forwarding configuration, subnet routing/exit nodes may \
                 not work: /proc/sys/x: nope{KB_LINK}"
            )),
            "an unreadable sysctl is Go's `err` slot, not its `warn` slot"
        );
        // Either position of the unreadable sysctl lands in the same slot.
        assert!(render_forwarding(Ok(true), Err("boom".to_string())).is_err());
        assert!(render_forwarding(Err("boom".to_string()), Err("boom".to_string())).is_err());
    }

    #[test]
    fn an_unreadable_sysctl_is_never_broken_to_the_warnable() {
        // Go: `if err != nil { return false // don't want false positives }`. The one thing this
        // mapping must never do is turn "I could not check" into an unhealthy `ip-forwarding-off`,
        // because that warnable also drives captive-portal probing.
        for other in [Ok(true), Ok(false), Err("also broken".to_string())] {
            let check = render_forwarding(Err("/proc/sys/x: nope".to_string()), other);
            assert_eq!(
                broken_from(&check),
                None,
                "a check that could not be run is not a broken check"
            );
            assert_ne!(broken_from(&check), Some(true));
        }
    }

    #[test]
    fn a_rendered_warning_is_broken_and_an_empty_one_is_not() {
        // The other half of Go's closure: `return warn != nil`.
        assert_eq!(
            broken_from(&render_forwarding(Ok(true), Ok(true))),
            Some(false)
        );
        assert_eq!(
            broken_from(&render_forwarding(Ok(false), Ok(false))),
            Some(true)
        );
        assert_eq!(
            broken_from(&render_forwarding(Ok(false), Ok(true))),
            Some(true)
        );
        assert_eq!(
            broken_from(&render_forwarding(Ok(true), Ok(false))),
            Some(true)
        );
    }

    #[test]
    fn netstack_mode_is_healthy_not_unknown_to_the_warnable() {
        // Go gates the install on `!b.sys.IsNetstackRouter()` and otherwise calls
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
