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
}
