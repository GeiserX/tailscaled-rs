//! Host- and operator-level gates on optional features — Go `envknob/featureknob/featureknob.go`.
//!
//! Go's `featureknob.CanRunTailscaleSSH()` is the single answer to "may this machine run the
//! Tailscale SSH server at all?", and `LocalBackend.checkSSHPrefsLocked` calls it **whenever
//! `RunSSH` is being set** — so the refusal lands on the pref edit, not on the listener. That
//! placement is the point: a refused `tailscale set --ssh` tells the operator the server will not
//! run, where a gate at the accept loop would leave the pref happily persisted and the server
//! silently absent.
//!
//! ## What this module ports
//!
//! Go's function is a `runtime.GOOS` switch followed by one portable check:
//!
//! ```go
//! func CanRunTailscaleSSH() error {
//!     switch runtime.GOOS {
//!     case "linux":
//!         if distro.Get() == distro.Synology && !envknob.UseWIPCode() { … }
//!         if distro.Get() == distro.QNAP && !envknob.UseWIPCode() { … }
//!     case "darwin":
//!         if version.IsSandboxedMacOS() { … }
//!     case "freebsd", "openbsd", "plan9":
//!     default:
//!         return errors.New("The Tailscale SSH server is not supported on " + runtime.GOOS)
//!     }
//!     if !envknob.CanSSHD() {
//!         return errors.New("The Tailscale SSH server has been administratively disabled.")
//!     }
//!     return nil
//! }
//! ```
//!
//! Two of those five refusals are ported here, and three are deliberately declined:
//!
//! - **`TS_DISABLE_SSH_SERVER` (ported).** `envknob.CanSSHD()` is `!Bool("TS_DISABLE_SSH_SERVER")`,
//!   and it is the reason the function exists: it is how an operator, an image build or a
//!   configuration-managed host turns the SSH server off for a machine *regardless* of what the
//!   tailnet or the user asks for. It is also the only arm that is fully portable — no distro
//!   detection, no packaging variant, just an environment read at the moment the pref is checked.
//!   This fork already honours an envknob of exactly this shape
//!   ([`portmap`](crate::portmap)'s `TS_DISABLE_PORTMAPPER`).
//! - **Unsupported OS (ported).** Cheap, portable, and expressed against an OS *name* rather than
//!   a `#[cfg]`, so the arm is compiled, linted and unit-tested on every target instead of rotting
//!   behind an attribute no builder ever type-checks (the same discipline
//!   [`hostreap`](crate::hostreap) uses for its macOS-only pass). Go's allowed set is
//!   linux/darwin/freebsd/openbsd/plan9; ours is the same set under Rust's spelling of it, where
//!   Go's `darwin` is `macos`. No supported OS name differs between the two, so the rendered
//!   message is byte-identical to Go's on every platform that can actually produce one.
//! - **Synology and QNAP (declined).** Both arms need NAS distro detection (Go's
//!   `distro.Get()`, which sniffs `/etc/synology_*`, `/etc/config/uLinux.conf` and friends) that
//!   this fork has no other use for: no other refusal, warning or default in this daemon branches
//!   on the distro, so porting them would mean carrying a detector for these two lines alone. They
//!   are also not a security boundary — both are liftable with `TS_DEBUG_ALLOW_WIP_CODE` — but a
//!   statement that the server is unproven on that hardware. Declined deliberately, not missed.
//! - **Sandboxed macOS GUI build (declined).** Go's `version.IsSandboxedMacOS()` distinguishes the
//!   sandboxed `Tailscale.app` GUI build from `tailscaled`; the refusal exists because a
//!   GUI-launched, App-Sandbox-confined daemon cannot host SSH sessions. This fork ships one
//!   binary, `tailnetd`, which is the `tailscaled`-mode build by construction — there is no
//!   sandboxed GUI variant for the check to detect, so the arm has no subject here. Declined
//!   deliberately.
//!
//! Everything here is a pure function over an OS name and an environment value; the
//! [`can_run_tailscale_ssh`] shim is the only thing that touches the process environment, so the
//! refusals are unit-testable without `set_var` (which is `unsafe` in edition 2024 and races the
//! parallel test harness).

use anyhow::{Result, bail};

/// Go `envknob.CanSSHD()`'s knob: set it truthy to refuse to run the Tailscale SSH server on this
/// machine, whatever the prefs or the tailnet say.
pub const DISABLE_SSH_SERVER_VAR: &str = "TS_DISABLE_SSH_SERVER";

/// The OS names on which Go is willing to run the Tailscale SSH server — its `runtime.GOOS` switch
/// arms, in Rust's spelling (`darwin` → `macos`). `plan9` has no Rust target today and so can never
/// match at runtime; it is listed anyway so the set reads 1:1 against upstream and a future target
/// does not silently acquire a refusal Go does not have.
const SSH_SUPPORTED_OS: [&str; 5] = ["linux", "macos", "freebsd", "openbsd", "plan9"];

/// Whether this machine may run the Tailscale SSH server (Go `featureknob.CanRunTailscaleSSH`),
/// against the real host OS and environment. `Ok(())` = allowed; the error is the operator-facing
/// sentence Go would have returned.
///
/// Call this **where the `ssh` pref is checked** — `check_prefs`, the `up`/`set` pre-validation and
/// the bring-up preflight all do — never where the server is started: the whole value of the knob
/// is that the refusal reaches the operator who asked for SSH.
pub fn can_run_tailscale_ssh() -> Result<()> {
    can_run_tailscale_ssh_in(
        std::env::consts::OS,
        std::env::var(DISABLE_SSH_SERVER_VAR).ok().as_deref(),
    )
}

/// The pure core of [`can_run_tailscale_ssh`]: the same decision against an arbitrary host `os`
/// name and an arbitrary [`DISABLE_SSH_SERVER_VAR`] value (`None` = unset).
///
/// Order matches Go exactly, and it is observable: the OS switch runs **first**, so an unsupported
/// OS reports being unsupported even when the knob is also set, and the administrative refusal is
/// checked **after** the switch, so it applies on every OS rather than only the Linux arm.
pub fn can_run_tailscale_ssh_in(os: &str, disable_ssh_server: Option<&str>) -> Result<()> {
    // Go's `runtime.GOOS` switch. The Synology/QNAP (linux) and sandboxed-GUI (darwin) arms are
    // declined — see the module docs — which leaves the switch with just its `default` arm.
    if !SSH_SUPPORTED_OS.contains(&os) {
        // Go concatenates the GOOS onto the sentence and, unlike its siblings, leaves it without a
        // full stop. Kept verbatim.
        bail!("The Tailscale SSH server is not supported on {os}");
    }
    if !can_sshd(disable_ssh_server) {
        bail!("The Tailscale SSH server has been administratively disabled.");
    }
    Ok(())
}

/// Go `envknob.CanSSHD()` — `!Bool("TS_DISABLE_SSH_SERVER")` — against an explicit value.
///
/// `true` means "an SSH server may run here". Unset **or empty** is `true`: Go's `envknob.String`
/// returns `""` for both, and `boolOr` maps `""` to its implicit `false` (not disabled).
fn can_sshd(value: Option<&str>) -> bool {
    match value {
        None | Some("") => true,
        Some(v) => match parse_go_bool(v) {
            Some(disabled) => !disabled,
            // Go's `envknob.Bool` does not tolerate an unparseable value: it `log.Fatalf`s, killing
            // the process. We cannot abort a daemon from inside a pref check, so we take the same
            // DIRECTION instead of the opposite one — an operator who wrote `TS_DISABLE_SSH_SERVER`
            // meant to switch the server off, and silently ignoring their typo would start the very
            // server they believed they had disabled. Fail closed, and say why.
            None => {
                tracing::warn!(
                    value = v,
                    "{DISABLE_SSH_SERVER_VAR}={v:?} is not a boolean; treating it as set and \
                     refusing to run the Tailscale SSH server (use 1/true or 0/false)"
                );
                false
            }
        },
    }
}

/// Go `strconv.ParseBool`, which is what `envknob.Bool` parses an environment value with: exactly
/// `1/t/T/TRUE/true/True` and `0/f/F/FALSE/false/False`, and nothing else (note that it is *not*
/// case-insensitive — `tRuE` is an error to Go, not `true`). `None` = Go would have refused it.
fn parse_go_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go's administrative refusal, verbatim — asserted against, never rebuilt from, the code.
    const ADMIN_DISABLED: &str = "The Tailscale SSH server has been administratively disabled.";

    #[test]
    fn ssh_allowed_on_every_os_go_allows() {
        // Go's switch falls through (no error) on these; ours must too, with the knob unset.
        for os in SSH_SUPPORTED_OS {
            assert!(
                can_run_tailscale_ssh_in(os, None).is_ok(),
                "{os} is in Go's allowed set and must not be refused"
            );
        }
    }

    #[test]
    fn ssh_refused_on_an_unsupported_os_with_gos_message() {
        // Go: `errors.New("The Tailscale SSH server is not supported on " + runtime.GOOS)`, whose
        // GOOS spelling matches Rust's for every name that can reach this arm.
        for os in ["windows", "netbsd", "android", "ios", "illumos"] {
            let err = can_run_tailscale_ssh_in(os, None)
                .expect_err("an OS outside Go's switch must be refused");
            assert_eq!(
                err.to_string(),
                format!("The Tailscale SSH server is not supported on {os}")
            );
        }
    }

    #[test]
    fn the_admin_knob_refuses_on_every_supported_os() {
        // The knob is checked AFTER Go's switch, so it applies everywhere — not just the Linux arm,
        // which is the whole reason it is the portable half of this function.
        for os in SSH_SUPPORTED_OS {
            let err = can_run_tailscale_ssh_in(os, Some("1"))
                .expect_err("every supported OS must honour the administrative disable");
            assert_eq!(err.to_string(), ADMIN_DISABLED, "on {os}");
        }
    }

    #[test]
    fn the_os_switch_is_checked_before_the_admin_knob() {
        // Go returns from the switch's default arm before it ever reaches `envknob.CanSSHD()`, so
        // an unsupported OS with the knob also set reports the OS, not the administrative refusal.
        let err = can_run_tailscale_ssh_in("windows", Some("1"))
            .expect_err("an unsupported OS must be refused");
        assert_eq!(
            err.to_string(),
            "The Tailscale SSH server is not supported on windows"
        );
    }

    #[test]
    fn every_go_true_spelling_disables_the_server() {
        // `strconv.ParseBool`'s true set, which is what `envknob.Bool` accepts.
        for v in ["1", "t", "T", "TRUE", "true", "True"] {
            let err = can_run_tailscale_ssh_in("linux", Some(v))
                .expect_err("a Go-true value must refuse the SSH server");
            assert_eq!(err.to_string(), ADMIN_DISABLED, "for value {v:?}");
        }
    }

    #[test]
    fn every_go_false_spelling_leaves_the_server_enabled() {
        // Including the unset and empty cases, which Go's `envknob.String` collapses to the same
        // "not set" answer.
        let values = [
            None,
            Some(""),
            Some("0"),
            Some("f"),
            Some("F"),
            Some("FALSE"),
            Some("false"),
            Some("False"),
        ];
        for v in values {
            assert!(
                can_run_tailscale_ssh_in("linux", v).is_ok(),
                "{DISABLE_SSH_SERVER_VAR}={v:?} must leave the SSH server enabled"
            );
        }
    }

    #[test]
    fn an_unparseable_value_fails_closed() {
        // Go `log.Fatalf`s on these; a daemon cannot, so we refuse the server rather than start one
        // the operator believed they had switched off.
        for v in ["yes", "on", "tRuE", "2", "-1", " 1", "1 ", "disabled"] {
            let err = can_run_tailscale_ssh_in("linux", Some(v))
                .expect_err("an unparseable value must not silently enable the server");
            assert_eq!(err.to_string(), ADMIN_DISABLED, "for value {v:?}");
        }
    }

    #[test]
    fn the_env_shim_agrees_with_its_pure_core_on_this_host() {
        // The shim only substitutes the real OS + environment; with the knob unset in the test
        // process the two must agree, which pins the wiring (the variable name included) rather
        // than the decision. If the surrounding environment already sets the knob, the comparison
        // has nothing to say, so re-derive the expected answer from that value instead.
        let live = std::env::var(DISABLE_SSH_SERVER_VAR).ok();
        assert_eq!(
            can_run_tailscale_ssh().is_ok(),
            can_run_tailscale_ssh_in(std::env::consts::OS, live.as_deref()).is_ok()
        );
    }
}
