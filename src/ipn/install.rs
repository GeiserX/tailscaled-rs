//! System-daemon install/uninstall — the Rust analogue of Go `tailscaled install-system-daemon` /
//! `uninstall-system-daemon` (`cmd/tailscaled`), turning `tailnetd` from a foreground process into a
//! boot service.
//!
//! `tnet install` copies the running `tailnetd` binary to the canonical path, writes the OS service
//! unit (the committed `packaging/{systemd,launchd}` files, embedded via [`include_str!`] so they ship
//! with the binary AND stay byte-for-byte in lockstep with the repo), then enables/loads it
//! (`systemctl enable --now` on Linux, `launchctl bootstrap system` on macOS). `tnet uninstall`
//! reverses it (disable/unload + remove the unit) and **leaves the state dir** (node key material).
//!
//! ## Pure plan vs. privileged apply
//!
//! The module is split so the per-OS *decision* is offline-testable and the privileged *effects* are
//! isolated and root-gated:
//!
//! - [`plan`] is **pure** (no I/O): it returns an [`InstallPlan`] describing where the binary goes,
//!   where the unit goes, the embedded unit content, and the enable/load + disable/unload argv. Off
//!   Linux/macOS it returns a clear "unsupported OS" error. This is what the unit tests exercise.
//! - [`apply_install`] / [`apply_uninstall`] perform the actual file copy + `systemctl`/`launchctl`
//!   commands. They are gated on root by [`run_install`] / [`run_uninstall`] (the CLI entry points),
//!   never run in CI, and live-verified on a real OS.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

/// A per-OS install/uninstall plan: every location + command needed to (un)install the system daemon.
///
/// Built purely by [`plan`] (no I/O), so it can be asserted by value in tests. `unit_content` is the
/// [`include_str!`] of the committed packaging file, so the embedded unit ships with the binary and
/// stays in lockstep with the repo. The argv vectors are full command lines (`argv[0]` is the program,
/// the rest are arguments), executed in order by [`apply_install`] / [`apply_uninstall`].
pub(crate) struct InstallPlan {
    /// Where the `tailnetd` binary is copied to (the canonical path both units reference).
    pub(crate) bin_dest: PathBuf,
    /// Where the service unit file is written.
    pub(crate) unit_path: PathBuf,
    /// The embedded unit file content (the committed packaging file, via [`include_str!`]).
    pub(crate) unit_content: &'static str,
    /// Commands to enable/load the service at boot, run in order after the unit is written.
    pub(crate) enable_argv: Vec<Vec<String>>,
    /// Commands to disable/unload the service, run in order before the unit is removed.
    pub(crate) disable_argv: Vec<Vec<String>>,
}

/// Build the install/uninstall [`InstallPlan`] for the current OS — **pure** (no I/O).
///
/// `cfg`-branched per target OS so the embedded unit + paths + argv are resolved at compile time:
/// - **Linux (systemd):** write `/etc/systemd/system/tailnetd.service`, then `systemctl daemon-reload`
///   + `systemctl enable --now tailnetd`.
/// - **macOS (launchd):** write `/Library/LaunchDaemons/cloud.tailscaled-rs.tailnetd.plist`, then
///   `launchctl bootstrap system <plist>`.
/// - **Other:** a clear "unsupported OS" error (no daemon manager to target).
pub(crate) fn plan() -> Result<InstallPlan> {
    #[cfg(target_os = "linux")]
    {
        // Pick the systemd unit that matches how this daemon was BUILT. A `tun`-feature build creates
        // a kernel TUN interface and would fail closed under the userspace unit's sandbox (which hides
        // /dev/net/tun, strips CAP_NET_ADMIN, and blocks the interface-config syscalls); a userspace
        // build needs none of those grants and is better off fully locked down. The unit is chosen at
        // compile time (`cfg!`) — the installed daemon binary and its unit always agree, so an
        // operator never gets a TUN binary under a sandbox that silently breaks it (or a userspace
        // binary needlessly granted CAP_NET_ADMIN). Both units are embedded so neither path needs the
        // packaging tree at install time.
        let unit_content: &str = if cfg!(feature = "tun") {
            include_str!("../../packaging/systemd/tailnetd-tun.service")
        } else {
            include_str!("../../packaging/systemd/tailnetd.service")
        };
        Ok(InstallPlan {
            bin_dest: PathBuf::from("/usr/local/bin/tailnetd"),
            unit_path: PathBuf::from("/etc/systemd/system/tailnetd.service"),
            unit_content,
            enable_argv: vec![
                vec!["systemctl".to_string(), "daemon-reload".to_string()],
                vec![
                    "systemctl".to_string(),
                    "enable".to_string(),
                    "--now".to_string(),
                    "tailnetd".to_string(),
                ],
            ],
            disable_argv: vec![
                vec![
                    "systemctl".to_string(),
                    "disable".to_string(),
                    "--now".to_string(),
                    "tailnetd".to_string(),
                ],
                vec!["systemctl".to_string(), "daemon-reload".to_string()],
            ],
        })
    }
    #[cfg(target_os = "macos")]
    {
        Ok(InstallPlan {
            bin_dest: PathBuf::from("/usr/local/bin/tailnetd"),
            unit_path: PathBuf::from("/Library/LaunchDaemons/cloud.tailscaled-rs.tailnetd.plist"),
            unit_content: include_str!(
                "../../packaging/launchd/cloud.tailscaled-rs.tailnetd.plist"
            ),
            enable_argv: vec![vec![
                "launchctl".to_string(),
                "bootstrap".to_string(),
                "system".to_string(),
                "/Library/LaunchDaemons/cloud.tailscaled-rs.tailnetd.plist".to_string(),
            ]],
            disable_argv: vec![vec![
                "launchctl".to_string(),
                "bootout".to_string(),
                "system/cloud.tailscaled-rs.tailnetd".to_string(),
            ]],
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        bail!("tnet install is only supported on Linux (systemd) and macOS (launchd)")
    }
}

/// Run one argv (`argv[0]` = program, rest = args) and bail with a clear error if it exits non-zero or
/// could not be spawned. `context` names the step for the error (e.g. "enable" / "disable").
fn run_step(argv: &[String], context: &str) -> Result<()> {
    let (prog, args) = argv
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("empty {context} command in plan"))?;
    let status = std::process::Command::new(prog)
        .args(args)
        .status()
        .with_context(|| format!("running `{}`", argv.join(" ")))?;
    if !status.success() {
        bail!("`{}` failed: {status}", argv.join(" "));
    }
    Ok(())
}

/// Apply an [`InstallPlan`]: copy the running binary into place (0755), write the unit (0644), then run
/// each `enable_argv` command in order. Prints progress per step. Surfaces every failure (a failed copy,
/// unit write, or enable command bails) so a partial install reports exactly what succeeded.
///
/// Must run as root — the CLI ([`run_install`]) gates on `geteuid()==0` before calling this.
pub(crate) fn apply_install(plan: &InstallPlan) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Copy the *running* tailnetd binary to the canonical path. `current_exe` is the binary the
    // operator is invoking (`tailnetd`/`tnet` ship as one binary today), so `tnet install` deploys
    // exactly the code that is running.
    let src = std::env::current_exe().context("resolving the running executable to copy")?;
    // Skip the copy when we are ALREADY the installed binary (a re-install / `install` run straight
    // from /usr/local/bin/tailnetd): copying a file onto itself is at best a no-op and at worst fails
    // (`EINVAL`, or `ETXTBSY` if that path is a running daemon). Prefer a canonicalized compare (so a
    // symlink or `./tailnetd` invocation matches the canonical dest), but fall back to a raw path
    // equality if `current_exe().canonicalize()` fails — otherwise a canonicalize hiccup would let us
    // copy onto the live daemon and hit ETXTBSY (the very case this guard exists to prevent). We still
    // (re)write the unit + re-enable below, so a same-binary re-install still refreshes the service.
    let same_binary = match (src.canonicalize(), plan.bin_dest.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        // Canonicalization failed on one side; fall back to a raw-path compare so we still skip a
        // copy-onto-self when the invoked path is literally the dest.
        _ => src == plan.bin_dest,
    };
    if same_binary {
        println!(
            "→ binary already at {} (running install from it); skipping copy",
            plan.bin_dest.display()
        );
    } else {
        std::fs::copy(&src, &plan.bin_dest)
            .with_context(|| format!("copying {} -> {}", src.display(), plan.bin_dest.display()))?;
        println!("→ copied binary to {}", plan.bin_dest.display());
    }
    // Always (re)assert 0755 — outside the copy branch so a same-binary re-install self-heals wrong
    // perms (and a fresh copy gets them too). chmod on an already-0755 file is a cheap no-op.
    std::fs::set_permissions(&plan.bin_dest, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod 0755 {}", plan.bin_dest.display()))?;

    // Write the embedded unit, then tighten to 0644 (the unit is world-readable config, NOT secret —
    // unlike the state dir, which holds key material and is enforced 0700 by the daemon).
    std::fs::write(&plan.unit_path, plan.unit_content)
        .with_context(|| format!("writing unit {}", plan.unit_path.display()))?;
    std::fs::set_permissions(&plan.unit_path, std::fs::Permissions::from_mode(0o644))
        .with_context(|| format!("chmod 0644 {}", plan.unit_path.display()))?;
    println!("→ wrote unit {}", plan.unit_path.display());

    // Enable/load the service. Each command's failure is surfaced (not swallowed); the prints above
    // already recorded the copy + unit write, so a failure here reports what succeeded.
    for argv in &plan.enable_argv {
        println!("→ {}", argv.join(" "));
        run_step(argv, "enable")?;
    }

    println!(
        "installed; the daemon will start at boot — check `tnet status` (state dir holds the node \
         key; `tnet uninstall` leaves it in place)"
    );
    Ok(())
}

/// Apply the uninstall side of an [`InstallPlan`]: run each `disable_argv` command **best-effort**
/// (the service may already be stopped/unloaded, so a failure is logged and we continue), then remove
/// the unit file (tolerating an already-absent file). **Never touches the state dir** — it holds the
/// node key material, so uninstall deliberately leaves it for a later `install` to resume from.
///
/// Must run as root — the CLI ([`run_uninstall`]) gates on `geteuid()==0` before calling this.
pub(crate) fn apply_uninstall(plan: &InstallPlan) -> Result<()> {
    // Disable/unload best-effort: the service may already be stopped (so `disable --now` /
    // `bootout` returns non-zero), which must not abort the uninstall. Log + continue.
    for argv in &plan.disable_argv {
        println!("→ {}", argv.join(" "));
        if let Err(e) = run_step(argv, "disable") {
            eprintln!("  (continuing) {e}");
        }
    }

    // Remove the unit file (idempotent — a missing file is success).
    match std::fs::remove_file(&plan.unit_path) {
        Ok(()) => println!("→ removed unit {}", plan.unit_path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("→ unit {} already absent", plan.unit_path.display());
        }
        Err(e) => {
            return Err(e).with_context(|| format!("removing unit {}", plan.unit_path.display()));
        }
    }

    println!("uninstalled; node state was left in place (the daemon's state dir is untouched)");
    Ok(())
}

/// `tnet install`: require root, build the [`plan`], and [`apply_install`] it. The CLI entry point —
/// root-check + plan + apply in one clean call.
pub fn run_install() -> Result<()> {
    require_root("install")?;
    let plan = plan()?;
    apply_install(&plan)
}

/// `tnet uninstall`: require root, build the [`plan`], and [`apply_uninstall`] it (disable/unload +
/// remove the unit; leave node state). The CLI entry point.
pub fn run_uninstall() -> Result<()> {
    require_root("uninstall")?;
    let plan = plan()?;
    apply_uninstall(&plan)
}

/// Fail with a clear "must run as root" error unless the effective uid is 0. `verb` is the
/// subcommand name (`install`/`uninstall`) so the message names what to re-run under `sudo`.
fn require_root(verb: &str) -> Result<()> {
    // SAFETY: geteuid() is infallible (no args, no preconditions) — same single-call pattern as
    // `auth::current_euid` / `lib::state_dir`.
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        bail!("tnet {verb} must run as root (try: sudo tnet {verb})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The plan is per-OS; the tests are `cfg`-gated to match, asserting the exact paths/argv and that
    // the embedded unit (`include_str!`) is present + carries an OS-specific sentinel. The sentinel
    // round-trips the include against the committed file: both are the same literal, so a present,
    // non-empty content containing the canonical bin path / launchd label proves the include resolved.

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_plan_paths_and_argv() {
        let p = plan().expect("linux plan");
        assert_eq!(p.bin_dest, PathBuf::from("/usr/local/bin/tailnetd"));
        assert_eq!(
            p.unit_path,
            PathBuf::from("/etc/systemd/system/tailnetd.service")
        );
        assert_eq!(
            p.enable_argv,
            vec![
                vec!["systemctl".to_string(), "daemon-reload".to_string()],
                vec![
                    "systemctl".to_string(),
                    "enable".to_string(),
                    "--now".to_string(),
                    "tailnetd".to_string()
                ],
            ]
        );
        assert_eq!(
            p.disable_argv,
            vec![
                vec![
                    "systemctl".to_string(),
                    "disable".to_string(),
                    "--now".to_string(),
                    "tailnetd".to_string()
                ],
                vec!["systemctl".to_string(), "daemon-reload".to_string()],
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_unit_content_is_the_embedded_systemd_unit() {
        let p = plan().expect("linux plan");
        // The include resolved (file built) and is a systemd unit: non-empty + the canonical
        // ExecStart sentinel, present in BOTH the userspace and TUN units.
        assert!(!p.unit_content.is_empty());
        assert!(
            p.unit_content.contains("ExecStart=/usr/local/bin/tailnetd"),
            "embedded unit missing the canonical ExecStart sentinel"
        );
        // The selected unit must match how the daemon was built (cfg!(feature = "tun")) — a true
        // round-trip against the file `plan()` embeds for this build.
        let expected = if cfg!(feature = "tun") {
            include_str!("../../packaging/systemd/tailnetd-tun.service")
        } else {
            include_str!("../../packaging/systemd/tailnetd.service")
        };
        assert_eq!(p.unit_content, expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tun_unit_is_selected_and_relaxed_under_tun_feature() {
        // The TUN-feature build must select the TUN-relaxed unit (the grants the kernel TUN data path
        // needs), and the userspace build must NOT carry those grants (stays fully sandboxed). This
        // pins the feature-aware selection so a refactor can't silently ship a TUN binary under the
        // userspace sandbox (which would fail closed at /dev/net/tun) or grant CAP_NET_ADMIN to a
        // userspace build that has no need for it.
        // Distinguish the units by ACTIVE directives only. A plain `contains(..)` would false-match
        // the userspace unit's Phase-3 NOTE, which *documents* the TUN directives (`DeviceAllow=...`,
        // `PrivateDevices=false`, `CAP_NET_ADMIN`) as commented examples — so a substring search hits
        // them in BOTH units. We therefore match line-anchored directives: trim each line and require
        // it to EQUAL the directive (a leading `#` makes the trimmed line `"# ..."`, never equal), so
        // commented examples can't satisfy the check.
        let p = plan().expect("linux plan");
        let has_directive =
            |unit: &str, directive: &str| unit.lines().any(|l| l.trim_start() == directive);
        let grants_tun = has_directive(p.unit_content, "DeviceAllow=/dev/net/tun rw")
            && has_directive(p.unit_content, "PrivateDevices=false");
        if cfg!(feature = "tun") {
            assert!(
                grants_tun,
                "TUN-feature build must select the TUN-relaxed unit (DeviceAllow=/dev/net/tun + PrivateDevices=false)"
            );
        } else {
            assert!(
                !grants_tun && has_directive(p.unit_content, "PrivateDevices=true"),
                "userspace build must keep the locked-down unit (PrivateDevices=true, no /dev/net/tun)"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_plan_paths_and_argv() {
        let p = plan().expect("macos plan");
        assert_eq!(p.bin_dest, PathBuf::from("/usr/local/bin/tailnetd"));
        assert_eq!(
            p.unit_path,
            PathBuf::from("/Library/LaunchDaemons/cloud.tailscaled-rs.tailnetd.plist")
        );
        assert_eq!(
            p.enable_argv,
            vec![vec![
                "launchctl".to_string(),
                "bootstrap".to_string(),
                "system".to_string(),
                "/Library/LaunchDaemons/cloud.tailscaled-rs.tailnetd.plist".to_string(),
            ]]
        );
        assert_eq!(
            p.disable_argv,
            vec![vec![
                "launchctl".to_string(),
                "bootout".to_string(),
                "system/cloud.tailscaled-rs.tailnetd".to_string(),
            ]]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_unit_content_is_the_embedded_launchd_plist() {
        let p = plan().expect("macos plan");
        // The include resolved (file built) and is the launchd plist: non-empty + the label sentinel
        // (byte-for-byte the committed packaging/launchd/cloud.tailscaled-rs.tailnetd.plist).
        assert!(!p.unit_content.is_empty());
        assert!(
            p.unit_content.contains("cloud.tailscaled-rs.tailnetd"),
            "embedded plist missing the launchd label sentinel"
        );
        assert!(
            p.unit_content.contains("/usr/local/bin/tailnetd"),
            "embedded plist missing the canonical program path"
        );
        // The include is the same literal the test references — a true round-trip against the file.
        assert_eq!(
            p.unit_content,
            include_str!("../../packaging/launchd/cloud.tailscaled-rs.tailnetd.plist")
        );
    }

    // On an unsupported OS, `plan()` must surface a clear error rather than a bogus plan. This arm
    // only compiles off Linux/macOS, so it is a no-op on the CI targets — present for completeness.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn unsupported_os_errors() {
        let err = plan().expect_err("plan() must error on an unsupported OS");
        assert!(err.to_string().contains("only supported on Linux"));
    }
}
