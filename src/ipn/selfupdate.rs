//! Can this installation replace its own binary? — the one predicate behind both `tnet update --yes`
//! and the `--auto-update` preference.
//!
//! Go splits the question in two. `clientupdate` owns the *mechanics* (which package manager or
//! tarball owns the binary, and how to swap it), and `feature.CanAutoUpdate()` reduces that to a
//! single bool which `checkAutoUpdatePrefsLocked` (`ipn/ipnlocal/local.go`) consults before it lets
//! a node opt in to `AutoUpdate.Apply`. The two are the same question asked at two moments: "will an
//! update work if one is triggered now?" and "may this node promise the admin console that one
//! will?".
//!
//! This fork already answered the first question — twice, in the install path of `tnet update`:
//! a binary a package manager owns is never swapped in place, and a host with no published release
//! artifact has nothing to swap it *with*. Those two refusals ARE this fork's `CanAutoUpdate`, so
//! they live here, where both callers can reach them, rather than in the CLI where only `update`
//! could.
//!
//! Why the *running* binary answers for the whole installation: `tailnetd` and `tnet` ship from one
//! release — the same tarball, the same Homebrew formula — so whichever of the two is asking, its
//! own provenance is the installation's provenance. That matters because the caller that needs the
//! answer most is the daemon (it is the process that advertises `Hostinfo.AllowsUpdate`), while the
//! binary that would do the replacing is the CLI.

use std::path::Path;

/// The host target triple this build's release assets are named with (`tailscaled-rs-vX.Y.Z-<triple>`,
/// see the release workflow). The fork publishes Linux glibc assets only; `None` on a platform with no
/// published asset (e.g. macOS) so the updater can report that honestly instead of 404-ing.
pub fn host_release_triple() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        // Only Linux x86_64/aarch64 release assets are published today (see `.github/workflows/release.yml`).
        _ => None,
    }
}

/// The Homebrew formula that owns the file at `exe`, if any — the `<formula>` of a
/// `<prefix>/Cellar/<formula>/<version>/bin/<binary>` path. Pure → unit-testable.
///
/// Homebrew installs every file of a package under `<prefix>/Cellar/<formula>/<version>/` and links
/// the binaries into `<prefix>/bin` as symlinks, so a *resolved* executable path is always the Cellar
/// one. Matching on the `Cellar` component rather than a hard-coded prefix covers every prefix
/// Homebrew uses — `/usr/local` (Intel macOS), `/opt/homebrew` (Apple Silicon),
/// `/home/linuxbrew/.linuxbrew` (Linux), and an operator's custom one.
pub fn homebrew_formula_owning(exe: &Path) -> Option<String> {
    let mut comps = exe.components();
    while let Some(c) = comps.next() {
        if c.as_os_str() != "Cellar" {
            continue;
        }
        let formula = comps.next()?.as_os_str().to_str()?.to_string();
        // `Cellar/<formula>/<version>/…`: a path that stops at the formula directory names no
        // installed file, so it is not evidence that this binary came from Homebrew.
        comps.next()?;
        return Some(formula);
    }
    None
}

/// The Homebrew formula that owns the *running* binary, if any. Resolves symlinks first, since the
/// binary on `PATH` is `<prefix>/bin/<name>`, a symlink into the Cellar.
pub fn running_binary_homebrew_formula() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    homebrew_formula_owning(&exe)
}

/// Why `update --yes` refuses on a Homebrew-installed binary, and what to run instead.
///
/// The same refusal Go makes when its binary came from a package manager rather than from a release
/// tarball (`clientupdate/clientupdate.go`, `updateFreeBSD`: "Tailscale was not installed via pkg,
/// binary updates on FreeBSD are not supported; please reinstall Tailscale using pkg or update
/// manually", plus the `pkg upgrade tailscale` hint). Swapping the binary in place would overwrite a
/// file Homebrew owns: the Cellar keeps one directory per installed version, so the next `brew`
/// command would report a version that is no longer on disk, and the following `brew upgrade` would
/// silently discard the update. Pure → unit-testable.
pub fn homebrew_update_refusal(formula: &str) -> String {
    format!(
        "this `tnet` was installed by Homebrew (it is a file of the `{formula}` formula, under \
         Homebrew's Cellar), and binary updates are not supported for a Homebrew install: replacing \
         it in place would overwrite a file Homebrew owns and leave `brew` reporting a version that \
         is no longer installed. Update it with `brew update && brew upgrade {formula}` instead \
         (or install a release tarball outside the Homebrew prefix and update that)"
    )
}

/// Go `feature.CanAutoUpdate()`, decided from the two facts the install path of `tnet update`
/// already decides on — given as arguments so the decision is pure and both outcomes are testable
/// on any host. `Some(reason)` = this installation can never replace its own binary, and `reason`
/// says why; `None` = it can.
///
/// `homebrew_formula` is the formula owning the running binary ([`running_binary_homebrew_formula`])
/// and `release_triple` the published artifact for this host ([`host_release_triple`]);
/// `platform` is the `os/arch` pair, used only to name the host in the message.
///
/// The package-manager question is asked first, matching the order `tnet update --yes` refuses in:
/// where both apply, "run `brew upgrade`" is the more useful answer than "there is no tarball for
/// your platform".
pub fn auto_update_refusal_for(
    homebrew_formula: Option<&str>,
    release_triple: Option<&str>,
    platform: &str,
) -> Option<String> {
    if let Some(formula) = homebrew_formula {
        return Some(format!(
            "Auto-updates are not supported on this installation: this binary is a file of the \
             `{formula}` Homebrew formula, so an update can only come from `brew upgrade \
             {formula}` — `tnet update --yes` refuses to replace a file Homebrew owns"
        ));
    }
    if release_triple.is_none() {
        // Go's wording, verbatim, then the local reason: the fork ships Linux x86_64/aarch64
        // tarballs only, so on any other host `tnet update --yes` has no artifact to install.
        return Some(format!(
            "Auto-updates are not supported on this platform. This build's platform ({platform}) \
             has no published release artifact (the project ships Linux x86_64/aarch64 tarballs \
             only), so `tnet update --yes` cannot replace this binary"
        ));
    }
    None
}

/// [`auto_update_refusal_for`] applied to *this* process's host and binary. `None` = this
/// installation can replace its own binary.
pub fn auto_update_refusal() -> Option<String> {
    auto_update_refusal_for(
        running_binary_homebrew_formula().as_deref(),
        host_release_triple(),
        &format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
    )
}

/// Go `feature.CanAutoUpdate()` as the bool its callers read.
pub fn can_auto_update() -> bool {
    auto_update_refusal().is_none()
}

/// Go `checkAutoUpdatePrefsLocked` (`ipn/ipnlocal/local.go`), the fifth child of `checkPrefsLocked`:
/// refuse an auto-update **opt-in** that the node could never honour. `Some(message)` = refuse.
///
/// `apply` is the prospective [`AutoUpdate.Apply`](crate::prefs::Prefs::auto_update_apply) tri-state
/// and `host_refusal` the answer from [`auto_update_refusal`] (passed in, so the rule is pure and a
/// test can drive both host outcomes anywhere). Like Go, only `EqualBool(true)` is checked: an
/// explicit decline and a never-stated preference are legal everywhere, because neither claims
/// anything to the tailnet.
///
/// The rule is not about this daemon's own appetite for updating itself — it is about what the pref
/// *says*. `AutoUpdate.Apply` is not local state: the engine advertises it as `Hostinfo.AllowsUpdate`
/// on registration and on every map request, which tells the tailnet admin that a remote update
/// trigger for this node will be honoured. Accepting the claim from an installation that cannot
/// replace its own binary is how an admin ends up believing a fleet is patched.
pub fn check_auto_update_pref(apply: Option<bool>, host_refusal: Option<&str>) -> Option<String> {
    if apply != Some(true) {
        return None;
    }
    let reason = host_refusal?;
    Some(format!(
        "{reason}. Enabling auto-update would advertise `Hostinfo.AllowsUpdate` to the tailnet — a \
         promise that a remote update trigger is honoured — which this node cannot keep. Decline it \
         (`--no-auto-update`) or leave it unstated"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_release_triple_is_linux_or_none() {
        // On a published-asset platform it's a Linux glibc triple; elsewhere (e.g. macOS) it's None
        // so `update --yes` can report "no artifact for this platform" instead of 404-ing.
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => {
                assert_eq!(host_release_triple(), Some("x86_64-unknown-linux-gnu"))
            }
            ("linux", "aarch64") => {
                assert_eq!(host_release_triple(), Some("aarch64-unknown-linux-gnu"))
            }
            _ => assert_eq!(host_release_triple(), None),
        }
    }

    #[test]
    fn homebrew_formula_owning_recognises_every_cellar_prefix() {
        // The three prefixes Homebrew ships with, plus a custom one: the formula is the component
        // after `Cellar`, whatever the prefix is.
        for prefix in [
            "/usr/local",
            "/opt/homebrew",
            "/home/linuxbrew/.linuxbrew",
            "/srv/brew",
        ] {
            let exe =
                std::path::PathBuf::from(format!("{prefix}/Cellar/tailscaled-rs/0.52.2/bin/tnet"));
            assert_eq!(
                homebrew_formula_owning(&exe).as_deref(),
                Some("tailscaled-rs"),
                "{} should be recognised as a Homebrew-owned file",
                exe.display()
            );
        }
    }

    #[test]
    fn homebrew_formula_owning_ignores_non_homebrew_paths() {
        // The paths a release tarball / `cargo install` / a distro package put the binary at — none
        // of them are Homebrew's, so `update --yes` must NOT refuse for them.
        for path in [
            "/usr/local/bin/tnet",
            "/usr/bin/tnet",
            "/home/alice/.cargo/bin/tnet",
            "/opt/tailscaled-rs/bin/tnet",
            // A directory literally named Cellar but with nothing installed under it: `Cellar/x`
            // alone names no file, so it is not evidence of a Homebrew install.
            "/usr/local/Cellar/tailscaled-rs",
        ] {
            assert_eq!(
                homebrew_formula_owning(std::path::Path::new(path)),
                None,
                "{path} is not a Homebrew-owned file"
            );
        }
    }

    #[test]
    fn homebrew_update_refusal_names_the_formula_and_the_brew_command() {
        // The refusal has to be actionable: it must say Homebrew owns the binary and give the exact
        // command that updates it (Go's package-manager refusals do the same — see
        // `clientupdate.updateFreeBSD`'s `pkg upgrade tailscale` hint).
        let msg = homebrew_update_refusal("tailscaled-rs");
        assert!(msg.contains("Homebrew"), "{msg}");
        assert!(
            msg.contains("brew update && brew upgrade tailscaled-rs"),
            "the refusal must name the command that does work: {msg}"
        );
        // The formula name is carried through rather than hard-coded, so a renamed/forked formula
        // still gets a command that works.
        assert!(
            homebrew_update_refusal("tailscaled-rs-git").contains("brew upgrade tailscaled-rs-git"),
            "the formula name must be interpolated, not assumed"
        );
    }

    // --- the CanAutoUpdate predicate ---------------------------------------------------------

    #[test]
    fn an_installation_that_can_replace_its_binary_is_updatable() {
        // A release tarball on a published platform: nothing owns the binary and there is an
        // artifact to install, so the node may honestly claim auto-update.
        assert_eq!(
            auto_update_refusal_for(None, Some("x86_64-unknown-linux-gnu"), "linux/x86_64"),
            None
        );
    }

    #[test]
    fn a_package_manager_owned_binary_is_not_updatable() {
        // Same condition `tnet update --yes` refuses on, and it is asked FIRST: where both apply,
        // `brew upgrade` is the useful answer, not "no tarball for your platform".
        let refusal = auto_update_refusal_for(Some("tailscaled-rs"), None, "macos/aarch64")
            .expect("a Homebrew-owned binary can never replace itself");
        assert!(
            refusal.contains("Auto-updates are not supported"),
            "{refusal}"
        );
        assert!(refusal.contains("brew upgrade tailscaled-rs"), "{refusal}");
        assert!(
            !refusal.contains("no published release artifact"),
            "the package-manager answer must win over the platform one: {refusal}"
        );
    }

    #[test]
    fn a_platform_with_no_published_artifact_is_not_updatable() {
        // macOS, which this daemon builds and runs on: no tarball is published for it, so the
        // binary provably cannot replace itself.
        let refusal = auto_update_refusal_for(None, None, "macos/aarch64")
            .expect("a platform with no artifact can never replace its binary");
        assert!(
            refusal.contains("Auto-updates are not supported on this platform."),
            "Go's wording must survive the port: {refusal}"
        );
        assert!(refusal.contains("macos/aarch64"), "{refusal}");
    }

    #[test]
    fn only_an_opt_in_is_ever_refused() {
        // Go acts on `Apply.EqualBool(true)` alone: declining, and never stating a preference, are
        // legal on every installation — neither promises the tailnet anything.
        let cannot = "Auto-updates are not supported on this platform. …";
        assert_eq!(check_auto_update_pref(None, Some(cannot)), None);
        assert_eq!(check_auto_update_pref(Some(false), Some(cannot)), None);
        // And on a host that CAN update, the opt-in passes.
        assert_eq!(check_auto_update_pref(Some(true), None), None);
    }

    #[test]
    fn an_opt_in_on_an_installation_that_cannot_update_is_refused() {
        let cannot = auto_update_refusal_for(None, None, "macos/aarch64").unwrap();
        let err = check_auto_update_pref(Some(true), Some(&cannot))
            .expect("opting in on a node that can never apply an update must be refused");
        // The refusal carries the host's reason AND why the pref is not a local preference.
        assert!(
            err.contains("Auto-updates are not supported on this platform."),
            "{err}"
        );
        assert!(err.contains("Hostinfo.AllowsUpdate"), "{err}");
        assert!(err.contains("--no-auto-update"), "{err}");
    }

    #[test]
    fn the_hosts_own_answer_agrees_with_its_parts() {
        // The env-reading wrapper is exactly the pure rule applied to this host — no second
        // definition of updatability that could drift from `tnet update`'s.
        let expected = auto_update_refusal_for(
            running_binary_homebrew_formula().as_deref(),
            host_release_triple(),
            &format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
        );
        assert_eq!(auto_update_refusal(), expected);
        assert_eq!(can_auto_update(), expected.is_none());
    }
}
