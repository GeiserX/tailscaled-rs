//! `tailnetd --tun` — Go `tailscaled`'s tunnel-interface flag, resolved onto this fork's TUN prefs.
//!
//! Go registers the flag as
//!
//! ```text
//! flag.StringVar(&args.tunname, "tun", defaultTunName(),
//!     `tunnel interface name; use "userspace-networking" (beta) to not use TUN`)
//! ```
//!
//! and it is the single most-copied entry on a `tailscaled` command line: packaged systemd units,
//! container entrypoints and cloud images all pass `--tun=userspace-networking` or
//! `--tun=tailscale0`. This fork models the data path as a **pref** instead (`tnet up --tun` /
//! `--tun-name` / `--tun-mtu`, persisted in [`Prefs::tun_enabled`](crate::prefs::Prefs::tun_enabled)),
//! so the flag has no engine field of its own to set. It is still accepted, and this module is the
//! translation: a Go-shaped `--tun` value in, this daemon's transport choice out.
//!
//! ## The grammar, and why it is a list
//!
//! Go's value is "a `/dev/net/tun` tunnel name (`tailscale0`), the string `userspace-networking`,
//! `tap:TAPNAME[:BRIDGENAME]`, or comma-separated list thereof" (`args.tunname`'s own comment), and
//! `createEngine` walks the list in order, taking the first candidate it can actually bring up:
//!
//! ```text
//! func createEngine(logf logger.Logf, sys *tsd.System) (onlyNetstack bool, err error) {
//!     if args.tunname == "" {
//!         return false, errors.New("no --tun value specified")
//!     }
//!     var errs []error
//!     for _, name := range strings.Split(args.tunname, ",") {
//!         onlyNetstack, err = tryEngine(logf, sys, name)
//!         if err == nil {
//!             return onlyNetstack, nil
//!         }
//!         errs = append(errs, err)
//!     }
//!     return false, errors.Join(errs...)
//! }
//! ```
//!
//! That loop is the whole reason `defaultTunName()` can return `"tailscale0,userspace-networking"`
//! on Synology: *try the kernel device, fall back to the netstack*. [`resolve`] reproduces it —
//! including the fallback, so a copied Go command line that asks for a device this build cannot
//! provide lands on `userspace-networking` when the operator said it may, instead of refusing.
//!
//! The difference is *when* the candidates are judged. Go finds out by constructing the engine;
//! this daemon decides here, from three static facts — whether the build carries the `tun` cargo
//! feature, whether the process is root, and whether the engine has a TAP transport at all (it does
//! not). Everything Go can only learn by trying, this fork already knows, so the answer is the same
//! and the failure arrives at startup rather than mid-handshake.
//!
//! Upstream: `cmd/tailscaled/tailscaled.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`.

/// Go's magic tunnel name for "do not use TUN" — the netstack data path this fork defaults to.
///
/// Spelled out rather than inlined because it appears in three roles: a candidate to match, the
/// remedy every refusal below points at, and the value packaged units pass.
pub const USERSPACE_NETWORKING: &str = "userspace-networking";

/// The data path a `--tun` value resolved to — the daemon's two transports, which is what Go's
/// `tryEngine` reduces its `name` to as well (`onlyNetstack = name == "userspace-networking"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunTransport {
    /// The engine's in-process userspace netstack (Go `--tun=userspace-networking`). Unprivileged,
    /// and this fork's default when no `--tun` is given and no TUN pref is set.
    Netstack,
    /// A kernel TUN interface. `name` is the interface to ask for; `None` means "let the platform
    /// default choose", which is what Go's bare `utun` means on macOS ("a magic value that
    /// uses/creates any free number", per `defaultTunName`) and what a `None`
    /// [`Prefs::tun_name`](crate::prefs::Prefs::tun_name) already means to
    /// [`build_config`](crate::ipn::Backend::build_config).
    Tun { name: Option<String> },
}

/// Resolve a `--tun` value against *this* build and process — the [`resolve_with`] entry point the
/// daemon uses, with the two facts it cannot pass in itself already filled in: whether this binary
/// was built with the `tun` cargo feature, and this process's effective uid.
///
/// `goos` is the caller's `runtime.GOOS` spelling (`tailnetd`'s `goos()`), so the darwin-only
/// `utun` carve-out is decided by the same string a ported Go message would print.
pub fn resolve(value: &str, goos: &str) -> Result<TunTransport, String> {
    resolve_with(value, cfg!(feature = "tun"), goos, euid())
}

/// This process's effective uid on unix; `0` elsewhere (Windows has no euid, and its TUN adapter is
/// gated by service privileges this daemon does not model — so the root condition is simply not a
/// reason to reject a candidate there).
fn euid() -> u32 {
    #[cfg(unix)]
    // SAFETY: `geteuid()` takes no arguments, has no preconditions and cannot fail.
    unsafe {
        libc::geteuid()
    }
    #[cfg(not(unix))]
    0
}

/// The pure resolver behind [`resolve`]: Go's `createEngine` loop over a comma-separated `--tun`
/// value, with each candidate judged by what this build can provide.
///
/// * `value` — the raw flag value, exactly as Go's `args.tunname`.
/// * `tun_feature` — whether the `tun` cargo feature is compiled in (there is no kernel-TUN
///   transport in the binary otherwise; [`crate::ipn`]'s `build_config` refuses the same way).
/// * `goos` — `runtime.GOOS` spelling, for the darwin `utun` carve-out.
/// * `euid` — the process's effective uid; a kernel TUN device needs root / `CAP_NET_ADMIN`.
///
/// Returns the chosen transport, or the operator-facing refusal. Two Go error paths port with it:
///
/// * **an empty value is an error**, not "the default" — Go's `createEngine` opens with
///   `if args.tunname == "" { return errors.New("no --tun value specified") }`, and that sentence is
///   reused verbatim here;
/// * **when no candidate works, every candidate's reason is reported**, the way Go returns
///   `errors.Join(errs...)` of each failed `tryEngine`. An operator who wrote a list gets told why
///   each entry was passed over, not just that the list failed.
pub fn resolve_with(
    value: &str,
    tun_feature: bool,
    goos: &str,
    euid: u32,
) -> Result<TunTransport, String> {
    // Go `createEngine`. An explicitly empty `--tun=` is NOT "use the default": Go's flag default is
    // already gone by then (the operator overrode it with the empty string), so it is an error.
    if value.is_empty() {
        return Err("no --tun value specified".to_string());
    }
    let mut reasons = Vec::new();
    for name in value.split(',') {
        match candidate(name, tun_feature, goos, euid) {
            Ok(transport) => return Ok(transport),
            // Go logs each failed candidate and keeps going; collect them for the joined refusal.
            Err(why) => reasons.push((name, why)),
        }
    }
    // One candidate reads as one sentence; a list reports every entry's reason, the way Go returns
    // `errors.Join(errs...)` — an operator who wrote a fallback list gets told why each entry was
    // passed over, not just that the line failed.
    let detail = match reasons.as_slice() {
        [(name, why)] => format!("--tun {name:?}: {why}"),
        many => format!(
            "no usable interface in --tun {value:?}:\n{}",
            many.iter()
                .map(|(name, why)| format!("  {name:?}: {why}"))
                .collect::<Vec<_>>()
                .join("\n")
        ),
    };
    Err(format!(
        "{detail}\n\
         Use --tun={USERSPACE_NETWORKING} for the userspace netstack (this daemon's default data \
         path), or add {USERSPACE_NETWORKING} to the list to fall back to it."
    ))
}

/// Judge one candidate from the comma-separated list — the analogue of one `tryEngine` call.
///
/// The order of the tests is the order in which the answers are knowable and useful: a candidate
/// this binary could never provide (no TAP transport, no `tun` feature) is rejected for *that*
/// reason on every host, so the refusal an operator reads does not change with the uid they happened
/// to run as. Root is checked last, and only for a candidate that is otherwise buildable.
fn candidate(name: &str, tun_feature: bool, goos: &str, euid: u32) -> Result<TunTransport, String> {
    // Go: `onlyNetstack = name == "userspace-networking"`. Always available — the netstack is the
    // engine's default data path and is compiled into every build of this daemon.
    if name == USERSPACE_NETWORKING {
        return Ok(TunTransport::Netstack);
    }
    if name.is_empty() {
        return Err("empty interface name".to_string());
    }
    // Go's `tap:TAPNAME[:BRIDGENAME]` is a layer-2 device, supported on Linux only and behind its
    // own build feature. The `tailscale-rs` engine has no TAP transport at all, so this can never
    // resolve here — but it stays a *named* reason, and (like Go) a later candidate can still win.
    if name.starts_with("tap:") {
        return Err(format!(
            "TAP (layer-2) mode is not supported: the tailscale-rs engine has no TAP transport \
             (Go itself supports {name:?} on Linux only)"
        ));
    }
    if !tun_feature {
        return Err(
            "this daemon was built without the `tun` cargo feature, so it has no kernel-TUN \
             transport; rebuild with `cargo build --features tun`"
                .to_string(),
        );
    }
    if euid != 0 {
        // Go refuses this early and by hand on macOS — `tailscaled requires root; use sudo
        // tailscaled (or use --tun=userspace-networking)` — and discovers it on every other platform
        // when `tstun.New` fails to open the device, which its candidate loop then falls back from.
        // Same outcome either way, so it is one condition here, phrased in Go's words.
        return Err(format!(
            "creating a kernel TUN interface requires root / CAP_NET_ADMIN; use sudo tailnetd (or \
             use --tun={USERSPACE_NETWORKING})"
        ));
    }
    // macOS: bare `utun` is Go's "any free unit number" (`defaultTunName`'s darwin case), and it is
    // NOT a literal interface name — `tun-rs` parses the trailing digits as the unit and rejects an
    // empty one. `None` is this daemon's spelling of the same intent: `build_config` fills it in
    // with the lowest free `utunN` (see `ipn::state::default_tun_name`).
    let name = if goos == "darwin" && name == "utun" {
        None
    } else {
        Some(name.to_string())
    };
    Ok(TunTransport::Tun { name })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The value every packaged unit file and container entrypoint passes. It must resolve to the
    /// netstack on any build, feature or uid — it is the one candidate that never depends on them.
    #[test]
    fn userspace_networking_resolves_to_the_netstack_everywhere() {
        for (feature, goos, euid) in [
            (false, "linux", 1000),
            (true, "linux", 0),
            (false, "darwin", 0),
            (true, "darwin", 501),
        ] {
            assert_eq!(
                resolve_with(USERSPACE_NETWORKING, feature, goos, euid),
                Ok(TunTransport::Netstack),
                "userspace-networking must resolve on ({feature}, {goos}, {euid})"
            );
        }
    }

    /// A device name on a `tun`-feature build running as root is the kernel-TUN path, carrying the
    /// name Go would hand to `tstun.New`.
    #[test]
    fn a_device_name_resolves_to_tun_with_that_name() {
        assert_eq!(
            resolve_with("tailscale0", true, "linux", 0),
            Ok(TunTransport::Tun {
                name: Some("tailscale0".to_string())
            })
        );
    }

    /// Go's darwin default `utun` means "any free unit", not an interface literally called `utun`.
    /// It must reach the daemon as "no name" so the macOS default picks a free `utunN`; the same
    /// spelling on another platform is an ordinary name.
    #[test]
    fn bare_utun_is_any_free_unit_on_darwin_only() {
        assert_eq!(
            resolve_with("utun", true, "darwin", 0),
            Ok(TunTransport::Tun { name: None }),
            "bare `utun` on darwin is Go's any-free-unit magic value"
        );
        assert_eq!(
            resolve_with("utun3", true, "darwin", 0),
            Ok(TunTransport::Tun {
                name: Some("utun3".to_string())
            }),
            "an explicit unit number is a real name, not the magic value"
        );
        assert_eq!(
            resolve_with("utun", true, "linux", 0),
            Ok(TunTransport::Tun {
                name: Some("utun".to_string())
            }),
            "off darwin, `utun` is just a name"
        );
    }

    /// Go's candidate loop is a *fallback* list, which is exactly why `defaultTunName()` returns
    /// `tailscale0,userspace-networking` on Synology. A build with no kernel-TUN transport must take
    /// the second entry rather than refuse.
    #[test]
    fn a_list_falls_back_to_the_first_candidate_this_build_can_provide() {
        assert_eq!(
            resolve_with("tailscale0,userspace-networking", false, "linux", 0),
            Ok(TunTransport::Netstack),
            "no `tun` feature: the device is skipped and the netstack wins"
        );
        assert_eq!(
            resolve_with("tailscale0,userspace-networking", true, "linux", 0),
            Ok(TunTransport::Tun {
                name: Some("tailscale0".to_string())
            }),
            "with the feature and root, the FIRST candidate wins — the list is ordered"
        );
        assert_eq!(
            resolve_with("tap:tap0,tailscale0", true, "linux", 0),
            Ok(TunTransport::Tun {
                name: Some("tailscale0".to_string())
            }),
            "an unsupported TAP entry is skipped, not fatal, when a later entry works"
        );
    }

    /// Go: `if args.tunname == "" { return errors.New("no --tun value specified") }`. An explicitly
    /// empty flag is an error, not a fall-back to the default.
    #[test]
    fn an_empty_value_is_gos_no_tun_value_specified() {
        assert_eq!(
            resolve_with("", true, "linux", 0),
            Err("no --tun value specified".to_string())
        );
    }

    /// TAP is refused by name — the engine has no layer-2 transport — and the message says so
    /// rather than blaming the platform, because unlike Go's the gap here is not Linux-specific.
    #[test]
    fn tap_is_refused_with_a_named_reason() {
        let err = resolve_with("tap:tap0:br0", true, "linux", 0).expect_err("TAP cannot resolve");
        assert!(
            err.contains("TAP (layer-2) mode is not supported"),
            "should name TAP as the missing support; got:\n{err}"
        );
        assert!(
            err.contains("tap:tap0:br0"),
            "should echo the rejected candidate; got:\n{err}"
        );
        assert!(
            err.contains(USERSPACE_NETWORKING),
            "should point at the value that always works; got:\n{err}"
        );
    }

    /// Without the `tun` cargo feature there is no kernel-TUN transport in the binary at all, so a
    /// device name is refused for THAT reason on every host — the uid must not change the answer,
    /// or the same command line would be explained two different ways on two machines.
    #[test]
    fn a_device_name_without_the_tun_feature_names_the_feature_not_the_uid() {
        for euid in [0, 1000] {
            let err = resolve_with("tailscale0", false, "linux", euid)
                .expect_err("no `tun` feature: a device name cannot resolve");
            assert!(
                err.contains("`tun` cargo feature"),
                "should name the missing feature (euid {euid}); got:\n{err}"
            );
            assert!(
                !err.contains("root"),
                "must not blame privileges for a transport that is not in the binary (euid \
                 {euid}); got:\n{err}"
            );
        }
    }

    /// With the transport compiled in, the remaining precondition is root — Go's own macOS refusal
    /// (`tailscaled requires root; use sudo tailscaled (or use --tun=userspace-networking)`), which
    /// every other platform reaches as a failed device open inside `tryEngine`.
    #[test]
    fn a_device_name_as_non_root_says_root_and_names_the_remedy() {
        let err = resolve_with("tailscale0", true, "darwin", 501)
            .expect_err("a kernel TUN device cannot be created as a non-root user");
        assert!(
            err.contains("requires root"),
            "should say root is required; got:\n{err}"
        );
        assert!(
            err.contains(&format!("--tun={USERSPACE_NETWORKING}")),
            "should name Go's remedy; got:\n{err}"
        );
    }

    /// When nothing in the list can be provided, every entry's reason is reported — Go's
    /// `errors.Join(errs...)` over the failed candidates.
    #[test]
    fn an_unusable_list_reports_every_candidates_reason() {
        let err = resolve_with("tap:tap0,tailscale0", false, "linux", 0)
            .expect_err("neither candidate is available on a no-`tun` build");
        assert!(
            err.contains("tap:tap0") && err.contains("TAP (layer-2)"),
            "should carry the TAP candidate's reason; got:\n{err}"
        );
        assert!(
            err.contains("tailscale0") && err.contains("`tun` cargo feature"),
            "should carry the device candidate's reason; got:\n{err}"
        );
        assert!(
            err.contains(USERSPACE_NETWORKING),
            "should tell the operator what to write instead; got:\n{err}"
        );
    }

    /// An empty entry inside a list is skipped with a reason (Go hands `""` to `tstun.New`, which
    /// fails, and the loop moves on) — a trailing comma must not take the whole daemon down.
    #[test]
    fn an_empty_entry_inside_a_list_is_skipped() {
        assert_eq!(
            resolve_with(",userspace-networking", true, "linux", 0),
            Ok(TunTransport::Netstack)
        );
        let err = resolve_with("tailscale0,", false, "linux", 0)
            .expect_err("no candidate is available here");
        assert!(
            err.contains("empty interface name"),
            "the empty entry should have its own reason; got:\n{err}"
        );
    }
}
