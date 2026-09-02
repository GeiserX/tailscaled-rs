//! `tailnetd --tun` must be a flag this daemon takes, in Go's grammar — not an unknown argument.
//!
//! Go `tailscaled` registers `--tun` as `tunnel interface name; use "userspace-networking" (beta) to
//! not use TUN`, and it is the single most-copied entry on a `tailscaled` command line: packaged
//! systemd units, container entrypoints and cloud images all pass `--tun=userspace-networking` or
//! `--tun=tailscale0`. This fork carries the data path as a *pref* (`tnet up --tun`), so the flag has
//! no engine field of its own — it resolves onto that pref instead.
//!
//! The unit tests in [`tailscaled_rs::tunflag`] pin the resolution of each candidate. What they
//! cannot see is the surface an operator actually hits: whether clap accepts the flag at all, and
//! where in startup an unusable value is refused. Both are checked here by running the built
//! `tailnetd`, the way `tests/bird_socket_refusal.rs` runs it for `--bird-socket`.
//!
//! Upstream: `cmd/tailscaled/tailscaled.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`.

use std::process::{Command, Output};

/// A socket path that is never created, so `--cleanup` finds nothing to do and exits 0. Keyed by pid
/// so concurrent test binaries cannot collide.
fn unused_socket_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("tailnetd-tun-test-{}.sock", std::process::id()))
}

/// Run the built `tailnetd` with `TS_RS_EXPERIMENT` **removed** from the environment.
///
/// Removing it is what makes "the flag was accepted" observable without starting a daemon: an
/// accepted `--tun` falls through to the experiment gate, which exits 1 with its own message. A
/// refusal terminates earlier, with a message about the flag. The two are told apart by which
/// message came back — and no case can reach a running daemon that would hang the test run.
fn tailnetd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tailnetd"))
        .args(args)
        .env_remove("TS_RS_EXPERIMENT")
        .output()
        .expect("the `tailnetd` binary built for this test should run")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The flag is on `tailnetd`'s own surface (clap's `--help`), so a command line copied from a unit
/// file reaches the daemon instead of "unexpected argument".
#[test]
fn tun_is_a_declared_flag() {
    let out = tailnetd(&["--help"]);
    assert!(out.status.success(), "--help should exit 0");
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("--tun"),
        "`tailnetd --help` should list --tun; got:\n{help}"
    );
}

/// The value every packaged unit file and container entrypoint passes. It must be accepted — this
/// daemon is already a userspace-networking daemon — and startup must continue past it (here into
/// the experiment gate, which is the next thing that stops a daemon with no environment set up).
#[test]
fn userspace_networking_is_accepted_and_startup_continues() {
    let out = tailnetd(&["--tun=userspace-networking"]);
    let err = stderr(&out);
    assert!(
        err.contains("TS_RS_EXPERIMENT"),
        "--tun=userspace-networking should be accepted and startup should reach the experiment \
         gate; got:\n{err}"
    );
    assert!(
        !err.contains("--tun"),
        "there should be no complaint about --tun at all; got:\n{err}"
    );
}

/// Go's `--tun` value is a fallback LIST, tried left to right — which is exactly why its own
/// Synology default is `tailscale0,userspace-networking`. A build with no kernel-TUN transport must
/// take the second entry rather than refuse the line.
#[test]
fn a_fallback_list_lands_on_userspace_networking() {
    let out = tailnetd(&["--tun=tailscale0,userspace-networking"]);
    let err = stderr(&out);
    assert!(
        err.contains("TS_RS_EXPERIMENT"),
        "a list ending in userspace-networking should resolve and startup should continue; \
         got:\n{err}"
    );
    assert!(
        !err.contains("no usable interface"),
        "the fallback entry should have been taken, not reported as unusable; got:\n{err}"
    );
}

/// A kernel TUN device with no kernel-TUN transport compiled in is refused by name, before the
/// experiment gate — so the operator is told which interface could not be provided and why, rather
/// than being sent off to an unrelated environment variable.
#[cfg(not(feature = "tun"))]
#[test]
fn a_device_name_without_the_tun_feature_refuses_by_name() {
    let out = tailnetd(&["--tun=tailscale0"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "an unusable --tun should exit 1; stderr:\n{}",
        stderr(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains("--tun") && err.contains("tailscale0"),
        "should name the flag and echo the rejected value; got:\n{err}"
    );
    assert!(
        err.contains("`tun` cargo feature"),
        "should say why the interface cannot be provided; got:\n{err}"
    );
    assert!(
        err.contains("userspace-networking"),
        "should point at the value that always works; got:\n{err}"
    );
    assert!(
        !err.contains("TS_RS_EXPERIMENT"),
        "the flag refusal must fire before the experiment gate, so the gate's message must not be \
         what the operator sees; got:\n{err}"
    );
}

/// Go's `tap:TAPNAME[:BRIDGENAME]` is a layer-2 device the engine has no transport for. It is
/// refused with that reason — never silently downgraded to the netstack, which would leave a bridge
/// that was asked for and never built.
#[test]
fn tap_is_refused_with_a_named_reason() {
    let out = tailnetd(&["--tun=tap:tap0:br0"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a TAP interface should exit 1; stderr:\n{}",
        stderr(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains("TAP (layer-2) mode is not supported"),
        "should refuse TAP by name; got:\n{err}"
    );
    assert!(
        err.contains("tap:tap0:br0"),
        "should echo the rejected candidate; got:\n{err}"
    );
}

/// Go's `createEngine` opens with `if args.tunname == "" { return errors.New("no --tun value
/// specified") }` — an explicitly empty flag is an error, not a fall-back to the default. Ported
/// sentence and all.
#[test]
fn an_empty_tun_value_is_gos_error() {
    let out = tailnetd(&["--tun="]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "an empty --tun should exit 1; stderr:\n{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("no --tun value specified"),
        "should be Go's own sentence; got:\n{}",
        stderr(&out)
    );
}

/// Go validates `--tun` inside `createEngine`, which a `--cleanup` run never reaches (and its one
/// earlier check, the macOS root refusal, carves cleanup out by hand). Ported: reclaiming a stale
/// socket keeps working with whatever `--tun` the unit file happens to carry.
#[test]
fn cleanup_ignores_an_unusable_tun_value() {
    let socket = unused_socket_path();
    let out = tailnetd(&[
        "--cleanup",
        "--tun=tap:tap0",
        "--socket",
        socket.to_str().expect("temp path should be UTF-8"),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "--cleanup should not be blocked by --tun; stderr:\n{}",
        stderr(&out)
    );
    assert!(
        !stderr(&out).contains("--tun"),
        "cleanup should produce no --tun complaint at all; got:\n{}",
        stderr(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("cleanup: nothing to do"),
        "startup should have continued into --cleanup; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
