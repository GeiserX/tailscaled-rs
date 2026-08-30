//! `tailnetd --bird-socket <path>` must refuse *as a named refusal*, not die as an unknown argument.
//!
//! Go `tailscaled` ships `--bird-socket` for a subnet router that hands its advertised routes to a
//! BIRD BGP daemon, and on a build with no BIRD hook linked in it refuses the flag loudly at startup
//! (`--bird-socket is not supported on %s`) rather than ignoring it. This fork has no BIRD
//! integration at all — the toggle lives in the engine's reconfigure cycle and the `tailscale-rs`
//! engine exposes no hook — so it is permanently in Go's "no hook" case and refuses the same way.
//!
//! The unit tests next to [`bird_socket_refusal`](../src/bin/tailnetd.rs) pin the decision function.
//! What they cannot see is the surface an operator actually hits: whether clap accepts the flag at
//! all, and *where* in startup the refusal fires. Both are checked here by running the built
//! `tailnetd`, the way `tests/restock_backlog_flag_names.rs` runs the built `tnet`.
//!
//! Upstream: `cmd/tailscaled/tailscaled.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`.

use std::process::{Command, Output};

/// A socket path that is never created, so `--cleanup` finds nothing to do and exits 0. Keyed by
/// pid so concurrent test binaries cannot collide.
fn unused_socket_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("tailnetd-bird-test-{}.sock", std::process::id()))
}

/// Run the built `tailnetd` with `TS_RS_EXPERIMENT` **removed** from the environment.
///
/// Removing it is deliberate: every case below must terminate on a flag decision made *before* the
/// experiment gate. If a refusal ever regressed into a fall-through, the daemon would hit the gate
/// and exit with the gate's message — a clean assertion failure — instead of coming up and hanging
/// the test run.
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

/// The flag is on `tailnetd`'s own surface (clap's `--help`, not a second copy of the flag list), so
/// a command line copied from Go reaches the refusal instead of "unexpected argument".
#[test]
fn bird_socket_is_a_declared_flag() {
    let out = tailnetd(&["--help"]);
    assert!(out.status.success(), "--help should exit 0");
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("--bird-socket"),
        "`tailnetd --help` should list --bird-socket; got:\n{help}"
    );
}

/// A non-empty path is refused with a message that names the flag and the missing integration, and
/// exits 1 — reached before the experiment gate, so the operator is told about the *flag* rather
/// than about an unrelated environment variable.
#[test]
fn bird_socket_path_refuses_with_a_named_reason() {
    let out = tailnetd(&["--bird-socket", "/run/bird.ctl"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a --bird-socket path should exit 1; stderr:\n{}",
        stderr(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains("--bird-socket is not supported"),
        "should refuse by name; got:\n{err}"
    );
    assert!(
        err.contains("/run/bird.ctl"),
        "should echo the rejected path; got:\n{err}"
    );
    assert!(
        err.contains("engine exposes no BIRD hook"),
        "should say why it is unsupported; got:\n{err}"
    );
    assert!(
        !err.contains("TS_RS_EXPERIMENT"),
        "the flag refusal must fire before the experiment gate, so the gate's message must not be \
         what the operator sees; got:\n{err}"
    );
}

/// Go checks `--bird-socket` at the top of `main`, above its `--cleanup` exit, so the refusal wins
/// over cleanup. Ported: `--cleanup --bird-socket <path>` refuses rather than quietly cleaning up.
#[test]
fn bird_socket_refusal_precedes_cleanup() {
    let socket = unused_socket_path();
    let out = tailnetd(&[
        "--cleanup",
        "--bird-socket",
        "/run/bird.ctl",
        "--socket",
        socket.to_str().expect("temp path should be UTF-8"),
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "--cleanup must not mask the --bird-socket refusal; stderr:\n{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("--bird-socket is not supported"),
        "should be the bird refusal, not a cleanup result; got:\n{}",
        stderr(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "cleanup should never have run, so it should print nothing"
    );
}

/// Go's guard is `birdSocketPath != ""`, so an explicitly empty `--bird-socket` means "no BIRD
/// socket" — identical to omitting the flag. Checked end-to-end through the real binary: startup
/// continues past the flag (here into `--cleanup`, which exits 0 having found no socket to remove).
#[test]
fn empty_bird_socket_is_not_a_refusal() {
    let socket = unused_socket_path();
    let out = tailnetd(&[
        "--cleanup",
        "--bird-socket=",
        "--socket",
        socket.to_str().expect("temp path should be UTF-8"),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "an empty --bird-socket should be inert, letting --cleanup run; stderr:\n{}",
        stderr(&out)
    );
    assert!(
        !stderr(&out).contains("--bird-socket"),
        "an empty path should produce no bird complaint at all; got:\n{}",
        stderr(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("cleanup: nothing to do"),
        "startup should have continued into --cleanup; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
