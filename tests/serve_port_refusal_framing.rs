//! `tnet serve`/`tnet funnel` must deliver a flag-grammar refusal the way `tailscale` delivers it.
//!
//! Upstream is `cmd/tailscale/cli/serve_v2.go` (`runServeCombined`) @
//! `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8` (v1.102.4). Every refusal in that function is simply
//! returned except one: when `srvTypeAndPortFromFlags` fails, Go prints the cause ITSELF —
//! `fmt.Fprintf(e.stderr(), "error: %v\n\n", err)` — and then returns `errHelpFunc(subcmd)`, whose
//! whole text is ``try `tailscale <serve|funnel> --help` for usage info``. Go's `main` prints that
//! second error bare and exits 1, so three things land on stderr: the cause under an `error: `
//! prefix, a blank line, and a pointer at the help page for the command that was actually run.
//!
//! The unit tests next to `check_serve_flags` (src/bin/tnet.rs) pin the rendering. What they cannot
//! see is the delivery — that the built binary writes those bytes to stderr rather than letting the
//! error propagate to `main` and print as a single `Error: try …` line with the cause dropped, that
//! stdout stays empty, and that the status is 1. That is what this file checks, by running the
//! binary.
//!
//! No daemon is needed and none is started: the refusal happens in the first statement of
//! `run_serve_v2`, before any LocalAPI round trip, so the `--socket` path below is never connected
//! to. A command line that reached the socket would fail at `connect` rather than hang, which is
//! itself visible as a wrong error here.

use std::path::PathBuf;
use std::process::{Command, Output};

/// A socket path that is never created, so a command line which slips past the refusal cannot
/// instead reach whatever daemon happens to be running on the build machine.
fn unused_socket_path() -> PathBuf {
    std::env::temp_dir().join(format!("tnet-serve-framing-{}.sock", std::process::id()))
}

fn tnet(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tnet"))
        .arg("--socket")
        .arg(unused_socket_path())
        .args(args)
        .output()
        .expect("the `tnet` binary built for this test should run")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// `serve --tcp=70000`: Go's `error: %v\n\n` + the serve help hint, exit 1, nothing on stdout.
///
/// The cause names the HTTPS flag for a `--tcp` port because Go formats `srvType` before its loop
/// assigns it; that sentence is kept as Go writes it, which is also why the hint earns its place —
/// it is the only part of this output that points at where the four port flags are documented.
#[test]
fn a_too_high_port_is_framed_like_go_and_exits_one() {
    let out = tnet(&["serve", "--tcp=70000", "3000"]);
    assert_eq!(
        stderr(&out),
        "error: port number 70000 is too high for https flag\n\ntry `tnet serve --help` for usage \
         info\n"
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
}

/// The same through `funnel`, which shares `serve_v2.go`: `errHelpFunc` names
/// `infoMap[subcmd].Name`, so the hint has to follow the command the operator actually typed.
#[test]
fn the_hint_names_the_subcommand_that_was_run() {
    let out = tnet(&["funnel", "--https=70000", "3000"]);
    assert_eq!(
        stderr(&out),
        "error: port number 70000 is too high for https flag\n\ntry `tnet funnel --help` for usage \
         info\n"
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
}

/// `srvTypeAndPortFromFlags`' other refusal comes out framed too: the framing belongs to the
/// function Go wraps, not to the one message.
#[test]
fn the_multiple_types_refusal_is_framed_too() {
    let out = tnet(&["serve", "--https=443", "--tcp=22", "3000"]);
    let err = stderr(&out);
    assert!(
        err.starts_with("error: cannot serve multiple types"),
        "{err}"
    );
    assert!(
        err.ends_with("\n\ntry `tnet serve --help` for usage info\n"),
        "{err}"
    );
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert_eq!(stdout(&out), "");
}

/// …and only that function's. A refusal `runServeCombined` simply RETURNS must reach stderr as one
/// plain line with no hint after it — otherwise the framing would be decoration rather than a port.
#[test]
fn a_refusal_go_returns_plainly_carries_no_hint() {
    for args in [
        &["serve", "--tun", "3000"][..],
        &["serve", "--tcp=2222", "--proxy-protocol=1", "3000"],
        &["serve", "--set-path=/a/../b", "3000"],
    ] {
        let out = tnet(args);
        let err = stderr(&out);
        assert!(!err.contains("--help` for usage info"), "{args:?}: {err}");
        assert!(!err.starts_with("error: "), "{args:?}: {err}");
        assert_eq!(out.status.code(), Some(1), "{args:?}: {err}");
        assert_eq!(stdout(&out), "", "{args:?}");
    }
}

/// Go runs `cleanURLPath` BEFORE it resolves the listener, so a command line with both a bad mount
/// point and a bad port is refused for the mount point — the framed port refusal never happens.
#[test]
fn the_mount_point_is_cleaned_before_the_port_is_resolved() {
    let out = tnet(&["serve", "--set-path=/a/../b", "--https=70000", "3000"]);
    let err = stderr(&out);
    assert!(
        err.contains(r#"failed to clean the mount point: invalid mount point "/a/../b""#),
        "{err}"
    );
    assert!(!err.contains("70000"), "{err}");
    assert_eq!(out.status.code(), Some(1), "{err}");
}
