//! `tnet exit-node list` must take Go's grammar: `--filter`, Go's refusals, Go's exit codes.
//!
//! Go's `runExitNodeList` (cmd/tailscale/cli/exitnode.go) refuses a stray positional with
//! `unexpected non-flag arguments to 'tailscale exit-node list'` **before** it contacts the daemon,
//! and its `list` sub-command carries one flag: `--filter` ("filter exit nodes by country"). Until
//! this change the fork's `list` took neither, so `tailscale exit-node list --filter=Canada` copied
//! from Go's docs died at argument parsing, and a typo'd positional was answered by clap instead of
//! by the command.
//!
//! The unit tests next to [`format_exit_node_list`](../src/bin/tnet.rs) pin the rendering and both of
//! Go's error strings. What they cannot see is the surface an operator actually hits: whether clap
//! accepts the flag at all, and *where* an unusable invocation fails. Those are checked here by
//! running the built `tnet`, the way `tests/whois_flow_arguments.rs` runs it for `whois`.
//!
//! HONEST SCOPE: `--filter` is accepted and applied, but on this build it can only ever reach Go's
//! `no exit nodes found for %q`. Go matches it against each peer's `Location.Country`, and the pinned
//! engine surfaces no per-peer `Location` (engine ask #37) — so every peer has an empty country, which
//! is the same state Go is in for exit nodes that declare no location.
//!
//! Upstream: `cmd/tailscale/cli/exitnode.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`.

use std::process::{Command, Output};

/// A socket path that is never created, so every invocation below either fails before the daemon
/// round trip (the refusal) or fails *at* it (the accepted command lines) — never against whatever
/// daemon happens to be running on the build machine. Keyed by pid so concurrent test binaries
/// cannot collide.
fn unused_socket_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "tnet-exit-node-list-test-{}.sock",
        std::process::id()
    ))
}

/// Run the built `tnet` against the never-created socket.
fn tnet(args: &[&str]) -> Output {
    let socket = unused_socket_path();
    Command::new(env!("CARGO_BIN_EXE_tnet"))
        .arg("--socket")
        .arg(&socket)
        .args(args)
        .output()
        .expect("the `tnet` binary built for this test should run")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Go's flag is on the fork's own surface, so a command line copied from Go's docs parses.
#[test]
fn exit_node_list_help_documents_gos_filter_flag() {
    let out = tnet(&["exit-node", "list", "--help"]);
    assert!(out.status.success(), "--help should exit 0");
    let help = String::from_utf8_lossy(&out.stdout);
    for expected in ["--filter", "COUNTRY", "country"] {
        assert!(
            help.contains(expected),
            "`tnet exit-node list --help` should mention {expected}; got:\n{help}"
        );
    }
    assert!(
        !help.contains("ARGS"),
        "the positional exists only to reproduce Go's refusal and must stay hidden:\n{help}"
    );
}

/// The flag survives argument parsing and gets as far as the daemon connection, which is the only
/// thing left to fail here.
#[test]
fn a_go_spelled_country_filter_reaches_the_daemon_round_trip() {
    let out = tnet(&["exit-node", "list", "--filter=Canada"]);
    assert!(
        !out.status.success(),
        "no daemon listens on the test socket, so this must fail"
    );
    let err = stderr(&out);
    assert!(
        err.contains("querying status at"),
        "the only remaining failure should be the daemon connection, not argument parsing: {err}"
    );
    for clap_noise in ["unexpected argument", "invalid value", "Usage:"] {
        assert!(
            !err.contains(clap_noise),
            "the command line must parse cleanly, but clap said {clap_noise:?}: {err}"
        );
    }
}

/// Go refuses a stray positional itself, before it opens the LocalAPI connection — so the operator is
/// told about the argument, not about a socket.
#[test]
fn a_stray_positional_is_refused_the_way_go_refuses_it() {
    let out = tnet(&["exit-node", "list", "Canada"]);
    assert!(
        !out.status.success(),
        "a stray positional must exit non-zero"
    );
    let err = stderr(&out);
    assert!(
        err.contains("unexpected non-flag arguments to 'tnet exit-node list'"),
        "Go's refusal should be reproduced verbatim: {err}"
    );
    assert!(
        !err.contains("querying status at"),
        "the refusal must come before the daemon round trip: {err}"
    );
}
