//! `tnet whois` must take Go's flow arguments: `whois [--json] [--proto tcp|udp] ip[:port]`.
//!
//! Go's `whois` is a *flow* lookup — `runWhoIs` (cmd/tailscale/cli/whois.go) calls
//! `localClient.WhoIsProto(ctx, whoIsArgs.proto, args[0])`, where `--proto` is documented as
//! `protocol; one of "tcp" or "udp"; empty means both` and the argument is `ip[:port]`. Until this
//! change the fork's `whois` took a bare `IP` positional, so a command copied from Go
//! (`tailscale whois --proto=tcp 100.64.0.9:22`) died at argument parsing.
//!
//! The unit tests next to [`whois_target`](../src/bin/tnet.rs) pin the pure argument functions —
//! Go's two arity refusals, the `ip[:port]` split, and the `--proto` value set. What they cannot see
//! is the surface an operator actually hits: whether clap accepts the flag and the `ip:port`
//! spelling at all, and *where* an unusable invocation fails. Those are checked here by running the
//! built `tnet`, the way `tests/tpm_flag_refusal.rs` runs `tailnetd` for its flags.
//!
//! HONEST SCOPE: `--proto` is accepted and carried to the daemon, but it cannot change the answer on
//! this build. Go consults it (and the port) only in its `ProxyMapper` fallback, reached when the
//! address matches no node in the netmap; for a tailnet address — the only kind this fork resolves —
//! Go answers by IP and ignores both too. The pinned engine keeps no proxied-flow table (engine ask
//! #35). That is the *request* half of the gap; `WhoisReport.user` always being empty is the
//! response half and is tracked separately.
//!
//! Upstream: `cmd/tailscale/cli/whois.go` (and `ipn/ipnlocal.LocalBackend.WhoIs`) @
//! `53a0d659afa51835dd7a9283873cca44261454f8`.

use std::process::{Command, Output};

/// A socket path that is never created, so every invocation below either fails before the daemon
/// round trip (the refusals) or fails *at* it (the accepted command line) — never against whatever
/// daemon happens to be running on the build machine. Keyed by pid so concurrent test binaries
/// cannot collide.
fn unused_socket_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("tnet-whois-test-{}.sock", std::process::id()))
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

/// Go's flag is on the fork's own surface, so a command line copied from Go's docs reaches the
/// lookup instead of "unexpected argument".
#[test]
fn whois_help_documents_gos_proto_flag_and_ip_port_argument() {
    let out = tnet(&["whois", "--help"]);
    assert!(out.status.success(), "--help should exit 0");
    let help = String::from_utf8_lossy(&out.stdout);
    for expected in ["--proto", "IP[:PORT]", "tcp", "udp"] {
        assert!(
            help.contains(expected),
            "`tnet whois --help` should mention {expected}; got:\n{help}"
        );
    }
}

/// The command from the bead — Go's flag and Go's argument form together — must survive argument
/// parsing and get as far as the daemon connection, which is the only thing left to fail here.
#[test]
fn a_go_spelled_flow_whois_reaches_the_daemon_round_trip() {
    let out = tnet(&["whois", "--proto=tcp", "100.64.0.9:22"]);
    assert!(
        !out.status.success(),
        "no daemon listens on the test socket, so this must fail"
    );
    let err = stderr(&out);
    assert!(
        err.contains("talking to daemon at"),
        "the only remaining failure should be the daemon connection, not argument parsing: {err}"
    );
    for clap_noise in ["unexpected argument", "invalid value", "Usage:"] {
        assert!(
            !err.contains(clap_noise),
            "the Go-spelled command must not be refused at parse time ({clap_noise}): {err}"
        );
    }
}

/// Go `runWhoIs`'s two arity refusals, verbatim, and before any daemon round trip.
#[test]
fn whois_ports_gos_two_argument_refusals() {
    let missing = tnet(&["whois"]);
    assert!(!missing.status.success(), "zero arguments must fail");
    let err = stderr(&missing);
    assert!(
        err.contains("missing argument, expected one peer"),
        "expected Go's zero-argument message: {err}"
    );

    let too_many = tnet(&["whois", "100.64.0.9", "100.64.0.10"]);
    assert!(!too_many.status.success(), "two arguments must fail");
    let err = stderr(&too_many);
    assert!(
        err.contains("too many arguments, expected at most one peer"),
        "expected Go's two-argument message: {err}"
    );

    for out in [&missing, &too_many] {
        assert!(
            !stderr(out).contains("talking to daemon at"),
            "an unusable invocation must not cost a daemon round trip"
        );
    }
}

/// A `--proto` value outside Go's documented pair, and an argument that is neither an IP nor
/// `ip:port`, are both refused locally — naming what was passed, and without a daemon round trip.
#[test]
fn whois_refuses_a_bad_proto_and_a_bad_address_before_the_daemon() {
    let bad_proto = tnet(&["whois", "--proto=sctp", "100.64.0.9"]);
    assert!(!bad_proto.status.success(), "an unknown proto must fail");
    let err = stderr(&bad_proto);
    assert!(
        err.contains("expected \"tcp\" or \"udp\""),
        "the refusal should name Go's documented values: {err}"
    );

    let bad_addr = tnet(&["whois", "peer-b"]);
    assert!(!bad_addr.status.success(), "a non-address must fail");
    let err = stderr(&bad_addr);
    assert!(
        err.contains("peer-b") && err.contains("ip[:port]"),
        "the refusal should name the value and the accepted forms: {err}"
    );

    for out in [&bad_proto, &bad_addr] {
        assert!(
            !stderr(out).contains("talking to daemon at"),
            "a refused invocation must not cost a daemon round trip"
        );
    }
}
