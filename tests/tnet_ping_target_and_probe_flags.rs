//! `tnet ping` must take Go's `<hostname-or-IP>` argument and Go's flag set, and must refuse the
//! probe shapes it cannot send *as named refusals* rather than as unknown arguments.
//!
//! Go's `ping` (`cmd/tailscale/cli/ping.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`) resolves
//! its argument through `tailscaleIPFromArg` — an IP literal as-is, else the peer list by MagicDNS
//! name, else the host resolver — and carries `--verbose`, `-c`, `--timeout`, `--until-direct`,
//! `--size` and three ping-type selectors (`--tsmp`, `--icmp`, `--peerapi`). This fork took an `IP`
//! only, so `tnet ping my-laptop` died at the parser, and none of the four probe shapes existed.
//!
//! The unit tests beside `ping_target_from_arg` and `ping_probe_refusal` in `src/bin/tnet.rs` pin
//! the resolution table and the refusal text. What they cannot see is the surface an operator
//! actually hits: whether clap takes the flags at all, what the positional is called, and *where*
//! in the command the refusal fires. Those are checked here by running the built `tnet`, the way
//! `tests/tnet_up_go_flag_spellings.rs` runs it for `up`.
//!
//! Every case below points `--socket` at a path that does not exist, so any invocation that gets as
//! far as the daemon fails on the socket. That is the discriminator: a refusal must name the flag,
//! and an accepted flag must fail on the socket instead.

use std::process::{Command, Output};

/// A socket path that is never created, so anything reaching the daemon fails to connect. Keyed by
/// pid so concurrent test binaries cannot collide.
fn missing_socket() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("tnet-ping-test-{}.sock", std::process::id()))
}

fn tnet(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tnet"))
        .args(args)
        .output()
        .expect("the `tnet` binary built for this test should run")
}

/// `tnet ping … --socket <a path that is not there>`.
fn ping(args: &[&str]) -> Output {
    let socket = missing_socket();
    let mut argv = vec!["ping", "--socket", socket.to_str().expect("utf-8 temp dir")];
    argv.extend_from_slice(args);
    tnet(&argv)
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Go's whole `ping` flag set is on this fork's surface, so a command line copied from Go's docs
/// reaches the command rather than clap's "unexpected argument".
#[test]
fn gos_ping_flags_are_all_declared() {
    let out = tnet(&["ping", "--help"]);
    assert!(out.status.success(), "`ping --help` should exit 0");
    let help = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--verbose",
        "--until-direct",
        "--tsmp",
        "--icmp",
        "--peerapi",
        "--size",
        "--timeout",
        "-c, --count",
    ] {
        assert!(
            help.contains(flag),
            "`tnet ping --help` should list {flag}; got:\n{help}"
        );
    }
    // Go's usage is `tailscale ping <hostname-or-IP>`; the positional must say so, because its old
    // `<IP>` name was the whole reason a name looked unsupported.
    assert!(
        help.contains("<HOSTNAME-OR-IP>"),
        "the positional should be Go's <hostname-or-IP>; got:\n{help}"
    );
}

/// The regression the port exists for: a MagicDNS name must get past the parser. It cannot resolve
/// without a daemon, so the failure must be the socket — never an argument error.
#[test]
fn a_hostname_argument_gets_past_the_parser() {
    let out = ping(&["my-laptop"]);
    assert_ne!(
        out.status.code(),
        Some(2),
        "a name must not be a usage error"
    );
    let err = stderr(&out);
    assert!(
        err.contains("querying status"),
        "a name should reach the netmap lookup and fail on the missing socket; got:\n{err}"
    );
}

/// Each engine-gated flag refuses by name, before the daemon is contacted — so the operator is told
/// about the *flag* rather than about a socket that was never the problem.
#[test]
fn engine_gated_probe_flags_refuse_by_name_before_any_daemon_contact() {
    for (args, flag) in [
        (vec!["--tsmp", "my-laptop"], "--tsmp"),
        (vec!["--peerapi", "my-laptop"], "--peerapi"),
        (vec!["--size", "1400", "my-laptop"], "--size"),
    ] {
        let out = ping(&args);
        assert!(
            !out.status.success(),
            "{flag} must not succeed; got status {:?}",
            out.status
        );
        let err = stderr(&out);
        assert!(
            err.contains(flag) && err.contains("not supported by this fork"),
            "{flag} should refuse by name; got:\n{err}"
        );
        assert!(
            !err.contains("querying status"),
            "{flag} must be refused before the daemon is contacted; got:\n{err}"
        );
    }
}

/// `--icmp` is NOT refused: the engine's `Device::ping` is an ICMP-level ping through WireGuard that
/// skips the local host OS stack, which is exactly what Go's `--icmp` asks for and exactly what this
/// daemon already sends. It must therefore reach the daemon and fail on the socket.
#[test]
fn icmp_is_honoured_rather_than_refused() {
    let out = ping(&["--icmp", "100.64.0.2"]);
    let err = stderr(&out);
    assert!(
        !err.contains("not supported by this fork"),
        "--icmp names the probe this fork already sends and must not be refused; got:\n{err}"
    );
    assert!(
        err.contains("querying status"),
        "--icmp should reach the daemon and fail on the missing socket; got:\n{err}"
    );
}

/// Go's `--size 0` means "minimum size", which is the probe this fork already sends — so it is
/// accepted, and only a request for a larger message is refused.
#[test]
fn size_zero_is_the_default_probe_and_is_accepted() {
    let out = ping(&["--size", "0", "100.64.0.2"]);
    let err = stderr(&out);
    assert!(
        !err.contains("not supported by this fork"),
        "`--size 0` asks for the probe already being sent; got:\n{err}"
    );
}

/// Go's `--size` is a signed int and takes a negative size without complaint; this one is unsigned,
/// so a negative size is a parse error rather than a padding request nothing below can honour.
#[test]
fn a_negative_size_is_a_parse_error() {
    let out = ping(&["--size=-1", "100.64.0.2"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a negative --size should fail at argument parsing; stderr:\n{}",
        stderr(&out)
    );
}

/// Go refuses `--until-direct` and this fork's `--no-until-direct` together; the pair is the fork's
/// spelling of Go's default-true bool, and clap owns the exclusion. Checked here so the port of the
/// surrounding flags cannot quietly drop it.
#[test]
fn until_direct_and_its_negation_stay_mutually_exclusive() {
    let out = ping(&["--until-direct", "--no-until-direct", "100.64.0.2"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "the two forms must not be usable together; stderr:\n{}",
        stderr(&out)
    );
}
