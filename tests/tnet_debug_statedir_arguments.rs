//! `tnet debug statedir` must refuse a stray positional the way Go does, not the way clap does.
//!
//! Go's `runPrintStateDir` (cmd/tailscale/cli/debug.go) opens with
//! `if len(args) > 0 { return errors.New("unexpected arguments") }`, and the CLI reports a returned
//! error on stderr with exit 1. `statedir` is a bare verb — it asks the daemon one question — so a
//! positional is a typo, most often a path the operator believed this command would *set*.
//!
//! The refusal did exist before this change, but it was clap's: a subcommand with no positional
//! field answers `error: unexpected argument '/var/lib' found` with a usage block and exit 2. Same
//! outcome, different contract — a script or runbook that keys on Go's exit 1 or on Go's wording
//! sees neither. The positional is now collected so the command itself can refuse, exactly as
//! `tnet down` already does with Go's `too many non-flag arguments`.
//!
//! The unit tests next to [`statedir_positional_refusal`](../src/bin/tnet.rs) pin the decision and
//! its position in the command; what they cannot see is the process-level surface an operator hits
//! — the exit code, and whether clap swallowed the argument before the command ever ran. That is
//! what is checked here, by running the built `tnet`.
//!
//! Upstream: `cmd/tailscale/cli/debug.go` (`runPrintStateDir`) @
//! `53a0d659afa51835dd7a9283873cca44261454f8`.

use std::path::PathBuf;
use std::process::{Command, Output};

/// A socket path nothing in this test ever creates, keyed by pid so concurrent test binaries cannot
/// collide. Any invocation that gets as far as the daemon round trip fails *at* it, with the
/// connect error naming this path — which is how "the refusal came first" is read off the output
/// rather than assumed.
fn unused_socket_path() -> PathBuf {
    std::env::temp_dir().join(format!("tnet-statedir-args-{}.sock", std::process::id()))
}

/// Run the built `tnet` against that never-created socket.
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

/// Go's refusal, with Go's exit code, and before the daemon is contacted.
#[test]
fn statedir_ports_gos_unexpected_arguments_refusal() {
    let out = tnet(&["debug", "statedir", "/var/lib"]);
    let err = stderr(&out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "Go returns this as the command's error, which exits 1 — clap's own refusal exits 2: {err}"
    );
    assert!(
        err.contains("unexpected arguments"),
        "expected Go's message: {err}"
    );
    // clap's refusal for an undeclared positional is `unexpected argument '<x>' found` — singular,
    // quoting the value — followed by a usage block and a `--help` tip. None of that is Go's. (The
    // singular stem is deliberately not matched here: it is a prefix of Go's own plural.)
    for clap_noise in ["' found", "Usage:", "--help"] {
        assert!(
            !err.contains(clap_noise),
            "the refusal must be Go's, not clap's ({clap_noise}): {err}"
        );
    }
    // The refusal is the whole error: no daemon-transport noise means no round trip was attempted.
    assert!(
        !err.contains("asking the daemon"),
        "an unusable invocation must not cost a daemon round trip: {err}"
    );
    assert!(
        out.stdout.is_empty(),
        "a refused invocation prints nothing on stdout"
    );
}

/// The same refusal on the `--local` form. `--local` is this fork's no-round-trip report and would
/// otherwise answer successfully with no daemon at all, so it is the form that shows the check runs
/// ahead of the command's body rather than merely ahead of the socket.
#[test]
fn statedir_local_refuses_a_positional_too() {
    let out = tnet(&["debug", "statedir", "--local", "/var/lib"]);
    let err = stderr(&out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "`--local` chooses which answer to give; neither answer takes an operand: {err}"
    );
    assert!(
        err.contains("unexpected arguments"),
        "expected Go's message: {err}"
    );
    assert!(
        out.stdout.is_empty(),
        "the local report must not be printed for a refused invocation: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// The accepted shape still works, and the collected positional stays out of the help.
#[test]
fn a_bare_statedir_is_unaffected() {
    // `--local` answers from this CLI's own environment, so it needs no daemon.
    let out = tnet(&["debug", "statedir", "--local"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "the shape Go accepts must still be accepted: {}",
        stderr(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("state dir:"),
        "the local report is still printed"
    );

    // The positional exists only to carry Go's refusal; advertising it in the help would read as an
    // invitation to pass one.
    let help = tnet(&["debug", "statedir", "--help"]);
    let text = String::from_utf8_lossy(&help.stdout).into_owned();
    assert!(help.status.success(), "--help should exit 0");
    assert!(
        !text.contains("[ARG]") && !text.contains("<ARG>"),
        "the leftover-argument slot must stay hidden: {text}"
    );
}
