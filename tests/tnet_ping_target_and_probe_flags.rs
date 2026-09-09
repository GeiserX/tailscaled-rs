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
//! The flag cases below point `--socket` at a path that does not exist, so any invocation that gets
//! as far as the daemon fails on the socket. That is the discriminator: a refusal must name the
//! flag, and an accepted flag must fail on the socket instead.
//!
//! The backend-state cases at the end need a daemon that answers, so they run the built `tnet`
//! against a stub speaking the LocalAPI's one-line JSON — the same style as
//! `tests/tnet_down_reason_and_risk.rs`. Go's `runPing` opens with `isRunningOrStarting(st)`
//! (`cmd/tailscale/cli/status.go`) and, on any state other than `Running`/`Starting`, prints that
//! state's description and exits 1 before the argument is resolved. What the stub records is the
//! point: a gated state must cost the status read and nothing else.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::mpsc;
use std::time::{Duration, Instant};

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

// ---------------------------------------------------------------------------
// Go's `isRunningOrStarting` gate, over a stub daemon.
// ---------------------------------------------------------------------------

/// A socket path only this test owns, keyed by case name + pid so concurrent test binaries cannot
/// collide. Distinct from [`missing_socket`], which must stay unbound.
///
/// The name is terse on purpose: an `AF_UNIX` path is capped at `SUN_LEN` (104 bytes on macOS,
/// 108 on Linux) INCLUDING the temp directory, and a build tree under a long `TMPDIR` has little
/// of that budget left. A descriptive case name here would bind nothing and fail with
/// `path must be shorter than SUN_LEN` instead of exercising the gate.
fn stub_socket_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tnet-png-{name}-{}.sock", std::process::id()))
}

/// A stand-in daemon: it serves exactly `replies.len()` connections of the LocalAPI's one-line JSON
/// protocol (read one request line, write one response line, close), then hands the request lines
/// back over the channel. One connection per round trip, so the reply list is the CLI's expected
/// call sequence — a `ping` that sends probes it should have been gated out of shows up as an extra
/// recorded request.
///
/// Accept is polled with a deadline rather than blocked on, so a CLI that opens FEWER connections
/// than expected fails an assertion instead of hanging the test.
fn stub_daemon(name: &str, replies: &[&str]) -> (PathBuf, mpsc::Receiver<Vec<String>>) {
    let path = stub_socket_path(name);
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind the stub daemon socket");
    listener
        .set_nonblocking(true)
        .expect("stub listener must be pollable");
    let replies: Vec<String> = replies.iter().map(|r| (*r).to_string()).collect();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(20);
        for reply in replies {
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break Some(stream),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            break None;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("stub daemon accept failed: {e}"),
                }
            };
            let Some(mut stream) = stream else { break };
            stream
                .set_nonblocking(false)
                .expect("stub connection must block for the request line");
            let mut line = String::new();
            BufReader::new(stream.try_clone().expect("clone the stub connection"))
                .read_line(&mut line)
                .expect("read the request line");
            seen.push(line.trim().to_string());
            writeln!(stream, "{reply}").expect("write the stub reply");
            stream.flush().expect("flush the stub reply");
        }
        let _ = tx.send(seen);
    });
    (path, rx)
}

/// Collect what the stub daemon was asked, failing rather than hanging if it never finished.
fn requests(rx: &mpsc::Receiver<Vec<String>>) -> Vec<String> {
    rx.recv_timeout(Duration::from_secs(30))
        .expect("the stub daemon should report the requests it served")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// `tnet ping … --socket <the stub's path>`.
fn ping_at(socket: &PathBuf, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tnet"));
    cmd.arg("ping").arg("--socket").arg(socket).args(args);
    cmd.output()
        .expect("the `tnet` binary built for this test should run")
}

/// Run one gated state end to end: the stub answers the status read with `status_reply`, and the
/// CLI must print the description, exit 1, and stop there.
///
/// The stub is given ONE reply. Without the gate the CLI would go on to send `{"cmd":"ping"…}` on a
/// second connection, so the served list is the direct evidence that no probe left the process.
fn gated_state(name: &str, status_reply: &str) -> (Output, Vec<String>) {
    let (socket, rx) = stub_daemon(name, &[status_reply]);
    // An IP literal, so a missing gate would resolve without any DNS and go straight to the probe:
    // the test then fails on the assertions rather than on the network.
    let out = ping_at(&socket, &["-c", "1", "100.64.0.2"]);
    let served = requests(&rx);
    let _ = std::fs::remove_file(&socket);
    (out, served)
}

/// Go: `case ipn.Stopped.String(): return "Tailscale is stopped.", false`. The node the operator is
/// sitting on is down, so the honest answer is about this node — not `no reply` about the peer.
#[test]
fn a_stopped_node_is_diagnosed_locally_instead_of_pinged() {
    let (out, served) = gated_state("stop", r#"{"kind":"status","state":"Stopped"}"#);
    assert_eq!(
        out.status.code(),
        Some(1),
        "Go exits 1 from the gate; stderr:\n{}",
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("Tailscale is stopped."),
        "expected Go's description on stdout (its `printf`); got stdout:\n{}stderr:\n{}",
        stdout(&out),
        stderr(&out)
    );
    // The regression this pins: probing anyway ends on Go's peer-side verdict, which blames the
    // wrong end of the connection.
    assert!(
        !stderr(&out).contains("no reply"),
        "a stopped node must not be reported as an unresponsive peer: {}",
        stderr(&out)
    );
    assert_eq!(
        served,
        vec![r#"{"cmd":"status"}"#.to_string()],
        "a gated state must cost the status read and nothing else: {served:?}"
    );
}

/// Go: `case ipn.NeedsLogin.String()` — `Logged out.`, plus `Log in at: <url>` when the daemon has
/// an auth URL, so the operator gets the one action that fixes it.
#[test]
fn a_logged_out_node_reports_gos_login_line() {
    let (out, served) = gated_state(
        "nolog",
        r#"{"kind":"status","state":"NeedsLogin","auth_url":"https://login.example.com/a/abc123"}"#,
    );
    assert_eq!(out.status.code(), Some(1), "stderr:\n{}", stderr(&out));
    let printed = stdout(&out);
    assert!(
        printed.contains("Logged out."),
        "expected Go's description; got:\n{printed}"
    );
    assert!(
        printed.contains("Log in at: https://login.example.com/a/abc123"),
        "an offered auth URL must be surfaced, as Go does; got:\n{printed}"
    );
    assert_eq!(served.len(), 1, "no probe may be sent: {served:?}");
}

/// A `NeedsLogin` with no URL to offer is Go's bare `Logged out.` — never a dangling `Log in at:`.
#[test]
fn a_logged_out_node_without_a_url_prints_only_the_bare_line() {
    let (out, _) = gated_state("bare", r#"{"kind":"status","state":"NeedsLogin"}"#);
    let printed = stdout(&out);
    assert!(printed.contains("Logged out."), "got:\n{printed}");
    assert!(
        !printed.contains("Log in at:"),
        "there is no URL to log in at; got:\n{printed}"
    );
}

/// Go's `default` arm. `NoState` has no case of its own, so it prints `unexpected state: %s` — which
/// still names the local fault rather than pinning it on the peer.
#[test]
fn an_unhandled_backend_state_is_named_rather_than_pinged_through() {
    let (out, served) = gated_state("nost", r#"{"kind":"status","state":"NoState"}"#);
    assert_eq!(out.status.code(), Some(1), "stderr:\n{}", stderr(&out));
    assert!(
        stdout(&out).contains("unexpected state: NoState"),
        "expected Go's default arm; got stdout:\n{}",
        stdout(&out)
    );
    assert_eq!(served.len(), 1, "no probe may be sent: {served:?}");
}

/// The control for the three above: a `Running` node passes the gate, so the probe IS sent and the
/// pong is reported. Without this, a gate that refused everything would look just as green.
#[test]
fn a_running_node_passes_the_gate_and_pings() {
    let (socket, rx) = stub_daemon(
        "run",
        &[
            r#"{"kind":"status","state":"Running"}"#,
            r#"{"kind":"ping","rtt_ms":12.5,"ip":"100.64.0.2","endpoint":"192.0.2.9:41641"}"#,
        ],
    );
    let out = ping_at(&socket, &["-c", "1", "100.64.0.2"]);
    let served = requests(&rx);
    let _ = std::fs::remove_file(&socket);

    assert!(
        out.status.success(),
        "a pong over a direct path is Go's success; stderr:\n{}",
        stderr(&out)
    );
    let printed = stdout(&out);
    assert!(
        printed.contains("pong from 100.64.0.2") && printed.contains("via 192.0.2.9:41641"),
        "the probe's result must be reported; got:\n{printed}"
    );
    assert_eq!(served.len(), 2, "status then the probe: {served:?}");
    assert!(
        served[1].contains(r#""cmd":"ping""#),
        "the second round trip must be the probe: {served:?}"
    );
    // And nothing from the gate leaked into a state it must not fire on.
    for gate_text in ["Tailscale is stopped.", "Logged out.", "unexpected state"] {
        assert!(
            !printed.contains(gate_text),
            "a Running node must not be gated ({gate_text}); got:\n{printed}"
        );
    }
}

/// `Starting` is explicitly on Go's allowed side of the gate: a node still assembling its netmap is
/// exactly where a ping is useful, because the probe is what nudges the path up.
#[test]
fn a_starting_node_is_not_gated() {
    let (socket, rx) = stub_daemon(
        "start",
        &[
            r#"{"kind":"status","state":"Starting"}"#,
            r#"{"kind":"ping","rtt_ms":30.0,"ip":"100.64.0.2","endpoint":"192.0.2.9:41641"}"#,
        ],
    );
    let out = ping_at(&socket, &["-c", "1", "100.64.0.2"]);
    let served = requests(&rx);
    let _ = std::fs::remove_file(&socket);

    assert!(out.status.success(), "stderr:\n{}", stderr(&out));
    assert_eq!(
        served.len(),
        2,
        "a starting node must still be allowed to probe: {served:?}"
    );
}
