//! `tnet down` must carry Go's two `down` behaviours: `--reason` and the lose-SSH refusal.
//!
//! Go's `down` is not a bare verb. `newDownFlagSet` (cmd/tailscale/cli/down.go) registers `--reason`
//! ("reason for the disconnect, if required by a policy"), which `runDown` attaches to the prefs
//! edit as `apitype.RequestReasonKey`, and it calls `registerAcceptRiskFlag`, so `runDown` refuses
//! when `isSSHOverTailscale()` — clearing `WantRunning` tears down the transport the operator's own
//! SSH session runs over — unless `--accept-risk=lose-ssh` (or `all`) was passed. Until this change
//! `tnet down` was a fieldless verb: a `tailscale down --reason "maintenance"` copied out of a
//! runbook died at argument parsing, and a `down` typed into a Tailscale SSH session cut it with no
//! warning.
//!
//! The unit tests next to [`down_positional_refusal`](../src/bin/tnet.rs) pin the pure decisions
//! (Go's leftover-argument message, the risk predicate, the `Stopped` comparison). What they cannot
//! see is the surface an operator hits: whether clap accepts the flags at all, *where* an unusable
//! invocation fails, and whether the reason actually reaches the daemon. Those are checked here by
//! running the built `tnet` against a stub daemon that speaks the LocalAPI's one-line JSON — the
//! same style as `tests/whois_flow_arguments.rs`.
//!
//! HONEST SCOPE: `--reason` is carried to the daemon and recorded in its log, not forwarded to the
//! control plane — this fork registers no policy store that could *require* a justification and the
//! engine has no audit-log transport. That is the same scope `logout --reason` already documents.
//!
//! Upstream: `cmd/tailscale/cli/down.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

/// A socket path only this test owns, keyed by test name + pid so concurrent test binaries cannot
/// collide. Nothing outside the test ever creates it, so an invocation either fails before the
/// daemon round trip (the refusals) or fails *at* it — never against whatever daemon happens to be
/// running on the build machine. [`stub_daemon`] and [`SocketWatch`] bind it deliberately.
fn unused_socket_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tnet-down-{name}-{}.sock", std::process::id()))
}

/// Run the built `tnet` against `socket`, with `SSH_CLIENT` set to `ssh_client` (or removed when
/// `None`, so a test that must NOT be refused stays green even when the whole suite is run over a
/// real SSH session).
fn tnet_with(socket: &PathBuf, ssh_client: Option<&str>, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tnet"));
    cmd.arg("--socket").arg(socket).args(args);
    match ssh_client {
        Some(value) => cmd.env("SSH_CLIENT", value),
        None => cmd.env_remove("SSH_CLIENT"),
    };
    cmd.output()
        .expect("the `tnet` binary built for this test should run")
}

/// Run `tnet` against a never-created socket, with no `SSH_CLIENT`.
fn tnet(name: &str, args: &[&str]) -> Output {
    tnet_with(&unused_socket_path(name), None, args)
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A stand-in daemon: it serves exactly `replies.len()` connections of the LocalAPI's one-line JSON
/// protocol (read one request line, write one response line, close), then hands the request lines
/// back over the channel. One connection per `round_trip`, so the reply list is the CLI's expected
/// call sequence — a `down` that skips or adds a round trip is visible in what the stub recorded.
///
/// Accept is polled with a deadline rather than blocked on, so a regression that makes the CLI open
/// FEWER connections than expected fails the assertion instead of hanging the test.
fn stub_daemon(name: &str, replies: &[&str]) -> (PathBuf, mpsc::Receiver<Vec<String>>) {
    let path = unused_socket_path(name);
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

/// A bound-but-unserved socket, for the refusals: it *observes* whether the CLI contacted the
/// daemon instead of inferring it from a diagnostic. The absence of `"talking to daemon at"` only
/// ever meant "no round trip failed" — that string is context on a transport error, so a reworded
/// or suppressed message, or a daemon that answered, would leave a refusal that silently opened the
/// socket looking clean. Watching the socket asks the question directly.
///
/// A watcher thread accepts every connection and drops it at once, so a CLI that does connect gets
/// an EOF and fails fast rather than blocking on a reply that will never come (which would hang the
/// test), and the accept is counted. [`SocketWatch::connections`] stops the watcher and reports the
/// count.
///
/// The count is exact, not sampled: `connect(2)` against a listening `AF_UNIX` socket queues the
/// connection in the backlog before it returns, so once the CLI has exited — which the caller has
/// already waited for — anything it opened is counted or still queued, and the watcher drains the
/// queue before it stops.
struct SocketWatch {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    watcher: std::thread::JoinHandle<usize>,
}

impl SocketWatch {
    fn bind(name: &str) -> Self {
        let path = unused_socket_path(name);
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind the watched socket");
        listener
            .set_nonblocking(true)
            .expect("watched listener must be pollable");
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let watcher = std::thread::spawn(move || {
            let mut seen = 0usize;
            loop {
                match listener.accept() {
                    // Dropped immediately: the peer, if any, sees EOF instead of waiting forever.
                    Ok(_) => seen += 1,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Backlog empty. Only now may a stop request end the watch, so a connection
                        // that arrived just before it is still counted.
                        if flag.load(Ordering::Relaxed) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("watched socket accept failed: {e}"),
                }
            }
            seen
        });
        Self {
            path,
            stop,
            watcher,
        }
    }

    fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Stop watching and report how many connections the CLI opened. Call it after the `tnet` run
    /// has exited.
    fn connections(self) -> usize {
        self.stop.store(true, Ordering::Relaxed);
        let seen = self
            .watcher
            .join()
            .expect("the socket watcher should not panic");
        let _ = std::fs::remove_file(&self.path);
        seen
    }
}

/// Go's flags are on the fork's own surface, so a command line copied from Go's docs parses.
#[test]
fn down_help_documents_gos_reason_and_accept_risk_flags() {
    let out = tnet("help", &["down", "--help"]);
    assert!(out.status.success(), "--help should exit 0");
    let help = String::from_utf8_lossy(&out.stdout);
    for expected in ["--reason", "--accept-risk", "lose-ssh"] {
        assert!(
            help.contains(expected),
            "`tnet down --help` should mention {expected}; got:\n{help}"
        );
    }
}

/// The command from a Go runbook — `tailscale down --reason "..."` — must reach the daemon with the
/// reason on the wire, exactly as `logout --reason` does.
#[test]
fn a_go_spelled_down_reason_reaches_the_daemon_verbatim() {
    // Round trip 1 is the status pre-check (Running ⇒ there IS something to disconnect), round
    // trip 2 is the edit itself.
    let (socket, rx) = stub_daemon(
        "reason",
        &[
            r#"{"kind":"status","state":"Running"}"#,
            r#"{"kind":"ok","message":"node brought down"}"#,
        ],
    );
    let out = tnet_with(
        &socket,
        None,
        &["down", "--reason", "scheduled maintenance"],
    );
    let served = requests(&rx);
    let _ = std::fs::remove_file(&socket);

    assert!(
        out.status.success(),
        "a `down` the stub daemon accepted should exit 0; stderr:\n{}",
        stderr(&out)
    );
    assert_eq!(
        served.len(),
        2,
        "expected a status pre-check then the edit: {served:?}"
    );
    assert_eq!(
        served[0], r#"{"cmd":"status"}"#,
        "the pre-check is a read-only status"
    );
    assert!(
        served[1].contains(r#""cmd":"down""#)
            && served[1].contains(r#""reason":"scheduled maintenance""#),
        "the operator's justification must reach the daemon verbatim: {}",
        served[1]
    );
}

/// A `down` with no `--reason` must still send the historical bare request — the flag is additive.
#[test]
fn a_bare_down_still_sends_the_historical_request() {
    let (socket, rx) = stub_daemon(
        "bare",
        &[
            r#"{"kind":"status","state":"Running"}"#,
            r#"{"kind":"ok","message":"node brought down"}"#,
        ],
    );
    let out = tnet_with(&socket, None, &["down"]);
    let served = requests(&rx);
    let _ = std::fs::remove_file(&socket);

    assert!(out.status.success(), "stderr:\n{}", stderr(&out));
    assert_eq!(served.len(), 2, "{served:?}");
    assert_eq!(
        served[1], r#"{"cmd":"down"}"#,
        "no reason must serialize to the bare form an older daemon understands"
    );
}

/// Go's `runDown` short-circuits on an already-stopped node: `warnf("Tailscale was already
/// stopped.")` and `return nil` — no redundant prefs edit, and a zero exit status.
#[test]
fn an_already_stopped_node_is_reported_and_not_edited_again() {
    // One reply only: if the CLI issues the edit anyway, the second connect is refused and the
    // command fails — which the assertions below catch.
    let (socket, rx) = stub_daemon("stopped", &[r#"{"kind":"status","state":"Stopped"}"#]);
    let out = tnet_with(&socket, None, &["down"]);
    let served = requests(&rx);
    let _ = std::fs::remove_file(&socket);

    assert!(
        out.status.success(),
        "an already-stopped node is not a failure (Go returns nil); stderr:\n{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("Tailscale was already stopped."),
        "expected Go's message on stderr: {}",
        stderr(&out)
    );
    assert_eq!(
        served,
        vec![r#"{"cmd":"status"}"#.to_string()],
        "a stopped node must cost the status read and nothing else: {served:?}"
    );
}

/// Go `runDown`'s leftover-argument refusal, verbatim, and before any daemon round trip.
#[test]
fn down_ports_gos_leftover_argument_refusal() {
    // The socket is bound and watched, so "no round trip" is read off the socket rather than off
    // the CLI's wording.
    let watch = SocketWatch::bind("args");
    // The classic typo: a flag value that lost its `--reason`.
    let out = tnet_with(watch.path(), None, &["down", "maintenance"]);
    let connections = watch.connections();
    assert!(!out.status.success(), "a positional argument must fail");
    let err = stderr(&out);
    assert!(
        err.contains(r#"too many non-flag arguments: ["maintenance"]"#),
        "expected Go's message with Go's %q rendering: {err}"
    );
    assert_eq!(
        connections, 0,
        "an unusable invocation must not cost a daemon round trip, and the socket saw {connections}"
    );
    // Secondary, on what the operator reads: no daemon-transport noise on top of Go's message.
    assert!(
        !err.contains("talking to daemon at"),
        "the refusal must be the whole error: {err}"
    );
    for clap_noise in ["unexpected argument", "Usage:"] {
        assert!(
            !err.contains(clap_noise),
            "the refusal must be Go's, not clap's ({clap_noise}): {err}"
        );
    }
}

/// The risk gate: a `down` typed into a Tailscale SSH session disconnects it, so it is refused —
/// locally, before the node is touched — unless `lose-ssh` was pre-accepted.
#[test]
fn down_over_tailscale_ssh_is_refused_unless_the_risk_is_accepted() {
    let watch = SocketWatch::bind("risk");
    let refused = tnet_with(watch.path(), Some("100.64.0.7 12345 22"), &["down"]);
    let refused_connections = watch.connections();
    assert!(!refused.status.success(), "the refusal must be non-zero");
    let err = stderr(&refused);
    assert!(
        err.contains("your session disconnecting"),
        "expected Go's riskLoseSSH wording: {err}"
    );
    assert!(
        err.contains("--accept-risk=lose-ssh"),
        "the refusal must name the override: {err}"
    );
    assert_eq!(
        refused_connections, 0,
        "a refused `down` must not reach the daemon; the socket saw {refused_connections}: {err}"
    );

    // An SSH client that is NOT on the tailnet has nothing to lose — Go's `isSSHOverTailscale` is
    // false there, so the command proceeds and does open the socket. That is the control for the
    // count above: the same observation registers the round trip a refusal must not make, so a
    // zero there is the gate working, not the watch failing to see anything.
    let control = SocketWatch::bind("risk-off-tailnet");
    let off_tailnet = tnet_with(control.path(), Some("192.0.2.9 12345 22"), &["down"]);
    assert_eq!(
        control.connections(),
        1,
        "an off-tailnet SSH session must not trip the gate: {}",
        stderr(&off_tailnet)
    );
    assert!(
        stderr(&off_tailnet).contains("talking to daemon at"),
        "and the round trip it made is the one that failed: {}",
        stderr(&off_tailnet)
    );
}

/// `--accept-risk=lose-ssh` (and the catch-all `all`) lift the refusal, exactly as Go's
/// `isRiskAccepted` does — the command then runs to completion against the daemon.
#[test]
fn accept_risk_lets_a_down_over_tailscale_ssh_through() {
    for (i, accept) in ["--accept-risk=lose-ssh", "--accept-risk=all"]
        .into_iter()
        .enumerate()
    {
        let (socket, rx) = stub_daemon(
            &format!("accept-{i}"),
            &[
                r#"{"kind":"status","state":"Running"}"#,
                r#"{"kind":"ok","message":"node brought down"}"#,
            ],
        );
        let out = tnet_with(&socket, Some("100.64.0.7 12345 22"), &["down", accept]);
        let served = requests(&rx);
        let _ = std::fs::remove_file(&socket);

        assert!(
            out.status.success(),
            "{accept} must lift the refusal; stderr:\n{}",
            stderr(&out)
        );
        assert!(
            served.iter().any(|r| r.contains(r#""cmd":"down""#)),
            "{accept} must let the edit through: {served:?}"
        );
    }
}
