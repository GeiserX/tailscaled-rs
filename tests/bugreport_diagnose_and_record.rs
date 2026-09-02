//! `tnet bugreport` must take Go's two flags: `bugreport [--diagnose] [--record] [note]`.
//!
//! Go's `runBugReport` (`cmd/tailscale/cli/bugreport.go`) has three behaviours this fork did not
//! model. `--diagnose` sets `ipn.BugReportOpts.Diagnose`, which makes the daemon run its `Doctor`
//! pass alongside the marker. `--record` is CLI choreography: it prints a marker, prints
//! "Recording started; please reproduce your issue and then press Enter...", blocks on stdin, and
//! then prints a second marker plus "Please provide both bugreport markers above to the support team
//! or GitHub issue." — so the operator hands over a pair bracketing the reproduction. And a second
//! positional is `unknown arguments`, not a silently-ignored word.
//!
//! The unit tests next to the code pin the pure pieces — [`bugreport_note`](../src/bin/tnet.rs)'s
//! arity refusal, the clap surface, and the check-pass renderer in `ipn::doctor`. What they cannot
//! see is the surface an operator actually hits: whether the whole loop, CLI to daemon and back,
//! produces the two markers and the two sentences in the right order, on the right streams. So this
//! runs the built `tnet` against a **real** `server::serve` over a Unix socket, the way
//! `tests/localapi_loop.rs` drives the daemon and `tests/whois_flow_arguments.rs` drives the CLI.
//!
//! The daemon here is offline — no engine, no network, no auth key, state `NoState`/`Stopped` — which
//! is both what CI can run and the state an operator most often files a bug report from.
//!
//! Upstream: `cmd/tailscale/cli/bugreport.go` (and `ipn/ipnlocal.LocalBackend.Doctor`) @
//! `53a0d659afa51835dd7a9283873cca44261454f8`.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tailscaled_rs::ipn::Backend;
use tailscaled_rs::server;
use tokio::net::UnixStream;
use tokio::sync::{Mutex, oneshot};

/// Per-process-unique counter so parallel tests never collide on a temp path.
static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// A running LocalAPI server plus what it takes to drive and tear it down.
struct Daemon {
    state_dir: PathBuf,
    socket_path: PathBuf,
    shutdown_tx: oneshot::Sender<()>,
    serve_task: tokio::task::JoinHandle<()>,
}

impl Daemon {
    /// Load an offline backend in a fresh state dir and serve it on a unique socket.
    async fn start() -> Daemon {
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let state_dir =
            std::env::temp_dir().join(format!("tnet-bugreport-{}-{}", std::process::id(), n));
        let _ = tokio::fs::remove_dir_all(&state_dir).await;
        tokio::fs::create_dir_all(&state_dir)
            .await
            .expect("create temp state dir");
        let socket_path = state_dir.join("tailnetd.sock");

        let backend = Backend::load(&state_dir)
            .await
            .expect("Backend::load must succeed offline (file read only)");
        let backend = Arc::new(Mutex::new(backend));

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let serve_socket = socket_path.clone();
        let serve_task = tokio::spawn(async move {
            server::serve(&serve_socket, backend, async {
                shutdown_rx.await.ok();
            })
            .await
            .expect("serve returned an error");
        });

        for _ in 0..200 {
            if UnixStream::connect(&socket_path).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        Daemon {
            state_dir,
            socket_path,
            shutdown_tx,
            serve_task,
        }
    }

    /// Run the built `tnet` against this daemon with stdin at EOF.
    ///
    /// EOF matters: it is what `--record`'s wait sees in a non-interactive run, so the command
    /// completes instead of hanging — the same thing Go's `fmt.Scanln()` does when stdin is closed.
    ///
    /// The child is waited for on a blocking thread (`tokio`'s `process` feature is not enabled in
    /// this crate) and awaited here, so the `serve` task keeps making progress on the runtime while
    /// the CLI talks to it — which it must, since the daemon under test is in this same process.
    async fn tnet(&self, args: &[&str]) -> std::process::Output {
        let bin = env!("CARGO_BIN_EXE_tnet");
        let socket = self.socket_path.clone();
        let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(bin)
                .arg("--socket")
                .arg(&socket)
                .args(&args)
                .stdin(Stdio::null())
                .output()
                .expect("the `tnet` binary built for this test should run")
        })
        .await
        .expect("the `tnet` child should be waited for without panicking")
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), self.serve_task).await;
        let _ = tokio::fs::remove_dir_all(&self.state_dir).await;
    }
}

/// The stdout lines that are markers, in order.
fn markers(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter(|l| l.starts_with("BUG-"))
        .collect::<Vec<_>>()
}

/// Go's `--record` flow, end to end: marker, prompt, (reproduction), marker, closing sentence.
#[tokio::test]
async fn record_brackets_the_reproduction_with_two_distinct_markers() {
    let daemon = Daemon::start().await;

    let out = daemon.tnet(&["bugreport", "--record", "dns broke"]).await;
    assert!(
        out.status.success(),
        "`bugreport --record` should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();

    let markers = markers(&stdout);
    assert_eq!(
        markers.len(),
        2,
        "a recording prints one marker before and one after the reproduction; got:\n{stdout}"
    );
    assert_ne!(
        markers[0], markers[1],
        "the pair must be distinguishable — two identical markers bracket nothing:\n{stdout}"
    );
    for marker in &markers {
        assert!(
            marker.contains("-note:dns broke"),
            "the note rides on both markers: {marker}"
        );
    }

    // Go's two sentences, verbatim, in Go's order: prompt between the markers, closing line after
    // the second.
    let prompt = "Recording started; please reproduce your issue and then press Enter...";
    let footer = "Please provide both bugreport markers above to the support team or GitHub issue.";
    let lines: Vec<&str> = stdout.lines().collect();
    let at = |needle: &str| {
        lines
            .iter()
            .position(|l| *l == needle)
            .unwrap_or_else(|| panic!("stdout should contain {needle:?}; got:\n{stdout}"))
    };
    let first = lines.iter().position(|l| *l == markers[0]).unwrap();
    let second = lines.iter().position(|l| *l == markers[1]).unwrap();
    assert!(
        first < at(prompt) && at(prompt) < second && second < at(footer),
        "order must be marker, prompt, marker, closing line; got:\n{stdout}"
    );

    daemon.shutdown().await;
}

/// `--diagnose` runs the extra pass and shows it to the operator — on stderr, so a pipe still
/// collects exactly the marker.
#[tokio::test]
async fn diagnose_prints_the_check_pass_beside_the_marker() {
    let daemon = Daemon::start().await;

    let plain = daemon.tnet(&["bugreport"]).await;
    assert!(plain.status.success(), "a bare bugreport should exit 0");
    assert!(
        !String::from_utf8_lossy(&plain.stderr).contains("in-depth checks"),
        "no --diagnose means no checks — Go's Doctor runs only for the flag"
    );

    let out = daemon.tnet(&["bugreport", "--diagnose"]).await;
    assert!(
        out.status.success(),
        "`bugreport --diagnose` should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    assert_eq!(
        stdout.lines().count(),
        1,
        "stdout stays exactly the marker so `> marker.txt` still works; got:\n{stdout}"
    );
    assert_eq!(markers(&stdout).len(), 1, "one marker; got:\n{stdout}");

    assert!(
        stderr.contains("in-depth checks (--diagnose):"),
        "the pass is announced; got:\n{stderr}"
    );
    for check in [
        "state:",
        "profile:",
        "prefs:",
        "permissions:",
        "dns-resolvers:",
        "interfaces:",
        "not-checked:",
    ] {
        assert!(
            stderr.contains(check),
            "the pass should report {check:?}; got:\n{stderr}"
        );
    }
    // This daemon is not up, so the DNS check must say it had nothing to judge rather than report a
    // clean result it never obtained.
    assert!(
        stderr.contains("dns-resolvers: not checked — the node is not up"),
        "a down node must say why the DNS check was skipped; got:\n{stderr}"
    );

    daemon.shutdown().await;
}

/// Go's argument refusal: more than one positional is `unknown arguments`, and it costs no daemon
/// round trip.
#[tokio::test]
async fn a_second_positional_is_gos_unknown_arguments_refusal() {
    let daemon = Daemon::start().await;

    let out = daemon.tnet(&["bugreport", "dns", "broke"]).await;
    assert!(
        !out.status.success(),
        "two positionals must fail, not silently drop one"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown arguments"),
        "the refusal is Go's own wording; got:\n{stderr}"
    );
    assert!(
        markers(&String::from_utf8_lossy(&out.stdout)).is_empty(),
        "a refused invocation prints no marker"
    );

    daemon.shutdown().await;
}
