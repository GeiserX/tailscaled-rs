//! Integration tests for the daemon<->CLI LocalAPI loop (tsd-2a9).
//!
//! These exercise the *real* `server::serve` Unix-domain-socket IPC against a real
//! [`tailscaled_rs::ipn::Backend`], with a raw `tokio::net::UnixStream` playing the role of the
//! `tnet` CLI. We deliberately never join a tailnet: no network, no auth key, no `up`. The node
//! sits in `NoState`/`Stopped`, which is exactly the regime we want to pin down — the IPC contract
//! and the unauthenticated read path, not connectivity.
//!
//! Why this is safe to run in CI (`cargo test --all-targets`):
//! - `Backend::load` only reads `prefs.json` (missing → defaults), no engine, no network.
//! - `Backend::status` short-circuits when no engine is present (`device == None`), so it returns
//!   a derived `NoState`/`Stopped` snapshot without touching the engine.
//! - `Backend::down` is a no-op teardown when no engine is present, then persists prefs.
//! - No root, no tailnet, no `TS_AUTH_KEY` required; everything is local file + Unix socket.
//!
//! Each test gets a UNIQUE state dir + socket (cargo runs tests in parallel within one process),
//! and best-effort-cleans them up at the end.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tailscaled_rs::ipn::Backend;
use tailscaled_rs::localapi::{Request, Response};
use tailscaled_rs::server;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, oneshot};

/// Per-process-unique counter so parallel tests never collide on a temp path, even within the same
/// PID (cargo runs `#[tokio::test]`s as threads in one process).
static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// A unique temp state directory for one test (`/tmp/tailnetd-it-<pid>-<n>`).
fn unique_state_dir() -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("tailnetd-it-{}-{}", std::process::id(), n))
}

/// A running LocalAPI server plus the handles to drive and tear it down.
struct Harness {
    state_dir: PathBuf,
    socket_path: PathBuf,
    /// Fire to ask `serve` to stop.
    shutdown_tx: oneshot::Sender<()>,
    /// The spawned `serve` task; await (with a timeout) to confirm clean exit.
    serve_task: tokio::task::JoinHandle<()>,
}

impl Harness {
    /// Build a fresh state dir, load an offline `Backend`, and spawn `server::serve` on a unique
    /// socket inside that dir. Returns once the socket is connectable.
    async fn start() -> Harness {
        let state_dir = unique_state_dir();
        // Start from a clean slate so a leftover prefs.json from a crashed prior run can't taint us.
        let _ = tokio::fs::remove_dir_all(&state_dir).await;
        tokio::fs::create_dir_all(&state_dir)
            .await
            .expect("create temp state dir");

        let socket_path = state_dir.join("tailnetd.sock");

        // Offline construction: this must NOT require the engine or any network.
        let backend = Backend::load(&state_dir)
            .await
            .expect("Backend::load must succeed offline (file read only)");
        let backend = Arc::new(Mutex::new(backend));

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let serve_socket = socket_path.clone();
        let serve_backend = Arc::clone(&backend);
        let serve_task = tokio::spawn(async move {
            server::serve(&serve_socket, serve_backend, async {
                // Resolve when the test fires `shutdown_tx`, or immediately if it's dropped.
                shutdown_rx.await.ok();
            })
            .await
            .expect("serve returned an error");
        });

        wait_for_socket(&socket_path).await;

        Harness {
            state_dir,
            socket_path,
            shutdown_tx,
            serve_task,
        }
    }

    /// Send one request line and read exactly one response line over a fresh connection.
    ///
    /// We use one connection per round-trip on purpose: the MVP transport is newline-delimited and
    /// the connection is long-lived, but a fresh connection per call keeps each assertion isolated
    /// and matches how the thin CLI behaves (connect, one command, done).
    async fn round_trip(&self, request_line: &str) -> Response {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .expect("CLI connect to LocalAPI socket");
        let (read_half, mut write_half) = stream.into_split();

        let mut line = request_line.to_string();
        if !line.ends_with('\n') {
            line.push('\n');
        }
        write_half
            .write_all(line.as_bytes())
            .await
            .expect("write request");
        write_half.flush().await.expect("flush request");

        let mut reader = BufReader::new(read_half);
        let mut response_line = String::new();
        let n = reader
            .read_line(&mut response_line)
            .await
            .expect("read response line");
        assert!(n > 0, "server closed without replying to: {request_line}");

        serde_json::from_str::<Response>(response_line.trim_end()).unwrap_or_else(|e| {
            panic!("response was not valid Response JSON ({e}): {response_line:?}")
        })
    }

    /// Fire shutdown, await the serve task with a timeout (a hang fails the test instead of
    /// blocking forever), assert the socket file was removed, and best-effort-clean the state dir.
    async fn shutdown_and_verify(self) {
        let Harness {
            state_dir,
            socket_path,
            shutdown_tx,
            serve_task,
        } = self;

        // Ask serve to stop. If the receiver were already gone this returns Err, which is fine.
        let _ = shutdown_tx.send(());

        match tokio::time::timeout(Duration::from_secs(5), serve_task).await {
            Ok(join_result) => join_result.expect("serve task panicked"),
            Err(_) => panic!("serve task did not exit within 5s after shutdown signal"),
        }

        // `serve` removes the socket on clean exit.
        assert!(
            !socket_path.exists(),
            "socket file should be removed after shutdown: {}",
            socket_path.display()
        );

        let _ = tokio::fs::remove_dir_all(&state_dir).await;
    }
}

/// Poll until the daemon has bound and the socket is connectable, or fail after a bounded wait.
async fn wait_for_socket(socket_path: &std::path::Path) {
    for _ in 0..200 {
        if UnixStream::connect(socket_path).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "LocalAPI socket never became connectable: {}",
        socket_path.display()
    );
}

/// 1. status round-trip: a fresh, never-configured node reports an unauthenticated, not-running
///    snapshot, and the server shuts down cleanly (socket removed).
#[tokio::test]
async fn status_round_trip_reports_offline_state() {
    let harness = Harness::start().await;

    let resp = harness.round_trip(r#"{"cmd":"status"}"#).await;
    match resp {
        Response::Status(report) => {
            // A node that has never been `up`'d and isn't logged out derives to NoState; once it
            // has been configured (or after a `down`) it derives to Stopped. Accept either of the
            // two offline states — both are correct "we have no engine" outcomes.
            assert!(
                report.state == "NoState" || report.state == "Stopped",
                "fresh offline node should be NoState or Stopped, got {:?}",
                report.state
            );
            assert!(
                !report.want_running,
                "a node that was never brought up must not want to be running"
            );
            // No engine → no self address and no peers.
            assert!(
                report.self_ipv4.is_none(),
                "offline node has no tailnet IPv4"
            );
            assert!(report.peers.is_empty(), "offline node has no peers");
        }
        other => panic!("expected Response::Status, got {other:?}"),
    }

    harness.shutdown_and_verify().await;
}

/// 2. down round-trip: `down` succeeds offline (no engine to tear down, just persists intent), and
///    a subsequent `status` reports the node as explicitly Stopped and not wanting to run.
#[tokio::test]
async fn down_round_trip_then_status_is_stopped() {
    let harness = Harness::start().await;

    let down_resp = harness.round_trip(r#"{"cmd":"down"}"#).await;
    match down_resp {
        Response::Ok { message } => {
            assert!(!message.is_empty(), "Ok response should carry a message");
        }
        other => panic!("expected Response::Ok from down, got {other:?}"),
    }

    // After an explicit `down`, the node is configured-but-stopped.
    let status_resp = harness.round_trip(r#"{"cmd":"status"}"#).await;
    match status_resp {
        Response::Status(report) => {
            assert!(
                !report.want_running,
                "after down, want_running must be false"
            );
            assert_eq!(
                report.state, "Stopped",
                "after an explicit down, the node should derive to Stopped"
            );
        }
        other => panic!("expected Response::Status after down, got {other:?}"),
    }

    harness.shutdown_and_verify().await;
}

/// 3. bad request: a malformed command yields a `Response::Error` and does NOT crash the
///    connection or the serve loop (a follow-up `status` on a new connection still works).
#[tokio::test]
async fn bad_request_yields_error_and_keeps_serving() {
    let harness = Harness::start().await;

    let resp = harness.round_trip(r#"{"cmd":"frobnicate"}"#).await;
    match resp {
        Response::Error { message } => {
            assert!(!message.is_empty(), "Error response should explain why");
        }
        other => panic!("expected Response::Error for unknown command, got {other:?}"),
    }

    // The loop must survive a bad request: a fresh, well-formed status still gets served.
    let follow_up = harness.round_trip(r#"{"cmd":"status"}"#).await;
    assert!(
        matches!(follow_up, Response::Status(_)),
        "server must keep serving after a bad request, got {follow_up:?}"
    );

    harness.shutdown_and_verify().await;
}

/// 3b. `debug capture` on an offline node (no device) yields "node is not up" — it never creates the
///     pcap file (the device-absent branch is reached before any file open). Confirms the write-gated
///     diagnostic degrades cleanly on a down node, like `ping`/`whois`.
#[tokio::test]
async fn debug_capture_on_offline_node_is_node_not_up() {
    let harness = Harness::start().await;

    let path = std::env::temp_dir().join(format!("tnet-capture-test-{}.pcap", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let req = format!(
        r#"{{"cmd":"debug_capture","path":{:?},"seconds":1}}"#,
        path.to_string_lossy()
    );
    let resp = harness.round_trip(&req).await;
    match resp {
        Response::Error { message } => {
            assert!(
                message.contains("not up"),
                "offline capture should say the node is not up, got: {message}"
            );
        }
        other => panic!("expected Response::Error for offline capture, got {other:?}"),
    }
    // The device-absent branch must not have created the file.
    assert!(
        !path.exists(),
        "no pcap file should be created when the node is down"
    );

    harness.shutdown_and_verify().await;
}

/// 4. wire-format guard: assert the exact on-the-wire bytes of the request/response discriminants
///    at the integration boundary. This mirrors the unit tests in `localapi.rs` but guards against
///    wire drift from the consumer's side (the bytes the daemon and CLI must agree on).
#[tokio::test]
async fn wire_format_discriminants_are_stable() {
    // Requests the CLI emits.
    assert_eq!(
        serde_json::to_string(&Request::Status).expect("serialize Status"),
        r#"{"cmd":"status"}"#,
        "status request wire format drifted"
    );
    assert_eq!(
        serde_json::to_string(&Request::Down).expect("serialize Down"),
        r#"{"cmd":"down"}"#,
        "down request wire format drifted"
    );

    // The error reply the daemon emits must be tagged `kind:"error"`.
    let err = Response::Error {
        message: "boom".to_string(),
    };
    assert_eq!(
        serde_json::to_string(&err).expect("serialize Error"),
        r#"{"kind":"error","message":"boom"}"#,
        "error response wire format drifted"
    );

    // And the bytes round-trip back into the same variant the daemon would dispatch on.
    let parsed: Request =
        serde_json::from_str(r#"{"cmd":"status"}"#).expect("parse status request");
    assert!(matches!(parsed, Request::Status));
    let parsed: Request = serde_json::from_str(r#"{"cmd":"down"}"#).expect("parse down request");
    assert!(matches!(parsed, Request::Down));
}
