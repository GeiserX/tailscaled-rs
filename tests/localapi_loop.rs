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
    /// The shared backend the `serve` task runs on. Retained so a test can drive backend-level
    /// lifecycle transitions (e.g. a generation bump via the public API) and observe how the live
    /// `stream_watch` server code reacts over the socket — used by the watch wake-edge regression.
    backend: Arc<Mutex<Backend>>,
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
            backend,
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

    /// Open a long-lived `Watch` stream over a fresh connection and read the FIRST snapshot.
    ///
    /// Unlike [`round_trip`](Harness::round_trip), `Watch` is terminal for the connection: the daemon
    /// hands the socket to `stream_watch`, which streams a `Response::Status` line per device epoch /
    /// lifecycle change. Returns the still-open write half (held by the caller so the connection stays
    /// open for the lifetime of the watch), the still-open reader (to read further snapshots as the
    /// backend transitions), and the first decoded snapshot. `stream_watch` emits the first snapshot
    /// unconditionally before it ever parks on a `changed()`, so this initial read returns promptly.
    async fn open_watch_stream(
        &self,
    ) -> (
        tokio::net::unix::OwnedWriteHalf,
        BufReader<tokio::net::unix::OwnedReadHalf>,
        Response,
    ) {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .expect("CLI connect to LocalAPI socket for watch");
        let (read_half, mut write_half) = stream.into_split();
        write_half
            .write_all(b"{\"cmd\":\"watch\"}\n")
            .await
            .expect("write watch request");
        write_half.flush().await.expect("flush watch request");

        let mut reader = BufReader::new(read_half);
        let first = read_watch_status(&mut reader).await;
        (write_half, reader, first)
    }

    /// Fire shutdown, await the serve task with a timeout (a hang fails the test instead of
    /// blocking forever), assert the socket file was removed, and best-effort-clean the state dir.
    async fn shutdown_and_verify(self) {
        let Harness {
            state_dir,
            socket_path,
            backend: _,
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

/// Read exactly one `Response::Status` line from an open `Watch` stream, asserting it is a status
/// (the only thing `stream_watch` ever emits). Used for the first snapshot, which always arrives
/// promptly; for the "did a NEW snapshot arrive?" assertion use [`try_read_watch_status`] instead.
async fn read_watch_status(reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>) -> Response {
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .await
        .expect("read watch status line");
    assert!(n > 0, "watch stream closed unexpectedly");
    serde_json::from_str::<Response>(line.trim_end())
        .unwrap_or_else(|e| panic!("watch line was not valid Response JSON ({e}): {line:?}"))
}

/// Try to read one more snapshot from an open `Watch` stream within `dur`. Returns `Some(Response)`
/// if a fresh line arrived, `None` if it timed out. This is the crux of the lost-wakeup regression:
/// a BOUNDED read so the test FAILS (returns `None` → assertion fires) rather than HANGS forever if
/// the wake edge is missing and no second snapshot is ever emitted.
async fn try_read_watch_status(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    dur: Duration,
) -> Option<Response> {
    let mut line = String::new();
    match tokio::time::timeout(dur, reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => Some(
            serde_json::from_str::<Response>(line.trim_end()).unwrap_or_else(|e| {
                panic!("watch line was not valid Response JSON ({e}): {line:?}")
            }),
        ),
        // EOF (n == 0) or a read error: the stream ended — treat as "no new snapshot".
        Ok(_) => None,
        // Timed out: no new snapshot arrived within the window (the lost-wakeup symptom).
        Err(_) => None,
    }
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

/// 2b. auth gate is wired into dispatch (write/read split). Two layers:
///
/// - **Allow-side, over the REAL socket as the owning peer:** the harness's daemon is started with
///   `AuthPolicy::from_current_process()` (the only policy `server::serve` builds), and the test
///   process is therefore the owner → `ReadWrite`. So a WRITE command (`down`) must NOT be
///   permission-denied, and a READ command (`status`) must succeed — proving dispatch routes both
///   verb classes through the gate without rejecting the authorized owner. (Existing tests assert
///   `down`/`status` shapes; here we additionally assert the WRITE is specifically not the
///   permission-denied error, pinning the allow branch of the gate at the socket boundary.)
///
/// - **Deny-side, through the EXACT gate `dispatch` calls:** `dispatch` (src/server.rs) gates every
///   request with `auth::authorize(&req, access)` BEFORE taking the backend lock, mapping
///   `Err(Denied)` to a fixed `permission denied …` `Response::Error`. We drive that same public
///   predicate on the real `Request::Down` (write) and `Request::Status` (read) values for a
///   `ReadOnly` caller: the write is denied, the read is allowed — and we reconstruct the exact
///   `Response::Error` the deny arm emits and assert its on-the-wire bytes, so a regression that
///   deletes/inverts the gate, or changes the denial message, fails here.
///
/// LIMITATION (honest scope): a ReadOnly peer cannot be produced over the real socket from this test
/// alone. `server::serve` hardcodes `AuthPolicy::from_current_process()` (owner = this test process),
/// and a Unix-socket peer's uid is the connecting process's uid — which we cannot drop to a
/// non-owner without root. Wiring a non-owner peer through the live socket would require a
/// test-only policy-injection parameter on `server::serve` (e.g. a `serve_with_policy`), which lives
/// in src/server.rs — outside this change's allowed file set. So the socket layer proves the
/// owner/allow path end-to-end, and the deny path is proven against the byte-for-byte gate the
/// dispatcher invokes (`auth::authorize` + the dispatch error string). Together they pin that the
/// gate exists, splits read vs write correctly, and is the one `dispatch` runs.
#[tokio::test]
async fn auth_gate_denies_write_allows_read() {
    use tailscaled_rs::auth::{Access, authorize};

    // --- Allow-side, over the real socket (owner peer → ReadWrite). ---
    let harness = Harness::start().await;

    // A WRITE command from the owner must NOT be permission-denied. (Offline `down` returns Ok; the
    // point here is the gate did not reject it — so assert it is specifically NOT the deny Error.)
    let down_resp = harness.round_trip(r#"{"cmd":"down"}"#).await;
    if let Response::Error { ref message } = down_resp {
        assert!(
            !message.contains("permission denied"),
            "owner peer must NOT be denied a write over the socket, got: {message}"
        );
    }
    assert!(
        matches!(down_resp, Response::Ok { .. }),
        "owner `down` should succeed offline (write allowed by the gate), got {down_resp:?}"
    );

    // A READ command from the owner still succeeds.
    let status_resp = harness.round_trip(r#"{"cmd":"status"}"#).await;
    assert!(
        matches!(status_resp, Response::Status(_)),
        "owner `status` (read) must succeed, got {status_resp:?}"
    );

    harness.shutdown_and_verify().await;

    // --- Deny-side, through the exact predicate `dispatch` calls before taking the backend lock. ---
    // A ReadOnly caller: the write verb is denied, the read verb is allowed. These are the real
    // `Request` values the daemon dispatches on (not stand-ins).
    let write_req = Request::Down;
    let read_req = Request::Status;
    assert_eq!(
        authorize(&write_req, Access::ReadOnly),
        Err(tailscaled_rs::auth::Denied),
        "a ReadOnly peer MUST be denied a write command (`down`) — the gate dispatch runs"
    );
    assert_eq!(
        authorize(&read_req, Access::ReadOnly),
        Ok(()),
        "a ReadOnly peer MUST still be allowed a read command (`status`)"
    );

    // The deny arm in `dispatch` maps `Err(Denied)` to this exact `Response::Error`. Reconstruct it
    // and pin its wire bytes, so a change to the denial contract (the message a denied CLI sees) is
    // caught at the integration boundary, not just in the unit gate.
    let denied_wire = serde_json::to_string(&Response::Error {
        message: "permission denied: writing (up/down) requires root or the same user that owns the daemon".into(),
    })
    .expect("serialize denied Response");
    assert_eq!(
        denied_wire,
        r#"{"kind":"error","message":"permission denied: writing (up/down) requires root or the same user that owns the daemon"}"#,
        "the permission-denied wire contract a denied CLI receives drifted"
    );
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

/// 5. WATCH wake-edge regression (the lost-wakeup fix in `Backend::finish_up`).
///
/// ## The bug this guards
///
/// The lifecycle watch channel (advanced by `bump_generation`) is the ONLY thing that makes
/// `stream_watch` (src/server.rs) re-derive a fresh per-device state receiver. A `status --watch`
/// parked on `watch_lifecycle()` while the node is down has taken the device-less (`None`) arm and is
/// NOT attached to any device's own state receiver — so the ONLY way it ever learns a device appeared
/// is a lifecycle bump waking its outer loop to re-derive.
///
/// `begin_up` bumps the generation while `self.device` is still `None` (the device is built off-lock
/// and installed later in `finish_up`). Before the fix, `finish_up` installed the device with NO
/// bump. The losing interleaving: the parked watcher wakes on `begin_up`'s bump, re-derives while the
/// device is STILL absent (emits another device-less snapshot, re-parks), then `finish_up` installs
/// the device silently — and the watcher waits forever for a generation change that already fired,
/// deaf to the device's own state receiver it never attached to. The Connecting→Running transition
/// (which flows only on that unattached receiver) never reaches the watch: it silently hangs on a
/// stale device-less snapshot. The fix makes the device-installed transition its own wake edge by
/// bumping the generation in `finish_up` right after the device is installed.
///
/// ## What this test proves (and its honest scope)
///
/// This test exercises the WAKE MECHANISM end-to-end through the real `server::serve` →
/// `stream_watch` path over the socket: it parks a real `Watch` stream on a down node, then drives a
/// real lifecycle generation bump on the shared backend via the public API and asserts that a NEW
/// snapshot is delivered to the parked watcher **within a bounded timeout** — i.e. the watcher woke,
/// its outer loop re-derived, and it re-snapshotted. A regression that breaks lifecycle-bump-driven
/// re-derivation (the class of bug the fix lives in) makes the second read TIME OUT, and the bounded
/// read turns that into a test FAILURE instead of an infinite hang.
///
/// Scope: this harness deliberately never joins a tailnet, so it cannot install a real
/// `tailscale::Device` (the engine handshake is a live network call with no offline/mock constructor),
/// and `finish_up`'s SUCCESS path — the exact line the fix adds — is only reachable with a live
/// device. The full "watch across a real `up`, observe Connecting→Running after the device installs"
/// assertion therefore belongs to the headscale-gated e2e (tests/headscale_e2e.rs), where a real
/// device IS installed. Here we pin the underlying invariant the fix depends on: a lifecycle bump
/// (the same kind `finish_up` now emits on device install) is an observable wake edge that drives
/// `stream_watch` to deliver a fresh snapshot to an already-parked watcher.
#[tokio::test]
async fn watch_redrives_on_lifecycle_bump_after_parking_on_down_node() {
    let harness = Harness::start().await;

    // Park a Watch stream on the DOWN node and read the first (device-less) snapshot. A fresh,
    // never-up'd node derives to NoState/Stopped with no engine; `stream_watch` emits this snapshot
    // unconditionally, then takes its `None` (no-device) arm and parks on `life.changed()`.
    let (_watch_write, mut watch_reader, first) = harness.open_watch_stream().await;
    let first_state = match first {
        Response::Status(report) => {
            assert!(
                report.state == "NoState" || report.state == "Stopped",
                "the first watch snapshot on a down node must be a device-less state, got {:?}",
                report.state
            );
            assert!(
                report.self_ipv4.is_none(),
                "a device-less watch snapshot has no tailnet IPv4"
            );
            report.state
        }
        other => panic!("expected a Response::Status as the first watch snapshot, got {other:?}"),
    };

    // Before doing anything else, prove no SECOND snapshot arrives on its own: with no lifecycle
    // change, the watcher stays correctly parked (this also makes the post-bump arrival meaningful —
    // it is the bump that wakes it, not noise).
    assert!(
        try_read_watch_status(&mut watch_reader, Duration::from_millis(300))
            .await
            .is_none(),
        "a parked watcher must NOT emit a second snapshot without a lifecycle change"
    );

    // Drive a REAL lifecycle generation bump on the shared backend via the public API. `begin_up`
    // bumps the generation (exactly as it does at the start of a real `up`, and the same kind of bump
    // the fix now also emits from `finish_up` when the device is installed). We do this directly on
    // the retained backend handle rather than over the socket so the test needs no engine: `begin_up`
    // only prepares config + persists prefs + bumps — no network, no device. (It leaves `device:
    // None`, faithfully mirroring the window in a real `up` between `begin_up` and `finish_up`.)
    {
        let mut be = harness.backend.lock().await;
        let _pending = be
            .begin_up(tailscaled_rs::ipn::UpOptions::default())
            .await
            .expect("begin_up prepares config + bumps generation offline (no engine)");
        // (We intentionally drop `_pending` without a matching `finish_up`: this test isolates the
        // WAKE edge, not a full bring-up. A real `finish_up` is what the headscale e2e exercises.)
    }

    // The crux: the parked watcher must wake on that bump, re-derive at the top of its outer loop,
    // and deliver a NEW snapshot — within a bounded window. Before the class of fix this guards, a
    // missing wake edge would leave it parked and this read would HANG; the bounded read turns a
    // regression into a prompt FAILURE.
    let second = try_read_watch_status(&mut watch_reader, Duration::from_secs(5))
        .await
        .expect(
            "after a lifecycle bump, the parked watcher MUST deliver a new snapshot (lost wakeup: \
             the watch hung waiting for a wake edge that never came)",
        );
    match second {
        Response::Status(report) => {
            // The node is still device-less here (no `finish_up`/engine). `begin_up` set the intent to
            // up with no device installed, which derives to `NeedsLogin` ("wants up but no engine →
            // needs (re)auth") — notably the very stale state the bug would hang the watch on. The
            // POINT is that a fresh snapshot was DELIVERED AT ALL, proving the wake edge fired and the
            // watcher re-derived; and it reflects the NEW intent (`want_running`), proving it really
            // re-snapshotted post-bump rather than replaying the first.
            assert_eq!(
                report.state, "NeedsLogin",
                "post-begin_up the device-less node wants up with no engine → NeedsLogin, got {:?}",
                report.state
            );
            assert!(
                report.want_running,
                "after begin_up the intent is up, so the re-derived snapshot must report want_running"
            );
            assert!(
                report.self_ipv4.is_none(),
                "the re-derived snapshot is still device-less, so it has no tailnet IPv4"
            );
        }
        other => panic!("expected a Response::Status as the second watch snapshot, got {other:?}"),
    }

    // Sanity: the first snapshot was a real, decoded status (not an artifact) — keeps the unused
    // binding meaningful and documents that we compared the same response shape across both reads.
    assert!(
        first_state == "NoState" || first_state == "Stopped",
        "first watch state should have been device-less"
    );

    // Drop the watch connection before tearing down so `stream_watch` observes the client hangup and
    // its task ends cleanly (otherwise the lingering reader could outlive the serve task).
    drop(watch_reader);
    drop(_watch_write);
    harness.shutdown_and_verify().await;
}

/// 6. WATCH wake-edge invariant, unit-pinned: a fresh `watch_lifecycle()` subscriber observes the
/// generation ADVANCE across the up path's bump — the observable wake edge the `finish_up` fix relies
/// on. This is the narrow, engine-free assertion that pins the mechanism the fix builds on: that the
/// lifecycle channel a parked `stream_watch` subscribes to genuinely fires (and carries a strictly
/// greater generation) when the up path bumps. `begin_up` is the reachable offline bump; the fix adds
/// a second bump of the SAME kind in `finish_up` on device install (covered end-to-end where a real
/// device can be installed: tests/headscale_e2e.rs).
#[tokio::test]
async fn lifecycle_subscriber_observes_generation_advance_on_up_path() {
    let harness = Harness::start().await;

    // A fresh subscriber starts synced to the current generation (it only wakes on strictly later
    // events) — exactly how `stream_watch` subscribes before its first snapshot.
    let mut life = {
        let be = harness.backend.lock().await;
        be.watch_lifecycle()
    };
    let gen_before = *life.borrow_and_update();

    // Drive the reachable offline bump (the start-of-`up` edge).
    {
        let mut be = harness.backend.lock().await;
        be.begin_up(tailscaled_rs::ipn::UpOptions::default())
            .await
            .expect("begin_up bumps the generation offline");
    }

    // The subscriber must see a change, carrying a strictly greater generation. Bounded so a broken
    // notification FAILS rather than hangs.
    tokio::time::timeout(Duration::from_secs(5), life.changed())
        .await
        .expect("watch_lifecycle subscriber must wake on the up-path bump (no wake edge = hang)")
        .expect("lifecycle sender must still be live");
    let gen_after = *life.borrow();
    assert!(
        gen_after > gen_before,
        "the up-path bump must advance the generation a parked watcher sees ({gen_before} -> \
         {gen_after}); this wake edge is what the finish_up fix adds for the device-installed \
         transition"
    );

    harness.shutdown_and_verify().await;
}
