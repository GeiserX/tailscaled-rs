//! The LocalAPI `shutdown` verb, end to end over the real socket.
//!
//! Go's `serveShutdown` (`ipn/localapi/localapi.go`) refuses a caller without write access, refuses
//! a caller WITH write access unless `polc.GetBoolean(pkey.AllowTailscaledRestart, false)` is true,
//! and otherwise writes its 200, flushes, and publishes the event that closes the LocalAPI listener
//! — which unwinds `Run` and ends the process. This file pins the two halves that only exist once
//! the verb is wired into a running daemon:
//!
//! 1. **default deny.** A daemon with no policy file refuses `shutdown` from its own owner and KEEPS
//!    SERVING. The refusal is not a rejected frame on a dying daemon — the next request still works.
//! 2. **the stop itself.** With `AllowTailscaledRestart` set, the caller is acknowledged and the
//!    daemon then stops on the verb alone — no signal is ever sent: the reply is delivered, the
//!    accept loop ends, and the socket is unlinked on the way out, exactly as it is on
//!    SIGINT/SIGTERM. No `process::exit` — which is what lets the daemon's own teardown (state
//!    file, live device) run at all. The write-then-notify ORDER inside the handler is not pinned
//!    here; see the note at the end of the test for why it cannot be, from outside the process.
//!
//! The refusal *ladder* — which rung answers, in which order — is unit-tested against the production
//! predicate in `src/server.rs` (`shutdown_verdict`), where both rungs are reachable. Here the peer
//! is always the test process itself, so it is always the daemon's owner and always has write
//! access; a read-only peer cannot be produced over a real Unix socket without a second uid.
//!
//! ## Why this is its own test binary
//!
//! Case 2 registers a policy source into the process-global registry (Go's `rsop` store list is
//! global too, and `tests/syspolicy_file.rs` carries the same note). `tests/localapi_loop.rs` asserts
//! an EMPTY policy snapshot, so registering there would break it from a distance. Both cases live in
//! ONE test function, in order, for the same reason: the first must run while the registry is still
//! empty, and cargo runs a binary's tests in parallel threads of one process.
//!
//! Upstream: `ipn/localapi/localapi.go` @ `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8`.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tailscaled_rs::ipn::{Backend, syspolicy};
use tailscaled_rs::localapi::Response;
use tailscaled_rs::server;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, oneshot};

/// Per-process-unique counter so the two daemons this file starts never collide on a path.
static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// How long any wait in this file may take before it is a failure. Generous for a loaded CI box,
/// but bounded: a `shutdown` that never stops the accept loop must fail the test rather than hang it.
const PATIENCE: Duration = Duration::from_secs(10);

/// A running LocalAPI server on its own socket, plus the handles to drive and tear it down.
struct Harness {
    state_dir: PathBuf,
    socket_path: PathBuf,
    /// Fire to ask `serve` to stop the ordinary way (the SIGINT/SIGTERM path).
    shutdown_tx: oneshot::Sender<()>,
    /// The spawned `serve` task; await it to observe a clean exit.
    serve_task: tokio::task::JoinHandle<()>,
}

impl Harness {
    /// Build a fresh state dir, load an offline `Backend` (file read only — no engine, no network,
    /// no auth key) and spawn the real `server::serve` on a unique socket inside it.
    async fn start() -> Harness {
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        // Kept as short as the existing integration harness's (`tailnetd-it-<pid>-<n>` in
        // `tests/localapi_loop.rs`): the socket goes INSIDE this directory, and `sun_path` is 104
        // bytes including the NUL, so every byte spent on a prefix is a byte of `TMPDIR` budget a
        // developer with a long temp directory no longer has.
        let state_dir =
            std::env::temp_dir().join(format!("tailnetd-sd-{}-{}", std::process::id(), n));
        let _ = tokio::fs::remove_dir_all(&state_dir).await;
        tokio::fs::create_dir_all(&state_dir)
            .await
            .expect("create temp state dir");
        let socket_path = state_dir.join("tailnetd.sock");

        let backend = Backend::load(&state_dir)
            .await
            .expect("Backend::load must succeed offline");
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

        wait_for_socket(&socket_path).await;
        Harness {
            state_dir,
            socket_path,
            shutdown_tx,
            serve_task,
        }
    }

    /// Send one request line and read the one-line reply, on a fresh connection (what `tnet` does).
    async fn round_trip(&self, request_line: &str) -> Response {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .expect("connect to the LocalAPI socket");
        let (read_half, mut write_half) = stream.into_split();
        write_half
            .write_all(format!("{request_line}\n").as_bytes())
            .await
            .expect("write request");
        write_half.flush().await.expect("flush request");

        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        tokio::time::timeout(PATIENCE, reader.read_line(&mut line))
            .await
            .expect("the daemon must reply within the patience window")
            .expect("read reply");
        assert!(
            !line.is_empty(),
            "the daemon closed the connection without replying to {request_line}"
        );
        serde_json::from_str(line.trim()).expect("parse the daemon's reply")
    }

    /// Stop the daemon the ordinary way and confirm `serve` returned cleanly.
    async fn stop_normally(self) {
        let _ = self.shutdown_tx.send(());
        tokio::time::timeout(PATIENCE, self.serve_task)
            .await
            .expect("serve must return after the shutdown signal")
            .expect("serve task must not panic");
        let _ = tokio::fs::remove_dir_all(&self.state_dir).await;
    }
}

/// Poll until the socket accepts a connection (the server binds asynchronously after spawn).
async fn wait_for_socket(socket_path: &std::path::Path) {
    let deadline = std::time::Instant::now() + PATIENCE;
    loop {
        if UnixStream::connect(socket_path).await.is_ok() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the LocalAPI socket never became connectable at {}",
            socket_path.display()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Both halves of the verb, in the one order the process-global policy registry allows.
#[tokio::test]
async fn shutdown_is_refused_by_default_and_stops_the_daemon_once_the_policy_allows_it() {
    // --- 1. Default deny: no policy source is registered yet. ---
    let harness = Harness::start().await;

    let refused = harness.round_trip(r#"{"cmd":"shutdown"}"#).await;
    let Response::Error { message } = refused else {
        panic!("an unconfigured daemon must REFUSE `shutdown`, got {refused:?}");
    };
    assert!(
        message.starts_with("shutdown access denied by policy"),
        "the owner has write access, so the refusal must be the POLICY one (Go's second rung), \
         got: {message}"
    );
    assert!(
        message.contains("AllowTailscaledRestart"),
        "the refusal must name the key that lifts it, got: {message}"
    );

    // The refusal must be a refusal and nothing else: the daemon is still serving, on a new
    // connection, after telling a caller no.
    let after = harness.round_trip(r#"{"cmd":"status"}"#).await;
    assert!(
        matches!(after, Response::Status(_)),
        "a refused `shutdown` must leave the daemon serving, got {after:?}"
    );
    harness.stop_normally().await;

    // --- 2. The administrator opts in, and the verb stops the daemon. ---
    // Registering into the process-global registry is what makes this the only test in this binary
    // (see the module docs). The file goes through the real `--syspolicy-file` loader, so the value
    // reaches the server the same way an operator's file does.
    let policy_path = std::env::temp_dir().join(format!(
        "tailnetd-shutdown-policy-{}.json",
        std::process::id()
    ));
    std::fs::write(&policy_path, r#"{"AllowTailscaledRestart": true}"#)
        .expect("write the policy file");
    let outcome = syspolicy::load_json_policy_file(syspolicy::JSON_FILE_SOURCE_NAME, &policy_path)
        .expect("the policy file must load");
    assert!(
        matches!(outcome, syspolicy::LoadOutcome::Registered { settings: 1 }),
        "the policy file must register exactly one setting, got {outcome:?}"
    );
    let _ = std::fs::remove_file(&policy_path);

    let harness = Harness::start().await;
    let accepted = harness.round_trip(r#"{"cmd":"shutdown"}"#).await;
    assert!(
        matches!(accepted, Response::Ok { .. }),
        "with `AllowTailscaledRestart` set, the owner's `shutdown` must be accepted, got \
         {accepted:?}"
    );

    // What the wait below pins is that the reply was DELIVERED and the daemon then stopped on the
    // verb alone, with no signal sent. It deliberately does not claim to prove the write-then-notify
    // ORDER: a handler that notified first would still get its reply out inside `serve`'s drain
    // window (`DRAIN_TIMEOUT`, `src/server.rs`), so this test passes either way. That ordering is
    // held structurally instead, by the shape of the `Request::Shutdown` arm in `handle_conn`
    // (`src/server.rs`) — acknowledge, flush, then notify — and there is no non-racy way to observe
    // it from outside the process, so nothing here tries to.
    let Harness {
        state_dir,
        socket_path,
        // Never fired: `serve` has to return on the VERB alone, so the ordinary shutdown future
        // stays pending for the whole of the wait below.
        shutdown_tx: _shutdown_tx,
        serve_task,
    } = harness;
    tokio::time::timeout(PATIENCE, serve_task)
        .await
        .expect("`shutdown` must unwind the accept loop without any signal being sent")
        .expect("serve task must not panic");
    // A clean stop, not an abort: `serve` unlinked its socket on the way out, exactly as it does on
    // a signal. This is the observable half of "the existing shutdown path ran".
    assert!(
        !socket_path.exists(),
        "a `shutdown` must unlink the socket like any other clean stop"
    );
    assert!(
        UnixStream::connect(&socket_path).await.is_err(),
        "nothing may still be accepting on a stopped daemon's socket"
    );
    let _ = std::fs::remove_dir_all(&state_dir);
}
