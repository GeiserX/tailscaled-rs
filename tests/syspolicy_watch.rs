//! The *positive* edge of the `policy` notify bit, over the real LocalAPI socket: a parked
//! `{"cmd":"watch","policy":true}` client is woken, and sent a fresh `Notify.Policy` frame carrying
//! the new rows, when the effective system policy genuinely changes.
//!
//! Why this is its own test binary. In this build the only thing that can move the effective policy
//! is a source being registered (the JSON store captures its file at construction and is never
//! re-read, so a `syspolicy reload` re-resolves the very rows a watcher already holds — Go's
//! `rsop.(*Policy).reloadNow` invokes its change callbacks only under `!old.EqualItems(new)`, so
//! that reload is silent). Registration is process-global, exactly as Go's `rsop` store list is, so
//! a test that registers cannot share a process with tests that need the effective policy to stay
//! empty. `tests/localapi_loop.rs` needs precisely that, and owns the negative half of the rule
//! (`a_policy_masked_watch_front_loads_the_snapshot_and_stays_quiet_on_an_unchanged_reload`); this
//! file owns the positive half, and is deliberately the ONLY test in its binary.
//!
//! What it covers that nothing else does: `server::stream_notify`'s policy arm — the wake on
//! `policy_rx.changed()` and the `emit_policy_frame` write — driven from a real registration and
//! read back off the wire as a decoded `Response::Notify`. The in-process channel edge alone is
//! pinned in `tests/syspolicy_file.rs`; this is the socket.
//!
//! Upstream: `util/syspolicy/rsop/resultant_policy.go` (`reloadNow`) and
//! `ipn/ipnlocal/local.go` (`sysPolicyChangedForSession`, `NotifySysPolicyChanges`) @
//! `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8`; the flag whose body does the registering is
//! `cmd/tailscaled/syspolicy.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tailscaled_rs::ipn::{Backend, syspolicy};
use tailscaled_rs::localapi::Response;
use tailscaled_rs::server;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, oneshot};

/// A temp path unique to this test binary's process, so a leftover from a previous run can never be
/// mistaken for this run's.
fn temp_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "tailnetd-syspolicy-watch-{}-{}",
        std::process::id(),
        tag
    ))
}

/// Read one line from an open watch stream within `dur`, decoded. `None` on timeout or EOF — a
/// BOUNDED read, so a missing wake edge FAILS the test rather than hanging it forever.
async fn try_read_frame(
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
        Ok(_) | Err(_) => None,
    }
}

/// Registering a policy source takes the effective policy from empty to the file's rows. That is a
/// real change, so every parked policy watcher must be woken and sent the new snapshot — over the
/// socket, through `stream_notify`'s policy arm, not merely on the in-process channel.
#[tokio::test]
async fn a_real_policy_change_pushes_a_policy_frame_to_a_parked_socket_watcher() {
    let state_dir = temp_path("statedir");
    let _ = tokio::fs::remove_dir_all(&state_dir).await;
    tokio::fs::create_dir_all(&state_dir)
        .await
        .expect("create temp state dir");
    let socket_path = state_dir.join("tailnetd.sock");

    // Offline backend + the real `server::serve`, exactly as a daemon runs it. No engine, no
    // network: policy is resolved from the registry, so the device-less arm of `stream_notify` is
    // the one under test — which is the arm a `syspolicy reload` on a down node would hit too.
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

    // Wait for the socket to be connectable, bounded.
    let mut connected = None;
    for _ in 0..200 {
        if let Ok(stream) = UnixStream::connect(&socket_path).await {
            connected = Some(stream);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let stream = connected.unwrap_or_else(|| {
        panic!(
            "LocalAPI socket never became connectable: {}",
            socket_path.display()
        )
    });

    let (read_half, mut write_half) = stream.into_split();
    write_half
        .write_all(b"{\"cmd\":\"watch\",\"policy\":true}\n")
        .await
        .expect("write masked watch request");
    write_half.flush().await.expect("flush watch request");
    let mut reader = BufReader::new(read_half);

    // The front-loaded frame (Go's `NotifySysPolicyChanges` contract), discarded past its emptiness:
    // nothing is registered yet, so this is the empty-but-present device-scope report.
    let first = try_read_frame(&mut reader, Duration::from_secs(5))
        .await
        .expect("a policy-masked watch must send its snapshot immediately");
    let Response::Notify(first) = first else {
        panic!("a masked watch streams Notify frames, got {first:?}");
    };
    let before = first
        .policy
        .as_ref()
        .expect("the first frame of a policy-masked watch carries the policy");
    assert!(
        before.settings.is_empty(),
        "no source is registered yet, so the front-loaded snapshot is empty: {before:?}"
    );
    assert!(
        try_read_frame(&mut reader, Duration::from_millis(300))
            .await
            .is_none(),
        "a parked policy watcher must stay quiet while the policy does not move"
    );

    // THE CHANGE. `load_json_policy_file` is the body of `tailnetd --syspolicy-file`; this is the
    // one event in this build that genuinely moves the effective policy.
    let path = temp_path("policy.json");
    std::fs::write(
        &path,
        br#"{"Hostname": "documented-node", "ExitNodeIP": "192.0.2.10"}"#,
    )
    .expect("the temp policy file should be writable");
    let outcome = syspolicy::load_json_policy_file(syspolicy::JSON_FILE_SOURCE_NAME, &path);
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        outcome,
        Ok(syspolicy::LoadOutcome::Registered { settings: 2 }),
        "both keys should register"
    );

    let second = try_read_frame(&mut reader, Duration::from_secs(5))
        .await
        .expect(
            "a real policy change must wake a parked policy watcher and push a fresh snapshot — \
             without it a watcher cannot tell 'policy unchanged' from 'policy changed and I have \
             not asked again'",
        );
    let Response::Notify(second) = second else {
        panic!("a masked watch streams Notify frames, got {second:?}");
    };
    let pushed = second
        .policy
        .as_ref()
        .expect("a policy tick emits a frame carrying the policy");
    let rows: Vec<(&str, &str, Option<&str>)> = pushed
        .settings
        .iter()
        .map(|s| (s.key.as_str(), s.origin.as_str(), s.value.as_deref()))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("ExitNodeIP", "JSONFile (Device)", Some("192.0.2.10")),
            ("Hostname", "JSONFile (Device)", Some("documented-node")),
        ],
        "the pushed frame carries the NEW rows, not the empty set the watcher already had"
    );
    assert_eq!(
        pushed,
        &Backend::policy_snapshot(),
        "one renderer of the snapshot: the pushed frame is the same report `syspolicy list` returns"
    );
    assert!(
        second.state.is_none() && second.net_map.is_none() && second.prefs.is_none(),
        "a policy-only watch must not be sent fields it did not ask for: {second:?}"
    );

    // And the tick was an edge, not a repeat: nothing further arrives while the policy sits still —
    // which is also the second half of the rule, since re-resolving cannot move these rows.
    assert!(
        try_read_frame(&mut reader, Duration::from_millis(500))
            .await
            .is_none(),
        "one change, one frame: the stream must go quiet again"
    );

    let _ = shutdown_tx.send(());
    match tokio::time::timeout(Duration::from_secs(5), serve_task).await {
        Ok(join_result) => join_result.expect("serve task panicked"),
        Err(_) => panic!("serve task did not exit within 5s after shutdown signal"),
    }
    assert!(
        !socket_path.exists(),
        "socket file should be removed after shutdown: {}",
        socket_path.display()
    );
    let _ = tokio::fs::remove_dir_all(&state_dir).await;
}
