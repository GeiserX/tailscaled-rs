//! The LocalAPI server: a Unix-domain-socket IPC surface the CLI talks to.
//!
//! Transport (MVP): newline-delimited JSON. One [`Request`] per line in, one [`Response`] JSON
//! object per line out, then the connection closes. This is deliberately the simplest thing that
//! works; the planned evolution is HTTP/1 over the same socket with `SO_PEERCRED` authorization
//! (read for anyone, write for root/same-UID), matching Tailscale's LocalAPI auth model.
//!
//! Concurrency: the [`Backend`] is shared behind a `Mutex` because every command either mutates
//! the lifecycle (`up`/`down`) or reads a consistent snapshot (`status`). Commands are naturally
//! serialized, which is the correct semantics for a node lifecycle. Connections themselves run on a
//! [`JoinSet`] (so in-flight handlers are drained on shutdown, not silently dropped) behind a
//! [`Semaphore`] cap (defense-in-depth against a connection flood).

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;

use crate::auth::{self, Access, AuthPolicy};
use crate::ipn::{self, Backend};
use crate::localapi::{Request, Response};

/// Max bytes for a single newline-delimited request line. LocalAPI requests are tiny JSON, so this
/// is generous; its only job is to stop a single newline-less connection from growing the read
/// buffer without bound (OOM the daemon). A line longer than this is rejected and its connection
/// closed.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Generous cap on concurrently-handled connections. Defense-in-depth against a flood: an
/// unprivileged local user that can reach the socket should not be able to exhaust the daemon's
/// tasks/fds. The CLI opens one short-lived connection per command, so 128 is far above normal use.
const MAX_CONNECTIONS: usize = 128;

/// How long to let in-flight connection handlers finish after a shutdown signal before they are
/// aborted. Bounds shutdown latency so a wedged handler can't keep the daemon from exiting.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Run the LocalAPI server until `shutdown` resolves, then clean up the socket.
pub async fn serve(
    socket_path: &Path,
    backend: Arc<Mutex<Backend>>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    if let Some(dir) = socket_path.parent() {
        tokio::fs::create_dir_all(dir)
            .await
            .with_context(|| format!("creating socket dir {}", dir.display()))?;
        // Harden the socket's parent dir to 0700 here, in `serve` itself — we don't trust the
        // caller to have done it, because `serve` is called directly (the integration tests, and
        // any deployment where `TAILNETD_SOCKET` points outside the 0700 state dir). The dir is the
        // real reach gate (mirrors `crate::ensure_state_dir_secure`): a different user typically
        // cannot even traverse into it. We deliberately leave the *socket inode* broadly connectable
        // (no 0600 chmod) — the "anyone who can reach it may read" contract relies on the dir, not
        // the socket mode, and a 0600 socket would also lock out root, breaking read-for-all.
        ensure_dir_0700(dir).await?;
    }
    // A stale socket from a prior run would make bind fail with EADDRINUSE.
    let _ = tokio::fs::remove_file(socket_path).await;

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("binding LocalAPI socket {}", socket_path.display()))?;
    tracing::info!(socket = %socket_path.display(), "LocalAPI listening");

    // Build the auth policy ONCE (it captures the daemon's effective uid); reused for every peer.
    let policy = AuthPolicy::from_current_process();
    // Cap concurrent connections; the permit is held for a connection's whole lifetime.
    let conn_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    // Track in-flight handlers so shutdown can drain them instead of dropping them mid-flight.
    let mut conns: JoinSet<()> = JoinSet::new();

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        // Authorize once, at accept: `for_peer` reads `peer_cred()` (which needs the
                        // whole stream) before `handle_conn` splits it into halves, and returns both
                        // the access decision and the uid we log — so the logged uid can never
                        // disagree with the authorization.
                        let (access, peer_uid) = policy.for_peer(&stream);
                        let backend = Arc::clone(&backend);
                        // Acquire a connection permit; if the cap is exhausted, drop the connection
                        // (closing it) rather than queueing unboundedly. Held for the handler's life.
                        let Ok(permit) = Arc::clone(&conn_limit).try_acquire_owned() else {
                            tracing::warn!("connection cap reached; dropping connection");
                            continue;
                        };
                        conns.spawn(async move {
                            let _permit = permit;
                            if let Err(e) = handle_conn(stream, access, peer_uid, backend).await {
                                tracing::warn!(error = %e, "LocalAPI connection error");
                            }
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "accept failed"),
                }
            }
        }
    }

    // Drain in-flight handlers so they finish (or are deliberately, boundedly cancelled) instead of
    // being silently dropped when the runtime ends. Bounded by `DRAIN_TIMEOUT`; on timeout the
    // remaining tasks are aborted by dropping the `JoinSet`.
    match tokio::time::timeout(DRAIN_TIMEOUT, async {
        while conns.join_next().await.is_some() {}
    })
    .await
    {
        Ok(()) => {}
        Err(_) => {
            tracing::warn!(
                "in-flight LocalAPI connections did not drain within {DRAIN_TIMEOUT:?}; aborting them"
            );
            conns.abort_all();
        }
    }

    let _ = tokio::fs::remove_file(socket_path).await;
    tracing::info!("LocalAPI stopped");
    Ok(())
}

/// Enforce `0700` on `dir` (the socket's parent). Mirrors [`crate::ensure_state_dir_secure`]: a
/// pre-existing group/world-accessible dir is tightened (and logged) rather than trusted. No-op
/// beyond the directory already existing on non-unix targets.
async fn ensure_dir_0700(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = tokio::fs::metadata(dir)
            .await
            .with_context(|| format!("stat socket dir {}", dir.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            tracing::warn!(
                path = %dir.display(),
                found = format!("{mode:o}"),
                "socket dir not 0700; tightening (it gates who can reach the control socket)"
            );
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            tokio::fs::set_permissions(dir, perms)
                .await
                .with_context(|| format!("chmod 0700 socket dir {}", dir.display()))?;
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

async fn handle_conn(
    stream: UnixStream,
    access: Access,
    peer_uid: Option<u32>,
    backend: Arc<Mutex<Backend>>,
) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = Vec::new();

    loop {
        match read_capped_line(&mut reader, &mut line).await? {
            LineResult::Eof => break,
            LineResult::TooLong => {
                // A line exceeded the cap: refuse it and close the connection (the framing is now
                // out of sync — we'd be mid-line). One response, then we're done with this peer.
                let response = Response::Error {
                    message: "request too large".into(),
                };
                write_response(&mut write_half, &response).await?;
                break;
            }
            LineResult::Line => {
                // Decode strictly: an invalid-UTF-8 line is rejected cleanly (not lossily patched
                // with U+FFFD and fed to the JSON parser). Like the malformed-JSON path below, we
                // answer with an error and keep handling subsequent lines, never closing the loop.
                let text = match std::str::from_utf8(&line) {
                    Ok(t) => t,
                    Err(_) => {
                        let response = Response::Error {
                            message: "bad request: invalid UTF-8".into(),
                        };
                        write_response(&mut write_half, &response).await?;
                        continue;
                    }
                };
                if text.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<Request>(text) {
                    // `Watch` is terminal for this connection: it takes over the socket and streams
                    // status lines until the client disconnects (or shutdown). It is read-only, so
                    // it is gated exactly like `Status` — anyone who may read may watch.
                    Ok(Request::Watch) => {
                        stream_watch(&mut write_half, &backend).await?;
                        break;
                    }
                    Ok(req) => {
                        let response = dispatch(req, access, peer_uid, &backend).await;
                        write_response(&mut write_half, &response).await?;
                    }
                    Err(e) => {
                        let response = Response::Error {
                            message: format!("bad request: {e}"),
                        };
                        write_response(&mut write_half, &response).await?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Stream `status` over a connection: emit an initial [`StatusReport`] line, then one more on each
/// engine connection-state transition, surviving device replacement (`down`+`up`), until the client
/// disconnects or the daemon shuts down. The analogue of `tailscale status --watch`.
///
/// ## Why it is a two-level loop (and not just `rx.changed()`)
///
/// The engine's `DeviceState` receiver is **per-device**: each `up` builds a fresh `Device` with a
/// fresh receiver. A naive single-receiver loop goes deaf the moment a `down`+`up` replaces the
/// device, and never starts at all if the watch began before the first `up`. So we also subscribe to
/// the backend's **lifecycle** channel ([`Backend::watch_lifecycle`], bumped on every `up`/`down`)
/// and re-derive the current device receiver on each lifecycle change. The outer loop owns one
/// "device epoch"; the inner loop streams that epoch's transitions until the device goes away or a
/// lifecycle change supersedes it.
///
/// ## The load-bearing rule: snapshot FIRST, then await
///
/// A freshly-acquired `watch` receiver's first `changed()` may fire immediately (the engine hands
/// out a clone pinned at the initial version) — so we must **never rely on `changed()` to deliver
/// the current value**. Each epoch emits a `status()` snapshot *before* awaiting any `changed()`,
/// treating `changed()` purely as a wake source. This closes the missed-edge window on the first
/// device and on every replacement.
///
/// ## Lock discipline
///
/// The backend guard is held only inside the brief blocks that subscribe / snapshot+grab-receiver /
/// re-snapshot — **never** across a `changed()` await — so a watcher never head-of-line blocks a
/// concurrent `up`/`down`/`status`. The snapshot and the receiver are grabbed in the *same* locked
/// block so they describe the same device.
async fn stream_watch(
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    backend: &Arc<Mutex<Backend>>,
) -> Result<()> {
    // Subscribe to lifecycle BEFORE the first snapshot so an up/down landing between the snapshot
    // and the subscribe is never lost. `subscribe()` starts synced to the current generation.
    let mut life = {
        let be = backend.lock().await;
        be.watch_lifecycle()
    };

    // Outer loop: one "device epoch" per iteration. Re-entered whenever the device is replaced
    // (down+up) or torn down (down) — re-deriving the current receiver each time.
    loop {
        // BRIEF LOCK: snapshot status + grab the current device receiver together, so the emitted
        // snapshot and the receiver we then watch describe the same device.
        let (report, mut dev_rx) = {
            let be = backend.lock().await;
            (be.status().await, be.watch_state_receiver())
        };
        // Emit the snapshot FIRST (never rely on changed() to deliver the value). Write error =
        // client hung up → done.
        if write_response(write_half, &Response::Status(report))
            .await
            .is_err()
        {
            return Ok(());
        }

        match dev_rx.as_mut() {
            // No device this epoch: nothing transitions. Wait only for the next lifecycle change,
            // then re-derive at the top (an `up` may now have installed a device).
            None => {
                if life.changed().await.is_err() {
                    return Ok(()); // lifecycle sender dropped (daemon gone)
                }
                continue;
            }
            // A device exists: stream its transitions, but also break out on a lifecycle change so a
            // replacement device is re-derived by the outer loop.
            Some(rx) => loop {
                tokio::select! {
                    res = rx.changed() => {
                        if res.is_err() {
                            // Device torn down (its watch::Sender dropped). Re-derive at the top:
                            // either a new device exists, or we fall into the None arm and wait.
                            break;
                        }
                        let report = {
                            let be = backend.lock().await;
                            be.status().await
                        };
                        if write_response(write_half, &Response::Status(report))
                            .await
                            .is_err()
                        {
                            return Ok(()); // client hung up
                        }
                    }
                    res = life.changed() => {
                        if res.is_err() {
                            return Ok(()); // lifecycle sender dropped (daemon gone)
                        }
                        // A down+up replaced the device — supersede this epoch; the outer loop
                        // re-derives the new receiver and snapshots it first.
                        break;
                    }
                }
            },
        }
    }
}

/// Serialize one [`Response`] as a single newline-terminated JSON line and flush it.
async fn write_response(
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    response: &Response,
) -> Result<()> {
    let mut bytes = serde_json::to_vec(response).expect("response serialize");
    bytes.push(b'\n');
    write_half.write_all(&bytes).await?;
    write_half.flush().await?;
    Ok(())
}

/// Outcome of [`read_capped_line`].
enum LineResult {
    /// A full line (without its trailing `\n`) is now in the output buffer.
    Line,
    /// Clean end of stream with no further data.
    Eof,
    /// The line exceeded [`MAX_LINE_BYTES`] before a newline arrived.
    TooLong,
}

/// Read one newline-delimited line into `out`, capped at [`MAX_LINE_BYTES`].
///
/// The bounded analogue of `AsyncBufReadExt::lines()`: `lines()`/`read_until` grow without bound on
/// a connection that never sends a newline, which a single client could use to OOM the daemon. We
/// instead scan the `BufReader`'s buffered chunks for `\n`, copying into `out` and bailing with
/// [`LineResult::TooLong`] the moment the accumulated line would exceed the cap. The trailing `\n`
/// is consumed but not stored. `out` is cleared on entry.
async fn read_capped_line(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    out: &mut Vec<u8>,
) -> Result<LineResult> {
    out.clear();
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            // EOF. A partial (newline-less) line at EOF is treated as no line: the peer closed
            // without completing a request, so there is nothing well-formed to dispatch.
            return Ok(LineResult::Eof);
        }
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            // Strict `>`: a line of exactly MAX_LINE_BYTES is allowed — the cap is inclusive.
            if out.len() + pos > MAX_LINE_BYTES {
                // The line (excluding the newline) is over the cap. Don't consume — the caller is
                // closing the connection anyway, and not consuming keeps this simple.
                return Ok(LineResult::TooLong);
            }
            out.extend_from_slice(&buf[..pos]);
            reader.consume(pos + 1); // drop the line and its '\n'
            return Ok(LineResult::Line);
        }
        // No newline in this chunk: would appending it exceed the cap?
        // Strict `>` for the same reason as above: MAX_LINE_BYTES bytes exactly is still in-bounds.
        if out.len() + buf.len() > MAX_LINE_BYTES {
            return Ok(LineResult::TooLong);
        }
        let n = buf.len();
        out.extend_from_slice(buf);
        reader.consume(n);
    }
}

async fn dispatch(
    req: Request,
    access: Access,
    peer_uid: Option<u32>,
    backend: &Arc<Mutex<Backend>>,
) -> Response {
    // Authorization gate: writes (`up`/`down`) require root or the daemon's owner. Reads (`status`)
    // are never gated. Checked before taking the backend lock so a denied caller never touches
    // lifecycle state.
    if auth::authorize(&req, access).is_err() {
        tracing::warn!(
            peer_uid = ?peer_uid,
            "denied LocalAPI write: caller lacks write permission"
        );
        return Response::Error {
            message: "permission denied: writing (up/down) requires root or the same user that owns the daemon".into(),
        };
    }

    match req {
        // `status` and `down` are fast under the lock, so take it directly.
        Request::Status => {
            let be = backend.lock().await;
            Response::Status(be.status().await)
        }
        // `Watch` is intercepted in `handle_conn` (it takes over the connection to stream) and never
        // reaches `dispatch`; this arm exists only for match exhaustiveness. Treat a stray `Watch`
        // here as a single status snapshot rather than erroring.
        Request::Watch => {
            let be = backend.lock().await;
            Response::Status(be.status().await)
        }
        // `version` (Go `tailscale version --daemon` reads `Status.Version`). The daemon's version is
        // its own compile-time crate version — a constant, needing no backend lock or engine.
        Request::Version => Response::Version {
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        // `get` (Go `tailscale get` / GetPrefs). Project the persisted prefs under a brief lock — no
        // engine round-trip, so it never head-of-line blocks. Shares `prefs_view()` with `status`.
        Request::GetPrefs => {
            let be = backend.lock().await;
            Response::Prefs(be.prefs_view())
        }
        // `switch --list` (Go `tailscale switch --list`). A read over the profile state dir.
        Request::ProfileList => {
            let be = backend.lock().await;
            Response::Profiles {
                profiles: be.list_profiles().await,
            }
        }
        // `metrics` (Go `tailscale metrics`). Off-lock device call (clone handle, drop lock) like the
        // other diagnostics; needs the node up (metrics come from the live engine).
        Request::Metrics => {
            let dev = { backend.lock().await.device_handle() };
            match dev {
                Some(dev) => Backend::metrics(&dev),
                None => Response::Error {
                    message: "node is not up".into(),
                },
            }
        }
        // `lock status` (Go `tailscale lock status`, read-only). Off-lock device call.
        Request::LockStatus => {
            let dev = { backend.lock().await.device_handle() };
            match dev {
                Some(dev) => Backend::lock_status(&dev).await,
                None => Response::Error {
                    message: "node is not up".into(),
                },
            }
        }
        // `switch <id>` (Go `tailscale switch`). Tears down the current device + swaps the active
        // profile under the lock (the teardown is a bounded graceful shutdown, not the multi-second
        // `Device::new` handshake, so holding the lock is correct and keeps the swap atomic). Does NOT
        // auto-up the target — the operator runs `up` if the new profile should connect.
        Request::SwitchProfile { target } => {
            let mut be = backend.lock().await;
            match be.switch_profile(&target).await {
                Ok(()) => Response::Ok {
                    message: format!("switched to profile {target}"),
                },
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        // `switch remove <id>` (Go `tailscale switch remove`). Refuses the current/default profile.
        Request::DeleteProfile { target } => {
            let mut be = backend.lock().await;
            match be.delete_profile(&target).await {
                Ok(()) => Response::Ok {
                    message: format!("removed profile {target}"),
                },
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        // `logout` (Go `tailscale logout`): deregisters the node key with control, tears down, and
        // discards the on-disk key so the next `up` re-registers fresh — distinct from `down` (which
        // resumes). Backend::logout holds the lock for the whole sequence: the control-plane
        // deregister is a quick mailbox round-trip (like `set`'s live exit-node, not the multi-second
        // `Device::new` handshake the begin/finish split exists for), so keeping it atomic under the
        // one lock is correct and simplest — no concurrent `up` should interleave a half-logout.
        Request::Logout => {
            let mut be = backend.lock().await;
            match be.logout().await {
                Ok(()) => Response::Ok {
                    message: "node logged out".to_string(),
                },
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        Request::Down => {
            let mut be = backend.lock().await;
            match be.down().await {
                Ok(()) => Response::Ok {
                    message: "node brought down".to_string(),
                },
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        // Read-only diagnostics (`ip`/`whois`/`ping`): these run engine calls that are NOT bounded
        // under the backend lock — `ping` in particular waits the caller's timeout (up to seconds),
        // and holding the lock across it would head-of-line block every concurrent `status`/`up`/
        // `down`. So we follow the same "clone the work out, drop the lock" discipline as `drive_up`:
        // lock only long enough to clone the engine handle (`device_handle()`), DROP the lock, then
        // run the engine call off-lock. `Some` reproduces each method's prior behavior; `None` is the
        // "node is not up" branch that used to live inside the method. The backend methods build the
        // typed reply verbatim (including their own bad-input error responses).
        Request::Ip => {
            let dev = { backend.lock().await.device_handle() };
            match dev {
                Some(dev) => Backend::ip_report(&dev).await,
                None => Response::Error {
                    message: "node is not up".into(),
                },
            }
        }
        Request::Whois { ip } => {
            let dev = { backend.lock().await.device_handle() };
            match dev {
                Some(dev) => Backend::whois(&dev, &ip).await,
                None => Response::Error {
                    message: "node is not up".into(),
                },
            }
        }
        Request::Ping { ip, timeout_ms } => {
            let dev = { backend.lock().await.device_handle() };
            match dev {
                Some(dev) => Backend::ping(&dev, &ip, timeout_ms).await,
                None => Response::Error {
                    message: "node is not up".into(),
                },
            }
        }
        // `up` performs a multi-second control-plane handshake (`Device::new`). Doing that under the
        // backend lock would head-of-line block every concurrent `status`. `ipn::drive_up` runs the
        // three-phase split — lock briefly for begin_up → DROP the lock for the slow handshake →
        // lock briefly for finish_up → settle any superseded orphan off-lock — so a `down`/`up` that
        // lands mid-flight supersedes this one and no concurrent call is blocked. The SIGHUP reload
        // path shares this exact helper. See `ipn::drive_up`.
        Request::Up {
            authkey,
            control_url,
            hostname,
            tun,
            tun_name,
            tun_mtu,
            exit_node,
            advertise_exit_node,
            advertise_routes,
            advertise_tags,
            accept_routes,
            ssh,
            reset,
        } => {
            // Confine the plaintext authkey to the smallest scope: wrap it into a `SecretString`
            // right at the boundary and hand the engine path the secret. (The wire type stays
            // `String` because `SecretString` does not serialize.)
            let authkey = authkey.map(secrecy::SecretString::from);
            // The routing fields (exit node + advertised exit/routes) flow straight through to
            // prefs via `UpOptions`; their semantics are documented on the field types.
            let opts = ipn::UpOptions {
                hostname,
                control_url,
                tun,
                tun_name,
                tun_mtu,
                exit_node,
                advertise_exit_node,
                advertise_routes,
                advertise_tags,
                accept_routes,
                ssh,
                reset,
            };
            // Accidental-revert guard (Go `checkForAccidentalSettingReverts`): unless this is a
            // `--reset` up, refuse an `up` that would silently revert a non-default pref it didn't
            // mention. This is a PURE READ that mutates nothing — done under a brief lock BEFORE
            // `drive_up` so a tripped guard leaves the node exactly as it was (no teardown, no
            // persist). On a non-empty result we return the structured reverts and the CLI renders
            // Go's "re-mention the current value of all non-default settings / pass --reset" message.
            // `--reset` opts out of the guard by construction (the operator accepts the reverts).
            if !opts.reset {
                let reverts = { backend.lock().await.up_revert_guard(&opts) };
                if !reverts.is_empty() {
                    return Response::RevertGuard { reverts };
                }
            }
            match ipn::drive_up(backend, authkey, opts).await {
                Ok(()) => Response::Ok {
                    message: "node brought up".to_string(),
                },
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        // `set` patches individual prefs without an up/down cycle (the `tailscale set` analogue). Like
        // `up`, it reconciles a live device (and `exit_node` is applied live with no reconnect), so it
        // goes through `ipn::drive_set` for the same off-lock handshake discipline rather than holding
        // the backend lock across the reconfigure. The fields move 1:1 into `SetOptions`.
        Request::Set {
            hostname,
            accept_routes,
            exit_node,
            advertise_exit_node,
            advertise_routes,
            advertise_tags,
            ssh,
        } => {
            let opts = ipn::SetOptions {
                hostname,
                accept_routes,
                exit_node,
                advertise_exit_node,
                advertise_routes,
                advertise_tags,
                ssh,
            };
            // `tailscale set` with no flags names no prefs: reject it as a usage error before touching
            // the backend, rather than driving a no-op reconcile.
            if opts.is_empty() {
                return Response::Error {
                    message: "set: no preferences specified".into(),
                };
            }
            match ipn::drive_set(backend, opts).await {
                Ok(()) => Response::Ok {
                    message: "preferences updated".to_string(),
                },
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        // Taildrop. `file_cp` and `file_get` run **slow, potentially unbounded** engine transfers
        // (an entire file over the overlay — `file_cp` has NO total deadline), so holding the backend
        // lock across them would freeze every concurrent `status`/`up`/`down` for the transfer's whole
        // duration — a daemon-wide DoS. We use the same clone-then-drop discipline as the diagnostics
        // above and as `drive_up`: lock only to clone the engine handle, DROP the lock, run the
        // transfer off-lock. `file_list` is a non-blocking store read (not part of that DoS) but takes
        // the identical shape for uniformity. The `None` arm is the prior in-method "node is not up"
        // branch. Each method builds the typed `Response` verbatim — no `Ok`/`Err` remap. `file_cp`/
        // `file_get` are writes (gated above); `file_list` is a read.
        //
        // NB: because the transfer runs off-lock holding only an `Arc` clone of the device, a
        // concurrent `down` may land mid-flight; `stop_device`'s `Arc::into_inner` then observes this
        // extra clone and takes the documented benign "drop the last clone" path. That is the correct
        // trade — a `down` no longer blocks for a multi-minute transfer — not a regression.
        Request::FileCp { path, peer } => {
            let dev = { backend.lock().await.device_handle() };
            match dev {
                Some(dev) => Backend::file_cp(&dev, &path, &peer).await,
                None => Response::Error {
                    message: "node is not up".into(),
                },
            }
        }
        Request::FileList => {
            let dev = { backend.lock().await.device_handle() };
            match dev {
                Some(dev) => Backend::file_list(&dev),
                None => Response::Error {
                    message: "node is not up".into(),
                },
            }
        }
        Request::FileGet {
            name,
            dest,
            delete_after,
        } => {
            let dev = { backend.lock().await.device_handle() };
            match dev {
                Some(dev) => Backend::file_get(&dev, &name, &dest, delete_after).await,
                None => Response::Error {
                    message: "node is not up".into(),
                },
            }
        }
    }
}
