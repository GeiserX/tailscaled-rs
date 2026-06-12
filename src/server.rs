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
                            tracing::warn!("LocalAPI: connection cap reached; dropping connection");
                            continue;
                        };
                        conns.spawn(async move {
                            let _permit = permit;
                            if let Err(e) = handle_conn(stream, access, peer_uid, backend).await {
                                tracing::warn!(error = %e, "LocalAPI: connection error");
                            }
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "LocalAPI: accept failed"),
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
                "LocalAPI: socket dir not 0700; tightening (it gates who can reach the control socket)"
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
                    // `nc` is terminal for this connection like `Watch`, but it is a WRITE (it opens
                    // an outbound connection), so it is authorized here before connecting. On a
                    // successful connect the daemon acks, then splices the LocalAPI socket <-> the
                    // overlay TCP stream bidirectionally (taking over `reader` + `write_half`). On a
                    // denied/failed connect it writes a normal error line and keeps the request loop
                    // alive (the connection was never hijacked).
                    Ok(Request::Nc { host, port }) => {
                        if auth::authorize(
                            &Request::Nc {
                                host: host.clone(),
                                port,
                            },
                            access,
                        )
                        .is_err()
                        {
                            tracing::warn!(peer_uid = ?peer_uid, "denied LocalAPI nc: caller lacks write permission");
                            write_response(
                                &mut write_half,
                                &Response::Error {
                                    message: "permission denied: nc requires root or the same user that owns the daemon".into(),
                                },
                            )
                            .await?;
                            continue;
                        }
                        // `stream_nc` returns Ok(true) if it hijacked the connection (spliced to EOF),
                        // Ok(false) if it only wrote an error line (connect failed) and the loop
                        // should continue serving this peer.
                        if stream_nc(&mut reader, &mut write_half, &backend, &host, port).await? {
                            break;
                        }
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

/// Connect to `host:port` over the tailnet and, on success, splice the LocalAPI connection to the
/// overlay TCP stream bidirectionally (the `tnet nc` path). Returns `Ok(true)` if it hijacked the
/// connection (spliced until EOF — the caller must stop serving this peer), or `Ok(false)` if it only
/// wrote an error line because the connect could not be established (the caller keeps the request
/// loop alive).
///
/// The connect runs off the backend lock (clone the device handle, drop the lock — like the other
/// diagnostics), so a long-lived `nc` never holds the lock. After the one-line `Ok` ack, the daemon
/// copies in both directions concurrently: `reader` (which carries any bytes the client already sent
/// after the request line) → the overlay stream, and the overlay stream → `write_half`. When either
/// direction hits EOF the splice ends and the connection closes.
async fn stream_nc(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    backend: &Arc<Mutex<Backend>>,
    host: &str,
    port: u16,
) -> Result<bool> {
    // Off-lock device handle, like the other diagnostics.
    let dev = { backend.lock().await.device_handle() };
    let Some(dev) = dev else {
        write_response(
            write_half,
            &Response::Error {
                message: "node is not up".into(),
            },
        )
        .await?;
        return Ok(false);
    };
    // Resolve + connect over the overlay (host may be a MagicDNS name or an IP). `connect_by_name`
    // handles both (it resolves a name, and an IP literal resolves to itself).
    let tcp = match dev.connect_by_name(host, port).await {
        Ok(s) => s,
        Err(e) => {
            write_response(
                write_half,
                &Response::Error {
                    message: format!("nc: connect to {host}:{port} failed: {e}"),
                },
            )
            .await?;
            return Ok(false);
        }
    };
    // Ack so the client knows the connection is live and can switch to raw piping.
    write_response(
        write_half,
        &Response::Ok {
            message: format!("connected to {host}:{port}"),
        },
    )
    .await?;

    // Splice: client→peer reads from `reader` (so any bytes buffered after the request line are not
    // lost) and writes to the overlay; peer→client reads the overlay and writes to `write_half`.
    let (mut tcp_r, mut tcp_w) = tokio::io::split(tcp);
    let client_to_peer = async {
        let r = tokio::io::copy(reader, &mut tcp_w).await;
        // Half-close the overlay write side on client EOF so the peer sees the end of input.
        let _ = tcp_w.shutdown().await;
        r
    };
    let peer_to_client = async {
        let r = tokio::io::copy(&mut tcp_r, write_half).await;
        let _ = write_half.shutdown().await;
        r
    };
    // Run both directions until each completes (or one errors). Either EOF naturally ends its copy;
    // we join so the connection lives as long as either direction is still flowing.
    let (_c2p, _p2c) = tokio::join!(client_to_peer, peer_to_client);
    Ok(true)
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
        // `nc` is intercepted in `handle_conn` (it hijacks the connection to splice) and never reaches
        // `dispatch`; this arm exists only for match exhaustiveness.
        Request::Nc { .. } => Response::Error {
            message: "internal error: nc must be handled by the connection splicer".into(),
        },
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
        // `dns status` (Go `tailscale dns status`, read-only). Off-lock device call; needs the node
        // up (the MagicDNS config comes from the live engine's netmap).
        Request::DnsStatus => {
            let dev = { backend.lock().await.device_handle() };
            match dev {
                Some(dev) => Backend::dns_status(&dev).await,
                None => Response::Error {
                    message: "node is not up".into(),
                },
            }
        }
        // `netcheck` (Go `tailscale netcheck`, read-only). Off-lock device call; needs the node up
        // (the net-report measurements come from the live engine).
        Request::Netcheck => {
            let dev = { backend.lock().await.device_handle() };
            match dev {
                Some(dev) => Backend::netcheck(&dev).await,
                None => Response::Error {
                    message: "node is not up".into(),
                },
            }
        }
        // `cert <domain>` (Go `tailscale cert`): issue a TLS cert+key via the tailnet ACME flow.
        // Off-lock device call (issuance is a control round-trip, potentially slow). Needs the node up
        // (issuance goes through the live engine's control connection); fail-closed without `acme`.
        Request::Cert { domain } => {
            let dev = { backend.lock().await.device_handle() };
            match dev {
                Some(dev) => Backend::cert_pair(&dev, &domain).await,
                None => Response::Error {
                    message: "node is not up".into(),
                },
            }
        }
        // `bugreport` (Go `tailscale bugreport`). Reads only daemon state under a brief lock (no
        // engine round-trip); works whether or not the node is up.
        Request::BugReport { note } => {
            let be = backend.lock().await;
            be.bugreport(note.as_deref())
        }
        // `serve status` (Go GetServeConfig): read the persisted serve config under a brief lock.
        Request::GetServeConfig => {
            let cfg = { backend.lock().await.serve_config().await };
            Response::ServeConfig(cfg)
        }
        // `serve tcp|https|http` / `serve reset` (Go SetServeConfig): persist the new config and
        // re-arm the serve runtime live (both lanes — TCP-forward accept loops + engine web serve)
        // when the node is up; see `Backend::set_serve_config`.
        Request::SetServeConfig { config } => {
            let mut be = backend.lock().await;
            match be.set_serve_config(&config).await {
                Ok(()) => Response::Ok {
                    message: "serve config updated".to_string(),
                },
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
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
                Ok(()) => {
                    tracing::info!(profile = %target, "switched profile (device torn down; run `up` to connect)");
                    Response::Ok {
                        message: format!("switched to profile {target}"),
                    }
                }
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
                Ok(()) => {
                    tracing::info!("logout: node deregistered + key wiped");
                    Response::Ok {
                        message: "node logged out".to_string(),
                    }
                }
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        Request::Down => {
            let mut be = backend.lock().await;
            match be.down().await {
                Ok(()) => {
                    tracing::info!("node down");
                    Response::Ok {
                        message: "node brought down".to_string(),
                    }
                }
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
        // `id-token` (Go `tailscale id-token <aud>`): mint an OIDC JWT for this node via control.
        // Needs the live device (the issuance goes over the Noise connection), so it uses the same
        // off-lock `device_handle` clone as `whois`/`ping`; a control refusal becomes `Response::Error`
        // inside `Backend::id_token`, not a panic.
        Request::IdToken { audience } => {
            let dev = { backend.lock().await.device_handle() };
            match dev {
                Some(dev) => {
                    // Audit the GRANT of a sensitive op (minting an OIDC credential): the deny path is
                    // already logged at the auth gate above; log the successful grant too.
                    tracing::info!(peer_uid = ?peer_uid, %audience, "minted id-token");
                    Backend::id_token(&dev, &audience).await
                }
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
        // `debug capture` taps the dataplane for `seconds` then writes a pcap. Off-lock (it runs for
        // multiple seconds — never hold the backend Mutex across it), like `ping`/`whois`/`file_cp`.
        Request::DebugCapture { path, seconds } => {
            let dev = { backend.lock().await.device_handle() };
            match dev {
                // Default the window to 10s when the client omits it (matches the CLI default).
                Some(dev) => {
                    // Audit the GRANT of a sensitive op (installing a dataplane packet tap).
                    let secs = seconds.unwrap_or(10);
                    tracing::info!(peer_uid = ?peer_uid, path = %path, seconds = secs, "debug capture started");
                    Backend::debug_capture(&dev, &path, secs).await
                }
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
            accept_dns,
            shields_up,
            ssh,
            reset,
            force_reauth,
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
                accept_dns,
                shields_up,
                ssh,
                reset,
                force_reauth,
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
            // Control-URL change guard (Go `up`'s `can't change --login-server without
            // --force-reauth`): changing which control server a Running node talks to is a
            // re-registration, so refuse it unless `--force-reauth` (which performs that fresh
            // registration) is also set. A PURE READ under the brief lock, BEFORE `drive_up`, so a
            // tripped guard leaves the node exactly as it was (Go returns the error before applying).
            // Unaffected: a bare `up`, a change on a down node, a default-synonym swap, or `up
            // --control-url X --force-reauth`.
            if backend.lock().await.up_control_url_guard(&opts) {
                return Response::Error {
                    message: "can't change --login-server without --force-reauth".to_string(),
                };
            }
            match ipn::drive_up(backend, authkey, opts).await {
                Ok(()) => {
                    tracing::info!("node up requested");
                    Response::Ok {
                        message: "node brought up".to_string(),
                    }
                }
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
            accept_dns,
            shields_up,
            exit_node,
            advertise_exit_node,
            advertise_routes,
            advertise_tags,
            ssh,
        } => {
            let opts = ipn::SetOptions {
                hostname,
                accept_routes,
                accept_dns,
                shields_up,
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
                Ok(()) => {
                    // The Live-vs-Rebuild reconcile decision (the "why did my set reconnect?" signal)
                    // is logged inside `begin_set`, where the `SetAction` is decided — dispatch only
                    // sees `Ok(())` here. This line marks that the operator's `set` completed.
                    tracing::info!("set reconciled");
                    Response::Ok {
                        message: "preferences updated".to_string(),
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    /// Drive `read_capped_line` with `input`: write the bytes into one end of a `UnixStream` pair
    /// (off-task so a write larger than the socket buffer cannot deadlock against the reader), drop
    /// the writer so EOF is observable, then read exactly one line from the other end's read half.
    ///
    /// `read_capped_line`'s reader parameter is the *concrete* `BufReader<OwnedReadHalf>` the server
    /// uses (not a generic `AsyncBufRead`), so it can only be exercised over a real `UnixStream` —
    /// an in-memory `Cursor` would not typecheck. This mirrors the integration harness in
    /// `tests/localapi_loop.rs`, which also drives the server over a real `UnixStream`.
    async fn read_one(input: Vec<u8>) -> (LineResult, Vec<u8>) {
        let (client, server) = UnixStream::pair().expect("UnixStream::pair");
        // Writer side: push all bytes, then drop to signal EOF. Spawned so a >socket-buffer write
        // (the over-cap case sends 64KiB+) never blocks waiting for the reader to drain.
        let writer = tokio::spawn(async move {
            let (_r, mut w) = client.into_split();
            w.write_all(&input).await.expect("write input");
            w.flush().await.expect("flush input");
            // `w`/`client` dropped here → the read half observes EOF after the buffered bytes.
        });

        let (read_half, _write_half) = server.into_split();
        let mut reader = BufReader::new(read_half);
        let mut out = Vec::new();
        let result = read_capped_line(&mut reader, &mut out)
            .await
            .expect("read_capped_line");
        writer.await.expect("writer task");
        (result, out)
    }

    #[tokio::test]
    async fn read_capped_line_returns_under_cap_line() {
        // An under-cap line ending in '\n' yields `Line`, with the trailing '\n' stripped.
        let (result, out) = read_one(b"hello\n".to_vec()).await;
        assert!(matches!(result, LineResult::Line), "expected Line");
        assert_eq!(
            out, b"hello",
            "trailing newline must be stripped, not stored"
        );
    }

    #[tokio::test]
    async fn read_capped_line_allows_exactly_max_bytes() {
        // The cap is INCLUSIVE: a line of exactly MAX_LINE_BYTES (plus its '\n') is still accepted.
        // This pins the load-bearing strict `>` boundary the function documents.
        let mut input = vec![b'a'; MAX_LINE_BYTES];
        input.push(b'\n');
        let (result, out) = read_one(input).await;
        assert!(
            matches!(result, LineResult::Line),
            "a line of exactly MAX_LINE_BYTES must be allowed (inclusive cap)"
        );
        assert_eq!(out.len(), MAX_LINE_BYTES);
    }

    #[tokio::test]
    async fn read_capped_line_refuses_over_cap_line() {
        // A newline-less line exceeding MAX_LINE_BYTES is refused with `TooLong` (the DoS guard:
        // a single connection must not be able to grow the read buffer without bound).
        let input = vec![b'a'; MAX_LINE_BYTES + 1];
        let (result, _out) = read_one(input).await;
        assert!(
            matches!(result, LineResult::TooLong),
            "a line over MAX_LINE_BYTES must be refused as TooLong"
        );
    }

    #[tokio::test]
    async fn read_capped_line_reports_clean_eof() {
        // A peer that closes without sending anything is a clean EOF, not an error or a line.
        let (result, out) = read_one(Vec::new()).await;
        assert!(matches!(result, LineResult::Eof), "empty stream is Eof");
        assert!(out.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ensure_dir_0700_tightens_loose_dir() {
        use std::os::unix::fs::PermissionsExt;

        // A process-id-namespaced temp dir (matches the harness convention in tests/localapi_loop.rs)
        // created world/group-accessible (0777) must be tightened to 0700 — it is the reach gate for
        // the control socket.
        let dir = std::env::temp_dir().join(format!(
            "tailnetd-ensure0700-{}-{}",
            std::process::id(),
            // A nanosecond suffix keeps parallel tests in this same PID from colliding on the path.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).expect("chmod 0777");

        ensure_dir_0700(&dir).await.expect("ensure_dir_0700");

        let mode = std::fs::metadata(&dir)
            .expect("stat dir")
            .permissions()
            .mode()
            & 0o777;
        // Best-effort cleanup before the assertion so a failure still removes the dir.
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(mode, 0o700, "loose socket dir must be tightened to 0700");
    }
}
