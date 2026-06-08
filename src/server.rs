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
                let text = String::from_utf8_lossy(&line);
                if text.trim().is_empty() {
                    continue;
                }
                let response = match serde_json::from_str::<Request>(&text) {
                    Ok(req) => dispatch(req, access, peer_uid, &backend).await,
                    Err(e) => Response::Error {
                        message: format!("bad request: {e}"),
                    },
                };
                write_response(&mut write_half, &response).await?;
            }
        }
    }
    Ok(())
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
        // `up` performs a multi-second control-plane handshake (`Device::new`). Doing that under the
        // backend lock would head-of-line block every concurrent `status`. So we use the three-phase
        // split: lock briefly to prep config (begin_up) → DROP the lock → run the slow handshake
        // (build_device) unlocked → lock briefly again to install (finish_up). A `down`/`up` that
        // lands during the handshake bumps the generation and supersedes this one (finish_up discards
        // the orphan). See `ipn::Backend::begin_up`.
        Request::Up {
            authkey,
            control_url,
            hostname,
        } => {
            // Confine the plaintext authkey to the smallest scope: wrap it into a `SecretString`
            // right at the boundary and hand the engine path the secret. (The wire type stays
            // `String` because `SecretString` does not serialize.)
            let authkey = authkey.map(secrecy::SecretString::from);

            // Phase 1: brief lock — prep + persist prefs, build Config, bump generation.
            let pending = {
                let mut be = backend.lock().await;
                be.begin_up(hostname, control_url).await
            };
            let pending = match pending {
                Ok(p) => p,
                Err(e) => {
                    return Response::Error {
                        message: format!("{e:#}"),
                    };
                }
            };

            // Phase 2: NO lock held — the slow handshake. Concurrent `status` proceeds freely here.
            let built = ipn::build_device(&pending, authkey).await;

            // Phase 3: brief lock — install iff still current, returning any orphan to shut down.
            // `finish_up` does NOT await the orphan's shutdown (that would re-block the lock for up
            // to SHUTDOWN_TIMEOUT); it hands the orphan back so we tear it down AFTER dropping the
            // lock, keeping concurrent `status`/`up`/`down` unblocked even on the supersede path.
            let outcome = {
                let mut be = backend.lock().await;
                be.finish_up(pending, built)
            };
            match outcome {
                Ok(orphan) => {
                    // Lock released — settle the (rare) superseded device off-lock.
                    ipn::shutdown_orphan(orphan).await;
                    Response::Ok {
                        message: "node brought up".to_string(),
                    }
                }
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            }
        }
    }
}
