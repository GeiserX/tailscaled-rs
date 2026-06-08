//! The LocalAPI server: a Unix-domain-socket IPC surface the CLI talks to.
//!
//! Transport (MVP): newline-delimited JSON. One [`Request`] per line in, one [`Response`] JSON
//! object per line out, then the connection closes. This is deliberately the simplest thing that
//! works; the planned evolution is HTTP/1 over the same socket with `SO_PEERCRED` authorization
//! (read for anyone, write for root/same-UID), matching Tailscale's LocalAPI auth model.
//!
//! Concurrency: the [`Backend`] is shared behind a `Mutex` because every command either mutates
//! the lifecycle (`up`/`down`) or reads a consistent snapshot (`status`). Commands are naturally
//! serialized, which is the correct semantics for a node lifecycle.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::auth::{self, Permissions};
use crate::ipn::Backend;
use crate::localapi::{Request, Response};

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
    }
    // A stale socket from a prior run would make bind fail with EADDRINUSE.
    let _ = tokio::fs::remove_file(socket_path).await;

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("binding LocalAPI socket {}", socket_path.display()))?;
    tracing::info!(socket = %socket_path.display(), "LocalAPI listening");

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        // Authorize once, at accept: `peer_cred()` needs the whole stream, so we
                        // resolve permissions before `handle_conn` splits it into read/write halves.
                        // A single `peer_cred()` read yields both the decision and the uid we log,
                        // so the logged uid can never disagree with the authorization.
                        let (perms, peer_uid) = auth::permissions_for_peer(&stream);
                        let backend = Arc::clone(&backend);
                        tokio::spawn(async move {
                            if let Err(e) = handle_conn(stream, perms, peer_uid, backend).await {
                                tracing::warn!(error = %e, "LocalAPI connection error");
                            }
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "accept failed"),
                }
            }
        }
    }

    let _ = tokio::fs::remove_file(socket_path).await;
    tracing::info!("LocalAPI stopped");
    Ok(())
}

async fn handle_conn(
    stream: UnixStream,
    perms: Permissions,
    peer_uid: Option<u32>,
    backend: Arc<Mutex<Backend>>,
) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => dispatch(req, perms, peer_uid, &backend).await,
            Err(e) => Response::Error {
                message: format!("bad request: {e}"),
            },
        };
        let mut bytes = serde_json::to_vec(&response).expect("response serialize");
        bytes.push(b'\n');
        write_half.write_all(&bytes).await?;
        write_half.flush().await?;
    }
    Ok(())
}

async fn dispatch(
    req: Request,
    perms: Permissions,
    peer_uid: Option<u32>,
    backend: &Arc<Mutex<Backend>>,
) -> Response {
    // Authorization gate: writes (`up`/`down`) require root or the daemon's owner. Reads
    // (`status`) are never gated. Checked before taking the backend lock so a denied caller never
    // touches lifecycle state.
    if auth::requires_write(&req) && !perms.write {
        tracing::warn!(
            peer_uid = ?peer_uid,
            "denied LocalAPI write: caller lacks write permission"
        );
        return Response::Error {
            message: "permission denied: writing (up/down) requires root or the same user that owns the daemon".into(),
        };
    }

    let mut be = backend.lock().await;
    match req {
        Request::Status => Response::Status(be.status().await),
        Request::Up {
            authkey,
            control_url,
            hostname,
        } => {
            // Confine the plaintext authkey to the smallest scope: wrap it into a `SecretString`
            // right at the boundary and hand the engine path the secret. (The wire type stays
            // `String` because `SecretString` does not serialize.)
            let authkey = authkey.map(secrecy::SecretString::from);
            match be.up(authkey, hostname, control_url).await {
                Ok(()) => Response::Ok {
                    message: "node brought up".to_string(),
                },
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        Request::Down => match be.down().await {
            Ok(()) => Response::Ok {
                message: "node brought down".to_string(),
            },
            Err(e) => Response::Error {
                message: format!("{e:#}"),
            },
        },
    }
}
