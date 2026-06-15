//! An optional debug HTTP server — the Rust analogue of Go `tailscaled`'s `--debug [ip]:port`
//! (`cmd/tailscaled/debug.go` `newDebugMux`, gated `!ts_omit_debug`).
//!
//! ## Why this exists
//!
//! Go's debug server exposes operator/observability endpoints on a separate listener:
//! `GET /debug/metrics` (Prometheus exposition — varz + client metrics) and `/debug/pprof/*` (Go
//! runtime profiling). This fork serves the **parity-meaningful** slice:
//!
//! - **`GET /debug/metrics`** — the daemon's Prometheus metrics, the same text the `Metrics` LocalAPI
//!   verb (`tnet metrics`) returns, sourced from the live engine (`Device::metrics()`). The single
//!   most useful debug endpoint: it lets a Prometheus scraper pull the node's metrics over plain HTTP
//!   without going through the unix LocalAPI socket.
//!
//! `/debug/pprof/*` has **no faithful Rust analogue** (it is Go-runtime profiling — `runtime/pprof`),
//! so it is intentionally omitted; a request to it gets a clear `404` naming the gap rather than a
//! silent hang.
//!
//! ## Security
//!
//! Like the SOCKS5/HTTP proxies, this listener is **unauthenticated — the bind address is the security
//! boundary**. Metrics can carry operational detail, so a bare port binds to loopback
//! (`127.0.0.1`) and a non-loopback bind requires the operator to pass an explicit address. The
//! server is read-only (it only ever *reads* metrics; no endpoint mutates state) and bounds every
//! request: a connection cap, a request-head deadline (slowloris guard), and a capped request-line
//! read. Off unless `--debug [ip:]port` is given.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::ipn::Backend;

/// Cap on concurrent debug connections (defense-in-depth; a scraper opens one at a time).
const MAX_CONNECTIONS: usize = 32;
/// Max bytes of the request line + headers we will read before giving up (a client that never sends a
/// complete request head must not grow the buffer without bound).
const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Deadline for reading the request head + producing the response. A scraper completes promptly; a
/// client that connects and sends nothing is dropped rather than parking a connection slot forever.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Run the debug HTTP server on `listen_addr` until `shutdown` resolves. Errors only on the initial
/// bind (a per-connection error is logged, never fatal) — matching the proxy listeners, where a failed
/// requested listener is a daemon-startup error.
pub async fn serve(
    listen_addr: &str,
    backend: Arc<Mutex<Backend>>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("binding debug HTTP listener {listen_addr}"))?;
    let bound = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| listen_addr.to_string());
    tracing::info!(addr = %bound, "debug HTTP server listening (GET /debug/metrics)");

    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let mut conns: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let Ok(permit) = Arc::clone(&conn_limit).try_acquire_owned() else {
                            tracing::warn!("debug: connection cap reached; dropping connection");
                            continue;
                        };
                        let backend = Arc::clone(&backend);
                        conns.spawn(async move {
                            let _permit = permit;
                            if let Err(e) = handle_connection(stream, &backend).await {
                                tracing::debug!(error = %e, %peer, "debug: connection ended");
                            }
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "debug: accept failed"),
                }
            }
        }
    }
    conns.shutdown().await;
    tracing::info!("debug HTTP server stopped");
    Ok(())
}

/// Handle one debug-HTTP client: read the request line (bounded + deadlined), route it, write the
/// response, close. A single request per connection (no keep-alive) — a debug scraper reconnects.
async fn handle_connection(client: TcpStream, backend: &Arc<Mutex<Backend>>) -> Result<()> {
    match tokio::time::timeout(REQUEST_TIMEOUT, serve_one_request(client, backend)).await {
        Ok(res) => res,
        Err(_) => Ok(()), // slow/idle client: drop the connection, release the permit
    }
}

/// Read the request line, route the `(method, path)`, write the response. Bounded reads throughout.
async fn serve_one_request(client: TcpStream, backend: &Arc<Mutex<Backend>>) -> Result<()> {
    let mut reader = BufReader::new(client);

    // Read the request line `METHOD PATH HTTP/1.x` (capped). We don't need the headers, but we must
    // consume up to the line terminator without unbounded buffering.
    let request_line = read_line_capped(&mut reader, MAX_HEAD_BYTES).await?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    let mut client = reader.into_inner();
    match (method, path) {
        // The one parity-meaningful endpoint: Prometheus metrics from the live engine.
        ("GET", "/debug/metrics") => {
            let body = {
                let dev = { backend.lock().await.device_handle() };
                match dev {
                    // `Device::metrics()` returns the Prometheus exposition text directly — the same
                    // source the `Metrics` LocalAPI verb (`tnet metrics`) uses.
                    Some(dev) => dev.metrics(),
                    None => {
                        // Node not up → no engine to read metrics from. 503, not an empty 200, so a
                        // scraper distinguishes "down" from "zero metrics".
                        return write_response(
                            &mut client,
                            503,
                            "Service Unavailable",
                            "text/plain; charset=utf-8",
                            "node is not up; no metrics available\n",
                        )
                        .await;
                    }
                }
            };
            // Go's servePrometheusMetrics sets text/plain; mirror that content type.
            write_response(&mut client, 200, "OK", "text/plain; charset=utf-8", &body).await
        }
        // pprof has no Rust analogue — honest 404 naming the gap (never a silent hang).
        ("GET", p) if p.starts_with("/debug/pprof") => {
            write_response(
                &mut client,
                404,
                "Not Found",
                "text/plain; charset=utf-8",
                "pprof profiling is Go-runtime-specific and not available in this fork\n",
            )
            .await
        }
        ("GET", _) => {
            write_response(
                &mut client,
                404,
                "Not Found",
                "text/plain; charset=utf-8",
                "not found; this debug server serves GET /debug/metrics\n",
            )
            .await
        }
        // Any non-GET method on the read-only debug surface.
        _ => {
            write_response(
                &mut client,
                405,
                "Method Not Allowed",
                "text/plain; charset=utf-8",
                "the debug server is read-only; use GET\n",
            )
            .await
        }
    }
}

/// Read one CRLF/LF-terminated line, refusing to buffer past `cap` bytes (a head-flood guard). Returns
/// the line without its terminator. EOF before any byte is an error (the client hung up).
async fn read_line_capped(reader: &mut BufReader<TcpStream>, cap: usize) -> Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            if buf.is_empty() {
                anyhow::bail!("client closed before sending a request");
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            buf.push(byte[0]);
        }
        if buf.len() > cap {
            anyhow::bail!("request line exceeded {cap} bytes");
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Write a minimal HTTP/1.1 response with `Connection: close` (one request per connection) and a
/// `Content-Length`-framed body.
async fn write_response(
    client: &mut TcpStream,
    code: u16,
    reason: &str,
    content_type: &str,
    body: &str,
) -> Result<()> {
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(resp.as_bytes()).await?;
    client.flush().await?;
    Ok(())
}

/// Normalize a `--debug` listen value: a bare port → `127.0.0.1:<port>` (loopback, since the endpoint
/// is unauthenticated); a full `host:port` SocketAddr is taken as-is. Delegates to the proxy
/// normalizer so the three listeners share one rule. Errors on an empty/garbage value or port 0.
pub fn normalize_listen_addr(addr: &str) -> Result<String> {
    crate::socks5::normalize_listen_addr(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_delegates_to_socks5() {
        // Same loopback-default rule as the proxy listeners (shared normalizer).
        assert_eq!(normalize_listen_addr("9090").unwrap(), "127.0.0.1:9090");
        assert_eq!(
            normalize_listen_addr("127.0.0.1:9090").unwrap(),
            "127.0.0.1:9090"
        );
        // An explicit non-loopback bind is allowed only when the operator types it in full.
        assert_eq!(
            normalize_listen_addr("0.0.0.0:9090").unwrap(),
            "0.0.0.0:9090"
        );
        assert!(normalize_listen_addr("nope").is_err());
    }
}
