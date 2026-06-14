//! An outbound HTTP proxy that dials **over the tailnet** — the Rust analogue of Go `tailscaled`'s
//! `--outbound-http-proxy-listen` (`cmd/tailscaled/proxy.go`, `httpProxyHandler`, wired alongside
//! SOCKS5 via the same `startProxy(logf, dialer)` path).
//!
//! ## Why this exists
//!
//! The sibling of the [SOCKS5 proxy](crate::socks5): the same general-purpose outbound path for the
//! netstack (no-TUN) daemon, but for clients that speak the HTTP-proxy protocol (`https_proxy=...`,
//! `curl -x`, system "HTTP proxy" settings) rather than SOCKS5. Both reuse the engine's overlay
//! dialer ([`Device::connect_by_name`]) — the exact primitive `tnet nc` uses — so a `CONNECT` to a
//! tailnet `host:port` resolves a MagicDNS name (or IP literal) to a peer and splices the streams.
//!
//! ## Scope (faithful to Go's `httpProxyHandler`, with one honest reduction)
//!
//! Go's handler serves **two** paths: `CONNECT` (HTTPS tunneling) and absolute-form forwarding (a
//! plain `GET http://host/...`, via an `httputil.ReverseProxy`). This module implements the
//! **`CONNECT`** path — the dominant case (every `https://` request through an HTTP proxy is a
//! CONNECT tunnel) — faithfully:
//! - success reply is Go's exact `HTTP/1.1 200 OK\r\n\r\n` (NOT the conventional
//!   `200 Connection established`);
//! - a dial failure is **HTTP 500** with a `Tailscale-Connect-Error: <err>` header, matching Go
//!   (not the more typical 502/503);
//! - unauthenticated (Go too — the bind address is the security boundary), CONNECT dials over the
//!   overlay, and an unresolvable/non-tailnet host fails the dial → 500 (never a host-network
//!   fallback: no split-tunnel leak).
//!
//! The absolute-form **forward** path (plain `GET http://…` proxying with hop-by-hop header
//! stripping) is a tracked follow-up (`tsd-httpfwd`): it needs full HTTP/1.1 request+response
//! parsing/relay, and is the less-common path (modern traffic is HTTPS → CONNECT). Until it lands, a
//! non-CONNECT request is answered with a clear `501 Not Implemented` naming the gap — an honest
//! omission, never a silent 400 of a request Go would have forwarded.
//!
//! Bound only when the operator passes `--outbound-http-proxy-listen <addr>`; off by default.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::ipn::Backend;

/// Cap on concurrent proxied connections (defense-in-depth; the proxy is a local convenience).
const MAX_CONNECTIONS: usize = 256;
/// Max bytes for the request line + headers before we give up (a client that never sends a complete
/// request head must not grow the buffer without bound).
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Run the outbound HTTP proxy on `listen_addr` until `shutdown` resolves. Errors only on the initial
/// bind (a per-connection error is logged, never fatal) — matching Go, where a failed
/// `--outbound-http-proxy-listen` bind is a daemon-startup error.
pub async fn serve(
    listen_addr: &str,
    backend: Arc<Mutex<Backend>>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("binding HTTP-proxy listener {listen_addr}"))?;
    let bound = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| listen_addr.to_string());
    tracing::info!(addr = %bound, "outbound HTTP proxy listening (dials over the tailnet)");

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
                            tracing::warn!("http-proxy: connection cap reached; dropping connection");
                            continue;
                        };
                        let backend = Arc::clone(&backend);
                        conns.spawn(async move {
                            let _permit = permit;
                            if let Err(e) = handle_connection(stream, &backend).await {
                                tracing::debug!(error = %e, %peer, "http-proxy: connection ended");
                            }
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "http-proxy: accept failed"),
                }
            }
        }
    }
    conns.shutdown().await;
    tracing::info!("outbound HTTP proxy stopped");
    Ok(())
}

/// Handle one HTTP-proxy client: read the request line, dispatch CONNECT (tunnel) vs everything else
/// (the not-yet-implemented forward path → honest 501).
async fn handle_connection(client: TcpStream, backend: &Arc<Mutex<Backend>>) -> Result<()> {
    let mut reader = BufReader::new(client);

    // Read the request line: `METHOD TARGET HTTP/1.x`.
    let mut request_line = String::new();
    let n = read_line_capped(&mut reader, &mut request_line, MAX_HEAD_BYTES).await?;
    if n == 0 {
        return Ok(()); // client closed before sending anything
    }
    let request_line = request_line.trim_end();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(reader, backend, target).await
    } else {
        // The absolute-form forward path (Go forwards a `GET http://…` via ReverseProxy) is a tracked
        // follow-up (tsd-httpfwd). Answer honestly with 501 — NOT a silent 400 of a request Go would
        // forward. We must still drain the rest of the request head so the write isn't on a
        // half-read connection, but we don't parse it.
        let body = "501 Not Implemented: this proxy currently supports only the CONNECT method \
                    (HTTPS tunneling). Plain absolute-form HTTP forwarding is not yet implemented \
                    (tsd-httpfwd); use CONNECT, or the SOCKS5 proxy (--socks5-server).";
        let resp = format!(
            "HTTP/1.1 501 Not Implemented\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let mut client = reader.into_inner();
        client.write_all(resp.as_bytes()).await?;
        client.flush().await?;
        bail!(
            "http-proxy: non-CONNECT method {method:?} not implemented (forward path is tsd-httpfwd)"
        );
    }
}

/// The CONNECT tunnel: parse `host:port` from the target, drain the remaining request headers, dial
/// over the overlay, reply `HTTP/1.1 200 OK` (Go's exact line), then bidirectionally splice.
async fn handle_connect(
    mut reader: BufReader<TcpStream>,
    backend: &Arc<Mutex<Backend>>,
    target: &str,
) -> Result<()> {
    let Some((host, port)) = parse_authority(target) else {
        let mut client = reader.into_inner();
        write_simple_status(
            &mut client,
            400,
            "Bad Request",
            "bogus CONNECT target (want host:port)",
        )
        .await?;
        bail!("http-proxy: bad CONNECT target {target:?}");
    };

    // Drain the rest of the request head (the headers up to the blank line). A CONNECT has no body;
    // we ignore the headers (no auth), but must consume them so the splice starts at the tunnel body.
    drain_headers(&mut reader).await?;

    // Off-lock device handle; if the node is down there's nothing to dial through → 500 like Go.
    let dev = { backend.lock().await.device_handle() };
    let Some(dev) = dev else {
        let mut client = reader.into_inner();
        write_connect_error(&mut client, "node is not up").await?;
        bail!("http-proxy CONNECT {host}:{port} refused: node is not up");
    };

    match dev.connect_by_name(&host, port).await {
        Ok(overlay) => {
            let mut client = reader.into_inner();
            // Go writes exactly "HTTP/1.1 200 OK\r\n\r\n" (NOT "200 Connection established").
            client.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
            client.flush().await?;
            splice(client, overlay).await;
            Ok(())
        }
        Err(e) => {
            // Go: HTTP 500 + a `Tailscale-Connect-Error` header (never a host-network fallback).
            let mut client = reader.into_inner();
            write_connect_error(&mut client, &e.to_string()).await?;
            bail!("http-proxy CONNECT {host}:{port} failed: {e}");
        }
    }
}

/// Parse a CONNECT authority `host:port` into `(host, port)`. Handles a bracketed IPv6 literal
/// (`[::1]:443`). Returns `None` if there is no port or the port is invalid. Pure → unit-testable.
fn parse_authority(target: &str) -> Option<(String, u16)> {
    let target = target.trim();
    if let Some(rest) = target.strip_prefix('[') {
        // `[ipv6]:port`
        let (host, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        let port: u16 = port.parse().ok()?;
        if host.is_empty() || port == 0 {
            return None;
        }
        return Some((host.to_string(), port));
    }
    // `host:port` — split on the LAST colon (host has no colon in the non-bracketed form).
    let (host, port) = target.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if host.is_empty() || port == 0 {
        return None;
    }
    Some((host.to_string(), port))
}

/// Read header lines from `reader` until the blank line that terminates the request head (or EOF /
/// the byte cap). Discards them — the CONNECT proxy consults no headers (no auth). Bounded so a
/// header flood can't grow memory without limit.
async fn drain_headers(reader: &mut BufReader<TcpStream>) -> Result<()> {
    let mut total = 0usize;
    loop {
        let mut line = String::new();
        let n = read_line_capped(reader, &mut line, MAX_HEAD_BYTES.saturating_sub(total)).await?;
        if n == 0 {
            break; // EOF before the blank line — client hung up; let the caller proceed/close.
        }
        total += n;
        if line == "\r\n" || line == "\n" {
            break; // end of header block
        }
        if total >= MAX_HEAD_BYTES {
            bail!("http-proxy: request head exceeded {MAX_HEAD_BYTES} bytes");
        }
    }
    Ok(())
}

/// `read_line` with a byte cap: reads up to and including the next `\n`, but errors if the line would
/// exceed `cap` (so a newline-less flood can't grow `buf` unbounded). Returns bytes read (0 = EOF).
async fn read_line_capped(
    reader: &mut BufReader<TcpStream>,
    buf: &mut String,
    cap: usize,
) -> Result<usize> {
    let mut raw = Vec::new();
    let mut limited = reader.take((cap as u64).saturating_add(1));
    let n = limited.read_until(b'\n', &mut raw).await?;
    if raw.len() as u64 > cap as u64 {
        bail!("http-proxy: request line exceeded {cap} bytes");
    }
    buf.push_str(&String::from_utf8_lossy(&raw));
    Ok(n)
}

/// Write Go's CONNECT-failure response: `HTTP/1.1 500 Internal Server Error` with the
/// `Tailscale-Connect-Error: <err>` header (sanitized to a single header-safe line).
async fn write_connect_error(client: &mut TcpStream, err: &str) -> Result<()> {
    // A header value must not carry CR/LF; collapse any control char so the error can't inject a
    // header (defense-in-depth — the err is engine-sourced, but never trust it into a header).
    let safe: String = err
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let resp = format!(
        "HTTP/1.1 500 Internal Server Error\r\nTailscale-Connect-Error: {safe}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    client.write_all(resp.as_bytes()).await?;
    client.flush().await?;
    Ok(())
}

/// Write a minimal `HTTP/1.1 <code> <reason>` response with a short text body.
async fn write_simple_status(
    client: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &str,
) -> Result<()> {
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(resp.as_bytes()).await?;
    client.flush().await?;
    Ok(())
}

/// Bidirectionally splice the client socket and the overlay stream until either side closes — the
/// same shape as the SOCKS5 / nc / serve splices.
async fn splice<O>(client: TcpStream, overlay: O)
where
    O: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = client.into_split();
    let (mut or, mut ow) = tokio::io::split(overlay);
    let client_to_peer = async {
        let _ = tokio::io::copy(&mut cr, &mut ow).await;
        let _ = ow.shutdown().await;
    };
    let peer_to_client = async {
        let _ = tokio::io::copy(&mut or, &mut cw).await;
        let _ = cw.shutdown().await;
    };
    tokio::join!(client_to_peer, peer_to_client);
}

/// Validate a `--outbound-http-proxy-listen` address (same rule as the SOCKS5 flag): a bare port →
/// `127.0.0.1:<port>` (loopback default, since the proxy is unauthenticated), a full `host:port`
/// as-is. Pure → unit-testable. Delegates to the shared SOCKS5 normalizer so both flags agree.
pub fn normalize_listen_addr(addr: &str) -> Result<String> {
    crate::socks5::normalize_listen_addr(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_authority_host_port() {
        assert_eq!(
            parse_authority("example.ts.net:443"),
            Some(("example.ts.net".to_string(), 443))
        );
        assert_eq!(
            parse_authority("100.64.0.9:22"),
            Some(("100.64.0.9".to_string(), 22))
        );
    }

    #[test]
    fn parse_authority_ipv6_bracketed() {
        assert_eq!(
            parse_authority("[fd7a:115c:a1e0::1]:443"),
            Some(("fd7a:115c:a1e0::1".to_string(), 443))
        );
    }

    #[test]
    fn parse_authority_rejects_bad() {
        assert_eq!(parse_authority("example.ts.net"), None); // no port
        assert_eq!(parse_authority("host:0"), None); // port 0
        assert_eq!(parse_authority("host:notaport"), None);
        assert_eq!(parse_authority(":443"), None); // empty host
        assert_eq!(parse_authority(""), None);
    }

    #[test]
    fn normalize_delegates_to_socks5() {
        // Same rules as the SOCKS5 flag (shared normalizer).
        assert_eq!(normalize_listen_addr("8080").unwrap(), "127.0.0.1:8080");
        assert_eq!(
            normalize_listen_addr("127.0.0.1:8080").unwrap(),
            "127.0.0.1:8080"
        );
        assert!(normalize_listen_addr("nope").is_err());
    }
}
