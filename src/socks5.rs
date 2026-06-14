//! A SOCKS5 proxy that dials **over the tailnet** — the Rust analogue of Go `tailscaled`'s
//! `--socks5-server` (`net/socks5`, wired in `cmd/tailscaled` via `startProxy(logf, dialer)`).
//!
//! ## Why this exists
//!
//! The daemon's default data path is the engine's **userspace netstack** (no TUN, unprivileged): the
//! OS routing table is untouched, so an ordinary app's traffic does NOT flow over the tailnet. The
//! SOCKS5 proxy is the general-purpose escape hatch for that mode — point any SOCKS5-aware client at
//! `localhost:1055` (curl `--socks5-hostname`, a browser, `ssh -o ProxyCommand`, …) and its
//! connections are dialed **through the overlay** to tailnet peers, with no root and no TUN. This is
//! exactly Go's model: the proxy reuses the engine's dialer ([`Device::connect_by_name`]), the same
//! primitive `tnet nc` already uses, so a CONNECT to `host:port` resolves a MagicDNS name (or an IP
//! literal) to a tailnet node and splices the streams.
//!
//! ## Scope (faithful to Go's `net/socks5` default)
//!
//! - **CONNECT** only (Go's server implements CONNECT; BIND/UDP-ASSOCIATE are not part of the
//!   `tailscaled` proxy). A `BIND`/`UDP ASSOCIATE` request is rejected with `CommandNotSupported`.
//! - **No authentication** (method `0x00`) — Go's `--socks5-server` runs unauthenticated, bound to a
//!   local address the operator controls (the security boundary is the bind address, e.g.
//!   `localhost:1055`, not SOCKS auth). If `USERNAME/PASSWORD` is offered we still select no-auth;
//!   if no-auth is not offered we reply "no acceptable methods" and close.
//! - **Address types:** IPv4 (`0x01`), DOMAINNAME (`0x03`), IPv6 (`0x04`) — all three are rendered to
//!   a host string and dialed via [`Device::connect_by_name`], which resolves the string against the
//!   netmap (a MagicDNS name → the peer's tailnet IP). NOTE: `connect_by_name` resolves by NAME and
//!   does **not** parse a bare IP literal, so a `CONNECT 100.64.0.5:22` to a bare tailnet IP currently
//!   fails `HostUnreachable` (a known gap vs Go, tracked in `tsd-httpfwd`'s sibling — use the peer's
//!   MagicDNS name). Either way the proxy only ever reaches **tailnet** destinations; a non-tailnet
//!   host (or an unresolvable name/IP) is answered with a SOCKS `HostUnreachable` reply and is
//!   **never** dialed on the host network (no split-tunnel leak — the engine's dialer has no
//!   host-socket egress path at all).
//!
//! Bound only when the operator passes `--socks5-server <addr>`; off by default (Go is the same).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::ipn::Backend;

/// SOCKS protocol version 5 (the only version this server speaks).
const SOCKS5_VERSION: u8 = 0x05;
/// SOCKS5 "no authentication required" method.
const METHOD_NO_AUTH: u8 = 0x00;
/// SOCKS5 "no acceptable methods" sentinel (sent when the client doesn't offer no-auth).
const METHOD_NO_ACCEPTABLE: u8 = 0xff;
/// SOCKS5 CONNECT command (the only command we support).
const CMD_CONNECT: u8 = 0x01;

/// SOCKS5 reply codes (RFC 1928 §6).
mod reply {
    pub(super) const SUCCEEDED: u8 = 0x00;
    pub(super) const GENERAL_FAILURE: u8 = 0x01;
    pub(super) const HOST_UNREACHABLE: u8 = 0x04;
    pub(super) const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub(super) const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// SOCKS5 address types (RFC 1928 §4 `ATYP`).
mod atyp {
    pub(super) const IPV4: u8 = 0x01;
    pub(super) const DOMAINNAME: u8 = 0x03;
    pub(super) const IPV6: u8 = 0x04;
}

/// Cap on a CONNECT to a busy server's connections — defense-in-depth against a local client opening
/// unbounded overlay dials. Generous; the proxy is a local convenience, not a high-fanout service.
const MAX_CONNECTIONS: usize = 256;
/// Deadline for the SOCKS5 negotiation + CONNECT request + the overlay dial (everything BEFORE the
/// splice). Without it a client that connects and sends nothing parks a handler task forever, holding
/// a [`MAX_CONNECTIONS`] permit — 256 such idle connections wedge the proxy (a slowloris). The splice
/// itself is deliberately NOT bounded (a proxied tunnel is legitimately long-lived). Matches the
/// engine's own loopback SOCKS5 `HANDSHAKE_TIMEOUT`.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Run the SOCKS5 proxy on `listen_addr` until `shutdown` resolves. Binds a TCP listener and serves
/// each accepted connection concurrently, dialing the engine over the overlay. Returns an error only
/// if the initial bind fails (a per-connection error is logged, never fatal) — matching Go, where a
/// failed `--socks5-server` bind is a daemon-startup error.
pub async fn serve(
    listen_addr: &str,
    backend: Arc<Mutex<Backend>>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("binding SOCKS5 listener {listen_addr}"))?;
    let bound = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| listen_addr.to_string());
    tracing::info!(addr = %bound, "SOCKS5 proxy listening (dials over the tailnet)");

    // Cap concurrent proxied connections; the permit is held for a connection's whole lifetime.
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
                            tracing::warn!("SOCKS5: connection cap reached; dropping connection");
                            continue;
                        };
                        let backend = Arc::clone(&backend);
                        conns.spawn(async move {
                            let _permit = permit;
                            if let Err(e) = handle_connection(stream, &backend).await {
                                // A client that hangs up mid-handshake is routine; log at debug.
                                tracing::debug!(error = %e, %peer, "SOCKS5: connection ended");
                            }
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "SOCKS5: accept failed"),
                }
            }
        }
    }
    // Drop in-flight handlers on shutdown (they own only the client socket + an overlay stream).
    conns.shutdown().await;
    tracing::info!("SOCKS5 proxy stopped");
    Ok(())
}

/// Handle one SOCKS5 client connection: method negotiation → CONNECT request → dial over the overlay
/// → reply → bidirectional splice. Every failure path sends the correct SOCKS reply before closing.
async fn handle_connection(mut client: TcpStream, backend: &Arc<Mutex<Backend>>) -> Result<()> {
    // Bound the negotiation + CONNECT request + overlay dial with a deadline so a client that never
    // sends (or a hung dial) cannot park this task forever holding a connection permit (slowloris).
    // The splice AFTER this returns is intentionally left unbounded — a real tunnel is long-lived.
    // On timeout we just drop the connection (the client is misbehaving; no reply is owed).
    let overlay = match tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        negotiate_method(&mut client).await?;
        let (host, port) = read_connect_request(&mut client).await?;

        // Dial over the overlay using the engine's dialer (the same primitive `tnet nc` uses). An
        // off-lock device handle, like the other diagnostics; if the node is down there is nothing to
        // dial through, so reply GENERAL_FAILURE (the SOCKS analogue of "the proxy can't serve you").
        let dev = { backend.lock().await.device_handle() };
        let Some(dev) = dev else {
            send_reply(&mut client, reply::GENERAL_FAILURE).await?;
            bail!("SOCKS5 CONNECT {host}:{port} refused: node is not up");
        };
        match dev.connect_by_name(&host, port).await {
            Ok(overlay) => {
                send_reply(&mut client, reply::SUCCEEDED).await?;
                Ok::<_, anyhow::Error>(overlay)
            }
            Err(e) => {
                // A name that doesn't resolve to a tailnet node, or a peer that won't accept: HOST
                // UNREACHABLE. We never fall back to a host-network dial (that would be a split-tunnel
                // leak — the whole point is to reach the TAILNET).
                send_reply(&mut client, reply::HOST_UNREACHABLE).await?;
                bail!("SOCKS5 CONNECT {host}:{port} failed: {e}");
            }
        }
    })
    .await
    {
        Ok(res) => res?,
        Err(_) => bail!("SOCKS5 handshake/dial timed out after {HANDSHAKE_TIMEOUT:?}"),
    };

    splice(client, overlay).await;
    Ok(())
}

/// SOCKS5 method negotiation (RFC 1928 §3): read `VER NMETHODS METHODS...`, select no-auth. Replies
/// `05 00` on success; `05 FF` (and errors) if the client doesn't offer no-auth or speaks a non-5
/// version.
async fn negotiate_method(client: &mut TcpStream) -> Result<()> {
    let mut head = [0u8; 2];
    client
        .read_exact(&mut head)
        .await
        .context("reading SOCKS5 greeting")?;
    let (ver, nmethods) = (head[0], head[1]);
    if ver != SOCKS5_VERSION {
        bail!("unsupported SOCKS version {ver:#x} (only SOCKS5)");
    }
    let mut methods = vec![0u8; nmethods as usize];
    client
        .read_exact(&mut methods)
        .await
        .context("reading SOCKS5 auth methods")?;
    if methods.contains(&METHOD_NO_AUTH) {
        client
            .write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH])
            .await
            .context("writing SOCKS5 method selection")?;
        client.flush().await?;
        Ok(())
    } else {
        // No acceptable method — tell the client and close (RFC 1928 §3).
        let _ = client
            .write_all(&[SOCKS5_VERSION, METHOD_NO_ACCEPTABLE])
            .await;
        let _ = client.flush().await;
        bail!("SOCKS5 client offered no no-auth method");
    }
}

/// Read a SOCKS5 CONNECT request (RFC 1928 §4): `VER CMD RSV ATYP DST.ADDR DST.PORT`. Returns the
/// `(host, port)` to dial. Rejects non-CONNECT commands (`CommandNotSupported`) and unknown address
/// types (`AddressTypeNotSupported`) with the correct reply before erroring.
async fn read_connect_request(client: &mut TcpStream) -> Result<(String, u16)> {
    let mut head = [0u8; 4];
    client
        .read_exact(&mut head)
        .await
        .context("reading SOCKS5 request header")?;
    let (ver, cmd, _rsv, address_type) = (head[0], head[1], head[2], head[3]);
    if ver != SOCKS5_VERSION {
        bail!("SOCKS5 request with bad version {ver:#x}");
    }
    if cmd != CMD_CONNECT {
        // BIND (0x02) / UDP ASSOCIATE (0x03) are not supported (Go's proxy is CONNECT-only).
        send_reply(client, reply::COMMAND_NOT_SUPPORTED).await?;
        bail!("SOCKS5 command {cmd:#x} not supported (only CONNECT)");
    }

    let host = match address_type {
        atyp::IPV4 => {
            let mut b = [0u8; 4];
            client
                .read_exact(&mut b)
                .await
                .context("reading IPv4 dest")?;
            IpAddr::V4(Ipv4Addr::from(b)).to_string()
        }
        atyp::IPV6 => {
            let mut b = [0u8; 16];
            client
                .read_exact(&mut b)
                .await
                .context("reading IPv6 dest")?;
            IpAddr::V6(Ipv6Addr::from(b)).to_string()
        }
        atyp::DOMAINNAME => {
            let mut len = [0u8; 1];
            client
                .read_exact(&mut len)
                .await
                .context("reading domain length")?;
            let mut name = vec![0u8; len[0] as usize];
            client
                .read_exact(&mut name)
                .await
                .context("reading domain name")?;
            String::from_utf8(name).context("SOCKS5 domain name is not valid UTF-8")?
        }
        other => {
            send_reply(client, reply::ADDRESS_TYPE_NOT_SUPPORTED).await?;
            bail!("SOCKS5 address type {other:#x} not supported");
        }
    };

    let mut port_bytes = [0u8; 2];
    client
        .read_exact(&mut port_bytes)
        .await
        .context("reading dest port")?;
    let port = u16::from_be_bytes(port_bytes);
    Ok((host, port))
}

/// Send a SOCKS5 reply (RFC 1928 §6): `VER REP RSV ATYP BND.ADDR BND.PORT`. We always report a
/// zero bound address (`0.0.0.0:0`, ATYP=IPv4) — the client does not use BND for a CONNECT reply,
/// and Go's server likewise returns a placeholder. `rep` is one of the [`reply`] codes.
async fn send_reply(client: &mut TcpStream, rep: u8) -> Result<()> {
    // VER, REP, RSV(0), ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
    let frame = [SOCKS5_VERSION, rep, 0x00, atyp::IPV4, 0, 0, 0, 0, 0, 0];
    client
        .write_all(&frame)
        .await
        .context("writing SOCKS5 reply")?;
    client.flush().await?;
    Ok(())
}

/// Bidirectionally splice the client socket and the overlay stream until either side closes — the
/// same shape as the `nc`/serve splices. Each direction half-closes its peer's write side on EOF so
/// the other end sees the end of input.
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

/// Validate a `--socks5-server` listen address, returning a normalized form. A bare port (`1055`) is
/// accepted as `127.0.0.1:1055` (loopback default — the safe, no-auth-appropriate bind); a full
/// `host:port` is taken as-is. Pure → unit-testable, and lets the daemon reject a bad value at
/// startup with a clear message rather than a deep bind error.
pub fn normalize_listen_addr(addr: &str) -> Result<String> {
    let addr = addr.trim();
    if addr.is_empty() {
        bail!("--socks5-server address must not be empty");
    }
    // A full socket address parses directly (covers `127.0.0.1:1055`, `[::1]:1055`, `0.0.0.0:1055`).
    if addr.parse::<SocketAddr>().is_ok() {
        return Ok(addr.to_string());
    }
    // A bare port → loopback. SOCKS5 here is unauthenticated, so default to localhost (never expose
    // an unauthenticated proxy on all interfaces unless the operator explicitly asks for `0.0.0.0`).
    if let Ok(port) = addr.parse::<u16>() {
        if port == 0 {
            bail!("--socks5-server port must not be 0");
        }
        return Ok(format!("127.0.0.1:{port}"));
    }
    bail!(
        "--socks5-server must be a port (e.g. 1055) or host:port (e.g. 127.0.0.1:1055), got {addr:?}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_bare_port_is_loopback() {
        assert_eq!(normalize_listen_addr("1055").unwrap(), "127.0.0.1:1055");
        assert_eq!(normalize_listen_addr(" 1080 ").unwrap(), "127.0.0.1:1080");
    }

    #[test]
    fn normalize_full_socketaddr_passthrough() {
        assert_eq!(
            normalize_listen_addr("127.0.0.1:1055").unwrap(),
            "127.0.0.1:1055"
        );
        assert_eq!(
            normalize_listen_addr("0.0.0.0:1080").unwrap(),
            "0.0.0.0:1080"
        );
        assert_eq!(normalize_listen_addr("[::1]:9050").unwrap(), "[::1]:9050");
    }

    #[test]
    fn normalize_rejects_garbage_and_zero() {
        assert!(normalize_listen_addr("").is_err());
        assert!(normalize_listen_addr("not-an-addr").is_err());
        assert!(normalize_listen_addr("0").is_err());
        // A hostname without a port is ambiguous (is "localhost" a host or a typo'd port?) → reject.
        assert!(normalize_listen_addr("localhost").is_err());
    }

    // Protocol-level encoding constants are asserted so a typo in a wire byte is caught.
    #[test]
    fn wire_constants_match_rfc1928() {
        assert_eq!(SOCKS5_VERSION, 0x05);
        assert_eq!(METHOD_NO_AUTH, 0x00);
        assert_eq!(METHOD_NO_ACCEPTABLE, 0xff);
        assert_eq!(CMD_CONNECT, 0x01);
        assert_eq!(atyp::IPV4, 0x01);
        assert_eq!(atyp::DOMAINNAME, 0x03);
        assert_eq!(atyp::IPV6, 0x04);
        assert_eq!(reply::SUCCEEDED, 0x00);
        assert_eq!(reply::HOST_UNREACHABLE, 0x04);
        assert_eq!(reply::COMMAND_NOT_SUPPORTED, 0x07);
    }
}
