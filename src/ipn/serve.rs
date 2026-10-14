//! `serve` configuration persistence + logic — the Rust analogue of Go's `ipn.ServeConfig`
//! (`ipn/serve.go`).
//!
//! The wire types ([`ServeConfig`]/[`TcpPortHandler`]) live in [`crate::localapi`] (the DTO home,
//! like [`crate::localapi::PrefsView`]); this module re-exports them and supplies the persistence +
//! served/not-served logic as free functions. Persisted per-profile next to `prefs.json` /
//! `node.key.json` (see [`super::profile`]).
//!
//! ## Who serves what
//!
//! - **Plain `TCPForward`** (`tcp_forward` set, no `HTTPS`/`HTTP`/`TerminateTLS`) is served by the
//!   daemon's own raw accept→dial→splice loop (a [`Device::tcp_listen`](tailscale::Device::tcp_listen)
//!   per port; see the server's serve task). No TLS, no cert — so it works on any tailnet.
//! - **Web ports and TLS-terminated forwards** go to the engine's own serve runtime
//!   ([`Device::set_serve_config`](tailscale::Device::set_serve_config)). The engine stores Go's
//!   `ipn.ServeConfig` shape, and [`build_web_serve_state`] maps this config onto it. The engine
//!   refuses what it would serve differently from Go (plain HTTP, `TerminateTLS`, `Text` and `Path`
//!   handlers, among others); each refused port is reported with the engine's
//!   [`ServeConfigError`](tailscale::ServeConfigError), never served differently and never dropped
//!   quietly. TLS is fail-closed: without an issuable cert (the engine's `acme` feature off, or a
//!   control plane that 501s on `set-dns`) nothing binds.
//! - **Funnel** is armed by the funnel lane through the engine's `listen_funnel`, not through the
//!   stored Serve config.

use std::path::{Path, PathBuf};

pub use crate::localapi::{
    HttpHandler, RedirectSpec, ServeConfig, TcpPortHandler, WebMount, WebServerConfig,
};

/// Whether a handler is a web entry served via engine delegation (the [`build_web_serve_state`]
/// lane), as opposed to the plain-TCP-forward lane ([`is_plain_tcp_forward`]) or a not-served
/// `TerminateTLS` entry, **judging the handler alone**: it carries a *legacy* web aspect — an
/// `https`/`http` proxy (a non-empty `tcp_forward`), a fixed `text` body, a `redirect`, or path
/// `mounts`. NOTE: a Go-shaped web port keeps its target in the top-level `Web` map (the per-port
/// handler is just `HTTPS:true` with no `tcp_forward`), so this handler-only predicate misses it —
/// use [`port_is_web_serve`] when the [`ServeConfig`] is available (LANE dispatch / `has_web`).
pub fn is_web_serve(h: &TcpPortHandler) -> bool {
    ((h.https || h.http) && !h.tcp_forward.is_empty())
        || h.text.is_some()
        || h.redirect.is_some()
        || !h.mounts.is_empty()
}

/// Whether the port keyed `port_str` is a servable web entry, judged against the WHOLE
/// [`ServeConfig`] (so it sees the top-level `Web` map, unlike the handler-only [`is_web_serve`]). A
/// port is a web serve if its handler carries a legacy web aspect ([`is_web_serve`]) OR it has an
/// `HTTPS`/`HTTP` flag set AND a matching `Web[host:port]` entry exists (any `host`, matched by the
/// `:port` suffix — the LANE dispatch doesn't resolve the node FQDN, and a port is unique per config).
pub fn port_is_web_serve(cfg: &ServeConfig, port_str: &str, h: &TcpPortHandler) -> bool {
    if is_web_serve(h) {
        return true;
    }
    if h.https || h.http {
        let suffix = format!(":{port_str}");
        return cfg.web.keys().any(|k| k.ends_with(&suffix));
    }
    false
}

/// Resolve the single proxy backend to splice for a **funnel** (or any raw-TCP-after-TLS) on `port`,
/// judged against the WHOLE [`ServeConfig`]. Funnel terminates TLS and splices L4 to one backend, so
/// it needs exactly one `host:port`.
///
/// This MUST consult both shapes a serve can take, in the same precedence the web lane
/// ([`build_web_serve_state`]) uses, because the two have drifted apart over the serve work:
/// - **Legacy** (pre-Web-map): the backend lived on the per-port handler as
///   [`TcpPortHandler::tcp_forward`] alongside the `HTTPS`/`HTTP` flag.
/// - **Go `Web` map** (current — what `build_web_serve` writes): the per-port handler is a bare
///   `{HTTPS:true}` flag with an EMPTY `tcp_forward`, and the real backend is the `proxy` of the
///   **root (`/`) handler** of the matching `Web[host:port]` entry.
///
/// Reading only `tcp_forward` (the old code path) therefore finds NOTHING for any serve created by
/// the current CLI, so funnel silently never arms. Prefer the legacy field when present (an older
/// on-disk config), else fall back to the `Web` map root proxy. Returns `None` when the port has no
/// proxy backend (e.g. a `text:`/`redirect`-only web entry, which has nothing to L4-splice — funnel
/// over such an entry is refused by the caller). The `Web` key is matched by `:port` suffix across
/// any host (the lane dispatch doesn't resolve the node FQDN, and a port is unique per config), the
/// same rule [`port_is_web_serve`] uses.
pub fn web_proxy_backend(cfg: &ServeConfig, port: u16) -> Option<String> {
    let port_str = port.to_string();
    // 1. Legacy: a non-empty `tcp_forward` on the per-port handler (with the web flag set).
    if let Some(h) = cfg.tcp.get(&port_str)
        && is_web_serve(h)
        && !h.tcp_forward.is_empty()
    {
        return Some(h.tcp_forward.clone());
    }
    // 2. Go `Web` map: the root (`/`) handler's proxy of the matching `Web[*:port]` entry.
    let suffix = format!(":{port_str}");
    let wsc = cfg
        .web
        .iter()
        .find(|(k, _)| k.ends_with(&suffix))
        .map(|(_, v)| v)?;
    let root = wsc.handlers.get("/")?;
    if root.proxy.is_empty() {
        return None; // a text:/redirect: root has no L4 backend to splice.
    }
    Some(root.proxy.clone())
}

/// The engine's Serve config for this daemon's persisted config, and the ports the engine refuses.
///
/// Built by [`build_web_serve_state`]. [`state`](Self::state) holds only ports the engine will
/// serve. Each refused port is listed in [`refused`](Self::refused) with the engine's own reason and
/// left out of `state`, so one refused handler does not take the node's other web ports down with
/// it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineServe {
    /// What [`Device::set_serve_config`](tailscale::Device::set_serve_config) is given.
    pub state: tailscale::ServeState,
    /// The ports left out of [`state`](Self::state), in port order.
    pub refused: Vec<RefusedPort>,
}

/// One port the engine refuses to serve, with the engine's reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedPort {
    /// The tailnet port.
    pub port: u16,
    /// Why: the engine's [`ServeConfigError`](tailscale::ServeConfigError) for this port.
    pub error: tailscale::ServeConfigError,
}

impl std::fmt::Display for RefusedPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "port {}: {}", self.port, self.error)
    }
}

impl EngineServe {
    /// The refusals as one message for the operator, or `None` when every port is served.
    pub fn refusal_message(&self) -> Option<String> {
        if self.refused.is_empty() {
            return None;
        }
        let ports: Vec<String> = self.refused.iter().map(ToString::to_string).collect();
        Some(format!("unable to serve {}", ports.join("; ")))
    }
}

/// Refuse a redirect target carrying any control character.
///
/// The target is written into the `Location:` response header. The engine refuses CR and LF, the
/// characters that split a response; this refuses every control character (NUL, other C0/C1, NEL
/// `U+0085`), a stricter rule that costs nothing.
fn check_redirect_target(to: &str) -> Result<(), tailscale::ServeConfigError> {
    if to.chars().any(char::is_control) {
        return Err(tailscale::ServeConfigError::Invalid(
            "serve redirect target must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

/// One Go-shaped [`HttpHandler`] as the engine's (Go `ipn.HTTPHandler`, field for field).
fn engine_http_handler(
    h: &HttpHandler,
) -> Result<tailscale::HttpHandler, tailscale::ServeConfigError> {
    if !h.redirect.is_empty() {
        check_redirect_target(&h.redirect)?;
    }
    Ok(tailscale::HttpHandler {
        path: h.path.clone(),
        proxy: h.proxy.clone(),
        text: h.text.clone(),
        redirect: h.redirect.clone(),
        ..Default::default()
    })
}

/// The Go `Web` handlers for a port this fork wrote in its legacy shape: the body on the per-port
/// handler (`text`, `redirect`, `mounts`, or an `https`/`http` proxy in `tcp_forward`) instead of in
/// the `Web` map. The same migration `tnet serve` applies when it next writes the port. Empty when
/// the handler carries no legacy body.
fn legacy_web_handlers(
    h: &TcpPortHandler,
) -> Result<std::collections::BTreeMap<String, tailscale::HttpHandler>, tailscale::ServeConfigError>
{
    fn redirect(
        to: &str,
        status: u16,
    ) -> Result<tailscale::HttpHandler, tailscale::ServeConfigError> {
        if !(300..=399).contains(&status) {
            return Err(tailscale::ServeConfigError::Invalid(format!(
                "serve redirect status {status} is not in 300..=399"
            )));
        }
        check_redirect_target(to)?;
        Ok(tailscale::HttpHandler {
            redirect: format!("{status}:{to}"),
            ..Default::default()
        })
    }
    let proxy = |to: &str| tailscale::HttpHandler {
        proxy: to.to_string(),
        ..Default::default()
    };
    let text = |body: &str| tailscale::HttpHandler {
        text: body.to_string(),
        ..Default::default()
    };
    let mut handlers = std::collections::BTreeMap::new();
    if !h.mounts.is_empty() {
        for (mount, m) in &h.mounts {
            let handler = match m {
                WebMount::Proxy { to } => proxy(to),
                WebMount::Text { body } => text(body),
                WebMount::Redirect { to, status } => redirect(to, *status)?,
            };
            handlers.insert(mount.clone(), handler);
        }
    } else if let Some(body) = &h.text {
        handlers.insert("/".to_string(), text(body));
    } else if let Some(r) = &h.redirect {
        handlers.insert("/".to_string(), redirect(&r.to, r.status)?);
    } else if (h.https || h.http) && !h.tcp_forward.is_empty() {
        handlers.insert("/".to_string(), proxy(&h.tcp_forward));
    }
    Ok(handlers)
}

/// The engine's Go-shaped config for one port of `cfg`, or `None` when the port belongs to no
/// engine lane: a plain TCP forward (served by the daemon's own accept loop) or a handler with
/// nothing set.
///
/// The shapes are the ones Go's `tailscale serve` writes (`cmd/tailscale/cli/serve_v2.go`, through
/// `ipn.ServeConfig.SetWebHandler` and `SetTCPForwarding`):
/// - a web port is `TCP[port] = {HTTPS}` (or `{HTTP}`) plus `Web["host:port"].Handlers`, taken from
///   this config's `Web` entry for `host:port`, else migrated from the legacy per-port body;
/// - a TLS-terminated forward is `TCP[port] = {TCPForward, TerminateTLS, ProxyProtocol}`.
fn engine_port(
    cfg: &ServeConfig,
    host: &str,
    port: u16,
    h: &TcpPortHandler,
) -> Result<Option<tailscale::ServeState>, tailscale::ServeConfigError> {
    let mut state = tailscale::ServeState::default();
    if is_plain_tcp_forward(h) {
        return Ok(None);
    }
    if !h.terminate_tls.is_empty() && !h.https && !h.http {
        state.tcp.insert(
            port,
            tailscale::TcpPortHandler {
                tcp_forward: h.tcp_forward.clone(),
                terminate_tls: h.terminate_tls.clone(),
                proxy_protocol: i64::from(h.proxy_protocol),
                ..Default::default()
            },
        );
        return Ok(Some(state));
    }
    if !(h.https || h.http || is_web_serve(h)) {
        return Ok(None);
    }
    // A legacy body with no flag was served TLS-terminated; it stays HTTPS (see `serve_type`).
    let https = h.https || !h.http;
    state.tcp.insert(
        port,
        tailscale::TcpPortHandler {
            https,
            http: h.http && !h.https,
            ..Default::default()
        },
    );
    let handlers = match cfg.web.get(&format!("{host}:{port}")) {
        Some(wsc) => wsc
            .handlers
            .iter()
            .map(|(mount, hh)| Ok((mount.clone(), engine_http_handler(hh)?)))
            .collect::<Result<_, tailscale::ServeConfigError>>()?,
        None => legacy_web_handlers(h)?,
    };
    // No handlers at all: leave `Web` out, so the engine names the gap itself ("HTTPS port N with
    // no Web config for it") rather than serving nothing quietly.
    if !handlers.is_empty() {
        state.web.insert(
            tailscale::HostPort::new(host, port),
            tailscale::WebServerConfig { handlers },
        );
    }
    Ok(Some(state))
}

/// Map the persisted [`ServeConfig`] onto the engine's Go-shaped
/// [`ServeState`](tailscale::ServeState) for
/// [`Device::set_serve_config`](tailscale::Device::set_serve_config), and list the ports the engine
/// refuses.
///
/// `name` is the node's MagicDNS name (e.g. `host.tailnet.ts.net`, a trailing dot is dropped): the
/// host of each `Web` key, and so the certificate each HTTPS port terminates with.
///
/// What goes to the engine: web ports and TLS-terminated forwards (see [`engine_port`]). What does
/// not: plain TCP forwards, which the daemon serves itself, and `AllowFunnel`, which the funnel lane
/// arms through the engine's `listen_funnel`. The engine refuses a funnel entry that is on in this
/// config, so it is never sent; the engine's state always has Funnel off.
///
/// Every port is checked on its own with the engine's
/// [`ServeState::serve_plan`](tailscale::ServeState::serve_plan), the same check
/// `set_serve_config` runs. A port it refuses goes to [`EngineServe::refused`] with the engine's
/// [`ServeConfigError`](tailscale::ServeConfigError): plain-HTTP ports, `TerminateTLS`, `Text` and
/// `Path` handlers, a proxy at a mount other than `/` or to an `https://` backend, and the rest the
/// engine lists. A redirect with a control character, or a legacy redirect status outside
/// `300..=399`, is refused here the same way. A config with no engine port yields the empty state,
/// which is how a previously armed web serve is cleared.
pub fn build_web_serve_state(cfg: &ServeConfig, name: &str) -> EngineServe {
    let host = name.trim_end_matches('.');
    let mut out = EngineServe::default();
    for (port_str, h) in &cfg.tcp {
        let Ok(port) = port_str.parse::<u16>() else {
            // A non-numeric key can't be a tailnet port; skip (the persistence layer keeps it).
            continue;
        };
        let checked = engine_port(cfg, host, port, h).and_then(|one| match one {
            Some(one) => one.serve_plan().map(|_| Some(one)),
            None => Ok(None),
        });
        match checked {
            Ok(Some(one)) => {
                out.state.tcp.extend(one.tcp);
                out.state.web.extend(one.web);
            }
            Ok(None) => {}
            Err(error) => out.refused.push(RefusedPort { port, error }),
        }
    }
    out
}

/// Whether a handler is a plain TCP forward this daemon can actually serve: a non-empty
/// `tcp_forward`, no HTTP(S) web handling, and no TLS termination. The serve accept loop runs only
/// for handlers where this is true; everything else is persisted-but-not-served.
pub fn is_plain_tcp_forward(h: &TcpPortHandler) -> bool {
    !h.tcp_forward.is_empty() && !h.https && !h.http && h.terminate_tls.is_empty()
}

/// A high-level descriptor of the *kind* of serve one port handler performs — the Rust analogue of
/// Go's `serveType` (`ipn/ipnlocal/serve.go`). Two handlers on the same port are "the same kind"
/// exactly when this compares equal, which is the test
/// [`validate_serve_config_update`] applies before letting an incoming config replace a port.
///
/// The rendered names are Go's `serveType.String()` **verbatim** (`http`, `https`, `tcp`,
/// `tls-terminated-tcp`, and `unknownServeType` for Go's unnamed `-1`), because they are interpolated
/// into an error message the operator reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeType {
    /// TLS-terminated HTTP, reverse-proxied to a backend (Go `serveTypeHTTPS`, `--https`).
    Https,
    /// Plaintext HTTP, reverse-proxied to a backend (Go `serveTypeHTTP`, `--http`).
    Http,
    /// A raw TCP forward with no TLS (Go `serveTypeTCP`, `--tcp`).
    Tcp,
    /// TLS terminated, then the plaintext spliced as raw TCP (Go `serveTypeTLSTerminatedTCP`,
    /// `--tls-terminated-tcp`).
    TlsTerminatedTcp,
    /// A handler that names no servable shape at all — Go's `default: return -1`, which its
    /// `String()` renders `unknownServeType`. Two unknowns compare EQUAL, so (as in Go) one
    /// shapeless handler may replace another without a refusal.
    Unknown,
}

impl std::fmt::Display for ServeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ServeType::Https => "https",
            ServeType::Http => "http",
            ServeType::Tcp => "tcp",
            ServeType::TlsTerminatedTcp => "tls-terminated-tcp",
            ServeType::Unknown => "unknownServeType",
        })
    }
}

/// Classify one port handler — the Rust analogue of Go's `serveTypeFromPortHandler`
/// (`ipn/ipnlocal/serve.go`).
///
/// Go's own switch, in Go's order, covers the four fields this fork's [`TcpPortHandler`] shares with
/// Go's `ipn.TCPPortHandler`: `HTTP` → `http`, `HTTPS` → `https`, a non-empty `TerminateTLS` →
/// `tls-terminated-tcp`, a non-empty `TCPForward` → `tcp`, else unknown. The flags come first, so an
/// `HTTPS` web entry whose proxy backend lives in `TCPForward` (this fork's legacy web shape) is
/// `https` and not `tcp` — which is what Go says too, since a Go `HTTPS` port never carries a
/// `TCPForward`.
///
/// **One arm is this fork's, not Go's.** Go keeps every web body in the top-level `Web` map, so its
/// TCP handler for a web port is a bare `HTTPS`/`HTTP` flag and the four fields above classify it
/// completely. This fork also accepts the *legacy* per-handler bodies
/// ([`text`](TcpPortHandler::text)/[`redirect`](TcpPortHandler::redirect)/[`mounts`](TcpPortHandler::mounts),
/// kept for read-compat with configs this fork already wrote), and an older one of those can carry a
/// body with NO `HTTPS`/`HTTP` flag set. Go has no field to express that, so a field-for-field copy
/// of its switch would call such a handler `unknownServeType` and let a `--tcp` silently replace a
/// live web serve — the very hole this check exists to close. [`build_web_serve_state`] serves those
/// entries on the TLS-terminating engine lane, exactly like an `https` one, so they classify
/// [`Https`](ServeType::Https).
///
/// That arm sits AFTER `TCPForward`, matching the precedence the serve runtime itself uses: the LANE
/// dispatch in the backend's `spawn_serve` tests [`is_plain_tcp_forward`] first, so a handler
/// carrying both a bare `tcp_forward` and a legacy body is dispatched as a plain TCP forward and is
/// classified as one here.
pub fn serve_type(h: &TcpPortHandler) -> ServeType {
    if h.http {
        ServeType::Http
    } else if h.https {
        ServeType::Https
    } else if !h.terminate_tls.is_empty() {
        ServeType::TlsTerminatedTcp
    } else if !h.tcp_forward.is_empty() {
        ServeType::Tcp
    } else if h.text.is_some() || h.redirect.is_some() || !h.mounts.is_empty() {
        // Flagless legacy web body — served TLS-terminated by the engine lane. See the doc above.
        ServeType::Https
    } else {
        ServeType::Unknown
    }
}

/// Validate an incoming serve config against the one already in force, and refuse a change that
/// would silently destroy a live serve — the Rust analogue of Go's `validateServeConfigUpdate`
/// (`ipn/ipnlocal/serve.go`, called from `setServeConfigLocked`).
///
/// `SetServeConfig` replaces the config wholesale, and every CLI write is a read-modify-write of the
/// current config, so without this check `tnet serve --tcp 443 tcp://localhost:8000` aimed at a port
/// already terminating HTTPS is a plain map insert: it reports success and the previous serve is
/// gone with no diagnostic. Go refuses it. The rule is Go's: **for every port the incoming config
/// serves that the existing config already serves, the two handlers must classify to the same
/// [`ServeType`]** ([`serve_type`]); otherwise the port must be taken down first (`tnet serve
/// --https=443 off`) and re-served. Ports are matched by PARSED value, so an alias spelling of a
/// busy port (`"0443"`, `"+443"`) is the same port as `"443"` and is refused the same way.
///
/// The returned message is Go's format string verbatim — `want to serve %q, but port %d is already
/// serving %q` — because Go's own comment on this function says its errors are shown to CLI users
/// and must carry enough to diagnose the conflict. It reaches the operator as the
/// [`Response::Error`](crate::localapi::Response::Error) body of the refused `SetServeConfig`.
///
/// Clearing is never refused: `tnet serve reset` sends an empty config, which serves no port, so the
/// loop body never runs — the same outcome as Go's `if !incoming.Valid() { return nil }`. Likewise a
/// first serve on a node with no existing config passes, matching Go's `if !existing.Valid()`.
/// Removing or re-targeting a port within its own serve type is untouched.
///
/// # What of Go's function is NOT ported, and why
///
/// Go validates four more things; none of them has state to run against in this daemon, so porting
/// them would be dead code, not parity. They are named here so that whoever adds the missing state
/// knows where the check belongs — each is a loop over an `existing`/`incoming` field this signature
/// already hands them:
///
/// - **`listener already exists for port %d`** — a NEW foreground session landing on a port some
///   other session already serves.
/// - **`foreground listener already exists for port %d`** — a background config overwriting a port a
///   foreground session holds.
///   Both need `ServeConfig.Foreground`, which this fork does not model: a foreground serve here is
///   torn down by `tnet` itself from its own signal handler (see `hold_foreground_serve` in the CLI),
///   not by a daemon-held session, so the daemon has no second session's ports to collide with. When
///   the daemon owns sessions, these two go in front of the serve-type loop below, in Go's order.
/// - **The per-service serve-type rule** (`… is already serving %q for %s`) and the **Service TUN
///   exclusivity** rules (`cannot configure TUN mode in combination with TCP or web handlers for %s`
///   and its two update-time variants) — both need `ServeConfig.Services`, and this fork's Tailscale
///   Services support is read-only (no `ServeConfig` field, nothing to write a service handler with).
pub fn validate_serve_config_update(
    existing: &ServeConfig,
    incoming: &ServeConfig,
) -> Result<(), String> {
    // Incoming configuration cannot change the serve type in use by a port. Ports are matched by
    // their PARSED value, never by the raw map key: this fork keys
    // [`ServeConfig::tcp`](crate::localapi::ServeConfig::tcp) by string (see that field for why),
    // and `u16::from_str` accepts leading zeros and a leading `+`, so `"443"`, `"0443"` and
    // `"+443"` are three distinct keys naming ONE tailnet port. They all arm it, too — every reader
    // of the map parses the key ([`build_web_serve_state`], the lane dispatch in the backend's
    // `spawn_serve`). Comparing raw keys therefore skipped the refusal for any spelling that did
    // not match character-for-character, which is exactly the hole this function exists to close.
    // Go has no such alias: its `ServeConfig.TCP` is keyed `uint16`, so `encoding/json` parses the
    // key at decode time and both spellings are already the same map entry before its check runs.
    for (port_str, incoming_handler) in &incoming.tcp {
        let Ok(port) = port_str.parse::<u16>() else {
            // Not a tailnet port at all; the rest of the serve code skips such a key rather than
            // serving it, so there is no live serve to protect and nothing to name in the message.
            continue;
        };
        let incoming_type = serve_type(incoming_handler);
        // Every existing key that names this port, not just the identically spelled one (a port
        // nothing serves yet matches none of them and is free). An existing config holding two
        // aliases of one port arms both handlers, so a conflict with EITHER is a conflict.
        for existing_handler in existing
            .tcp
            .iter()
            .filter(|(k, _)| k.parse::<u16>().is_ok_and(|p| p == port))
            .map(|(_, h)| h)
        {
            let existing_type = serve_type(existing_handler);
            if incoming_type != existing_type {
                return Err(format!(
                    "want to serve \"{incoming_type}\", but port {port} is already serving \
                     \"{existing_type}\""
                ));
            }
        }
    }
    Ok(())
}

/// Set (or replace) the TCP forward for `port` → `forward_to` (Go `SetTCPForwarding`). `forward_to`
/// is stored verbatim as the dial target (`IP:port`). The map key is the port rendered as a string
/// (see [`ServeConfig::tcp`](crate::localapi::ServeConfig::tcp) for why the key is a string).
///
/// TRUST MODEL: the forward target is an ARBITRARY local `host:port`, by design (Go parity — Go's
/// `tailscale serve` likewise accepts any proxy host; the bare-port→`127.0.0.1` default is applied at
/// the CLI in `normalize_serve_target`). Inbound tailnet (serve) or public-internet (funnel) bytes are
/// then spliced to it, so a target like a metadata endpoint or another LAN host IS reachable through
/// this node. The security boundary is the LocalAPI **write authorization** on `SetServeConfig`
/// (root / daemon-owner uid — see `auth::requires_write`): only a principal already trusted to
/// reconfigure the daemon can set a target. This is the inbound inverse of the proxy SSRF guard, and
/// it is intentionally NOT restricted to loopback (that would diverge from Go).
pub fn set_tcp_forward(cfg: &mut ServeConfig, port: u16, forward_to: String) {
    cfg.tcp.insert(
        port.to_string(),
        TcpPortHandler {
            tcp_forward: forward_to,
            ..Default::default()
        },
    );
}

/// The Go `HostPort` key (`host:port`) for a funnel entry — the node's MagicDNS name joined to the
/// port. Matches Go's `net.JoinHostPort(dnsName, port)` for a DNS host (a plain `host:port` concat;
/// no IPv6 brackets, since a MagicDNS name never contains a colon).
pub fn funnel_host_port(host: &str, port: u16) -> String {
    format!("{}:{port}", host.trim_end_matches('.'))
}

/// Turn Funnel on or off for `host`:`port` (Go `ServeConfig.SetFunnel`). On `on`, inserts the
/// `host:port` → `true` entry; on `off`, removes EVERY key ending in `:port` regardless of host (so an
/// off port never lingers on the wire — our `skip_serializing_if` omits an empty map).
///
/// `off` matches by `:port` suffix rather than the exact current `host:port` because the funnel
/// arming path ([`funnel_ports`]) is itself host-insensitive (it parses the port out of every `true`
/// key). If the node's MagicDNS name changed since the entry was written, an exact-key removal would
/// leave the stale-host key behind and funnel would stay armed despite the operator's `off`. Removing
/// by port closes that asymmetry. (A MagicDNS host never contains a `:`, so the suffix is unambiguous.)
pub fn set_funnel(cfg: &mut ServeConfig, host: &str, port: u16, on: bool) {
    if on {
        cfg.allow_funnel.insert(funnel_host_port(host, port), true);
    } else {
        let suffix = format!(":{port}");
        cfg.allow_funnel.retain(|hp, _| !hp.ends_with(&suffix));
    }
}

/// The set of tailnet ports with Funnel enabled, parsed from the `host:port` keys of
/// [`allow_funnel`](crate::localapi::ServeConfig::allow_funnel) whose value is `true`. The port is the
/// substring after the LAST `:` (a MagicDNS host has no colon, so this is unambiguous). A
/// non-numeric/zero port key is skipped.
pub fn funnel_ports(cfg: &ServeConfig) -> std::collections::BTreeSet<u16> {
    cfg.allow_funnel
        .iter()
        .filter(|(_, on)| **on)
        .filter_map(|(hp, _)| hp.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()))
        .filter(|&p| p != 0)
        .collect()
}

/// The `(host, port)` pairs with Funnel enabled, split from each `true` `host:port` key (port after
/// the last `:`, host before it — a MagicDNS host has no colon). Lets a renderer show the real
/// MagicDNS name instead of a placeholder. Sorted by the BTreeMap key order; a bad port key is
/// skipped.
pub fn funnel_host_ports(cfg: &ServeConfig) -> Vec<(String, u16)> {
    cfg.allow_funnel
        .iter()
        .filter(|(_, on)| **on)
        .filter_map(|(hp, _)| {
            hp.rsplit_once(':').and_then(|(h, p)| {
                p.parse::<u16>()
                    .ok()
                    .filter(|&p| p != 0)
                    .map(|p| (h.to_string(), p))
            })
        })
        .collect()
}

/// The funnel-enabled ports whose web-proxy backend resolves to a **non-loopback** target, paired
/// with that backend `host:port`. Funnel publishes a port to the PUBLIC internet, so a non-loopback
/// backend means inbound internet traffic is spliced to something other than this host's loopback
/// (another LAN host, a metadata endpoint, a public IP) — worth a heads-up. A loopback backend
/// (`127.0.0.1` / `::1` / `localhost`) is the normal, expected case and is omitted.
///
/// "Non-loopback" is decided by parsing the backend host: a literal loopback IP, or the name
/// `localhost`, is loopback; a parseable non-loopback IP is flagged; an unparseable name (a DNS name
/// other than `localhost`) is conservatively treated as non-loopback (it could resolve anywhere).
pub fn funnel_nonloopback_backends(cfg: &ServeConfig) -> Vec<(u16, String)> {
    let mut out = Vec::new();
    for port in funnel_ports(cfg) {
        if let Some(backend) = web_proxy_backend(cfg, port)
            && backend_is_nonloopback(&backend)
        {
            out.push((port, backend));
        }
    }
    out
}

/// Whether a serve/funnel backend target (`host:port`, or a bare host) points at a NON-loopback host.
/// Loopback = a loopback IP literal or the name `localhost`; everything else (a routable IP, or any
/// other DNS name, which could resolve anywhere) is non-loopback. Bracketed IPv6 (`[::1]:443`) is
/// handled.
fn backend_is_nonloopback(backend: &str) -> bool {
    // A bare IP literal (incl. an unbracketed IPv6 like `::1`, which has multiple colons and no
    // port) parses directly — try that first so the host:port split below never mis-slices it.
    if let Ok(ip) = backend.parse::<std::net::IpAddr>() {
        return !ip.is_loopback();
    }
    // Otherwise isolate the host from a `host:port` / `[v6]:port` form.
    let host = if let Some(rest) = backend.strip_prefix('[') {
        // `[v6]` or `[v6]:port` → the part inside the brackets.
        rest.split(']').next().unwrap_or(rest)
    } else {
        // `host:port` → host is before the last `:`; a bare host (no `:`) is itself.
        backend.rsplit_once(':').map(|(h, _)| h).unwrap_or(backend)
    };
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => !ip.is_loopback(),
        // A non-IP host that isn't `localhost` (a DNS name) could resolve anywhere → treat as
        // non-loopback (conservative — the warning is advisory, false-positives are acceptable).
        Err(_) => true,
    }
}

/// Path of the serve-config file for `state_dir` + profile id (next to prefs/key). The default
/// profile uses a top-level `serve-config.json`; named profiles nest under `profiles/<id>/`.
pub fn config_path(state_dir: &Path, profile_id: &str) -> PathBuf {
    if profile_id == super::profile::DEFAULT_PROFILE_ID {
        state_dir.join("serve-config.json")
    } else {
        state_dir
            .join("profiles")
            .join(profile_id)
            .join("serve-config.json")
    }
}

/// Load the serve config for the given profile. Missing → empty (no serve); malformed → empty with a
/// warning (a bad serve config must not stop the daemon, just like prefs).
pub async fn load(state_dir: &Path, profile_id: &str) -> ServeConfig {
    let path = config_path(state_dir, profile_id);
    match tokio::fs::read(&path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!(error = %e, path = %path.display(), "serve-config is malformed; treating as empty (no serve)");
            ServeConfig::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ServeConfig::default(),
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "serve-config unreadable; treating as empty");
            ServeConfig::default()
        }
    }
}

/// Persist the serve config for the given profile.
pub async fn save(cfg: &ServeConfig, state_dir: &Path, profile_id: &str) -> std::io::Result<()> {
    let path = config_path(state_dir, profile_id);
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir).await?;
    }
    let bytes = serde_json::to_vec_pretty(cfg).expect("serve config serialize");
    // Atomic write (temp+rename), the same crash-safety prefs uses: a crash mid-write must leave the
    // OLD complete config or the NEW one, never a truncated file that `load` would discard back to an
    // empty serve config (silently un-serving a node after a crash).
    crate::prefs::atomic_write(&path, &bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipn::profile::DEFAULT_PROFILE_ID;

    #[test]
    fn wire_shape_matches_go() {
        let mut sc = ServeConfig::default();
        set_tcp_forward(&mut sc, 8443, "127.0.0.1:5000".into());
        let json = serde_json::to_string(&sc).unwrap();
        assert_eq!(json, r#"{"TCP":{"8443":{"TCPForward":"127.0.0.1:5000"}}}"#);
        let back: ServeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sc);
    }

    #[test]
    fn empty_config_serializes_to_empty_object() {
        assert_eq!(
            serde_json::to_string(&ServeConfig::default()).unwrap(),
            "{}"
        );
        assert!(ServeConfig::default().tcp.is_empty());
        // The new Web map is also empty + omitted from the wire on a default config.
        assert!(ServeConfig::default().web.is_empty());
    }

    #[test]
    fn go_authored_web_map_deserializes_without_dropping_targets() {
        // THE tsd-6p4 gap: a web serve config authored by a real Go `tailscaled` carries the handler
        // body in a top-level `Web` map (TCP[port]={HTTPS:true} merely flags it). Before Stage A the
        // `Web` key was silently dropped (serde ignore-unknown) and the proxy target was LOST. Now it
        // must deserialize intact.
        let go_json = r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"host.tailnet.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000"}}}}}"#;
        let cfg: ServeConfig = serde_json::from_str(go_json).expect("Go web config must parse");
        // The HTTPS flag survived on the port handler.
        assert!(cfg.tcp.get("443").is_some_and(|h| h.https));
        // The Web map carried the handler body (NOT dropped).
        let wsc = cfg
            .web
            .get("host.tailnet.ts.net:443")
            .expect("Web[host:443] entry must be present");
        assert_eq!(
            wsc.handlers.get("/").map(|h| h.proxy.as_str()),
            Some("http://127.0.0.1:3000"),
            "the proxy target must survive deserialize: {cfg:?}"
        );
        // And it round-trips back to byte-identical Go wire (PascalCase, omitempty, no extra keys).
        assert_eq!(serde_json::to_string(&cfg).unwrap(), go_json);
    }

    #[test]
    fn web_handler_text_and_redirect_round_trip() {
        // Text + the Go string-form Redirect (`<code>:<url>`) round-trip in the Web map.
        let go_json = r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"h:443":{"Handlers":{"/info":{"Text":"hi"},"/old":{"Redirect":"301:https://h/new"}}}}}"#;
        let cfg: ServeConfig = serde_json::from_str(go_json).expect("parse");
        let h = &cfg.web["h:443"].handlers;
        assert_eq!(h["/info"].text, "hi");
        assert_eq!(h["/old"].redirect, "301:https://h/new");
        assert!(h.get("/missing").is_none(), "absent mount has no handler");
        assert!(h["/info"].proxy.is_empty() && h["/info"].redirect.is_empty());
        assert_eq!(serde_json::to_string(&cfg).unwrap(), go_json);
    }

    #[test]
    fn legacy_handler_bodies_still_deserialize() {
        // Read-compat: a serve-config.json this fork ALREADY wrote (web bodies on the per-port handler
        // via the legacy Text/Redirect/Mounts fields) must still deserialize after Stage A — removing
        // those fields would silently drop existing users' web serves on upgrade.
        let legacy = r#"{"TCP":{"443":{"HTTPS":true,"Text":"hello"}}}"#;
        let cfg: ServeConfig =
            serde_json::from_str(legacy).expect("legacy config must still parse");
        assert_eq!(cfg.tcp["443"].text.as_deref(), Some("hello"));
        assert!(cfg.web.is_empty(), "legacy shape has no Web map");
    }

    #[test]
    fn plain_tcp_forward_predicate() {
        let fwd = TcpPortHandler {
            tcp_forward: "127.0.0.1:22".into(),
            ..Default::default()
        };
        assert!(is_plain_tcp_forward(&fwd));
        assert!(!is_plain_tcp_forward(&TcpPortHandler {
            https: true,
            ..fwd.clone()
        }));
        assert!(!is_plain_tcp_forward(&TcpPortHandler {
            http: true,
            ..fwd.clone()
        }));
        assert!(!is_plain_tcp_forward(&TcpPortHandler {
            terminate_tls: "host.ts.net".into(),
            ..fwd.clone()
        }));
        assert!(!is_plain_tcp_forward(&TcpPortHandler::default()));
    }

    #[test]
    fn web_serve_predicate_classifies_handlers() {
        // HTTPS web with a backend → web-serve.
        assert!(is_web_serve(&TcpPortHandler {
            https: true,
            tcp_forward: "127.0.0.1:3000".into(),
            ..Default::default()
        }));
        // HTTP web with a backend → web-serve.
        assert!(is_web_serve(&TcpPortHandler {
            http: true,
            tcp_forward: "127.0.0.1:3000".into(),
            ..Default::default()
        }));
        // Plain TCP forward (no https/http) → NOT web-serve (it's the hand-rolled lane).
        assert!(!is_web_serve(&TcpPortHandler {
            tcp_forward: "127.0.0.1:22".into(),
            ..Default::default()
        }));
        // Web flag but no backend → NOT web-serve (nothing to proxy to).
        assert!(!is_web_serve(&TcpPortHandler {
            https: true,
            ..Default::default()
        }));
        // The two lanes are mutually exclusive.
        let web = TcpPortHandler {
            https: true,
            tcp_forward: "127.0.0.1:3000".into(),
            ..Default::default()
        };
        assert!(is_web_serve(&web) && !is_plain_tcp_forward(&web));
    }

    /// The engine's Go-shaped handler for a proxy backend.
    fn engine_proxy(to: &str) -> tailscale::HttpHandler {
        tailscale::HttpHandler {
            proxy: to.into(),
            ..Default::default()
        }
    }

    /// The handlers the engine state holds for `host:port`.
    fn engine_web<'a>(
        state: &'a tailscale::ServeState,
        host: &str,
        port: u16,
    ) -> &'a std::collections::BTreeMap<String, tailscale::HttpHandler> {
        &state
            .web
            .get(&tailscale::HostPort::new(host, port))
            .unwrap_or_else(|| panic!("no Web entry for {host}:{port} in {state:?}"))
            .handlers
    }

    #[test]
    fn https_proxy_maps_to_gos_https_flag_and_web_entry() {
        let mut cfg = ServeConfig::default();
        // A plain TCP forward stays on the daemon's own lane: not in the engine state.
        set_tcp_forward(&mut cfg, 2222, "127.0.0.1:22".into());
        // An HTTPS proxy, as `tnet serve --https 443 3000` writes it (Go `SetWebHandler`).
        go_web(&mut cfg, "host.example.ts.net", 443, true, "127.0.0.1:3000");
        let built = build_web_serve_state(&cfg, "host.example.ts.net.");
        assert!(built.refused.is_empty(), "{:?}", built.refused);
        let state = &built.state;
        // Go's shape: TCP[443] = {HTTPS} and the backend in Web["host:443"].Handlers["/"].
        assert_eq!(
            state.tcp.get(&443),
            Some(&tailscale::TcpPortHandler {
                https: true,
                ..Default::default()
            })
        );
        assert!(!state.tcp.contains_key(&2222));
        assert_eq!(
            engine_web(state, "host.example.ts.net", 443).get("/"),
            Some(&engine_proxy("127.0.0.1:3000"))
        );
        assert!(state.allow_funnel.is_empty() && state.services.is_empty());
        // The engine serves it: TLS terminated with the node's name, proxied to the backend.
        let plan = state
            .serve_plan()
            .expect("the engine accepts an HTTPS proxy");
        assert_eq!(plan[&443].cert_name.as_deref(), Some("host.example.ts.net"));
        match &plan[&443].target {
            tailscale::ServeTarget::Path { handlers } => assert_eq!(
                handlers.get("/"),
                Some(&tailscale::ServeTarget::Proxy {
                    to: "127.0.0.1:3000".into()
                })
            ),
            other => panic!("expected the engine's path mux, got {other:?}"),
        }
    }

    #[test]
    fn tls_terminated_forward_maps_to_gos_shape_and_the_engine_refuses_it() {
        // `tnet serve --tls-terminated-tcp 9000 9`, as Go's `SetTCPForwarding` writes it.
        let tls_fwd = TcpPortHandler {
            tcp_forward: "127.0.0.1:9".into(),
            terminate_tls: "host.ts.net".into(),
            ..Default::default()
        };
        // It belongs to neither of the other lanes.
        assert!(!is_plain_tcp_forward(&tls_fwd));
        assert!(!is_web_serve(&tls_fwd));
        let mut cfg = ServeConfig::default();
        cfg.tcp.insert("9000".into(), tls_fwd.clone());
        cfg.tcp.insert(
            "9001".into(),
            TcpPortHandler {
                proxy_protocol: 2,
                ..tls_fwd
            },
        );
        // The mapped port is Go's handler, field for field.
        let one = engine_port(&cfg, "host.ts.net", 9001, &cfg.tcp["9001"])
            .unwrap()
            .expect("a TLS-terminated forward goes to the engine lane");
        assert_eq!(
            one.tcp.get(&9001),
            Some(&tailscale::TcpPortHandler {
                tcp_forward: "127.0.0.1:9".into(),
                terminate_tls: "host.ts.net".into(),
                proxy_protocol: 2,
                ..Default::default()
            })
        );
        // The engine cannot terminate TLS on a forward the way Go does, so both ports are refused
        // with its own reason, and nothing is handed to it.
        let built = build_web_serve_state(&cfg, "host.ts.net");
        let refusal =
            tailscale::ServeConfigError::Unsupported("TCPForward with TerminateTLS".into());
        assert_eq!(
            built.refused,
            vec![
                RefusedPort {
                    port: 9000,
                    error: refusal.clone()
                },
                RefusedPort {
                    port: 9001,
                    error: refusal
                },
            ]
        );
        assert_eq!(built.state, tailscale::ServeState::default());
    }

    #[test]
    fn plain_http_port_is_refused_by_the_engine() {
        // `tnet serve --http 80 3000`: Go serves plain HTTP; the engine refuses rather than
        // terminate TLS on a port the operator asked to be plaintext.
        let mut cfg = ServeConfig::default();
        go_web(&mut cfg, "host.ts.net", 80, false, "127.0.0.1:3000");
        let built = build_web_serve_state(&cfg, "host.ts.net");
        assert_eq!(
            built.refused,
            vec![RefusedPort {
                port: 80,
                error: tailscale::ServeConfigError::Unsupported("plain-HTTP ports".into()),
            }]
        );
        assert!(built.state.tcp.is_empty());
    }

    #[test]
    fn build_web_serve_state_reads_the_go_web_map() {
        // A Go-shaped config: TCP[443]={HTTPS:true} + the target in Web[host:443].Handlers["/"].
        // The Web key is looked up with `name`, whose trailing dot is dropped.
        let go_json = r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"host.ts.net:443":{"Handlers":{"/":{"Proxy":"127.0.0.1:3000"}}}}}"#;
        let cfg: ServeConfig = serde_json::from_str(go_json).unwrap();
        let built = build_web_serve_state(&cfg, "host.ts.net.");
        assert!(built.refused.is_empty(), "{:?}", built.refused);
        assert_eq!(
            engine_web(&built.state, "host.ts.net", 443).get("/"),
            Some(&engine_proxy("127.0.0.1:3000")),
            "the Web[host:443] proxy handler must be served, not dropped"
        );
        // And the engine's state is the same document Go would store.
        assert_eq!(serde_json::to_string(&built.state).unwrap(), go_json);
    }

    #[test]
    fn build_web_serve_state_web_map_multi_mount_and_redirect() {
        // A proxy at `/` plus a Go string-form redirect at `/old`: the engine serves both behind
        // one path mux, and reads the `301:` prefix as the status.
        let go_json = r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"host.ts.net:443":{"Handlers":{"/":{"Proxy":"127.0.0.1:3000"},"/old":{"Redirect":"301:https://host.ts.net/new"}}}}}"#;
        let cfg: ServeConfig = serde_json::from_str(go_json).unwrap();
        let built = build_web_serve_state(&cfg, "host.ts.net");
        assert!(built.refused.is_empty(), "{:?}", built.refused);
        let plan = built.state.serve_plan().unwrap();
        match &plan[&443].target {
            tailscale::ServeTarget::Path { handlers } => {
                assert_eq!(
                    handlers.get("/"),
                    Some(&tailscale::ServeTarget::Proxy {
                        to: "127.0.0.1:3000".into()
                    })
                );
                assert_eq!(
                    handlers.get("/old"),
                    Some(&tailscale::ServeTarget::Redirect {
                        to: "https://host.ts.net/new".into(),
                        status: 301
                    })
                );
            }
            other => panic!("expected a Path mux, got {other:?}"),
        }
    }

    #[test]
    fn build_web_serve_state_legacy_fallback_when_no_web_entry() {
        // A legacy-shaped config (HTTPS flag + tcp_forward on the handler, NO Web map) is migrated
        // into the Web map the way `tnet serve` migrates it, and still serves.
        let mut cfg = ServeConfig::default();
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                tcp_forward: "127.0.0.1:3000".into(),
                ..Default::default()
            },
        );
        let built = build_web_serve_state(&cfg, "h.ts.net");
        assert!(built.refused.is_empty(), "{:?}", built.refused);
        assert_eq!(
            built.state.tcp.get(&443),
            Some(&tailscale::TcpPortHandler {
                https: true,
                ..Default::default()
            }),
            "the backend moves to the Web map; Go's HTTPS port carries no TCPForward"
        );
        assert_eq!(
            engine_web(&built.state, "h.ts.net", 443).get("/"),
            Some(&engine_proxy("127.0.0.1:3000"))
        );
    }

    #[test]
    fn port_is_web_serve_consults_the_web_map() {
        // A Go-shaped port (HTTPS flag, target only in Web) has a handler that is_web_serve misses,
        // but port_is_web_serve sees via the Web map.
        let cfg: ServeConfig = serde_json::from_str(
            r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"h:443":{"Handlers":{"/":{"Text":"hi"}}}}}"#,
        )
        .unwrap();
        let h = &cfg.tcp["443"];
        assert!(
            !is_web_serve(h),
            "handler-only predicate misses the Web map"
        );
        assert!(
            port_is_web_serve(&cfg, "443", h),
            "config-aware predicate must see the Web[h:443] entry"
        );
        // A flag-set port with NO matching Web entry is not a web serve (nothing to serve).
        let orphan: ServeConfig =
            serde_json::from_str(r#"{"TCP":{"8443":{"HTTPS":true}}}"#).unwrap();
        assert!(!port_is_web_serve(&orphan, "8443", &orphan.tcp["8443"]));
    }

    #[test]
    fn web_proxy_backend_finds_go_web_map_and_legacy_shapes() {
        // REGRESSION GUARD: this is the funnel-never-arms bug. A serve created by the current CLI
        // (`build_web_serve`) writes the Go `Web` map with an EMPTY `tcp_forward`; the old funnel
        // resolver read only `tcp_forward` + `is_web_serve(h)` and so found NOTHING, leaving funnel
        // silently un-armed. `web_proxy_backend` must resolve the root (`/`) handler's proxy here.
        let go_shape: ServeConfig = serde_json::from_str(
            r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"host.ts.net:443":{"Handlers":{"/":{"Proxy":"127.0.0.1:3000"}}}}}"#,
        )
        .unwrap();
        assert_eq!(
            web_proxy_backend(&go_shape, 443).as_deref(),
            Some("127.0.0.1:3000"),
            "funnel backend must come from the Web map root proxy (the shape build_web_serve writes)"
        );

        // Legacy on-disk shape: the backend on the per-port handler's `tcp_forward`.
        let legacy: ServeConfig =
            serde_json::from_str(r#"{"TCP":{"443":{"HTTPS":true,"TCPForward":"127.0.0.1:9000"}}}"#)
                .unwrap();
        assert_eq!(
            web_proxy_backend(&legacy, 443).as_deref(),
            Some("127.0.0.1:9000"),
            "legacy tcp_forward backend must still resolve (back-compat)"
        );

        // A `text:`-only Web entry has no L4 backend to splice → None (funnel over it is refused).
        let text_only: ServeConfig = serde_json::from_str(
            r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"host.ts.net:443":{"Handlers":{"/":{"Text":"hi"}}}}}"#,
        )
        .unwrap();
        assert_eq!(
            web_proxy_backend(&text_only, 443),
            None,
            "a text-only serve has no proxy backend to funnel-splice"
        );

        // No serve on the port at all → None.
        assert_eq!(web_proxy_backend(&ServeConfig::default(), 443), None);
    }

    #[test]
    fn web_serve_predicate_recognizes_text_redirect_mounts() {
        // Text-only handler → web.
        assert!(is_web_serve(&TcpPortHandler {
            text: Some("hi".into()),
            ..Default::default()
        }));
        // Redirect-only handler → web.
        assert!(is_web_serve(&TcpPortHandler {
            redirect: Some(RedirectSpec {
                to: "https://x.ts.net/".into(),
                status: 302
            }),
            ..Default::default()
        }));
        // Mounts → web.
        let mut mounts = std::collections::BTreeMap::new();
        mounts.insert(
            "/api".to_string(),
            WebMount::Proxy {
                to: "127.0.0.1:3000".into(),
            },
        );
        assert!(is_web_serve(&TcpPortHandler {
            mounts,
            ..Default::default()
        }));
    }

    #[test]
    fn a_text_handler_surfaces_the_engines_refusal_and_the_other_ports_still_serve() {
        let mut cfg = ServeConfig::default();
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                text: Some("hello world".into()),
                ..Default::default()
            },
        );
        cfg.tcp.insert(
            "8443".into(),
            TcpPortHandler {
                https: true,
                redirect: Some(RedirectSpec {
                    to: "https://dest.ts.net/".into(),
                    status: 301,
                }),
                ..Default::default()
            },
        );
        let built = build_web_serve_state(&cfg, "host.example.ts.net");
        // Go frames `Text` as an HTTP response; the engine would write bare bytes, so it refuses.
        assert_eq!(
            built.refused,
            vec![RefusedPort {
                port: 443,
                error: tailscale::ServeConfigError::Unsupported("Text handlers".into()),
            }]
        );
        assert_eq!(
            built.refusal_message().as_deref(),
            Some(
                "unable to serve port 443: serve config not supported by this runtime: Text handlers"
            )
        );
        // The refused port is left out; the redirect port is still handed over and served.
        assert!(!built.state.tcp.contains_key(&443));
        assert_eq!(
            engine_web(&built.state, "host.example.ts.net", 8443)
                .get("/")
                .map(|h| h.redirect.as_str()),
            Some("301:https://dest.ts.net/")
        );
        assert!(built.state.serve_plan().is_ok());
    }

    #[test]
    fn a_redirect_placeholder_is_refused_by_the_engine() {
        // Go expands `${HOST}` and `${REQUEST_URI}` per request; the engine writes one fixed
        // response, so it refuses the placeholders rather than send them to the client literally.
        let mut cfg = ServeConfig::default();
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                redirect: Some(RedirectSpec {
                    to: "https://${HOST}/${REQUEST_URI}".into(),
                    status: 302,
                }),
                ..Default::default()
            },
        );
        let built = build_web_serve_state(&cfg, "host.example.ts.net");
        assert_eq!(
            built.refused,
            vec![RefusedPort {
                port: 443,
                error: tailscale::ServeConfigError::Unsupported(
                    "Redirect with ${HOST} or ${REQUEST_URI}".into()
                ),
            }]
        );
    }

    #[test]
    fn build_web_serve_state_lone_root_mount_is_bare_target() {
        // A legacy `/` mount becomes the Web map's `/` handler.
        let mut mounts = std::collections::BTreeMap::new();
        mounts.insert(
            "/".to_string(),
            WebMount::Proxy {
                to: "127.0.0.1:3000".into(),
            },
        );
        let mut cfg = ServeConfig::default();
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                mounts,
                ..Default::default()
            },
        );
        let built = build_web_serve_state(&cfg, "host.example.ts.net");
        assert!(built.refused.is_empty(), "{:?}", built.refused);
        let handlers = engine_web(&built.state, "host.example.ts.net", 443);
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers.get("/"), Some(&engine_proxy("127.0.0.1:3000")));
    }

    #[test]
    fn build_web_serve_state_multi_mount_is_path_mux() {
        let mut mounts = std::collections::BTreeMap::new();
        mounts.insert(
            "/".to_string(),
            WebMount::Proxy {
                to: "127.0.0.1:3000".into(),
            },
        );
        mounts.insert(
            "/old".to_string(),
            WebMount::Redirect {
                to: "https://host.example.ts.net/new".into(),
                status: 308,
            },
        );
        let mut cfg = ServeConfig::default();
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                mounts: mounts.clone(),
                ..Default::default()
            },
        );
        let built = build_web_serve_state(&cfg, "host.example.ts.net");
        assert!(built.refused.is_empty(), "{:?}", built.refused);
        match &built.state.serve_plan().unwrap()[&443].target {
            tailscale::ServeTarget::Path { handlers } => {
                assert_eq!(handlers.len(), 2);
                assert_eq!(
                    handlers.get("/old"),
                    Some(&tailscale::ServeTarget::Redirect {
                        to: "https://host.example.ts.net/new".into(),
                        status: 308
                    })
                );
            }
            other => panic!("expected Path mux, got {other:?}"),
        }

        // Go strips the mount from the path before proxying; the engine does not, so a proxy at a
        // mount other than `/` is refused.
        mounts.insert(
            "/api".to_string(),
            WebMount::Proxy {
                to: "127.0.0.1:4000".into(),
            },
        );
        cfg.tcp.get_mut("443").unwrap().mounts = mounts;
        let built = build_web_serve_state(&cfg, "host.example.ts.net");
        assert_eq!(
            built.refused,
            vec![RefusedPort {
                port: 443,
                error: tailscale::ServeConfigError::Unsupported(
                    "Proxy at a mount other than /".into()
                ),
            }]
        );
    }

    #[test]
    fn build_web_serve_state_refuses_invalid_redirect() {
        let refused = |to: &str, status: u16| {
            let mut cfg = ServeConfig::default();
            cfg.tcp.insert(
                "443".into(),
                TcpPortHandler {
                    https: true,
                    redirect: Some(RedirectSpec {
                        to: to.into(),
                        status,
                    }),
                    ..Default::default()
                },
            );
            let built = build_web_serve_state(&cfg, "host.example.ts.net");
            assert!(
                built.state.tcp.is_empty(),
                "nothing is handed over: {built:?}"
            );
            built.refused
        };
        let invalid = |msg: &str| {
            vec![RefusedPort {
                port: 443,
                error: tailscale::ServeConfigError::Invalid(msg.into()),
            }]
        };
        // An out-of-range status on a legacy redirect.
        assert_eq!(
            refused("https://x.ts.net/", 200),
            invalid("serve redirect status 200 is not in 300..=399")
        );
        // CR/LF (response splitting) and any other control character in the target.
        for to in [
            "https://x.ts.net/\r\nSet-Cookie: evil",
            "https://x.ts.net/\0",
        ] {
            assert_eq!(
                refused(to, 302),
                invalid("serve redirect target must not contain control characters")
            );
        }
        // The same rule holds for a Go-shaped `Web` redirect.
        let go_json = "{\"TCP\":{\"443\":{\"HTTPS\":true}},\"Web\":{\"h.ts.net:443\":{\"Handlers\":{\"/\":{\"Redirect\":\"https://x/\\u0000\"}}}}}";
        let cfg: ServeConfig = serde_json::from_str(go_json).unwrap();
        assert_eq!(
            build_web_serve_state(&cfg, "h.ts.net").refused,
            invalid("serve redirect target must not contain control characters")
        );
    }

    #[test]
    fn set_funnel_on_off_and_ports() {
        let mut cfg = ServeConfig::default();
        // On: inserts the host:port -> true entry.
        set_funnel(&mut cfg, "host.example.ts.net", 443, true);
        set_funnel(&mut cfg, "host.example.ts.net.", 8443, true); // trailing dot stripped
        assert_eq!(cfg.allow_funnel.get("host.example.ts.net:443"), Some(&true));
        assert_eq!(
            cfg.allow_funnel.get("host.example.ts.net:8443"),
            Some(&true)
        );
        assert_eq!(
            funnel_ports(&cfg),
            std::collections::BTreeSet::from([443, 8443])
        );

        // Off: removes the key (never lingers as false).
        set_funnel(&mut cfg, "host.example.ts.net", 443, false);
        assert!(!cfg.allow_funnel.contains_key("host.example.ts.net:443"));
        assert_eq!(funnel_ports(&cfg), std::collections::BTreeSet::from([8443]));

        // Turning the last one off empties the map (so the wire omits AllowFunnel).
        set_funnel(&mut cfg, "host.example.ts.net", 8443, false);
        assert!(cfg.allow_funnel.is_empty());
        assert!(funnel_ports(&cfg).is_empty());
    }

    #[test]
    fn backend_loopback_classification() {
        // Loopback (no warning): loopback IPs + the name `localhost`, with/without port + brackets.
        assert!(!backend_is_nonloopback("127.0.0.1:8080"));
        assert!(!backend_is_nonloopback("127.0.0.1"));
        assert!(!backend_is_nonloopback("localhost:3000"));
        assert!(!backend_is_nonloopback("LOCALHOST"));
        assert!(!backend_is_nonloopback("[::1]:443"));
        assert!(!backend_is_nonloopback("::1"));
        // Non-loopback (warn): routable IPs, the metadata endpoint, a LAN host, a DNS name.
        assert!(backend_is_nonloopback("169.254.169.254:80"));
        assert!(backend_is_nonloopback("10.0.0.5:8080"));
        assert!(backend_is_nonloopback("192.168.1.10"));
        assert!(backend_is_nonloopback("[2001:db8::1]:443"));
        assert!(
            backend_is_nonloopback("internal.example.com:443"),
            "a non-localhost DNS name could resolve anywhere → treated as non-loopback"
        );
    }

    #[test]
    fn set_funnel_off_clears_a_stale_host_key_after_a_hostname_change() {
        // `off` must remove by :port suffix regardless of host. If the node's MagicDNS name changed
        // since funnel was enabled, the persisted key carries the OLD host; an `off` computed from the
        // NEW host must still clear it (else funnel_ports keeps arming the port — funnel stuck on).
        let mut cfg = ServeConfig::default();
        set_funnel(&mut cfg, "old-name.example.ts.net", 443, true);
        assert_eq!(funnel_ports(&cfg), std::collections::BTreeSet::from([443]));

        // The node was renamed; `funnel 443 off` now resolves the key from the NEW host.
        set_funnel(&mut cfg, "new-name.example.ts.net", 443, false);
        assert!(
            cfg.allow_funnel.is_empty(),
            "off by :port must clear the stale old-host key, not leave funnel armed"
        );
        assert!(funnel_ports(&cfg).is_empty());
    }

    #[test]
    fn funnel_host_ports_splits_key() {
        let mut cfg = ServeConfig::default();
        set_funnel(&mut cfg, "host.example.ts.net", 443, true);
        set_funnel(&mut cfg, "host.example.ts.net", 8443, true);
        let hps = funnel_host_ports(&cfg);
        assert_eq!(
            hps,
            vec![
                ("host.example.ts.net".to_string(), 443),
                ("host.example.ts.net".to_string(), 8443),
            ]
        );
    }

    #[test]
    fn allow_funnel_wire_matches_go_and_is_omitted_when_empty() {
        // Empty → omitted (existing wire unchanged).
        let mut cfg = ServeConfig::default();
        set_tcp_forward(&mut cfg, 8443, "127.0.0.1:5000".into());
        assert_eq!(
            serde_json::to_string(&cfg).unwrap(),
            r#"{"TCP":{"8443":{"TCPForward":"127.0.0.1:5000"}}}"#
        );
        // With funnel → AllowFunnel present, keyed by host:port (Go wire shape).
        let mut cfg = ServeConfig::default();
        set_funnel(&mut cfg, "host.example.ts.net", 443, true);
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(json, r#"{"AllowFunnel":{"host.example.ts.net:443":true}}"#);
        let back: ServeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn new_web_fields_round_trip_and_dont_disturb_existing_wire() {
        // The existing plain-forward wire is byte-identical (no new keys when the fields are unset).
        let mut cfg = ServeConfig::default();
        set_tcp_forward(&mut cfg, 8443, "127.0.0.1:5000".into());
        assert_eq!(
            serde_json::to_string(&cfg).unwrap(),
            r#"{"TCP":{"8443":{"TCPForward":"127.0.0.1:5000"}}}"#
        );

        // The new fields round-trip when set.
        let mut cfg = ServeConfig::default();
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                text: Some("hi".into()),
                ..Default::default()
            },
        );
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains(r#""Text":"hi""#), "{json}");
        let back: ServeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn plain_tcp_forward_stays_on_the_daemons_lane_and_yields_the_empty_state() {
        // A config with only a plain TCP forward hands the engine the empty config (Go's `{}`),
        // which is also how a previously armed web serve is cleared (REPLACE semantics).
        let mut cfg = ServeConfig::default();
        set_tcp_forward(&mut cfg, 2222, "127.0.0.1:22".into());
        let built = build_web_serve_state(&cfg, "host.example.ts.net");
        assert_eq!(built, EngineServe::default());
        assert_eq!(built.refusal_message(), None);
        assert_eq!(serde_json::to_string(&built.state).unwrap(), "{}");

        // An entirely empty config likewise.
        let built = build_web_serve_state(&ServeConfig::default(), "host.example.ts.net");
        assert_eq!(built, EngineServe::default());
    }

    #[test]
    fn funnel_stays_off_in_the_engine_state() {
        // Funnel is armed by the funnel lane through `listen_funnel`. The engine refuses an
        // AllowFunnel entry that is on, so the stored config the engine gets always has it off,
        // and a funnel-enabled web port is handed over as a plain HTTPS port.
        let mut cfg = ServeConfig::default();
        go_web(&mut cfg, "host.ts.net", 443, true, "127.0.0.1:3000");
        set_funnel(&mut cfg, "host.ts.net", 443, true);
        assert_eq!(
            funnel_ports(&cfg).into_iter().collect::<Vec<_>>(),
            vec![443]
        );
        let built = build_web_serve_state(&cfg, "host.ts.net");
        assert!(built.refused.is_empty(), "{:?}", built.refused);
        assert!(built.state.allow_funnel.is_empty());
        assert!(built.state.tcp[&443].https);
        assert!(built.state.serve_plan().is_ok());
    }

    /// Build a web port handler in the Go shape: the `TCP[port]` flag plus a `Web[host:port]` body.
    fn go_web(cfg: &mut ServeConfig, host: &str, port: u16, tls: bool, proxy: &str) {
        cfg.tcp.insert(
            port.to_string(),
            TcpPortHandler {
                https: tls,
                http: !tls,
                ..Default::default()
            },
        );
        cfg.web.insert(
            format!("{host}:{port}"),
            WebServerConfig {
                handlers: std::collections::BTreeMap::from([(
                    "/".to_string(),
                    HttpHandler {
                        proxy: proxy.to_string(),
                        ..Default::default()
                    },
                )]),
            },
        );
    }

    #[test]
    fn serve_type_classifies_every_handler_shape() {
        // Go's four arms, in Go's order (`serveTypeFromPortHandler`).
        assert_eq!(
            serve_type(&TcpPortHandler {
                https: true,
                ..Default::default()
            }),
            ServeType::Https
        );
        assert_eq!(
            serve_type(&TcpPortHandler {
                http: true,
                ..Default::default()
            }),
            ServeType::Http
        );
        assert_eq!(
            serve_type(&TcpPortHandler {
                tcp_forward: "127.0.0.1:8000".into(),
                ..Default::default()
            }),
            ServeType::Tcp
        );
        assert_eq!(
            serve_type(&TcpPortHandler {
                terminate_tls: "host.example.ts.net".into(),
                tcp_forward: "127.0.0.1:8000".into(),
                ..Default::default()
            }),
            ServeType::TlsTerminatedTcp,
            "TerminateTLS outranks TCPForward, as in Go"
        );
        // A handler naming no servable shape is Go's `-1`.
        assert_eq!(serve_type(&TcpPortHandler::default()), ServeType::Unknown);

        // Flag before backend: this fork's legacy web shape keeps the proxy backend in TCPForward
        // alongside the HTTPS flag, and it must still classify `https`, never `tcp`.
        assert_eq!(
            serve_type(&TcpPortHandler {
                https: true,
                tcp_forward: "127.0.0.1:3000".into(),
                ..Default::default()
            }),
            ServeType::Https
        );

        // The one arm that is this fork's and not Go's: a legacy web BODY with no HTTPS/HTTP flag.
        // `build_web_serve_state` serves these on the TLS-terminating engine lane, so they are https.
        for h in [
            TcpPortHandler {
                text: Some("hi".into()),
                ..Default::default()
            },
            TcpPortHandler {
                redirect: Some(RedirectSpec {
                    to: "https://example.com/".into(),
                    status: 302,
                }),
                ..Default::default()
            },
            TcpPortHandler {
                mounts: std::collections::BTreeMap::from([(
                    "/".to_string(),
                    WebMount::Text { body: "hi".into() },
                )]),
                ..Default::default()
            },
        ] {
            assert!(
                is_web_serve(&h),
                "fixture must be a web serve for the classification to be the honest one: {h:?}"
            );
            assert_eq!(serve_type(&h), ServeType::Https, "for {h:?}");
        }

        // …but a bare TCPForward wins over a legacy body, matching the LANE dispatch, which tests
        // `is_plain_tcp_forward` first.
        let both = TcpPortHandler {
            tcp_forward: "127.0.0.1:8000".into(),
            text: Some("hi".into()),
            ..Default::default()
        };
        assert!(is_plain_tcp_forward(&both));
        assert_eq!(serve_type(&both), ServeType::Tcp);
    }

    #[test]
    fn serve_type_renders_gos_names() {
        // These strings are interpolated into an operator-facing message, so they are Go's
        // `serveType.String()` verbatim — including the unnamed `-1` case.
        assert_eq!(ServeType::Https.to_string(), "https");
        assert_eq!(ServeType::Http.to_string(), "http");
        assert_eq!(ServeType::Tcp.to_string(), "tcp");
        assert_eq!(
            ServeType::TlsTerminatedTcp.to_string(),
            "tls-terminated-tcp"
        );
        assert_eq!(ServeType::Unknown.to_string(), "unknownServeType");
    }

    #[test]
    fn second_serve_on_a_busy_port_is_refused_with_gos_message() {
        // THE gap: port 443 terminates HTTPS; `tnet serve --tcp 443 tcp://localhost:8000` read the
        // config, inserted over the port and sent it back. It used to succeed and the HTTPS serve
        // was gone with no diagnostic.
        let mut existing = ServeConfig::default();
        go_web(
            &mut existing,
            "host.example.ts.net",
            443,
            true,
            "127.0.0.1:3000",
        );

        let mut incoming = existing.clone();
        incoming.tcp.insert(
            "443".into(),
            TcpPortHandler {
                tcp_forward: "127.0.0.1:8000".into(),
                ..Default::default()
            },
        );
        incoming.web.retain(|k, _| !k.ends_with(":443"));

        assert_eq!(
            validate_serve_config_update(&existing, &incoming),
            Err(r#"want to serve "tcp", but port 443 is already serving "https""#.to_string()),
            "Go's message verbatim — it is what the operator is shown"
        );
    }

    #[test]
    fn an_alias_spelling_of_a_busy_port_is_refused_like_the_port_itself() {
        // `ServeConfig::tcp` is keyed by string, so `"443"` and `"0443"` are two map keys — but
        // every reader of the map parses the key, so both arm tailnet port 443. Matching raw keys
        // let the second one straight through: the https serve stayed under `"443"` while `"0443"`
        // armed a plain TCP forward on the same port, which is the silent replacement this check
        // exists to refuse, reached by spelling the port differently.
        let tcp = TcpPortHandler {
            tcp_forward: "127.0.0.1:8000".into(),
            ..Default::default()
        };

        let mut existing = ServeConfig::default();
        go_web(
            &mut existing,
            "host.example.ts.net",
            443,
            true,
            "127.0.0.1:3000",
        );

        // A read-modify-write that keeps the live `"443"` entry and adds the alias beside it.
        let mut incoming = existing.clone();
        incoming.tcp.insert("0443".into(), tcp.clone());
        assert_eq!(
            validate_serve_config_update(&existing, &incoming),
            Err(r#"want to serve "tcp", but port 443 is already serving "https""#.to_string()),
            "an alias key names the same tailnet port, and the message names the parsed port"
        );

        // The same with the alias alone (the existing entry dropped in the same write), and with
        // the `+` sign `u16::from_str` also accepts.
        let mut incoming = ServeConfig::default();
        incoming.tcp.insert("0443".into(), tcp.clone());
        assert_eq!(
            validate_serve_config_update(&existing, &incoming),
            Err(r#"want to serve "tcp", but port 443 is already serving "https""#.to_string())
        );
        let mut incoming = ServeConfig::default();
        incoming.tcp.insert("+443".into(), tcp.clone());
        assert_eq!(
            validate_serve_config_update(&existing, &incoming),
            Err(r#"want to serve "tcp", but port 443 is already serving "https""#.to_string())
        );

        // …and the other direction: the alias is what is in force, the canonical spelling arrives.
        let mut existing = ServeConfig::default();
        existing.tcp.insert(
            "08443".into(),
            TcpPortHandler {
                terminate_tls: "host.example.ts.net".into(),
                tcp_forward: "127.0.0.1:3000".into(),
                ..Default::default()
            },
        );
        let mut incoming = ServeConfig::default();
        incoming.tcp.insert("8443".into(), tcp.clone());
        assert_eq!(
            validate_serve_config_update(&existing, &incoming),
            Err(
                r#"want to serve "tcp", but port 8443 is already serving "tls-terminated-tcp""#
                    .to_string()
            )
        );

        // Matching by parsed port only ADDS refusals for the same serve type: re-targeting port
        // 8443's forward under an alias key is still a re-target, not a conflict.
        let mut existing = ServeConfig::default();
        set_tcp_forward(&mut existing, 8443, "127.0.0.1:22".into());
        let mut incoming = ServeConfig::default();
        incoming.tcp.insert("08443".into(), tcp.clone());
        assert_eq!(validate_serve_config_update(&existing, &incoming), Ok(()));

        // A non-numeric key is still not a port: no parse, no live serve to protect, no refusal —
        // and it never collides with a numeric one.
        let mut existing = ServeConfig::default();
        existing.tcp.insert(
            "https".into(),
            TcpPortHandler {
                https: true,
                ..Default::default()
            },
        );
        let mut incoming = ServeConfig::default();
        incoming.tcp.insert("443".into(), tcp);
        assert_eq!(validate_serve_config_update(&existing, &incoming), Ok(()));
    }

    #[test]
    fn every_serve_type_change_on_a_busy_port_is_refused() {
        let shapes = [
            (
                ServeType::Https,
                TcpPortHandler {
                    https: true,
                    ..Default::default()
                },
            ),
            (
                ServeType::Http,
                TcpPortHandler {
                    http: true,
                    ..Default::default()
                },
            ),
            (
                ServeType::Tcp,
                TcpPortHandler {
                    tcp_forward: "127.0.0.1:8000".into(),
                    ..Default::default()
                },
            ),
            (
                ServeType::TlsTerminatedTcp,
                TcpPortHandler {
                    terminate_tls: "host.example.ts.net".into(),
                    tcp_forward: "127.0.0.1:8000".into(),
                    ..Default::default()
                },
            ),
        ];
        for (old_type, old_h) in &shapes {
            for (new_type, new_h) in &shapes {
                let mut existing = ServeConfig::default();
                existing.tcp.insert("8443".into(), old_h.clone());
                let mut incoming = ServeConfig::default();
                incoming.tcp.insert("8443".into(), new_h.clone());
                let got = validate_serve_config_update(&existing, &incoming);
                if old_type == new_type {
                    assert_eq!(
                        got,
                        Ok(()),
                        "re-serving {old_type} over {old_type} is a re-target, not a conflict"
                    );
                } else {
                    assert_eq!(
                        got,
                        Err(format!(
                            "want to serve \"{new_type}\", but port 8443 is already serving \
                             \"{old_type}\""
                        ))
                    );
                }
            }
        }
    }

    #[test]
    fn same_serve_type_may_be_re_targeted_and_free_ports_are_untouched() {
        let mut existing = ServeConfig::default();
        go_web(
            &mut existing,
            "host.example.ts.net",
            443,
            true,
            "127.0.0.1:3000",
        );
        set_tcp_forward(&mut existing, 2222, "127.0.0.1:22".into());

        // Re-point the https serve at another backend: same serve type → allowed.
        let mut incoming = ServeConfig::default();
        go_web(
            &mut incoming,
            "host.example.ts.net",
            443,
            true,
            "127.0.0.1:9000",
        );
        set_tcp_forward(&mut incoming, 2222, "127.0.0.1:22".into());
        // …and add a serve on a port nothing holds.
        set_tcp_forward(&mut incoming, 8443, "127.0.0.1:5000".into());
        assert_eq!(validate_serve_config_update(&existing, &incoming), Ok(()));

        // Taking a port down (`serve --https=443 off`) is never a conflict: the rule only looks at
        // ports the INCOMING config serves.
        let mut down = existing.clone();
        down.tcp.remove("443");
        down.web.retain(|k, _| !k.ends_with(":443"));
        assert_eq!(validate_serve_config_update(&existing, &down), Ok(()));

        // `serve reset` sends an empty config — Go's `if !incoming.Valid() { return nil }`.
        assert_eq!(
            validate_serve_config_update(&existing, &ServeConfig::default()),
            Ok(())
        );
        // A first serve with nothing in force — Go's `if !existing.Valid() { return nil }`.
        assert_eq!(
            validate_serve_config_update(&ServeConfig::default(), &existing),
            Ok(())
        );
    }

    #[test]
    fn shapeless_handlers_and_unservable_port_keys_do_not_conflict() {
        // Two handlers that name no serve shape are both Go's `-1`, which compares equal: no refusal.
        let mut existing = ServeConfig::default();
        existing.tcp.insert(
            "443".into(),
            TcpPortHandler {
                proxy_protocol: 2,
                ..Default::default()
            },
        );
        let mut incoming = ServeConfig::default();
        incoming.tcp.insert("443".into(), TcpPortHandler::default());
        assert_eq!(validate_serve_config_update(&existing, &incoming), Ok(()));

        // Going from shapeless to a real serve IS a change of kind, and Go names the unknown side.
        let mut incoming = ServeConfig::default();
        set_tcp_forward(&mut incoming, 443, "127.0.0.1:8000".into());
        assert_eq!(
            validate_serve_config_update(&existing, &incoming),
            Err(
                r#"want to serve "tcp", but port 443 is already serving "unknownServeType""#
                    .to_string()
            )
        );

        // A key that is not a tailnet port is never served (the LANE dispatch and
        // `build_web_serve_state` both skip it), so there is no live serve to protect.
        let mut existing = ServeConfig::default();
        existing.tcp.insert(
            "not-a-port".into(),
            TcpPortHandler {
                https: true,
                ..Default::default()
            },
        );
        let mut incoming = ServeConfig::default();
        incoming.tcp.insert(
            "not-a-port".into(),
            TcpPortHandler {
                tcp_forward: "127.0.0.1:8000".into(),
                ..Default::default()
            },
        );
        assert_eq!(validate_serve_config_update(&existing, &incoming), Ok(()));
    }

    #[tokio::test]
    async fn config_round_trips_on_disk_per_profile() {
        let dir = std::env::temp_dir().join(format!("tailnetd-serve-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        assert!(load(&dir, DEFAULT_PROFILE_ID).await.tcp.is_empty());

        let mut sc = ServeConfig::default();
        set_tcp_forward(&mut sc, 8443, "127.0.0.1:5000".into());
        save(&sc, &dir, DEFAULT_PROFILE_ID).await.unwrap();
        assert!(
            tokio::fs::try_exists(dir.join("serve-config.json"))
                .await
                .unwrap()
        );
        assert_eq!(load(&dir, DEFAULT_PROFILE_ID).await, sc);

        // Named profile nests under profiles/<id>/.
        save(&sc, &dir, "work").await.unwrap();
        assert!(
            tokio::fs::try_exists(dir.join("profiles").join("work").join("serve-config.json"))
                .await
                .unwrap()
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
