//! `serve` configuration persistence + logic — the Rust analogue of Go's `ipn.ServeConfig`
//! (`ipn/serve.go`), scoped to the **TCP-forward** subset this daemon can serve with a raw tailnet
//! listener.
//!
//! The wire types ([`ServeConfig`]/[`TcpPortHandler`]) live in [`crate::localapi`] (the DTO home,
//! like [`crate::localapi::PrefsView`]); this module re-exports them and supplies the persistence +
//! served/not-served logic as free functions. Persisted per-profile next to `prefs.json` /
//! `node.key.json` (see [`super::profile`]).
//!
//! ## What is (and isn't) served — two lanes
//!
//! - **Plain `TCPForward`** (`tcp_forward` set, no `HTTPS`/`HTTP`/`TerminateTLS`) is served by the
//!   daemon's own raw accept→dial→splice loop (a [`Device::tcp_listen`](tailscale::Device::tcp_listen)
//!   per port; see the server's serve task). No TLS, no cert — so it works on any tailnet.
//! - **`HTTPS`/`HTTP` web** entries are served by **delegating to the engine's native serve stack**
//!   ([`Device::set_serve_config`](tailscale::Device::set_serve_config) + `ServeState`): the engine
//!   terminates TLS for the node's MagicDNS name and reverse-proxies each decrypted stream to the
//!   configured backend. [`build_web_serve_state`] translates the web subset of our DTO into the
//!   engine's [`ServeState`](tailscale::ServeState). This lane is **fail-closed**: a TLS port never
//!   downgrades to plaintext, and without an issuable cert (the engine's `acme` feature off, or a
//!   control plane that 501s on `set-dns`) the engine returns a cert error and nothing binds.
//!
//! `TerminateTLS` (raw-TCP-after-TLS-termination) has no engine `ServeTarget` analogue at this pin,
//! so it remains persisted-but-not-served.

use std::path::{Path, PathBuf};

pub use crate::localapi::{RedirectSpec, ServeConfig, TcpPortHandler, WebMount};

/// Whether a handler is a web entry served via engine delegation (the [`build_web_serve_state`]
/// lane), as opposed to the plain-TCP-forward lane ([`is_plain_tcp_forward`]) or a not-served
/// `TerminateTLS` entry. A handler is web if it carries ANY web aspect: an `https`/`http` proxy (a
/// non-empty `tcp_forward`), a fixed `text` body, a `redirect`, or path `mounts`.
pub fn is_web_serve(h: &TcpPortHandler) -> bool {
    ((h.https || h.http) && !h.tcp_forward.is_empty())
        || h.text.is_some()
        || h.redirect.is_some()
        || !h.mounts.is_empty()
}

/// Translate one [`WebMount`] into the engine's nested [`ServeTarget`](tailscale::ServeTarget).
/// Errors (as a static reason) on the same conditions the engine's `validate_target` rejects, so an
/// invalid mount is caught daemon-side before the engine call rather than failing the whole arm.
fn mount_to_target(m: &WebMount) -> Result<tailscale::ServeTarget, &'static str> {
    match m {
        WebMount::Proxy { to } => {
            if to.trim().is_empty() {
                return Err("serve proxy target must not be empty");
            }
            Ok(tailscale::ServeTarget::Proxy { to: to.clone() })
        }
        WebMount::Text { body } => Ok(tailscale::ServeTarget::Text { body: body.clone() }),
        WebMount::Redirect { to, status } => {
            validate_redirect(to, *status)?;
            Ok(tailscale::ServeTarget::Redirect {
                to: to.clone(),
                status: *status,
            })
        }
    }
}

/// Fail-closed redirect validation, matching the engine's `validate_target`: non-empty `to`, no CR/LF
/// (response-splitting guard), status in `300..=399`.
fn validate_redirect(to: &str, status: u16) -> Result<(), &'static str> {
    if to.trim().is_empty() {
        return Err("serve redirect target must not be empty");
    }
    if to.contains(['\r', '\n']) {
        return Err("serve redirect target must not contain CR/LF");
    }
    if !(300..=399).contains(&status) {
        return Err("serve redirect status must be in 300..=399");
    }
    Ok(())
}

/// Translate one web [`TcpPortHandler`] into the engine [`ServeTarget`](tailscale::ServeTarget) for
/// its port. Precedence (a port serves exactly one thing): non-empty `mounts` → `Path` (or, if the
/// only mount is `/`, the bare target it holds); else `text` → `Text`; else `redirect` → `Redirect`;
/// else the `tcp_forward` proxy backend → `Proxy`. Returns `Err(reason)` if the handler is web-shaped
/// but produces nothing valid (so the caller can skip + log it rather than emit an invalid state).
fn handler_to_target(h: &TcpPortHandler) -> Result<tailscale::ServeTarget, &'static str> {
    if !h.mounts.is_empty() {
        // A lone "/" mount is just the bare handler it holds (avoids a needless one-level Path mux).
        if h.mounts.len() == 1
            && let Some(root) = h.mounts.get("/")
        {
            return mount_to_target(root);
        }
        let mut handlers = std::collections::BTreeMap::new();
        for (mount, m) in &h.mounts {
            handlers.insert(mount.clone(), mount_to_target(m)?);
        }
        return Ok(tailscale::ServeTarget::Path { handlers });
    }
    if let Some(body) = &h.text {
        return Ok(tailscale::ServeTarget::Text { body: body.clone() });
    }
    if let Some(r) = &h.redirect {
        validate_redirect(&r.to, r.status)?;
        return Ok(tailscale::ServeTarget::Redirect {
            to: r.to.clone(),
            status: r.status,
        });
    }
    if (h.https || h.http) && !h.tcp_forward.is_empty() {
        return Ok(tailscale::ServeTarget::Proxy {
            to: h.tcp_forward.clone(),
        });
    }
    Err("web handler has no servable target")
}

/// Translate the **web** subset of a [`ServeConfig`] into the engine's
/// [`ServeState`](tailscale::ServeState) for [`Device::set_serve_config`](tailscale::Device::set_serve_config).
///
/// Each [`is_web_serve`] entry becomes one [`ServeTarget`](tailscale::ServeTarget) on its port via
/// [`handler_to_target`]: a `text` body → `Text`, a `redirect` → `Redirect`, path `mounts` → `Path`
/// (or the bare target for a lone `/` mount), and an `https`/`http` proxy → `Proxy` (the existing
/// behavior; `HTTP` and `HTTPS` both map to `Proxy` — the engine has no distinct plaintext-web variant
/// at this pin, every web `ServeTarget` rides a TLS-terminating port). Plain `tcp_forward` entries (no
/// web aspect) and `terminate_tls` entries are **excluded** — the former stays on the daemon's
/// hand-rolled accept loop, the latter is not served. A web-shaped entry that produces no valid target
/// (or an invalid mount/redirect) is skipped + logged rather than poisoning the whole state.
///
/// `name` is the node's MagicDNS name (e.g. `host.tailnet.ts.net`, no trailing dot) — the cert the
/// engine's TLS-terminating ports share. It is set only when at least one web port is produced; an
/// input with no web entries yields [`ServeState::default()`](tailscale::ServeState) (empty name + no
/// ports), which is a valid "serve nothing" config (and, via `set_serve_config`'s REPLACE semantics,
/// the way to clear a previously-armed web serve). The returned state passes the engine's
/// `ServeState::validate()` for valid inputs.
pub fn build_web_serve_state(cfg: &ServeConfig, name: &str) -> tailscale::ServeState {
    let mut ports = std::collections::BTreeMap::new();
    for (port_str, h) in &cfg.tcp {
        if !is_web_serve(h) {
            continue;
        }
        let Ok(port) = port_str.parse::<u16>() else {
            // A non-numeric key can't be a tailnet port; skip (the persistence layer keeps it).
            continue;
        };
        match handler_to_target(h) {
            Ok(target) => {
                ports.insert(port, target);
            }
            Err(reason) => {
                tracing::warn!(port, reason, "serve: skipping invalid web handler");
            }
        }
    }
    let name = if ports.is_empty() {
        // No TLS-terminating port → no cert needed → leave the name empty (and keep ports empty so
        // this is the canonical "serve nothing / clear" state).
        String::new()
    } else {
        // The engine's TLS ports share this single MagicDNS-name cert. Strip any trailing dot (Go's
        // ServeConfig names carry none; the engine's `is_tailnet_name` tolerates it but we normalize).
        name.trim_end_matches('.').to_string()
    };
    tailscale::ServeState { name, ports }
}

/// Whether a handler is a plain TCP forward this daemon can actually serve: a non-empty
/// `tcp_forward`, no HTTP(S) web handling, and no TLS termination. The serve accept loop runs only
/// for handlers where this is true; everything else is persisted-but-not-served.
pub fn is_plain_tcp_forward(h: &TcpPortHandler) -> bool {
    !h.tcp_forward.is_empty() && !h.https && !h.http && h.terminate_tls.is_empty()
}

/// Set (or replace) the TCP forward for `port` → `forward_to` (Go `SetTCPForwarding`). `forward_to`
/// is stored verbatim as the dial target (`IP:port`). The map key is the port rendered as a string
/// (see [`ServeConfig::tcp`](crate::localapi::ServeConfig::tcp) for why the key is a string).
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
/// `host:port` → `true` entry; on `off`, removes the key (so an off port never lingers on the wire,
/// matching Go's delete-and-nil-when-empty semantics — our `skip_serializing_if` omits an empty map).
pub fn set_funnel(cfg: &mut ServeConfig, host: &str, port: u16, on: bool) {
    let hp = funnel_host_port(host, port);
    if on {
        cfg.allow_funnel.insert(hp, true);
    } else {
        cfg.allow_funnel.remove(&hp);
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
        Err(_) => ServeConfig::default(),
    }
}

/// Persist the serve config for the given profile.
pub async fn save(cfg: &ServeConfig, state_dir: &Path, profile_id: &str) -> std::io::Result<()> {
    let path = config_path(state_dir, profile_id);
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir).await?;
    }
    let bytes = serde_json::to_vec_pretty(cfg).expect("serve config serialize");
    tokio::fs::write(&path, bytes).await
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

    #[test]
    fn build_web_serve_state_maps_only_web_entries_to_proxy() {
        let mut cfg = ServeConfig::default();
        // A plain TCP forward (hand-rolled lane) — must be EXCLUDED from the engine state.
        set_tcp_forward(&mut cfg, 2222, "127.0.0.1:22".into());
        // An HTTPS web entry — must become a Proxy port.
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                tcp_forward: "127.0.0.1:3000".into(),
                ..Default::default()
            },
        );
        let state = build_web_serve_state(&cfg, "host.example.ts.net.");
        // Only the web port is present; the plain forward is excluded.
        assert_eq!(state.ports.len(), 1);
        assert_eq!(
            state.ports.get(&443),
            Some(&tailscale::ServeTarget::Proxy {
                to: "127.0.0.1:3000".into()
            })
        );
        assert!(!state.ports.contains_key(&2222));
        // Name is set (trailing dot stripped) because a TLS-terminating port exists.
        assert_eq!(state.name, "host.example.ts.net");
        // The produced state is valid per the engine's fail-closed checks.
        assert!(state.validate().is_ok());
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
    fn build_web_serve_state_maps_text_and_redirect() {
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
        let state = build_web_serve_state(&cfg, "host.example.ts.net");
        assert_eq!(
            state.ports.get(&443),
            Some(&tailscale::ServeTarget::Text {
                body: "hello world".into()
            })
        );
        assert_eq!(
            state.ports.get(&8443),
            Some(&tailscale::ServeTarget::Redirect {
                to: "https://dest.ts.net/".into(),
                status: 301
            })
        );
        assert!(state.validate().is_ok());
    }

    #[test]
    fn build_web_serve_state_lone_root_mount_is_bare_target() {
        // A single "/" mount collapses to the bare target (no needless Path mux).
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
        let state = build_web_serve_state(&cfg, "host.example.ts.net");
        assert_eq!(
            state.ports.get(&443),
            Some(&tailscale::ServeTarget::Proxy {
                to: "127.0.0.1:3000".into()
            })
        );
        assert!(state.validate().is_ok());
    }

    #[test]
    fn build_web_serve_state_multi_mount_is_path_mux() {
        let mut mounts = std::collections::BTreeMap::new();
        mounts.insert(
            "/".to_string(),
            WebMount::Text {
                body: "root".into(),
            },
        );
        mounts.insert(
            "/api".to_string(),
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
        let state = build_web_serve_state(&cfg, "host.example.ts.net");
        match state.ports.get(&443) {
            Some(tailscale::ServeTarget::Path { handlers }) => {
                assert_eq!(handlers.len(), 2);
                assert_eq!(
                    handlers.get("/api"),
                    Some(&tailscale::ServeTarget::Proxy {
                        to: "127.0.0.1:3000".into()
                    })
                );
            }
            other => panic!("expected Path mux, got {other:?}"),
        }
        assert!(state.validate().is_ok());
    }

    #[test]
    fn build_web_serve_state_skips_invalid_redirect() {
        // A redirect with an out-of-range status / CRLF is fail-closed: skipped, not emitted.
        let mut cfg = ServeConfig::default();
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                redirect: Some(RedirectSpec {
                    to: "https://x.ts.net/".into(),
                    status: 200, // out of 300..=399
                }),
                ..Default::default()
            },
        );
        let state = build_web_serve_state(&cfg, "host.example.ts.net");
        assert!(state.ports.is_empty(), "invalid redirect must be skipped");

        // CRLF in the target is rejected too.
        let mut cfg = ServeConfig::default();
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                redirect: Some(RedirectSpec {
                    to: "https://x.ts.net/\r\nSet-Cookie: evil".into(),
                    status: 302,
                }),
                ..Default::default()
            },
        );
        let state = build_web_serve_state(&cfg, "host.example.ts.net");
        assert!(state.ports.is_empty(), "CRLF redirect must be skipped");
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
    fn build_web_serve_state_empty_without_web_entries() {
        // A config with only a plain TCP forward yields the canonical empty "serve nothing" state
        // (empty name + no ports), which is also how a web serve is cleared via REPLACE semantics.
        let mut cfg = ServeConfig::default();
        set_tcp_forward(&mut cfg, 2222, "127.0.0.1:22".into());
        let state = build_web_serve_state(&cfg, "host.example.ts.net");
        assert!(state.ports.is_empty());
        assert!(state.name.is_empty());
        assert_eq!(state, tailscale::ServeState::default());
        assert!(state.validate().is_ok());

        // An entirely empty config likewise.
        let state = build_web_serve_state(&ServeConfig::default(), "host.example.ts.net");
        assert_eq!(state, tailscale::ServeState::default());
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
