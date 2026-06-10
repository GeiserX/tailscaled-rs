//! `serve` configuration persistence + logic — the Rust analogue of Go's `ipn.ServeConfig`
//! (`ipn/serve.go`), scoped to the **TCP-forward** subset this daemon can serve with a raw tailnet
//! listener.
//!
//! The wire types ([`ServeConfig`]/[`TcpPortHandler`]) live in [`crate::localapi`] (the DTO home,
//! like [`crate::localapi::PrefsView`]); this module re-exports them and supplies the persistence +
//! served/not-served logic as free functions. Persisted per-profile next to `prefs.json` /
//! `node.key.json` (see [`super::profile`]).
//!
//! ## What is (and isn't) served
//!
//! Only `TCPForward` entries with no `HTTPS`/`HTTP`/`TerminateTLS` are actually served (a raw
//! accept→dial→splice loop; see the server's serve task). `HTTPS`/`HTTP` need an HTTP reverse-proxy
//! stack and `TerminateTLS` needs an ACME-provisioned TLS server — neither exists on the engine
//! facade — so those entries are **persisted faithfully but not served** (recognized + reported as
//! "not served by this build"), leaving a clean seam for a future HTTP/TLS lane.

use std::path::{Path, PathBuf};

pub use crate::localapi::{ServeConfig, TcpPortHandler};

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
