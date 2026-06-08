//! Persisted daemon intent — the Rust analogue of Tailscale's `ipn.Prefs`.
//!
//! This is the mutable, on-disk "what the node is trying to do" that the [`crate::ipn`] state
//! machine reconciles against what the control plane actually reports. The engine takes an
//! immutable `tailscale::Config` at construction; this struct is the *reconfigurable* layer above
//! it, rebuilt into a fresh `Config` each time the node is brought up.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The node's persisted preferences.
///
/// Container-level `#[serde(default)]`: any field missing from an on-disk `prefs.json` falls back
/// to [`Prefs::default`], so adding fields in future releases stays backward-compatible with older
/// files (and forward-compatible — an old daemon ignores unknown fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Whether the node should be connected — the spine of `up` vs `down`.
    pub want_running: bool,
    /// Whether the user explicitly logged out (suppresses auto-start on daemon launch).
    pub logged_out: bool,
    /// Control server URL, or `None` to use the engine/`TS_CONTROL_URL` default.
    pub control_url: Option<String>,
    /// Requested hostname, or `None` to use the OS hostname.
    pub hostname: Option<String>,
    /// Register as an ephemeral node (garbage-collected by control shortly after disconnect).
    pub ephemeral: bool,
    /// Accept (and route traffic to) subnet routes advertised by peers.
    pub accept_routes: bool,
    /// Use a real kernel TUN interface for the node's data path instead of the userspace netstack.
    ///
    /// `false` (default) = the engine's in-process smoltcp netstack: unprivileged, app reaches the
    /// tailnet via the LocalAPI/loopback. `true` = `TransportMode::Tun`, giving the host OS
    /// networking stack direct tailnet access (closer to real `tailscaled`) — but it needs root /
    /// `CAP_NET_ADMIN`, a TUN-capable platform, AND a daemon built with the `tun` cargo feature. If
    /// `true` without that feature, the daemon fails loudly at `up` rather than silently falling back.
    pub tun_enabled: bool,
    /// Desired TUN interface name (e.g. `tailscale0`); `None` lets the OS pick (`utunN` on macOS).
    /// Ignored unless [`tun_enabled`](Prefs::tun_enabled) is `true`.
    pub tun_name: Option<String>,
    /// TUN interface MTU; `None` uses the transport default. Tailscale's overlay MTU is 1280.
    /// Ignored unless [`tun_enabled`](Prefs::tun_enabled) is `true`.
    pub tun_mtu: Option<u16>,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            want_running: false,
            logged_out: false,
            control_url: None,
            hostname: None,
            ephemeral: true,
            accept_routes: false,
            tun_enabled: false,
            tun_name: None,
            tun_mtu: None,
        }
    }
}

impl Prefs {
    /// Load prefs from `path`. A missing file yields [`Prefs::default`]; a malformed file is
    /// treated as default rather than failing the daemon (the node simply starts unconfigured).
    pub async fn load(path: &Path) -> std::io::Result<Self> {
        match tokio::fs::read(path).await {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).unwrap_or_default()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Atomically-enough persist prefs to `path`, creating parent directories as needed.
    pub async fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        let bytes = serde_json::to_vec_pretty(self).expect("prefs serialize");
        tokio::fs::write(path, bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_down_and_not_logged_out() {
        let p = Prefs::default();
        assert!(!p.want_running, "a fresh node must not auto-connect");
        assert!(!p.logged_out);
        assert!(
            p.ephemeral,
            "ephemeral is the safe default for short-lived nodes"
        );
    }

    #[tokio::test]
    async fn missing_file_yields_default() {
        let dir =
            std::env::temp_dir().join(format!("tailnetd-prefs-missing-{}", std::process::id()));
        let path = dir.join("prefs.json");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let loaded = Prefs::load(&path).await.expect("load missing");
        assert!(!loaded.want_running);
    }

    #[tokio::test]
    async fn save_then_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("tailnetd-prefs-rt-{}", std::process::id()));
        let path = dir.join("prefs.json");
        let _ = tokio::fs::remove_dir_all(&dir).await;

        let p = Prefs {
            want_running: true,
            hostname: Some("node-a".to_string()),
            accept_routes: true,
            ..Prefs::default()
        };
        p.save(&path).await.expect("save");

        let loaded = Prefs::load(&path).await.expect("load");
        assert!(loaded.want_running);
        assert_eq!(loaded.hostname.as_deref(), Some("node-a"));
        assert!(loaded.accept_routes);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn partial_json_defaults_missing_fields() {
        // Container-level `#[serde(default)]` lets an old/partial prefs file deserialize with only
        // the fields it carries; everything else takes the `Default` value.
        let p: Prefs = serde_json::from_str(r#"{"want_running": true}"#).expect("partial parse");
        assert!(p.want_running, "the field that was present must win");
        let d = Prefs::default();
        assert_eq!(p.logged_out, d.logged_out);
        assert_eq!(p.control_url, d.control_url);
        assert_eq!(p.hostname, d.hostname);
        assert_eq!(p.ephemeral, d.ephemeral);
        assert_eq!(p.accept_routes, d.accept_routes);
    }

    #[tokio::test]
    async fn malformed_file_falls_back_to_default() {
        let dir = std::env::temp_dir().join(format!("tailnetd-prefs-bad-{}", std::process::id()));
        let path = dir.join("prefs.json");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(&path, b"not json at all").await.unwrap();

        let loaded = Prefs::load(&path).await.expect("load malformed");
        assert!(
            !loaded.want_running,
            "malformed prefs must not leave a node connected"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
