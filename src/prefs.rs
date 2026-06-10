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
    /// Route this node's traffic out through a peer exit node, selected by IP or MagicDNS name
    /// (the Go `--exit-node` flag). `None` = no exit node (direct egress). Stored as the raw
    /// selector string and parsed into the engine's `ExitNodeSelector` in `build_config`.
    ///
    /// DNS leak-safety: this is leak-free only in TUN mode, where the engine takes over the OS
    /// resolver and routes recursive DNS to the exit node's peerAPI DoH over the overlay (never a
    /// host socket). If the chosen exit node does NOT advertise DNS-proxy capability, recursive
    /// resolution falls back to this node's own configured upstreams — still sent over the overlay,
    /// not the host's real resolver, so it is not an OS-level leak (matches Go's behavior for a
    /// non-DNS-proxy exit). In netstack mode the OS resolver is untouched (see `build_config`).
    pub exit_node: Option<String>,
    /// Advertise this node as an exit node so peers can route their traffic out through it (Go
    /// `--advertise-exit-node`). Egress still requires control/admin approval (autoApprovers or a
    /// manual route approval) before peers may use it.
    ///
    /// Advertising is decoupled from actually forwarding: the engine only egresses a peer's traffic
    /// when `forward_exit_egress` is set (which the daemon does not set), so the default
    /// `DirectDialer` structurally refuses exit egress and this node's real IP cannot leak just from
    /// advertising. Forwarded-client DNS on the advertise side is an engine concern (tracked
    /// upstream as `tsr-c39`), not a daemon responsibility.
    pub advertise_exit_node: bool,
    /// Subnet routes (CIDRs) this node advertises to the tailnet so peers can reach the LANs behind
    /// it (Go `--advertise-routes`). Stored as raw CIDR strings, parsed into `ipnet::IpNet` in
    /// `build_config`. Empty = advertise nothing. v6 prefixes are dropped by the engine (v4-only).
    pub advertise_routes: Vec<String>,
    /// Run the Tailscale SSH server on this node (Go `--ssh`): accept tailnet SSH connections on
    /// `<tailnet-ip>:22`, authorized by the control-pushed SSH policy (fail-closed). Requires a
    /// daemon built with the `ssh` cargo feature AND running as root (to drop privileges to the
    /// policy-mapped local user); the daemon fails loudly otherwise. Default `false` — SSH is a
    /// remote-shell surface, opt-in at both build and runtime.
    pub ssh_enabled: bool,
    /// Directory where inbound Taildrop files are received (Go `tailscale file`). `None` = Taildrop
    /// receiving is off (the engine refuses inbound transfers, fail-closed). When set, it maps to the
    /// engine's `Config.taildrop_dir`; peers can then send files to this node and `tnet file
    /// list`/`get` surface them. Sending (`tnet file cp`) does not require this — only receiving does.
    pub taildrop_dir: Option<String>,
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
            exit_node: None,
            advertise_exit_node: false,
            advertise_routes: Vec::new(),
            ssh_enabled: false,
            taildrop_dir: None,
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
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                // Fail safe but not silent: a corrupted prefs file is otherwise
                // indistinguishable from a fresh node. Log it (the node still boots on
                // defaults — a parse error must not stop startup) so the fallback is visible.
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "prefs file is malformed; falling back to default prefs (node starts unconfigured)"
                );
                Self::default()
            })),
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
