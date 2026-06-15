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
    /// Register as an ephemeral node (control garbage-collects it shortly after disconnect). **Default
    /// `false`** (persistent), matching Go `tailscaled`: a persistent node keeps its registration across
    /// reboots and resumes from its key alone. `true` opts into an ephemeral node (`tnet up
    /// --ephemeral`) — useful for short-lived CI/containers, but it will NOT rejoin after a reboot
    /// without a fresh auth key (control will have GC'd it). Set at registration via `up`; like Go it is
    /// a registration-time property, not a live-`set` pref.
    pub ephemeral: bool,
    /// Accept (and route traffic to) subnet routes advertised by peers.
    pub accept_routes: bool,
    /// Accept the tailnet's MagicDNS configuration pushed by control (Go `--accept-dns` /
    /// `ipn.Prefs.CorpDNS`). Maps to the engine `Config.accept_dns`. **Default `true`** (Go's
    /// default): the node uses tailnet DNS. Set `false` to ignore the pushed DNS config and keep the
    /// system resolver. Default `true` is honored on upgrade by the container-level `#[serde(default)]`
    /// above (a `prefs.json` written before this field existed has no `accept_dns` key → it falls back
    /// to `Prefs::default()`'s `true`, NOT `false`), so a daemon update never silently switches an
    /// existing node off tailnet DNS.
    pub accept_dns: bool,
    /// Shields-up (Go `--shields-up` / `ipn.Prefs.ShieldsUp`): block all **inbound** connections
    /// from peers that terminate on this node, regardless of the control-pushed packet filter, while
    /// leaving outbound + forwarded subnet/exit transit working. Maps to the engine
    /// `Config.block_incoming`. Default `false` (use the control filter as provided).
    #[serde(default)]
    pub shields_up: bool,
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
    /// ACL tags this node requests at registration (Go `--advertise-tags`), each `tag:<name>`.
    /// Mapped to the engine's `Config.requested_tags`. Empty = request no tags (a user-owned node).
    /// A tagged node is owned by the tailnet policy rather than a user; control must approve the tags.
    pub advertise_tags: Vec<String>,
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
    /// Whether this node has ever actually **logged in** (completed registration / reached `Running`).
    /// The faithful analogue of Go's `Persist.UserProfile.LoginName != ""` — distinct from "has a
    /// prefs file" (the daemon's `ever_configured`, derived from prefs.json existence + flipped by a
    /// bare `set`/`logout`). Used **only** by the accidental-revert guard's fresh-node exemption (Go's
    /// `curPrefs.ControlURL == ""` early-return): a node that has never logged in has no settings worth
    /// guarding, so the first real `up` is unguarded even if a prior `tnet set` already wrote a
    /// prefs.json. Set `true` when the node registers (see the bring-up path); never reset by `set`;
    /// **reset to `false` by `logout`** (logout ends the registration → no longer logged in, matching
    /// Go clearing `Persist.UserProfile.LoginName`); **preserved across `down`** (down keeps the
    /// registration). `#[serde(default)]` (container-level) migrates an old prefs.json with no key → `false`, so the
    /// first `up` after a daemon upgrade is unguarded once (acceptable — it cannot lose a setting the
    /// operator didn't just then decline to re-mention on an already-running node).
    #[serde(default)]
    pub has_logged_in: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            want_running: false,
            logged_out: false,
            control_url: None,
            hostname: None,
            ephemeral: false,
            accept_routes: false,
            accept_dns: true,
            shields_up: false,
            exit_node: None,
            advertise_exit_node: false,
            advertise_routes: Vec::new(),
            advertise_tags: Vec::new(),
            ssh_enabled: false,
            taildrop_dir: None,
            tun_enabled: false,
            tun_name: None,
            tun_mtu: None,
            has_logged_in: false,
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
                    "prefs: file is malformed; falling back to default prefs (node starts unconfigured)"
                );
                Self::default()
            })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Reset every "up-managed" pref (one a `tnet up` flag controls) to its [`Default`] value,
    /// leaving lifecycle/registration prefs untouched. This is the mutation behind `up --reset` (Go
    /// `tailscale up --reset`): the single path where `up` is a true wholesale REPLACE rather than a
    /// PATCH of only the mentioned flags. [`crate::ipn::Backend::begin_up`] calls this **before**
    /// applying the command's overrides, so e.g. `up --reset --ssh` ends with only `ssh_enabled` set
    /// and every other up-managed pref back at its default.
    ///
    /// Deliberately NOT reset: `want_running` / `logged_out` (lifecycle — `up` sets `want_running`
    /// itself just after), `ephemeral` (settable via `up --ephemeral` but a REGISTRATION-TIME intent
    /// the engine only honors on a fresh register — a no-op on a registered node — and with our PATCH
    /// merge it is never reverted, so resetting it on a live node is meaningless), and `taildrop_dir`
    /// (not an `up`-managed pref). The set reset here is exactly the set the accidental-revert guard
    /// (`crate::ipn::revert_guard`) checks — they must stay in lockstep.
    pub fn reset_up_managed_to_default(&mut self) {
        let d = Self::default();
        self.control_url = d.control_url;
        self.hostname = d.hostname;
        self.accept_routes = d.accept_routes;
        self.accept_dns = d.accept_dns;
        self.shields_up = d.shields_up;
        self.exit_node = d.exit_node;
        self.advertise_exit_node = d.advertise_exit_node;
        self.advertise_routes = d.advertise_routes;
        self.advertise_tags = d.advertise_tags;
        self.ssh_enabled = d.ssh_enabled;
        self.tun_enabled = d.tun_enabled;
        self.tun_name = d.tun_name;
        self.tun_mtu = d.tun_mtu;
    }

    /// Atomically persist prefs to `path`, creating parent directories as needed.
    ///
    /// Crash-safe via write-to-temp-then-rename: the bytes land in a sibling temp file in the *same*
    /// directory (so the final [`tokio::fs::rename`] is a same-filesystem POSIX rename, which is
    /// atomic), then the temp file replaces `path` in one step. A crash mid-write therefore leaves
    /// either the OLD complete `prefs.json` or the NEW complete one — never a truncated file that
    /// [`Prefs::load`] would treat as malformed and discard (which would silently read the node back
    /// as never-configured). The file mode is umask/dir-derived (this writer sets no explicit mode),
    /// and the temp file inherits the same perms, so the renamed-into-place file is unchanged from the
    /// previous behavior.
    pub async fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        let bytes = serde_json::to_vec_pretty(self).expect("prefs serialize");
        atomic_write(path, &bytes).await
    }
}

/// Write `bytes` to `path` atomically: stage them in a temp file in the *same* directory, then
/// [`tokio::fs::rename`] it over `path` (atomic on POSIX within one filesystem). On any failure the
/// temp file is removed best-effort so no stray `.tmp` is left behind. Same-dir staging is required —
/// a cross-filesystem rename is neither atomic nor guaranteed to succeed.
///
/// `pub(crate)` so the other per-profile state writers (e.g. serve-config) get the same crash-safety
/// instead of each open-coding a non-atomic `fs::write`.
pub(crate) async fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    let mut tmp_name = file_name;
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp = dir.join(tmp_name);

    if let Err(e) = tokio::fs::write(&tmp, bytes).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    if let Err(e) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    Ok(())
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
            !p.ephemeral,
            "a fresh node defaults to PERSISTENT (Go-faithful) so it survives reboots; \
             ephemeral is opt-in via `up --ephemeral`"
        );
    }

    #[test]
    fn accept_dns_defaults_on() {
        // Go's CorpDNS / `--accept-dns` is on by default — a fresh node uses tailnet DNS.
        assert!(
            Prefs::default().accept_dns,
            "accept_dns must default to true (Go CorpDNS default-on)"
        );
    }

    #[tokio::test]
    async fn accept_dns_migrates_to_true_for_prefs_without_the_field() {
        // MIGRATION: a prefs.json written before `accept_dns` existed has no such key. It MUST load as
        // `true` (the Go default) — NOT `false` — so a daemon UPGRADE never silently switches an
        // existing node off tailnet DNS. (Container `#[serde(default)]` fills the missing field from
        // `Prefs::default()`, whose `accept_dns` is true.)
        let dir = std::env::temp_dir().join(format!("tailnetd-prefs-adns-{}", std::process::id()));
        let path = dir.join("prefs.json");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        // An "old" prefs file: valid JSON, real fields, but no `accept_dns` key.
        tokio::fs::write(
            &path,
            br#"{"want_running":true,"logged_out":false,"accept_routes":true}"#,
        )
        .await
        .unwrap();

        let loaded = Prefs::load(&path).await.expect("load old prefs");
        assert!(loaded.want_running);
        assert!(loaded.accept_routes);
        assert!(
            loaded.accept_dns,
            "an upgraded prefs file with no accept_dns key must load as true, not false"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn missing_file_yields_default() {
        let dir =
            std::env::temp_dir().join(format!("tailnetd-prefs-missing-{}", std::process::id()));
        let path = dir.join("prefs.json");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let loaded = Prefs::load(&path).await.expect("load missing");
        assert!(!loaded.want_running);
        // A missing file → Prefs::default() → accept_dns on.
        assert!(loaded.accept_dns);
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
