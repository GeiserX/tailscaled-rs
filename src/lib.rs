//! `tailscaled-rs` — the daemon layer over the `tailscale-rs` engine.
//!
//! The engine (`tailscale-rs`) is an embeddable, `tsnet`-style library: you construct a
//! [`tailscale::Device`] from an immutable config and get a running tailnet node in-process. It
//! deliberately omits the parts that make a *daemon* — a long-running service, a reconcilable
//! state machine, persisted preferences, and an external control surface.
//!
//! This crate adds exactly that layer:
//!
//! - [`ipn`] — the state machine (the spine): `NoState → NeedsLogin → NeedsMachineAuth →
//!   Starting → Running → Stopped`, owning the mutable, persisted [`prefs::Prefs`] (the node's
//!   *intent*) and reconciling it against the engine.
//! - [`prefs`] — the on-disk intent store (the analogue of Tailscale's `ipn.Prefs`).
//! - [`localapi`] — the request/response DTOs spoken over the local control socket.
//! - [`auth`] — peer-credential authorization for the control socket (read for all, write for
//!   root/same-uid).
//! - [`server`] — the LocalAPI server, a Unix-domain-socket IPC surface the CLI talks to.
//!
//! Two binaries consume it: `tailnetd` (the daemon) and `tnet` (the thin CLI client).

pub mod auth;
pub mod ipn;
pub mod localapi;
pub mod prefs;
pub mod server;

use std::path::PathBuf;

/// The conventional system-wide state directory used when running as root.
///
/// `/var/lib/tailnetd` on Linux, `/usr/local/var/tailnetd` on macOS — matching the packaged
/// systemd unit / launchd plist. Mirrors how the real `tailscaled` keeps its socket+state under a
/// fixed system path so the unprivileged-shell CLI and the root daemon agree without env juggling.
#[cfg(target_os = "macos")]
const SYSTEM_STATE_DIR: &str = "/usr/local/var/tailnetd";
#[cfg(not(target_os = "macos"))]
const SYSTEM_STATE_DIR: &str = "/var/lib/tailnetd";

/// Directory holding the daemon's persistent state (node keys, prefs).
///
/// Resolution order: `TAILNETD_STATE_DIR`; else — **when running as root** (the daemon under
/// systemd/launchd, and a `sudo tnet …`) — the system path [`SYSTEM_STATE_DIR`], so the CLI and the
/// packaged daemon resolve the *same* socket without any env being set; else `$XDG_STATE_HOME/tailnetd`,
/// else `$HOME/.local/state/tailnetd`, else `/tmp/tailnetd`.
///
/// The root branch is the fix for the otherwise-silent split where `tailnetd` (env-configured to
/// `/var/lib/tailnetd`) and a bare `sudo tnet status` (which has no env) looked in different places.
pub fn state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("TAILNETD_STATE_DIR") {
        return PathBuf::from(dir);
    }
    // Root → the fixed system path the packaged service uses. SAFETY: geteuid() is infallible.
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        return PathBuf::from(SYSTEM_STATE_DIR);
    }
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join("tailnetd")
}

/// Path to the LocalAPI Unix domain socket.
///
/// Resolved from `TAILNETD_SOCKET`, else `<state_dir>/tailnetd.sock`.
pub fn socket_path() -> PathBuf {
    std::env::var_os("TAILNETD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir().join("tailnetd.sock"))
}

/// Create the state directory if absent and enforce `0700` permissions on it.
///
/// The engine persists key material (node/machine keys, pre-auth keys) into this directory
/// **without at-rest encryption**, so restricting it to the owning user is the daemon's
/// responsibility. On unix this `chmod`s the dir to `0700`; a pre-existing world/group-accessible
/// state dir is tightened (and logged) rather than trusted. No-op beyond `create_dir_all` on
/// non-unix targets.
pub async fn ensure_state_dir_secure(dir: &std::path::Path) -> std::io::Result<()> {
    tokio::fs::create_dir_all(dir).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = tokio::fs::metadata(dir).await?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            tracing::warn!(
                path = %dir.display(),
                found = format!("{mode:o}"),
                "state dir not 0700; tightening (it holds unencrypted key material)"
            );
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            tokio::fs::set_permissions(dir, perms).await?;
        }
    }
    Ok(())
}
