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
//! - [`hardening`] — best-effort OS-level protection (no-coredump / no-ptrace / no-swap) for the
//!   secrets the engine holds in memory, the in-RAM analogue of [`ensure_state_dir_secure`].
//!
//! Two binaries consume it: `tailnetd` (the daemon) and `tnet` (the thin CLI client).

pub mod auth;
pub mod hardening;
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
    socket_path_in(&state_dir())
}

/// Path to the LocalAPI Unix domain socket, deriving the default from an **explicit** state dir.
///
/// Same resolution as [`socket_path`] — `TAILNETD_SOCKET` still wins — but the fallback joins
/// `tailnetd.sock` onto the caller-supplied `state_dir` rather than the env/default one. This lets a
/// caller that has already resolved the state dir (e.g. `tailnetd --statedir <dir>`) keep the socket
/// alongside it without re-deriving the state dir. `socket_path()` is the `state_dir()`-derived shim
/// over this, so existing callers are unchanged.
pub fn socket_path_in(state_dir: &std::path::Path) -> PathBuf {
    std::env::var_os("TAILNETD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir.join("tailnetd.sock"))
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
                "state-dir: not 0700; tightening (it holds unencrypted key material)"
            );
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            tokio::fs::set_permissions(dir, perms).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A process-id-namespaced temp dir (matches the convention in `tests/localapi_loop.rs`), with a
    /// nanosecond suffix so parallel tests in this same PID never collide on the path.
    fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "tailnetd-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ensure_state_dir_secure_tightens_loose_dir() {
        use std::os::unix::fs::PermissionsExt;

        // A pre-existing world/group-accessible (0777) state dir must be tightened to 0700 — it
        // holds unencrypted key material, so a loose dir is corrected rather than trusted.
        let dir = unique_temp_dir("statedir-loose");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).expect("chmod 0777");

        ensure_state_dir_secure(&dir)
            .await
            .expect("ensure_state_dir_secure");

        let mode = std::fs::metadata(&dir)
            .expect("stat dir")
            .permissions()
            .mode()
            & 0o777;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(mode, 0o700, "loose state dir must be tightened to 0700");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ensure_state_dir_secure_creates_missing_dir_at_0700() {
        use std::os::unix::fs::PermissionsExt;

        // A non-existent path is CREATED (create_dir_all) and locked to 0700 in one call — the boot
        // path relies on this so the first key file never lands in a world-readable dir.
        let dir = unique_temp_dir("statedir-missing");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!dir.exists(), "precondition: dir must not exist yet");

        ensure_state_dir_secure(&dir)
            .await
            .expect("ensure_state_dir_secure must create the dir");

        assert!(dir.exists(), "dir must have been created");
        let mode = std::fs::metadata(&dir)
            .expect("stat dir")
            .permissions()
            .mode()
            & 0o777;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(mode, 0o700, "freshly-created state dir must be 0700");
    }
}
