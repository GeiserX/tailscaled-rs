//! LocalAPI peer authorization (the `ipnauth` analogue).
//!
//! The control socket is a Unix domain socket. We authorize each connection by the **peer
//! process credentials** (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/`getpeereid` on macOS — both
//! surfaced by `tokio::net::UnixStream::peer_cred()`), mirroring Tailscale's model:
//!
//! - **Anyone may read** (`status`) — read commands are not gated.
//! - **Only root (uid 0) or the same user that owns the daemon may write** (`up` / `down`, which
//!   mutate node lifecycle and prefs).
//!
//! This is deliberately the MVP policy. The richer Tailscale "operator user" GID matrix is a
//! later phase; this module is the seam where that grows.

/// What a caller is allowed to do over the LocalAPI, decided from its peer credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions {
    /// May issue read-only commands (always true today).
    pub read: bool,
    /// May issue mutating commands (`up`, `down`, prefs edits).
    pub write: bool,
}

impl Permissions {
    /// Read-only caller (peer is neither root nor the daemon's owner).
    pub const READ_ONLY: Permissions = Permissions {
        read: true,
        write: false,
    };
    /// Fully-authorized caller (root or same-uid).
    pub const READ_WRITE: Permissions = Permissions {
        read: true,
        write: true,
    };
}

/// The effective uid of the current process (the daemon's owner), used for the same-user check.
///
/// Implemented with `libc::geteuid()` (libc is already in the dependency tree). Isolated here so
/// the rest of the daemon never calls libc directly.
pub fn current_euid() -> u32 {
    // SAFETY: geteuid() is always-succeeds, takes no arguments, and has no preconditions.
    unsafe { libc::geteuid() }
}

/// Decide a peer's [`Permissions`] from its uid and the daemon's own euid.
///
/// Policy: root (uid 0) or same-uid → read+write; everyone else → read-only. Pure function so it
/// is unit-testable without a socket.
pub fn permissions_for(peer_uid: u32, daemon_euid: u32) -> Permissions {
    if peer_uid == 0 || peer_uid == daemon_euid {
        Permissions::READ_WRITE
    } else {
        Permissions::READ_ONLY
    }
}

/// Resolve the [`Permissions`] for a connected LocalAPI peer, plus its uid for logging.
///
/// On unix, reads the peer's uid via `stream.peer_cred()` **once** and applies [`permissions_for`]
/// against [`current_euid`]. Returns `(permissions, Some(uid))` so the caller can log the exact uid
/// that drove the decision (no second `peer_cred()` syscall, and the log can never disagree with
/// the authorization). If the credential lookup fails, we fail **closed** (read-only, `None` uid) —
/// an unidentifiable caller must never get write.
pub fn permissions_for_peer(stream: &tokio::net::UnixStream) -> (Permissions, Option<u32>) {
    match stream.peer_cred() {
        Ok(cred) => {
            let uid = cred.uid();
            (permissions_for(uid, current_euid()), Some(uid))
        }
        Err(e) => {
            tracing::warn!(error = %e, "peer_cred lookup failed; defaulting to read-only");
            (Permissions::READ_ONLY, None)
        }
    }
}

/// Whether a given LocalAPI command requires write permission.
///
/// Centralized so the server has one authority on which verbs mutate. Read commands (`status`)
/// return false; lifecycle/prefs commands (`up`, `down`) return true.
pub fn requires_write(request: &crate::localapi::Request) -> bool {
    use crate::localapi::Request;
    match request {
        Request::Status => false,
        Request::Up { .. } | Request::Down => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_gets_write() {
        assert_eq!(permissions_for(0, 1000), Permissions::READ_WRITE);
    }

    #[test]
    fn same_uid_gets_write() {
        assert_eq!(permissions_for(1000, 1000), Permissions::READ_WRITE);
    }

    #[test]
    fn other_uid_is_read_only() {
        let p = permissions_for(1001, 1000);
        assert!(p.read);
        assert!(!p.write);
    }

    #[test]
    fn read_commands_need_no_write() {
        assert!(!requires_write(&crate::localapi::Request::Status));
    }

    #[test]
    fn lifecycle_commands_need_write() {
        assert!(requires_write(&crate::localapi::Request::Down));
        assert!(requires_write(&crate::localapi::Request::Up {
            authkey: None,
            control_url: None,
            hostname: None,
        }));
    }
}
