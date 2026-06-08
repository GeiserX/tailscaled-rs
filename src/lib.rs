//! `tailnetd` — the daemon layer over the `tailscale-rs` engine.
//!
//! The engine (`tailscale-rs`) is an embeddable, `tsnet`-style library: you construct a
//! [`tailscale::Device`] from an immutable config and get a running tailnet node in-process. It
//! deliberately omits the parts that make a *daemon* — a long-running service, a reconcilable
//! state machine, persisted preferences, and an external control surface.
//!
//! This crate adds exactly that layer:
//!
//! - [`ipn`] — the state machine (the spine): `NoState → NeedsLogin → Starting → Running →
//!   Stopped`, owning the mutable, persisted [`prefs::Prefs`] (the node's *intent*) and
//!   reconciling it against the engine.
//! - [`prefs`] — the on-disk intent store (the analogue of Tailscale's `ipn.Prefs`).
//! - [`localapi`] — the request/response DTOs spoken over the local control socket.
//! - [`server`] — the LocalAPI server, a Unix-domain-socket IPC surface the CLI talks to.
//!
//! Two binaries consume it: `tailnetd` (the daemon) and `tnet` (the thin CLI client).

pub mod ipn;
pub mod localapi;
pub mod prefs;
pub mod server;

use std::path::PathBuf;

/// Directory holding the daemon's persistent state (node keys, prefs).
///
/// Resolved from `TAILNETD_STATE_DIR`, else `$XDG_STATE_HOME/tailnetd`, else
/// `$HOME/.local/state/tailnetd`, else `/tmp/tailnetd`.
pub fn state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("TAILNETD_STATE_DIR") {
        return PathBuf::from(dir);
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
