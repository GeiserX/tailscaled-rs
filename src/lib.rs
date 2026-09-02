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
//! - [`debugmode`] — `tailnetd debug`, the daemon-less network diagnostics subcommand (Go
//!   `tailscaled debug`), which runs without a daemon or a socket — for the node that will not
//!   come up at all.
//! - [`hostreap`] — startup cleanup of host routes/DNS a *hard-killed* previous run left behind
//!   (the engine's graceful teardown never ran), so a crash cannot outlive the daemon.
//! - [`tunflag`] — `tailnetd --tun`, Go's tunnel-interface flag, resolved onto this fork's TUN
//!   prefs so a `tailscaled` command line copied from a unit file or a container image starts.
//!
//! Two binaries consume it: `tailnetd` (the daemon) and `tnet` (the thin CLI client).

pub mod auth;
pub mod conffile;
pub mod debugmode;
pub mod debugserver;
pub mod goduration;
pub mod hardening;
pub mod hostreap;
pub mod httpproxy;
pub mod ipforward;
pub mod ipn;
pub mod localapi;
pub mod prefs;
pub mod server;
pub mod socks5;
pub mod tunflag;

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
    state_dir_with_source().0
}

/// Which rule in [`state_dir`]'s cascade produced the path.
///
/// The cascade itself is invisible in the resulting path, which makes the classic failure — the root
/// daemon and an unprivileged `tnet` silently resolving *different* state dirs, and so different
/// sockets — hard to see. Reporting the winning rule alongside the path turns that into one readable
/// line (`tnet debug statedir`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateDirSource {
    /// `TAILNETD_STATE_DIR` was set: the explicit override, which beats every other rule.
    Env,
    /// No override and the process is root, so the fixed system path the packaged systemd/launchd
    /// service uses ([`SYSTEM_STATE_DIR`]) — this is what makes `sudo tnet …` agree with the daemon.
    SystemRoot,
    /// `$XDG_STATE_HOME/tailnetd`.
    XdgStateHome,
    /// `$HOME/.local/state/tailnetd` (no `XDG_STATE_HOME`).
    Home,
    /// Neither `XDG_STATE_HOME` nor `HOME` is set — the last-resort `/tmp/tailnetd`.
    Tmp,
}

impl StateDirSource {
    /// A one-line human explanation of the winning rule, for `tnet debug statedir`.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Env => "$TAILNETD_STATE_DIR (explicit override)",
            Self::SystemRoot => "running as root, so the packaged system state dir",
            Self::XdgStateHome => "$XDG_STATE_HOME/tailnetd",
            Self::Home => "$HOME/.local/state/tailnetd",
            Self::Tmp => "no $XDG_STATE_HOME and no $HOME, so the /tmp fallback",
        }
    }
}

/// [`state_dir`], plus which rule produced it. `state_dir()` is the path-only shim over this, so
/// there is exactly one copy of the cascade.
pub fn state_dir_with_source() -> (PathBuf, StateDirSource) {
    // SAFETY: geteuid() is infallible. Off unix there is no root branch (as before).
    #[cfg(unix)]
    let is_root = unsafe { libc::geteuid() } == 0;
    #[cfg(not(unix))]
    let is_root = false;
    state_dir_from(|name| std::env::var_os(name), is_root)
}

/// The pure core of [`state_dir_with_source`]: the cascade against an arbitrary environment lookup
/// `get` (`name -> Option<value>`) and an explicit `is_root`, so it is unit-testable without mutating
/// the process-global environment (`std::env::set_var` is `unsafe` and races the parallel test
/// harness — the same reason `socket_path_in`'s test avoids it).
fn state_dir_from(
    get: impl Fn(&str) -> Option<std::ffi::OsString>,
    is_root: bool,
) -> (PathBuf, StateDirSource) {
    if let Some(dir) = get("TAILNETD_STATE_DIR") {
        return (PathBuf::from(dir), StateDirSource::Env);
    }
    // Root → the fixed system path the packaged service uses.
    if is_root {
        return (PathBuf::from(SYSTEM_STATE_DIR), StateDirSource::SystemRoot);
    }
    let (base, source) = match get("XDG_STATE_HOME") {
        Some(x) => (PathBuf::from(x), StateDirSource::XdgStateHome),
        None => match get("HOME") {
            Some(h) => (PathBuf::from(h).join(".local/state"), StateDirSource::Home),
            None => (PathBuf::from("/tmp"), StateDirSource::Tmp),
        },
    };
    (base.join("tailnetd"), source)
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

    #[test]
    fn socket_path_in_joins_explicit_state_dir() {
        // The new join branch (the main contract `--statedir` relies on): with `TAILNETD_SOCKET`
        // UNSET, the socket is `<state_dir>/tailnetd.sock` for the explicit dir passed in — NOT the
        // env/default state dir. Race-free: this branch never touches env. (The env-wins branch is
        // deliberately not asserted here — reading/setting TAILNETD_SOCKET races under the parallel
        // test harness; its precedence is covered by the `socket_path_in` body + the daemon's
        // resolution order, and the env check structurally precedes this join.)
        if std::env::var_os("TAILNETD_SOCKET").is_none() {
            let dir = std::path::Path::new("/var/lib/tailnetd-explicit");
            assert_eq!(socket_path_in(dir), dir.join("tailnetd.sock"));
        }
    }

    /// Build an env lookup over a fixed table, so the cascade is exercised without touching (and
    /// racing on) the real process environment.
    fn fake_env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<std::ffi::OsString> + use<> {
        let table: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |name: &str| {
            table
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| std::ffi::OsString::from(v))
        }
    }

    #[test]
    fn state_dir_env_override_wins_over_root_and_home() {
        // `TAILNETD_STATE_DIR` is the explicit override: it beats BOTH the root system path and the
        // per-user cascade, so an operator can always point a daemon+CLI pair at one dir.
        let env = fake_env(&[
            ("TAILNETD_STATE_DIR", "/srv/tailnetd"),
            ("XDG_STATE_HOME", "/home/u/.state"),
            ("HOME", "/home/u"),
        ]);
        assert_eq!(
            state_dir_from(&env, true),
            (PathBuf::from("/srv/tailnetd"), StateDirSource::Env)
        );
        assert_eq!(
            state_dir_from(&env, false),
            (PathBuf::from("/srv/tailnetd"), StateDirSource::Env)
        );
    }

    #[test]
    fn state_dir_root_takes_the_packaged_system_path() {
        // Root with no override → the packaged system dir, IGNORING $HOME/$XDG_STATE_HOME. This is
        // the branch that makes `sudo tnet status` find the systemd daemon's socket; a regression
        // here reintroduces the silent root-vs-user split.
        let env = fake_env(&[("XDG_STATE_HOME", "/root/.state"), ("HOME", "/root")]);
        assert_eq!(
            state_dir_from(&env, true),
            (PathBuf::from(SYSTEM_STATE_DIR), StateDirSource::SystemRoot)
        );
    }

    #[test]
    fn state_dir_non_root_cascade_prefers_xdg_then_home_then_tmp() {
        // Non-root, no override: XDG_STATE_HOME, else $HOME/.local/state, else /tmp — each reported
        // with the rule that produced it.
        assert_eq!(
            state_dir_from(
                fake_env(&[("XDG_STATE_HOME", "/home/u/.state"), ("HOME", "/home/u")]),
                false
            ),
            (
                PathBuf::from("/home/u/.state/tailnetd"),
                StateDirSource::XdgStateHome
            )
        );
        assert_eq!(
            state_dir_from(fake_env(&[("HOME", "/home/u")]), false),
            (
                PathBuf::from("/home/u/.local/state/tailnetd"),
                StateDirSource::Home
            )
        );
        assert_eq!(
            state_dir_from(fake_env(&[]), false),
            (PathBuf::from("/tmp/tailnetd"), StateDirSource::Tmp)
        );
    }
}
