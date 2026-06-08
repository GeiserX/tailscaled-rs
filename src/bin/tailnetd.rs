//! `tailnetd` — the daemon binary.
//!
//! Loads persisted prefs, optionally auto-starts the node if the last intent was "up", then serves
//! the LocalAPI socket until SIGINT/SIGTERM, shutting the engine down cleanly on exit.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

/// Env var the underlying engine reads to confirm the operator opted into experimental software.
const EXPERIMENT_VAR: &str = "TS_RS_EXPERIMENT";
/// The exact value the engine requires; anything else (or unset) is a refusal.
const REQUIRED_EXPERIMENT_VALUE: &str = "this_is_unstable_software";

#[tokio::main]
async fn main() -> Result<()> {
    // Gate FIRST, before any logging is set up: the engine refuses to run unless
    // `TS_RS_EXPERIMENT=this_is_unstable_software` is set, so mirror that gate here and surface it
    // early with an actionable message instead of a deep engine error. We deliberately do NOT set
    // the var ourselves — auto-defeating the experimental gate would hide that this is unaudited
    // software. The packaged systemd/launchd units set it for the operator. On refusal we emit a
    // single stderr line and exit(1) (matching `tnet`'s error path) rather than logging + returning
    // an Err, which would otherwise print the same refusal across stdout and stderr.
    if !experiment_gate_ok(std::env::var(EXPERIMENT_VAR).ok().as_deref()) {
        eprintln!(
            "error: {EXPERIMENT_VAR} is not set to `{REQUIRED_EXPERIMENT_VALUE}`.\n\
             The underlying engine is experimental and unaudited; it refuses to run without an \
             explicit opt-in.\n\
             To run tailnetd, set `{EXPERIMENT_VAR}={REQUIRED_EXPERIMENT_VALUE}` in the environment \
             (the packaged systemd/launchd units already do this for you)."
        );
        std::process::exit(1);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("TAILNETD_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let state_dir = tailscaled_rs::state_dir();
    let socket_path = tailscaled_rs::socket_path();
    tracing::info!(state_dir = %state_dir.display(), "starting tailnetd");

    // The state dir holds unencrypted key material; lock it to 0700 before any key file is written.
    if let Err(e) = tailscaled_rs::ensure_state_dir_secure(&state_dir).await {
        tracing::error!(error = %e, state_dir = %state_dir.display(), "failed to secure state dir");
        return Err(e.into());
    }

    let mut backend = tailscaled_rs::ipn::Backend::load(&state_dir).await?;

    // Auto-start if the persisted intent was "up".
    //
    // A real daemon should *resume* from its persisted node key on reboot, the way `tailscaled`
    // does: it re-`POST`s `/machine/register` with the node key it already holds and, for a node
    // control still recognizes as authorized, comes straight back up with NO auth key. The engine
    // does exactly this — `Device::new(cfg, None)` → `check_auth`/`register` send the persisted
    // `node_key` and simply omit the `auth` field when there is no key (see
    // `ts_control::tokio::register`). So an auth key must only be required when there is *no* usable
    // persisted key (first run, or the key was expired/GC'd by control), not on every boot.
    //
    // Path selection:
    //   - persisted key present AND no `TS_AUTH_KEY`  → RESUME (`up(None, ..)`).
    //   - `TS_AUTH_KEY` set                           → FRESH AUTH (env key wins; covers first run
    //                                                    and deliberate re-pair / key rotation).
    //   - no persisted key AND no `TS_AUTH_KEY`       → nothing to resume from and no key to auth
    //                                                    with; still attempt `up(None, ..)` so the
    //                                                    engine yields the authoritative
    //                                                    needs-login state instead of a guess.
    if backend.wants_running() {
        // Wrap the env auth key in `SecretString` so it is never logged or accidentally printed.
        // `auth_key_from_env()` returns `Some("")` for a set-but-empty var; treat that as absent
        // (matching the CLI's guard) so an empty `TS_AUTH_KEY` doesn't masquerade as a real key.
        let env_authkey = tailscale::config::auth_key_from_env()
            .filter(|k| !k.is_empty())
            .map(secrecy::SecretString::from);
        let has_key = backend.has_persisted_node_key().await;

        // The auth key, if any, that we hand to the engine. We resume (no key) only when we hold a
        // persisted node key and no env key was provided; otherwise the env key (possibly `None`)
        // governs. An explicit `TS_AUTH_KEY` always wins, so an operator can force re-auth / rotate.
        let (authkey, resuming) = if has_key && env_authkey.is_none() {
            (None, true)
        } else {
            (env_authkey, false)
        };

        if resuming {
            tracing::info!(
                "persisted intent is up and a persisted node key exists; \
                 resuming registration without an auth key"
            );
            // Honest caveat: an ephemeral node (the default — see `ipn::Backend::build_config`) is
            // garbage-collected by control shortly after it disconnects, so its persisted key may
            // already be invalid after a reboot and this resume can still fail at registration. A
            // node meant to survive reboots and resume from its key alone needs `ephemeral = false`.
            if backend.prefs_ephemeral() {
                tracing::warn!(
                    "node is configured ephemeral; control may have garbage-collected it after \
                     its last disconnect, so resume-without-authkey may fail — a node that must \
                     survive reboots needs ephemeral=false (or pass TS_AUTH_KEY to re-register)"
                );
            }
        } else if authkey.is_some() {
            tracing::info!("persisted intent is up; auto-starting with TS_AUTH_KEY (fresh auth)");
        } else {
            // No key to resume from and none provided — surface why so the operator can act.
            tracing::warn!(
                "persisted intent is up but there is no persisted node key and no TS_AUTH_KEY; \
                 cannot resume or authenticate — set TS_AUTH_KEY (or run `tnet up`) to register"
            );
        }

        if let Err(e) = backend.up(authkey, None, None).await {
            // Non-fatal: come up in a needs-login/stopped state and let the CLI drive `up`.
            tracing::warn!(error = %format!("{e:#}"), "auto-start failed; awaiting `tnet up`");
        }
    }

    let backend = Arc::new(Mutex::new(backend));
    let server_backend = Arc::clone(&backend);

    tailscaled_rs::server::serve(&socket_path, server_backend, shutdown_signal()).await?;

    backend.lock().await.shutdown().await;
    Ok(())
}

/// Resolve when the process receives SIGINT or SIGTERM.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = sigint.recv() => tracing::info!("SIGINT received, shutting down"),
        _ = sigterm.recv() => tracing::info!("SIGTERM received, shutting down"),
    }
}

/// The experimental-gate decision, pure so it can be unit-tested: the gate passes only when the
/// env var holds exactly the required opt-in value. `None` (unset) and any other value fail.
fn experiment_gate_ok(value: Option<&str>) -> bool {
    value == Some(REQUIRED_EXPERIMENT_VALUE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn experiment_gate_rejects_unset() {
        assert!(!experiment_gate_ok(None));
    }

    #[test]
    fn experiment_gate_rejects_wrong_value() {
        assert!(!experiment_gate_ok(Some("")));
        assert!(!experiment_gate_ok(Some("yes")));
        assert!(!experiment_gate_ok(Some("this_is_unstable_software ")));
    }

    #[test]
    fn experiment_gate_accepts_exact_value() {
        assert!(experiment_gate_ok(Some(REQUIRED_EXPERIMENT_VALUE)));
        assert!(experiment_gate_ok(Some("this_is_unstable_software")));
    }
}
