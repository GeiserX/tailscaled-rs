//! `tailnetd` — the daemon binary.
//!
//! Loads persisted prefs, optionally auto-starts the node if the last intent was "up", then serves
//! the LocalAPI socket until SIGINT/SIGTERM, shutting the engine down cleanly on exit.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

/// Env var the underlying engine reads to confirm the operator opted into experimental software.
const EXPERIMENT_VAR: &str = "TS_RS_EXPERIMENT";
/// The exact value the engine requires; anything else (or unset) is a refusal.
const REQUIRED_EXPERIMENT_VALUE: &str = "this_is_unstable_software";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("TAILNETD_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // The engine refuses to run unless `TS_RS_EXPERIMENT=this_is_unstable_software` is set; mirror
    // that gate here and surface it early with an actionable message instead of a deep engine error.
    // We deliberately do NOT set the var ourselves — auto-defeating the experimental gate would hide
    // that this is unaudited software. The packaged systemd/launchd units set it for the operator.
    if !experiment_gate_ok(std::env::var(EXPERIMENT_VAR).ok().as_deref()) {
        tracing::error!(
            "{EXPERIMENT_VAR} is not set to `{REQUIRED_EXPERIMENT_VALUE}`. The underlying engine is \
             experimental and unaudited, so it refuses to run without an explicit opt-in. To run \
             tailnetd, set `{EXPERIMENT_VAR}={REQUIRED_EXPERIMENT_VALUE}` in the environment (the \
             packaged systemd/launchd units already do this for you)."
        );
        eprintln!(
            "error: {EXPERIMENT_VAR} is not set to `{REQUIRED_EXPERIMENT_VALUE}`.\n\
             The underlying engine is experimental and unaudited; it refuses to run without an \
             explicit opt-in.\n\
             To run tailnetd, set `{EXPERIMENT_VAR}={REQUIRED_EXPERIMENT_VALUE}` in the environment \
             (the packaged systemd/launchd units already do this for you)."
        );
        return Err(anyhow!(
            "{EXPERIMENT_VAR} must be set to `{REQUIRED_EXPERIMENT_VALUE}` to run the experimental engine"
        ));
    }

    let state_dir = tailscaled_rs::state_dir();
    let socket_path = tailscaled_rs::socket_path();
    tracing::info!(state_dir = %state_dir.display(), "starting tailnetd");

    // The state dir holds unencrypted key material; lock it to 0700 before any key file is written.
    if let Err(e) = tailscaled_rs::ensure_state_dir_secure(&state_dir).await {
        tracing::error!(error = %e, state_dir = %state_dir.display(), "failed to secure state dir");
        return Err(e.into());
    }

    let mut backend = tailscaled_rs::ipn::Backend::load(&state_dir).await?;

    // Auto-start if the persisted intent was "up". The MVP relies on an auth key in the
    // environment (`TS_AUTH_KEY`) for non-interactive re-registration on launch.
    if backend.wants_running() {
        tracing::info!("persisted intent is up; auto-starting");
        // Wrap the env auth key in `SecretString` so it is never logged or accidentally printed.
        // `auth_key_from_env()` returns `Some("")` for a set-but-empty var; treat that as absent
        // (matching the CLI's guard) so an empty `TS_AUTH_KEY` doesn't masquerade as a real key.
        let authkey = tailscale::config::auth_key_from_env()
            .filter(|k| !k.is_empty())
            .map(secrecy::SecretString::from);
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
