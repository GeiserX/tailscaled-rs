//! `tailnetd` — the daemon binary.
//!
//! Loads persisted prefs, optionally auto-starts the node if the last intent was "up", then serves
//! the LocalAPI socket until SIGINT/SIGTERM, shutting the engine down cleanly on exit. A SIGHUP is
//! handled separately — as a *reload*, not a shutdown (see [`sighup_reload_loop`]).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use tailscaled_rs::ipn::Backend;
use tailscaled_rs::prefs::Prefs;
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

    // Best-effort OS-level hardening (no-coredump / no-ptrace / no-swap) for the secrets the engine
    // will hold in memory. Done here — after the experiment gate and logging init (so its outcome is
    // logged), but BEFORE `Backend::load` reads any key material — so the protection is in place
    // before the first secret lands in a page. Non-fatal by design: a denied step is a warning, not
    // a refusal to start (see `tailscaled_rs::hardening`). Skippable with `TAILNETD_NO_HARDEN=1`.
    let _ = tailscaled_rs::hardening::harden_process();

    // Install the SIGHUP handler NOW, before the (potentially multi-second) `Backend::load` +
    // `auto_start` handshake. `tokio::signal::unix::signal` overrides the OS default (terminate) the
    // moment it is created and queues any signal until `recv().await`, so a SIGHUP that arrives
    // during startup is reloaded later rather than killing the daemon mid-boot. (Creating it here vs.
    // inside `sighup_reload_loop` only changes *when the default is overridden* — the consuming loop
    // still starts in the `select!` below.)
    let sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e, "failed to install SIGHUP handler; reload disabled");
            None
        }
    };

    let state_dir = tailscaled_rs::state_dir();
    let socket_path = tailscaled_rs::socket_path();
    tracing::info!(state_dir = %state_dir.display(), "starting tailnetd");

    // The state dir holds unencrypted key material; lock it to 0700 before any key file is written.
    if let Err(e) = tailscaled_rs::ensure_state_dir_secure(&state_dir).await {
        tracing::error!(error = %e, state_dir = %state_dir.display(), "failed to secure state dir");
        return Err(e.into());
    }

    // The prefs path the backend persists to / loads from; SIGHUP re-reads it to re-evaluate intent.
    let prefs_path = state_dir.join("prefs.json");

    let mut backend = Backend::load(&state_dir).await?;

    // Auto-start if the persisted intent was "up".
    auto_start(&mut backend).await;

    let backend = Arc::new(Mutex::new(backend));

    // Serve the LocalAPI socket until SIGINT/SIGTERM, with SIGHUP handled *concurrently* as a reload
    // (never a shutdown). `serve`'s shutdown future is still SIGINT/SIGTERM only — the SIGHUP loop is
    // a SEPARATE `select!` branch that holds its own `Arc` clone and runs forever, so a SIGHUP can
    // reconcile the live backend without ending `serve`. The `select!` returns when `serve` returns
    // (i.e. on SIGINT/SIGTERM): at that point the still-pending `sighup_reload_loop` future is simply
    // dropped (cancelled) — it owns no resource that needs an orderly teardown beyond the `Arc`.
    let serve_result = {
        let server_backend = Arc::clone(&backend);
        let sighup_backend = Arc::clone(&backend);
        let sighup_prefs_path = prefs_path.clone();
        tokio::select! {
            r = tailscaled_rs::server::serve(&socket_path, server_backend, shutdown_signal()) => r,
            // `sighup_reload_loop` never returns; this arm only wins if it somehow does (it logs and
            // exits the loop only if installing the SIGHUP handler fails), in which case we keep
            // serving — losing reload is not a reason to tear the daemon down.
            () = sighup_reload_loop(sighup, sighup_backend, sighup_prefs_path) => {
                tracing::warn!("SIGHUP reload loop ended; continuing to serve without reload support");
                // Re-await serve alone so the daemon still shuts down cleanly on SIGINT/SIGTERM.
                let server_backend = Arc::clone(&backend);
                tailscaled_rs::server::serve(&socket_path, server_backend, shutdown_signal()).await
            }
        }
    };
    serve_result?;

    backend.lock().await.shutdown().await;
    Ok(())
}

/// Resolve when the process receives SIGINT or SIGTERM. **Deliberately not SIGHUP** — SIGHUP is a
/// reload, handled by [`sighup_reload_loop`], and must never end `serve` (that would drop a healthy
/// tunnel on a config re-read).
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = sigint.recv() => tracing::info!("SIGINT received, shutting down"),
        _ = sigterm.recv() => tracing::info!("SIGTERM received, shutting down"),
    }
}

/// Handle `SIGHUP` as a **graceful reload** for as long as the daemon runs.
///
/// SIGHUP is the conventional "re-read your config" signal, and a reload must NOT tear down a
/// healthy engine: this loop never resolves under normal operation, so it can sit in a `tokio::select!`
/// arm beside `serve` without ever ending it (see `main`). On each SIGHUP it [`reconcile_on_reload`]s
/// the live backend against the persisted prefs on disk.
///
/// It returns (ending the loop) only if the SIGHUP handler cannot be installed — an unexpected,
/// process-fatal-ish condition we treat as "reload unsupported" rather than crashing the daemon; the
/// caller keeps serving.
async fn sighup_reload_loop(
    sighup: Option<tokio::signal::unix::Signal>,
    backend: Arc<Mutex<Backend>>,
    prefs_path: PathBuf,
) {
    // The handler was installed early in `main` (before the startup handshake) so SIGHUP can't kill
    // the daemon mid-boot. If installation failed there, reload is disabled — but we must still never
    // return (returning ends the `select!` arm); park forever so `serve` remains the only exit path.
    let Some(mut sighup) = sighup else {
        std::future::pending::<()>().await;
        unreachable!("pending() never resolves");
    };
    loop {
        if sighup.recv().await.is_none() {
            // The signal stream closed (shouldn't happen for SIGHUP) — stop reloading, keep serving.
            tracing::warn!("SIGHUP signal stream closed; reload disabled");
            return;
        }
        tracing::info!("SIGHUP: reloading");
        let mut be = backend.lock().await;
        reconcile_on_reload(&mut be, &prefs_path).await;
    }
}

/// Reconcile the live backend against the persisted prefs on disk after a SIGHUP.
///
/// ## What this does (the honest, non-destructive slice)
///
/// 1. Re-reads `prefs.json` from disk (the operator may have hand-edited it — the classic SIGHUP
///    use case) and reports any drift from the backend's in-memory intent.
/// 2. Re-evaluates **auto-start for a currently-down node**: if the intent is `want_running` and no
///    device is up, it re-runs [`auto_start`] (the same resume/auth-key path used at boot). A
///    transient registration failure that left the node down can thus be retried with `kill -HUP`.
/// 3. If a device is already up and the intent is still `want_running`, it is a **no-op** — a reload
///    must never churn a working tunnel.
///
/// ## Deliberate limitations (kept honest rather than half-built)
///
/// - **No teardown on SIGHUP.** If the persisted intent is *not* `want_running` while a device is
///   up, this does NOT bring the node down. Tearing a tunnel down is a destructive action that
///   belongs to an explicit `tnet down`, not a config re-read; doing it from SIGHUP would surprise
///   operators who HUP for an unrelated reason. (`bd` follow-up if a reload-driven down is ever
///   wanted.)
/// - **Out-of-band prefs edits are not pushed into the live engine config.** The engine's
///   construction config (hostname / control_url / ephemeral) is rebuilt from the backend's
///   *in-memory* [`Prefs`] inside `Backend::up` → `build_config`. This crate does not own `ipn.rs`
///   and `Backend` exposes no primitive to replace its in-memory prefs from disk, so a SIGHUP cannot
///   adopt an out-of-band edit to those fields into a running engine. We DETECT the drift and warn;
///   fully applying it needs a minimal `Backend::reload_prefs(&mut self) -> Result<()>` added to
///   `ipn.rs` (which would re-`Prefs::load` into `self.prefs`). Filed as a follow-up there rather
///   than faking a partial reload across a file this crate doesn't own.
async fn reconcile_on_reload(backend: &mut Backend, prefs_path: &std::path::Path) {
    // Re-read persisted prefs from disk. A read/parse error is non-fatal: log and keep the running
    // state untouched (a transient FS error must not knock a healthy node off).
    let disk = match Prefs::load(prefs_path).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, path = %prefs_path.display(),
                "SIGHUP reload: failed to re-read prefs; leaving running state unchanged");
            return;
        }
    };
    let disk_wants_running = disk.want_running && !disk.logged_out;

    // Surface drift between the on-disk intent and the backend's in-memory view. In normal operation
    // the daemon is the sole writer of prefs.json, so these agree; a disagreement means an
    // out-of-band edit, which we can detect+report but not fully adopt (see the doc note above).
    if disk_wants_running != backend.wants_running() {
        tracing::warn!(
            disk_want_running = disk_wants_running,
            live_want_running = backend.wants_running(),
            "SIGHUP reload: on-disk intent differs from the live backend (an out-of-band prefs \
             edit); auto-start is re-evaluated from the live intent, but config-field edits \
             (hostname/control_url/ephemeral) cannot be adopted into a running engine without an \
             ipn.rs reload_prefs primitive — see reconcile_on_reload docs"
        );
    }

    // Is a device currently up? `status()` reports Running/Starting exactly when a device exists.
    let state = backend.status().await.state;
    let device_up = matches!(state.as_str(), "Running" | "Starting");

    if backend.wants_running() {
        if device_up {
            // Healthy tunnel + still-up intent → leave it. Do NOT churn on a reload.
            tracing::info!(state = %state, "SIGHUP reload: intent is up and a device is running; no-op");
        } else {
            // Intent is up but nothing is running (e.g. a prior auto-start failed) → retry the same
            // resume/auth-key path used at boot. This is the actionable half of the reload.
            tracing::info!(state = %state,
                "SIGHUP reload: intent is up but no device is running; re-evaluating auto-start");
            auto_start(backend).await;
        }
    } else {
        // Intent is down. We deliberately do not tear a device down from SIGHUP (see doc note).
        tracing::info!(state = %state,
            "SIGHUP reload: intent is not 'want_running'; nothing to start (no teardown on reload)");
    }
}

/// Bring the node up iff the persisted intent is "up", picking resume-vs-fresh-auth from the
/// available key material. Shared by the boot path and the SIGHUP reload so the resume logic lives
/// in exactly one place.
///
/// A real daemon should *resume* from its persisted node key on reboot, the way `tailscaled`
/// does: it re-`POST`s `/machine/register` with the node key it already holds and, for a node
/// control still recognizes as authorized, comes straight back up with NO auth key. The engine
/// does exactly this — `Device::new(cfg, None)` → `check_auth`/`register` send the persisted
/// `node_key` and simply omit the `auth` field when there is no key (see
/// `ts_control::tokio::register`). So an auth key must only be required when there is *no* usable
/// persisted key (first run, or the key was expired/GC'd by control), not on every boot.
///
/// Path selection (highest-priority match wins):
///
/// - persisted key present AND no `TS_AUTH_KEY` → RESUME (`up(None, ..)`).
/// - `TS_AUTH_KEY` set → FRESH AUTH (env key wins; covers first run and deliberate re-pair / key
///   rotation).
/// - no persisted key AND no `TS_AUTH_KEY` → nothing to resume from and no key to auth with; still
///   attempt `up(None, ..)` so the engine yields the authoritative needs-login state, not a guess.
async fn auto_start(backend: &mut Backend) {
    if !backend.wants_running() {
        return;
    }
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
