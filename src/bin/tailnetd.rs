//! `tailnetd` — the daemon binary.
//!
//! Loads persisted prefs, optionally auto-starts the node if the last intent was "up", then serves
//! the LocalAPI socket until SIGINT/SIGTERM, shutting the engine down cleanly on exit. A SIGHUP is
//! handled separately — as a *reload*, not a shutdown (see [`sighup_reload_loop`]).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tailscaled_rs::ipn::{self, Backend};
use tailscaled_rs::prefs::Prefs;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

/// Env var the underlying engine reads to confirm the operator opted into experimental software.
const EXPERIMENT_VAR: &str = "TS_RS_EXPERIMENT";
/// The exact value the engine requires; anything else (or unset) is a refusal.
const REQUIRED_EXPERIMENT_VALUE: &str = "this_is_unstable_software";

/// `tailnetd` command-line flags (the analogue of Go `tailscaled`'s flag set).
///
/// The daemon was historically env-only (`TAILNETD_STATE_DIR` / `TAILNETD_SOCKET` / `TAILNETD_LOG`);
/// these flags are the Go-faithful CLI surface over the same knobs. **A flag, when given, OVERRIDES
/// the corresponding env var** (Go resolves flags first); when omitted, the existing env/default
/// resolution (`tailscaled_rs::state_dir` / `socket_path`) is unchanged, so existing env-driven
/// deployments behave exactly as before.
///
/// Two Go daemon flags Go also exposes are deliberately NOT daemon-startup flags in this fork, for
/// different reasons: `--tun` (and its name/MTU) is a **pref**, set via `tnet up`
/// (`--tun`/`--tun-name`/`--tun-mtu`); `--port` (the WireGuard listen port) is **engine-gated** —
/// the `tailscale` engine binds an ephemeral port and exposes no configurable listen port, so there
/// is nothing for a daemon flag to set (tracked if/when the engine adds the knob). `--config`
/// (declarative `ipn.ConfigVAlpha`) is a tracked follow-up that hangs off this flag surface.
#[derive(Parser, Debug)]
#[command(
    name = "tailnetd",
    about = "The tailscaled-rs daemon (experimental WireGuard mesh node)",
    version
)]
struct Args {
    /// Directory for daemon state (node key, prefs). Overrides `TAILNETD_STATE_DIR`. When omitted,
    /// resolves as before: `TAILNETD_STATE_DIR`, else the system path when root, else an XDG/HOME
    /// path. Go `tailscaled --statedir`. NOTE: relocating the state dir also moves the default socket
    /// to `<DIR>/tailnetd.sock` (unless `TAILNETD_SOCKET`/`--socket` is set), so the `tnet` client
    /// must be pointed at it — `tnet --socket <DIR>/tailnetd.sock …` (or export `TAILNETD_SOCKET`) —
    /// since `tnet` has no `--statedir` of its own.
    #[arg(long, value_name = "DIR")]
    statedir: Option<PathBuf>,
    /// Path of the LocalAPI control socket. Overrides `TAILNETD_SOCKET`. When omitted, resolves to
    /// `TAILNETD_SOCKET` else `<statedir>/tailnetd.sock`. Go `tailscaled --socket`.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
    /// Log verbosity: `0` (default, info), `1` (debug), `2+` (trace). Overrides the `TAILNETD_LOG`
    /// env filter when given. Go `tailscaled --verbose`.
    #[arg(long, short = 'v', value_name = "LEVEL")]
    verbose: Option<u8>,
    /// Declarative config file (Go `tailscaled --config`, the `ipn.ConfigVAlpha` JSON). Loaded at
    /// startup and merged over the persisted prefs — the headless/automated path for setting prefs
    /// without an interactive `tnet up`. An `AuthKey` (or `file:<path>`) in the config registers the
    /// node. Fails fast on a malformed/unsupported-version file. (SIGHUP re-read is a follow-up: it
    /// shares the same blocker as the existing prefs reload — adopting changed config fields into a
    /// *running* engine needs an `ipn` `reload_prefs` primitive this crate does not yet own.)
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Run a SOCKS5 proxy on `[host:]port` that dials **over the tailnet** (Go `tailscaled
    /// --socks5-server`). A bare port (`1055`) binds `127.0.0.1:<port>`; pass an explicit address to
    /// bind elsewhere (the proxy is UNAUTHENTICATED — the bind address is the security boundary, so it
    /// defaults to loopback). CONNECT requests resolve a MagicDNS name or IP to a tailnet node and
    /// splice over the overlay (the engine's dialer), so a netstack/no-TUN daemon can route an app's
    /// traffic through the tailnet without root or a TUN device. Off unless given.
    #[arg(long, value_name = "[HOST:]PORT")]
    socks5_server: Option<String>,
    /// Run an outbound HTTP proxy on `[host:]port` that dials **over the tailnet** (Go `tailscaled
    /// --outbound-http-proxy-listen`). The HTTP-proxy sibling of `--socks5-server` for clients that
    /// speak the HTTP-proxy protocol (`https_proxy=...`, `curl -x`). Supports the `CONNECT` method
    /// (HTTPS tunneling — the common case); a bare port binds `127.0.0.1`. Unauthenticated, so the
    /// bind address is the security boundary. Off unless given.
    #[arg(long, value_name = "[HOST:]PORT")]
    outbound_http_proxy_listen: Option<String>,
}

/// Restore the default `SIGPIPE` disposition (terminate) before any output. The Rust runtime sets
/// `SIG_IGN`, which turns a write to a closed pipe into `EPIPE` → a `print!` panic; resetting to
/// `SIG_DFL` makes a broken output pipe (e.g. `tailnetd --version | head`) terminate cleanly instead,
/// the Unix-idiomatic behavior (same as the `tnet` CLI; see its `reset_sigpipe`). Output-only — does
/// not affect the LocalAPI socket I/O.
fn reset_sigpipe() {
    // SAFETY: `signal(SIGPIPE, SIG_DFL)` is async-signal-safe, no preconditions; called once at the
    // very start of `main` before any threads/output. The `unsafe` is only the `libc::signal` FFI.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Restore default SIGPIPE before any output (a broken `--version`/`--help` pipe should terminate
    // cleanly, not panic the print). Must run before clap, which prints help/version.
    reset_sigpipe();
    // Parse flags FIRST: clap handles `--help`/`--version` (print + exit 0) and rejects unknown
    // flags before we touch the experiment gate or any state, matching how Go `tailscaled` parses its
    // flag set up front. The parsed values then override the env-derived defaults below.
    let args = Args::parse();

    // Gate, before any logging is set up: the engine refuses to run unless
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

    // Log filter: `--verbose <n>` (when given) wins and maps to a level (Go's numeric verbosity);
    // otherwise fall back to the `TAILNETD_LOG` env filter, else `info`. `--verbose` overriding the
    // env mirrors the flags-first resolution Go uses.
    tracing_subscriber::fmt()
        .with_env_filter(match args.verbose {
            Some(level) => EnvFilter::new(verbose_to_level(level)),
            None => {
                EnvFilter::try_from_env("TAILNETD_LOG").unwrap_or_else(|_| EnvFilter::new("info"))
            }
        })
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

    // Resolve the state dir + socket: a flag wins; otherwise the existing env/default resolution.
    // The socket default is derived from the *resolved* state dir (matching `socket_path()`'s own
    // `<state_dir>/tailnetd.sock` fallback), so `--statedir` alone also relocates the socket.
    let state_dir = args.statedir.unwrap_or_else(tailscaled_rs::state_dir);
    let socket_path = args
        .socket
        .unwrap_or_else(|| tailscaled_rs::socket_path_in(&state_dir));
    tracing::info!(state_dir = %state_dir.display(), "starting tailnetd");

    // The state dir holds unencrypted key material; lock it to 0700 before any key file is written.
    if let Err(e) = tailscaled_rs::ensure_state_dir_secure(&state_dir).await {
        tracing::error!(error = %e, state_dir = %state_dir.display(), "failed to secure state dir");
        return Err(e.into());
    }

    // Validate `--socks5-server` / `--outbound-http-proxy-listen` NOW (fail-fast, before any state
    // work) so a bad listen address is a clear startup error rather than a deep bind failure later.
    // `None` when the flag is absent.
    let socks5_listen = match &args.socks5_server {
        Some(addr) => Some(
            tailscaled_rs::socks5::normalize_listen_addr(addr)
                .context("invalid --socks5-server address")?,
        ),
        None => None,
    };
    let http_proxy_listen = match &args.outbound_http_proxy_listen {
        Some(addr) => Some(
            tailscaled_rs::httpproxy::normalize_listen_addr(addr)
                .context("invalid --outbound-http-proxy-listen address")?,
        ),
        None => None,
    };

    // The prefs path the backend persists to / loads from; SIGHUP re-reads it to re-evaluate intent.
    let prefs_path = state_dir.join("prefs.json");

    let mut backend = Backend::load(&state_dir).await?;

    // `--config <file>`: load the declarative config and merge it over the just-loaded prefs (Go
    // `tailscaled --config`). The merge is layered + persisted by `apply_config`, so the config
    // refines the stored prefs and the merged intent survives a later restart. A malformed or
    // unsupported-version file fails the daemon HARD (a misconfigured headless deploy must not start
    // half-configured) — propagate the error rather than logging + continuing. The config's auth key
    // (if any) is threaded into auto-start as a registration credential (never persisted into prefs).
    let config_authkey = match &args.config {
        Some(path) => {
            let config = tailscaled_rs::conffile::load(path)
                .with_context(|| format!("loading --config {}", path.display()))?;
            tracing::info!(path = %path.display(), version = %config.version, "applying --config");
            backend.apply_config(&config).await?
        }
        None => None,
    };

    // Describe the daemon's effective posture once at boot so an operator tailing the log knows which
    // control plane it talks to, which data path it uses, and the exact build — without having to run
    // `tnet status`/`version`. (`control_url = None` → the engine default, Tailscale SaaS; `transport`
    // is the kernel-TUN data path vs the userspace netstack.)
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        control_url = backend.prefs_control_url().unwrap_or("default"),
        transport = if backend.prefs_tun() {
            "tun"
        } else {
            "netstack"
        },
        ephemeral = backend.prefs_ephemeral(),
        ssh = backend.prefs_ssh(),
        "tailnetd posture"
    );

    // Auto-start if the persisted intent was "up". A `--config` auth key (if supplied, already a
    // `SecretString`) is threaded in as the registration credential, taking precedence over
    // `TS_AUTH_KEY`.
    auto_start(&mut backend, config_authkey).await;

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
        // Optional SOCKS5 proxy (Go `--socks5-server`): a process-level listener that dials over the
        // tailnet, sharing the same backend handle. Bound only when the flag is given; otherwise the
        // arm is an inert `pending()` future that never fires, so the `select!` shape is uniform. The
        // listen address was validated above (fail-fast), so this only fails on a real bind error —
        // which, like Go, ends the daemon (a requested proxy that can't bind is a startup failure).
        let socks5_backend = Arc::clone(&backend);
        let socks5_addr = socks5_listen.clone();
        let http_proxy_backend = Arc::clone(&backend);
        let http_proxy_addr = http_proxy_listen.clone();
        tokio::select! {
            r = tailscaled_rs::server::serve(&socket_path, server_backend, shutdown_signal()) => r,
            // The SOCKS5 proxy arm: a bind/serve error ends the daemon (matches Go). When no
            // `--socks5-server` was given, `run_optional_socks5` is `pending()` and never wins.
            r = run_optional_socks5(socks5_addr, socks5_backend) => r,
            // The HTTP-proxy arm: same model — bind/serve error ends the daemon; `pending()` when the
            // `--outbound-http-proxy-listen` flag is absent.
            r = run_optional_http_proxy(http_proxy_addr, http_proxy_backend) => r,
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

/// Run the SOCKS5 proxy if `--socks5-server` was given, else an inert future that never resolves.
///
/// Returning a uniform `Result` future lets `main`'s `select!` treat the proxy as a peer of `serve`:
/// when configured, a bind/serve error ends the daemon (Go does the same — a requested proxy that
/// can't bind is a startup failure); when not configured, this is `pending()` and the arm never wins.
/// The proxy shares the backend handle and shuts down with the daemon (its own `shutdown_signal`).
async fn run_optional_socks5(
    listen: Option<String>,
    backend: Arc<Mutex<tailscaled_rs::ipn::Backend>>,
) -> anyhow::Result<()> {
    match listen {
        Some(addr) => tailscaled_rs::socks5::serve(&addr, backend, shutdown_signal()).await,
        // No proxy requested: never resolve, so this `select!` arm stays dormant for the daemon's life.
        None => std::future::pending().await,
    }
}

/// Run the outbound HTTP proxy if `--outbound-http-proxy-listen` was given, else an inert future.
/// Same uniform-`select!`-arm pattern as [`run_optional_socks5`].
async fn run_optional_http_proxy(
    listen: Option<String>,
    backend: Arc<Mutex<tailscaled_rs::ipn::Backend>>,
) -> anyhow::Result<()> {
    match listen {
        Some(addr) => tailscaled_rs::httpproxy::serve(&addr, backend, shutdown_signal()).await,
        None => std::future::pending().await,
    }
}

/// Resolve when the process receives SIGINT or SIGTERM. **Deliberately not SIGHUP** — SIGHUP is a
/// reload, handled by [`sighup_reload_loop`], and must never end `serve` (that would drop a healthy
/// tunnel on a config re-read).
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    // PROOF: `signal()` registration only fails on resource exhaustion (out of memory/fds) or for a
    // reserved signal already overridden by a non-default disposition; neither is reachable for
    // SIGINT/SIGTERM at daemon startup (first handler install, on a fresh process), so the expect is
    // safe — an early panic here is the correct response to an impossible-in-practice OS failure.
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
        // Pass the shared `Arc<Mutex<Backend>>` (NOT a held guard): `reconcile_on_reload` must be
        // free to release the lock across the multi-second bring-up handshake, exactly like the
        // LocalAPI server, so a reload-triggered re-auth never head-of-line blocks concurrent
        // `status`/`down`. Holding the guard here (the previous design) reintroduced that stall.
        reconcile_on_reload(&backend, &prefs_path).await;
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
///   *in-memory* [`Prefs`] inside the bring-up path → `build_config`. This crate does not own `ipn.rs`
///   and `Backend` exposes no primitive to replace its in-memory prefs from disk, so a SIGHUP cannot
///   adopt an out-of-band edit to those fields into a running engine. We DETECT the drift and warn;
///   fully applying it needs a minimal `Backend::reload_prefs(&mut self) -> Result<()>` added to
///   `ipn.rs` (which would re-`Prefs::load` into `self.prefs`). Filed as a follow-up there rather
///   than faking a partial reload across a file this crate doesn't own.
/// - **SIGHUP only retries a bring-up THIS process already attempted (`boot_attempted_up`).** It will
///   not *originate* a connection from a node that was never auto-started this run — so a stale or
///   hand-restored `prefs.json` flipped to `want_running=true` out-of-band does NOT cause a silent
///   rejoin on the next `kill -HUP`. The actionable case (a transient boot-time registration failure)
///   is retried; the surprising case (resurrecting a node the operator downed) is not.
///
/// Takes the shared `Arc<Mutex<Backend>>` rather than a held `&mut Backend` guard precisely so it can
/// **release the lock across the bring-up handshake** (via [`ipn::drive_up`]); holding the lock here
/// would block every concurrent `status`/`down` for the multi-second re-auth.
async fn reconcile_on_reload(backend: &Arc<Mutex<Backend>>, prefs_path: &std::path::Path) {
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

    // Snapshot the live view under a brief lock, then DROP it before any handshake.
    let (live_wants_running, device_up, boot_attempted_up, state) = {
        let be = backend.lock().await;
        let state = be.status().await.state;
        (
            be.wants_running(),
            matches!(state.as_str(), "Running" | "Starting"),
            be.boot_attempted_up(),
            state,
        )
    };

    // Surface drift between the on-disk intent and the backend's in-memory view. In normal operation
    // the daemon is the sole writer of prefs.json, so these agree; a disagreement means an
    // out-of-band edit, which we can detect+report but not fully adopt (see the doc note above).
    if disk_wants_running != live_wants_running {
        tracing::warn!(
            disk_want_running = disk_wants_running,
            live_want_running = live_wants_running,
            "SIGHUP reload: on-disk intent differs from the live backend (an out-of-band prefs \
             edit); config-field edits (hostname/control_url/ephemeral) cannot be adopted into a \
             running engine without an ipn.rs reload_prefs primitive, and a reload will NOT \
             originate a connection from an out-of-band intent flip — see reconcile_on_reload docs"
        );
    }

    if !live_wants_running {
        // Intent is down. We deliberately do not tear a device down from SIGHUP (see doc note).
        tracing::info!(state = %state,
            "SIGHUP reload: intent is not 'want_running'; nothing to start (no teardown on reload)");
        return;
    }
    if device_up {
        // Healthy tunnel + still-up intent → leave it. Do NOT churn on a reload.
        tracing::info!(state = %state, "SIGHUP reload: intent is up and a device is running; no-op");
        return;
    }
    if !boot_attempted_up {
        // Intent says up, nothing is running, and THIS process never attempted to bring it up — so
        // the "up" intent arrived out-of-band (stale/hand-edited prefs). Do not silently resurrect a
        // node the operator may have intentionally downed; require an explicit `tnet up`.
        tracing::warn!(state = %state,
            "SIGHUP reload: on-disk intent is up but this process never auto-started the node \
             (likely an out-of-band prefs edit); NOT auto-starting — run `tnet up` to bring it up");
        return;
    }
    // Intent is up, nothing is running, and we DID attempt bring-up at boot (it failed transiently,
    // e.g. control was unreachable) → retry the same resume/auth-key path, OFF-LOCK via drive_up.
    tracing::info!(state = %state,
        "SIGHUP reload: intent is up but no device is running; retrying auto-start (off-lock)");
    auto_start_arc(backend).await;
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
async fn auto_start(backend: &mut Backend, config_authkey: Option<secrecy::SecretString>) {
    if !backend.wants_running() {
        return;
    }
    // Record that THIS process attempted a bring-up. The SIGHUP path consults this so it only
    // *retries* a boot we already attempted (a transient failure), never *originates* a connection
    // from an out-of-band intent flip.
    backend.mark_boot_attempted_up();

    // Registration credential precedence: a `--config` auth key (the explicit declarative source for
    // a config-driven boot) wins over `TS_AUTH_KEY`; either is a fresh-auth key that beats resume.
    let explicit_authkey = config_authkey.or_else(env_authkey);
    let has_key = backend.has_persisted_node_key().await;
    let (authkey, resuming) = resume_decision(has_key, explicit_authkey);
    log_resume_decision(resuming, authkey.is_some(), backend.prefs_ephemeral());

    // Auto-start uses persisted prefs as-is (no overrides) — TUN/hostname/control-url all come from
    // the stored prefs the user set via `tnet up`, not from the boot path. No external lock is held
    // at boot (this runs before `serve`), so the inline `up` is fine here.
    match backend.up(authkey, ipn::UpOptions::default()).await {
        // Boot success was previously silent — log it so an operator tailing the log sees the node
        // came up at boot (the node then converges to Running once the netmap arrives).
        Ok(()) => tracing::info!("auto-start: node is up"),
        Err(e) => {
            // Non-fatal: come up in a needs-login/stopped state and let the CLI drive `up`. Append the
            // resulting state so the warn says *what* state we're awaiting `up` from (e.g. NeedsLogin).
            let state = backend.status().await.state;
            tracing::warn!(
                error = %format!("{e:#}"),
                state = %state,
                "auto-start failed; awaiting `tnet up`"
            );
        }
    }
}

/// SIGHUP-path counterpart to [`auto_start`] that runs against the shared `Arc<Mutex<Backend>>` and
/// drives the bring-up **off-lock** via [`ipn::drive_up`], so a reload-triggered re-auth never
/// head-of-line blocks concurrent `status`/`down`. The caller ([`reconcile_on_reload`]) has already
/// established that the intent is up, no device is running, and this process attempted bring-up at
/// boot (`boot_attempted_up`); this fn re-reads the key material under a brief lock, then handshakes
/// unlocked.
async fn auto_start_arc(backend: &Arc<Mutex<Backend>>) {
    let env_authkey = env_authkey();
    // Brief lock to read the resume inputs; released before the handshake.
    let (has_key, ephemeral) = {
        let be = backend.lock().await;
        (be.has_persisted_node_key().await, be.prefs_ephemeral())
    };
    let (authkey, resuming) = resume_decision(has_key, env_authkey);
    log_resume_decision(resuming, authkey.is_some(), ephemeral);

    // The SIGHUP reload resume carries no workload-identity creds (it resumes from the persisted key
    // or the env auth key) → `None`.
    if let Err(e) = ipn::drive_up(backend, authkey, None, ipn::UpOptions::default()).await {
        tracing::warn!(error = %format!("{e:#}"), "SIGHUP auto-start retry failed; awaiting `tnet up`");
    }
}

/// Read `TS_AUTH_KEY` as a `SecretString` (never logged), treating a set-but-empty value as absent
/// (matching the CLI's guard) so an empty `TS_AUTH_KEY` doesn't masquerade as a real key.
fn env_authkey() -> Option<secrecy::SecretString> {
    tailscale::config::auth_key_from_env()
        .filter(|k| !k.is_empty())
        .map(secrecy::SecretString::from)
}

/// The resume-vs-fresh-auth decision, pure so it is unit-testable without an engine.
///
/// Returns `(authkey_to_use, resuming)`. We resume (no key) only when a persisted node key exists
/// AND no env key was provided; otherwise the env key (possibly `None`) governs. An explicit
/// `TS_AUTH_KEY` always wins, so an operator can force re-auth / rotate. With neither a persisted key
/// nor an env key, we still attempt `up(None)` so the engine yields the authoritative needs-login
/// state rather than the daemon guessing.
fn resume_decision(
    has_persisted_key: bool,
    env_authkey: Option<secrecy::SecretString>,
) -> (Option<secrecy::SecretString>, bool) {
    if has_persisted_key && env_authkey.is_none() {
        (None, true)
    } else {
        (env_authkey, false)
    }
}

/// Emit the operator-facing log line explaining which auth path the bring-up took. Split out so both
/// [`auto_start`] and [`auto_start_arc`] log identically.
fn log_resume_decision(resuming: bool, have_authkey: bool, ephemeral: bool) {
    if resuming {
        tracing::info!(
            "persisted intent is up and a persisted node key exists; \
             resuming registration without an auth key"
        );
        // Honest caveat: an ephemeral node (the default — see `ipn::Backend::build_config`) is
        // garbage-collected by control shortly after it disconnects, so its persisted key may
        // already be invalid after a reboot and this resume can still fail at registration. A
        // node meant to survive reboots and resume from its key alone needs `ephemeral = false`.
        if ephemeral {
            tracing::warn!(
                "node is configured ephemeral; control may have garbage-collected it after \
                 its last disconnect, so resume-without-authkey may fail — a node that must \
                 survive reboots needs ephemeral=false (or pass TS_AUTH_KEY to re-register)"
            );
        }
    } else if have_authkey {
        tracing::info!("persisted intent is up; auto-starting with TS_AUTH_KEY (fresh auth)");
    } else {
        // No key to resume from and none provided — surface why so the operator can act.
        tracing::warn!(
            "persisted intent is up but there is no persisted node key and no TS_AUTH_KEY; \
             cannot resume or authenticate — set TS_AUTH_KEY (or run `tnet up`) to register"
        );
    }
}

/// The experimental-gate decision, pure so it can be unit-tested: the gate passes only when the
/// env var holds exactly the required opt-in value. `None` (unset) and any other value fail.
fn experiment_gate_ok(value: Option<&str>) -> bool {
    value == Some(REQUIRED_EXPERIMENT_VALUE)
}

/// Map a numeric `--verbose` level to a `tracing` env-filter directive (Go's numeric verbosity →
/// our level-based filter). `0` = `info` (the default), `1` = `debug`, `2` or higher = `trace` (the
/// most verbose level `tracing` has — Go's higher integers just mean "even more", which saturates
/// here). Pure → unit-testable.
fn verbose_to_level(level: u8) -> &'static str {
    match level {
        0 => "info",
        1 => "debug",
        _ => "trace",
    }
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

    // `resume_decision` is the resume-vs-fresh-auth path selection shared by the boot and SIGHUP
    // auto-start paths. It is pure, so the four quadrants are table-testable without an engine — and
    // a regression here (e.g. inverting the priority so the env key loses to a persisted key) would
    // otherwise be invisible. `secrecy::SecretString` has no value-equality, so we assert on
    // `is_some()` + the `resuming` flag, which fully characterizes the decision.
    fn sk(s: &str) -> secrecy::SecretString {
        secrecy::SecretString::from(s.to_owned())
    }

    #[test]
    fn resume_decision_persisted_key_no_env_resumes() {
        // Persisted key, no env key → resume with NO auth key.
        let (key, resuming) = resume_decision(true, None);
        assert!(resuming);
        assert!(key.is_none());
    }

    #[test]
    fn resume_decision_env_key_always_wins() {
        // Env key present → fresh auth, even when a persisted key also exists (operator forcing a
        // re-pair / rotation must win over resume).
        let (key, resuming) = resume_decision(true, Some(sk("tskey-auth-x")));
        assert!(!resuming);
        assert!(key.is_some());

        let (key, resuming) = resume_decision(false, Some(sk("tskey-auth-x")));
        assert!(!resuming);
        assert!(key.is_some());
    }

    #[test]
    fn resume_decision_no_key_no_env_attempts_unauthed() {
        // Neither a persisted key nor an env key → not "resuming", and no key to send; the daemon
        // still attempts `up(None)` so the engine yields the authoritative needs-login state.
        let (key, resuming) = resume_decision(false, None);
        assert!(!resuming);
        assert!(key.is_none());
    }

    #[test]
    fn verbose_to_level_maps_go_verbosity() {
        // 0 = info (default), 1 = debug, 2+ saturates at trace (the most verbose tracing level).
        assert_eq!(verbose_to_level(0), "info");
        assert_eq!(verbose_to_level(1), "debug");
        assert_eq!(verbose_to_level(2), "trace");
        assert_eq!(verbose_to_level(9), "trace");
    }

    #[test]
    fn args_parse_flags_and_defaults() {
        use clap::Parser;
        // All flags omitted → every override is None (env/default resolution stands).
        let a = Args::parse_from(["tailnetd"]);
        assert!(a.statedir.is_none() && a.socket.is_none() && a.verbose.is_none());
        // Flags parse to their override values.
        let a = Args::parse_from([
            "tailnetd",
            "--statedir",
            "/var/lib/x",
            "--socket",
            "/run/x.sock",
            "--verbose",
            "2",
        ]);
        assert_eq!(
            a.statedir.as_deref(),
            Some(std::path::Path::new("/var/lib/x"))
        );
        assert_eq!(
            a.socket.as_deref(),
            Some(std::path::Path::new("/run/x.sock"))
        );
        assert_eq!(a.verbose, Some(2));
        // `-v` short form works too.
        assert_eq!(Args::parse_from(["tailnetd", "-v", "1"]).verbose, Some(1));
    }

    #[test]
    fn args_rejects_unknown_flag() {
        use clap::Parser;
        // An unknown flag is a parse error (clap), not silently ignored — matches Go's flag set.
        assert!(Args::try_parse_from(["tailnetd", "--nope"]).is_err());
    }
}
