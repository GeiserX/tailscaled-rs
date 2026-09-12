//! The IPN state machine — the daemon's spine.
//!
//! This is the Rust analogue of Tailscale's `ipn/ipnlocal.LocalBackend`: the single authority that
//! owns the node's [`Prefs`] (its *intent*) and reconciles that intent against what the engine and
//! control plane actually report. The engine ([`tailscale::Device`]) is immutable once
//! constructed, so "reconfigure" means *rebuild the device from current prefs*; this backend owns
//! that lifecycle.
//!
//! ## State model (MVP subset)
//!
//! ```text
//! NoState ── up ──▶ Starting ── netmap arrives ──▶ Running
//!    ▲                                                 │
//!    │                                              down│
//!    └────────────────── Stopped ◀────────────────────┘
//! ```
//!
//! The reported [`State`] is *derived* from `(device present?, netmap received?, prefs)` rather
//! than stored, so it can never drift from reality. The [`State::NeedsMachineAuth`] and
//! [`State::InUseOtherUser`] variants exist for parity with Go's `ipn.State`, but the MVP cannot
//! actually *reach* either today — the engine does not surface a "machine authorized / awaiting
//! admin approval" signal (see the `// LIMITATION:` note on [`Backend::derive_state`]), and
//! `Backend::up` maps every engine error to a string `Response::Error` rather than to a typed
//! state, so no path produces `NeedsMachineAuth`. `InUseOtherUser` is likewise unreachable in this
//! single-user daemon (auth-key registration only, no interactive multi-profile login). Honest gaps
//! over fabricated states.
//!
//! ## Tailscale SSH server (Phase 4, tsd-46c)
//!
//! When `prefs.ssh_enabled` is set, the backend runs the engine's turnkey, **fail-closed**
//! `Device::listen_ssh` accept loop as a side task bound to the device's lifecycle:
//!
//! - **Spawn-on-install:** [`finish_up`](Backend::finish_up) spawns the SSH server task (an
//!   [`Arc`](std::sync::Arc) clone of the just-installed [`Device`](tailscale::Device)) right after
//!   installing the device, storing its [`JoinHandle`](tokio::task::JoinHandle) in
//!   [`ssh_task`](Backend::ssh_task). The engine authorizes every connection against the
//!   control-pushed SSH policy and drops privileges to the policy-mapped local user.
//! - **Abort + reclaim-on-stop:** [`stop_device`](Backend::stop_device) **aborts** the SSH task and
//!   awaits the aborted handle (so its `Arc` clone is gone), **then** reclaims the sole `Device` from
//!   the `Arc` via [`Arc::into_inner`](std::sync::Arc::into_inner) for a graceful, bounded
//!   `shutdown`. Toggling SSH via `set` on a running node takes the device-rebuild path (a brief
//!   reconnect; see [`drive_set`]), which tears the task down and re-spawns it from the updated pref.
//! - **Opt-in twice — build AND runtime:** the server task is compiled in only with the `ssh` cargo
//!   feature, and only ever started when the `ssh_enabled` pref is set. [`build_config`](Backend::build_config)
//!   preflights both requirements and **fails the bring-up loudly** if SSH was requested without the
//!   feature, or without root (the engine needs root to drop privileges) — never a silent no-SSH node.
//!
//! ## Exit-node leak-safety invariant (tsd-iqq.3)
//!
//! The project's hard constraint is leak-free residential egress: when an exit node is in use, the
//! destination must see the exit's IP, never this host's real IP, and DNS must not leak either. That
//! invariant is satisfied by **construction**, split across the two transport modes:
//!
//! - **TUN mode** is the only OS-wide mode, and it is leak-safe: the engine captures the OS default
//!   route AND takes over the OS resolver (points it at the in-datapath MagicDNS responder, which
//!   delegates recursive resolution to the *exit node's* peerAPI DoH over the overlay — a fresh
//!   overlay socket per query, v4-only, never a host socket). The daemon adds nothing here; the
//!   engine's `ts_host_net` does the takeover (and ONLY in TUN mode).
//! - **Netstack mode** (default) touches neither the OS default route nor the OS resolver, so it has
//!   no OS-level leak surface — but it is also *not* machine-wide egress (only traffic apps send
//!   through the daemon uses the exit). [`build_config`](Backend::build_config) emits a `warn!` when
//!   an exit node is set without TUN, so the "this isn't whole-machine egress" gap is never silent.
//!
//! Consequently the dangerous "OS-wide exit with DNS leaking" configuration is **unreachable**: OS-
//! wide capture *is* TUN mode, and TUN mode *is* where the engine performs the DNS takeover. No
//! per-OS DNS subsystem is needed in the daemon — only the guard + this documented invariant.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};

use crate::localapi::{PeerReport, StatusReport};
use crate::prefs::Prefs;

pub mod alwayson;
mod captive;
mod config;
mod control_url;
mod diag;
pub mod doctor;
pub mod exitnodepolicy;
pub mod install;
pub(crate) mod linkmon;
mod profile;
mod revert_guard;
pub mod selfupdate;
pub mod serve;
mod state;
pub mod syspolicy;

// The reported [`State`] enum lives in [`state`] (with the pure state-derivation helpers) but is
// part of `ipn`'s public surface — `crate::ipn::State` is referenced by `localapi` — so re-export
// it here so the move is invisible to callers.
pub use state::State;

// Crate-internal pure helpers, factored into [`state`] so they are unit-testable without a live
// `Backend`/engine. Imported here so the method call sites below read unchanged.
use state::{derive_state_from, state_from_device};

/// How long to wait for a graceful engine shutdown before it is dropped (more violently). Bounds
/// teardown latency so a wedged engine can't hang the daemon (or an orphaned, superseded `up`).
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// The link-change monitor loop (Go `tailscaled`'s netmon → magicsock `Rebind`): every
/// [`POLL_INTERVAL`](linkmon::POLL_INTERVAL), snapshot the host's interface addresses and, when the
/// network path changed since the last poll, call [`Device::rebind`](tailscale::Device::rebind) so
/// magicsock re-STUNs / re-DERPs / re-binds its UDP sockets to the new path. Runs until the task is
/// aborted (in `stop_device`). The first poll establishes the baseline — the node's own address
/// coming up during bring-up sets the baseline rather than triggering a spurious rebind. A `rebind`
/// error is non-fatal (logged; the loop keeps polling) — a transient rebind failure must not kill the
/// monitor.
async fn link_monitor_loop(device: std::sync::Arc<tailscale::Device>) {
    let mut last = linkmon::snapshot();
    tracing::debug!("linkmon: monitor started; baseline snapshot taken");
    loop {
        tokio::time::sleep(linkmon::POLL_INTERVAL).await;
        let now = linkmon::snapshot();
        if last.changed(&now) {
            tracing::info!("linkmon: host network path changed; rebinding the engine");
            if let Err(e) = device.rebind().await {
                // Non-fatal: a transient rebind failure must not stop the monitor; the next change
                // (or the next poll if this one's effect didn't land) will retry.
                tracing::warn!(error = %e, "linkmon: rebind failed (will keep monitoring)");
            }
            last = now;
        }
    }
}

/// What this daemon can observe of Go's `ImpactsConnectivity` warnables — one field per member of
/// [`captive::ConnectivityWarnable`], carrying the raw fact rather than the verdict.
///
/// Every field is a three-valued answer, because "we could not read this signal" is not the same as
/// "this signal is bad". `None` is *unknown* and never makes the node impacted, which is how Go's
/// tracker behaves too: a warnable it was never told about is healthy, not unhealthy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ConnectivityHealth {
    /// Whether any host interface could carry Internet traffic (Go `netmon.State.AnyInterfaceUp`,
    /// fed to `health.Tracker.SetAnyInterfaceUp`). `false` is Go's `network-status` warnable.
    any_interface_up: Option<bool>,
    /// Whether the engine's net report names a reachable DERP region. `false` is Go's `no-derp-home`
    /// warnable.
    derp_home: Option<bool>,
}

impl ConnectivityHealth {
    /// Nothing observed — every signal unknown, so nothing is unhealthy. Used outside `Running`,
    /// where upstream's loop is not even alive and neither observation is worth paying for.
    const UNKNOWN: Self = Self {
        any_interface_up: None,
        derp_home: None,
    };
}

/// The captive-portal trigger, as a pure decision — extracted from
/// [`Backend::connectivity_impacted`] so the "which state does this run in, and off which signals"
/// question is testable without a live engine (the same split [`derive_state_from`] gets).
///
/// Returns the warnable that makes the node impacted, or `None` when it is not. Impacted means Go's
/// pair: the loop is alive (upstream runs it **only** between entering and leaving `ipn.Running`)
/// *and* at least one `ImpactsConnectivity` warnable is unhealthy — upstream's
/// `for _, w := range state.Warnings { if w.ImpactsConnectivity && w.WarnableCode !=
/// captivePortalWarnable.Code }` (`feature/captiveportal/captiveportal.go`), over the members of that
/// set this daemon can observe.
///
/// When more than one is unhealthy the one with the shortest
/// [`time_to_visible`](captive::ConnectivityWarnable::time_to_visible) wins. Go breaks on whichever
/// warning its map iteration reaches first — order it does not care about, because the *event* that
/// wakes its loop is the first warnable to become visible. Picking the soonest-visible reproduces
/// that timing and is deterministic, which the map order is not.
fn connectivity_impacted_from(
    state: State,
    health: ConnectivityHealth,
) -> Option<captive::ConnectivityWarnable> {
    if state != State::Running {
        return None;
    }
    // Go's `for _, w := range state.Warnings`, over the members this daemon observes: one row per
    // warnable, paired with the signal that decides it. Adding a member is one row.
    [
        (
            captive::ConnectivityWarnable::NetworkStatus,
            health.any_interface_up,
        ),
        (captive::ConnectivityWarnable::NoDerpHome, health.derp_home),
    ]
    .into_iter()
    .filter(|(_, healthy)| *healthy == Some(false))
    .map(|(warnable, _)| warnable)
    .min_by_key(|w| w.time_to_visible())
}

/// The captive-portal detection loop — Go `ipn/ipnlocal/captiveportal.go`, its
/// `checkCaptivePortalLoop` and `performCaptiveDetection`: notice when this node is stuck behind an
/// airport/hotel Wi-Fi login page, and say so, instead of leaving the operator with an opaque
/// "cannot reach control".
///
/// The task runs for the daemon's whole life, but it is **inert outside `Running`**: the gate below
/// is false in every other state, which is how this fork expresses Go's loop *lifetime*. Upstream
/// spawns `checkCaptivePortalLoop` when the backend enters `ipn.Running` and cancels its context on
/// the way out (`ipn/ipnlocal/local.go`, `enterStateLocked`); a poll whose gate is false is the same
/// thing without a task per state edge. Never returns.
///
/// ## The trigger
///
/// Detection is not periodic background chatter: it runs only while
/// [`connectivity_impacted`](Backend::connectivity_impacted) names a warnable — the node is `Running`
/// and one of Go's `ImpactsConnectivity` warnables this daemon can observe
/// ([`captive::ConnectivityWarnable`]) is unhealthy — and
/// [`should_run_captive_portal_detection`](Backend::should_run_captive_portal_detection) allows it
/// (the operator wants the node up). A healthy `Running` node, a node still coming up, and a
/// deliberately-`down` node all probe **zero** times.
///
/// The first pass of an episode waits the triggering warnable's
/// [`settle_time`](captive::ConnectivityWarnable::settle_time) — its Go `TimeToVisible` plus
/// [`DETECTION_INTERVAL`](captive::DETECTION_INTERVAL). Upstream spends both: its health tracker only
/// makes a warnable visible after the former, and its captive loop then spends the latter on its
/// timer before probing. The sum is why a node whose first DERP measurement is merely still in flight
/// does not probe on every bring-up. The wait is measured from the moment *that* warnable became the
/// unhealthy one, so a warnable taking over mid-episode gets its own wait rather than inheriting the
/// previous one's clock ([`captive::EpisodeTimer`]).
///
/// While connectivity stays impacted the pass repeats every
/// [`RECHECK_INTERVAL`](captive::RECHECK_INTERVAL). Go instead re-arms its 2s timer off health-tracker
/// events; this fork has no health event bus, so it polls — and backing the repeat off keeps a node on
/// a genuinely dead network from probing tailscale.com every two seconds forever (which matters most
/// for exactly the headless cloud node that will never have a portal).
///
/// ## Why the lock is dropped across the probe
///
/// A detection pass makes real HTTP requests and can take [`TIMEOUT`](captive::TIMEOUT). It therefore
/// runs with the backend lock **released** — the same discipline `reconcile_on_reload` follows — so a
/// probe can never head-of-line block a concurrent `status`/`up`/`down`. The lock is retaken only to
/// read the gate and to write the verdict.
pub async fn captive_portal_loop(backend: std::sync::Arc<tokio::sync::Mutex<Backend>>) {
    // The episode's schedule: which warnable is being waited out and since when, plus when this
    // episode last probed. Cleared whenever connectivity recovers, so a later episode waits out the
    // settle time again rather than probing instantly. See [`captive::EpisodeTimer`] for why the
    // wait is bound to the warnable rather than to the episode.
    let mut timer = captive::EpisodeTimer::default();

    loop {
        tokio::time::sleep(captive::POLL_INTERVAL).await;

        // Brief lock: read the gate, and on the healthy path clear the warning in the same
        // acquisition. Never hold it across the probe below.
        let impacted = {
            let mut be = backend.lock().await;
            let impacted = if be.should_run_captive_portal_detection() {
                be.connectivity_impacted().await
            } else {
                None
            };
            if impacted.is_none() {
                // Go's healthy branch: connectivity is fine, so we know for sure there is no portal
                // in the way — drop any warning. `set_captive_portal_detected` is a no-op (and
                // silent) when nothing was raised, so a healthy node's tick costs one uncontended
                // lock and two field reads.
                be.set_captive_portal_detected(false);
            }
            impacted
        };

        let Some(warnable) = impacted else {
            timer.recovered();
            continue;
        };

        if !timer.probe_due(warnable, tokio::time::Instant::now()) {
            continue;
        }

        // OFF-LOCK. The endpoint set is empty because the engine exposes no DERP map to the daemon —
        // see `captive`'s module docs and engine ask #33; `available_endpoints` then yields the two
        // Tailscale endpoints Go always appends, which need no map. When a map does become available,
        // this is the one call site that changes.
        let found = captive::detect(&[], None).await;

        // Re-read the gate under the lock before recording: the node may have found a relay (or left
        // `Running` altogether) while we were probing, in which case Go's healthy branch owns the
        // verdict, not a stale one.
        let mut be = backend.lock().await;
        if be.should_run_captive_portal_detection() && be.connectivity_impacted().await.is_some() {
            be.set_captive_portal_detected(found);
        } else {
            be.set_captive_portal_detected(false);
        }
    }
}

/// The always-on reconnect timer's runtime half — Go's `b.clock.AfterFunc` callback from
/// `startReconnectTimerLocked`, plus the always-on slice of `sysPolicyChanged`
/// (`ipn/ipnlocal/local.go`). A daemon-lifetime task, spawned by `tailnetd` beside
/// [`captive_portal_loop`]. Never returns.
///
/// ## What it is for
///
/// A disconnect the always-on gate permits leaves the node down and, by itself, indefinitely so:
/// [`Backend::override_always_on`] is what stops the policy re-assert from undoing it. `ReconnectAfter`
/// is the administrator's bound on that window — "a user with a reason may take the node down for
/// exactly this long and no longer" — and something has to be awake to close it. That is this loop.
///
/// ## Why a loop rather than a task per arming
///
/// Firing means a bring-up, and a bring-up needs the `Arc<Mutex<Backend>>` that the backend cannot
/// hand to itself from inside `down`. So the arming lives in a [`watch`](tokio::sync::watch) cell on
/// the backend ([`Backend::watch_reconnect`]) and this loop — which does hold the `Arc` — sleeps
/// against it. Arming, re-arming and cancelling are all a `send` into that cell, which wakes the
/// loop immediately: there is no poll interval to make a cancellation lag, and a node that never
/// disconnects costs exactly one parked task.
///
/// The same loop carries the policy-change subscription, because Go resets the override from
/// `sysPolicyChanged` and this fork's policy-change edge is a process-global tick
/// ([`syspolicy::watch_policy`]) with no backend receiver to hang off. Honest scope note: this
/// build's one policy source captures its file at startup, so that tick fires on a `syspolicy
/// reload` without any value having moved — which is exactly why
/// [`Backend::sys_policy_changed`] compares a snapshot instead of resetting on every tick.
///
/// ## The guards
///
/// When the sleep elapses, the arming has to re-prove itself under the lock — it is still the live
/// timer, and its profile is still the current one — before anything is brought up. See
/// [`ReconnectTimer`] for why each guard exists. The bring-up itself runs **off-lock** through
/// [`drive_up`], the same discipline every other bring-up path here follows, so an automatic
/// reconnect never head-of-line blocks a concurrent `status`/`down`.
pub async fn reconnect_loop(backend: std::sync::Arc<tokio::sync::Mutex<Backend>>) {
    let mut armed_rx = backend.lock().await.watch_reconnect();
    let mut policy_rx = syspolicy::watch_policy();

    loop {
        // Take a copy of the current arming: the sleep below must not hold a borrow of the cell,
        // and the value is what the fire-time guards are checked against.
        let armed = armed_rx.borrow_and_update().clone();
        tokio::select! {
            // The cell moved: a new arming replaced this one, or it was cancelled. Re-read it.
            changed = armed_rx.changed() => {
                if changed.is_err() {
                    // The backend (and its sender) is gone — the daemon is shutting down.
                    return;
                }
            }
            // The effective policy may have moved. Only a change to an always-on key revokes an
            // outstanding exemption, which `sys_policy_changed` decides.
            changed = policy_rx.changed() => {
                if changed.is_err() {
                    // The policy bus is a process-global `LazyLock` sender that nothing drops, so
                    // this is unreachable in a running daemon. Ending the loop is still the right
                    // answer if it ever happens: a receiver that returns an error immediately would
                    // otherwise spin this task at full speed.
                    tracing::warn!(
                        "always-on: the policy-change bus closed; stopping the reconnect loop"
                    );
                    return;
                }
                let always_on = syspolicy::always_on_keys();
                let exit_node = syspolicy::exit_node_keys();
                let mut be = backend.lock().await;
                be.sys_policy_changed(always_on);
                // The second of Go's two independent `HasChangedAnyOf` questions in
                // `sysPolicyChanged`: an exit-node key moving revokes a standing exit-node override
                // and says nothing about the always-on exemption (or the reverse).
                be.exit_node_policy_changed(exit_node);
            }
            // The window elapsed.
            () = sleep_until_armed(armed.as_ref()) => {
                let Some(armed) = armed else {
                    unreachable!("sleep_until_armed never completes without an arming");
                };
                reconnect_now(&backend, &armed).await;
            }
        }
    }
}

/// Sleep until `armed`'s deadline, or forever when nothing is armed — the "no timer" arm of
/// [`reconnect_loop`]'s `select!`, kept a named future so the loop reads as the three edges it is.
async fn sleep_until_armed(armed: Option<&ReconnectTimer>) {
    match armed {
        Some(timer) => tokio::time::sleep_until(timer.deadline()).await,
        None => std::future::pending().await,
    }
}

/// Fire one due reconnect: re-check Go's two guards under the lock, then bring the node up off-lock
/// and log the outcome in Go's words (`automatically reconnected as %q after %v`, or the matching
/// failure line).
///
/// The bring-up carries **no auth key**, which is what Go's `WantRunning:true` edit amounts to: the
/// node resumes from the registration it still holds. A profile whose key a `logout` discarded has
/// nothing to resume, so this reaches `NeedsLogin` and takes the failure line — the honest report,
/// and the same terminal state Go's edit leaves that profile in.
async fn reconnect_now(
    backend: &std::sync::Arc<tokio::sync::Mutex<Backend>>,
    armed: &ReconnectTimer,
) {
    let profile = {
        let mut be = backend.lock().await;
        if !be.claim_due_reconnect(armed) {
            return;
        }
        // Go names the profile's login name in the message; this fork has no user profile on the
        // backend, so it names the profile the way every other operator-facing line here does (the
        // display name, falling back to the id) — the same choice the always-on audit record makes.
        be.current_profile_name().await
    };
    let after = armed.after_go();
    match drive_up(backend, None, None, UpOptions::default()).await {
        Ok(()) => tracing::info!(
            "always-on: automatically reconnected as {} after {after}",
            syspolicy::quoted(&profile)
        ),
        Err(e) => tracing::warn!(
            error = %format!("{e:#}"),
            "always-on: failed to automatically reconnect as {} after {after}",
            syspolicy::quoted(&profile)
        ),
    }
}

/// One `serve --tcp` accept loop: bind the node's tailnet IPv4 on `port` and splice every inbound
/// connection to `target` (a localhost `host:port`). Runs forever until the listener errors (engine
/// torn down) or the task is aborted. Spawns one sub-task per accepted connection so a slow peer
/// never blocks new accepts. This is the `nc` splice, inbound: `tcp_listen`/`accept` then
/// `copy_bidirectional` to a `TcpStream::connect`.
///
/// The detached splice tasks are bounded two ways so a flood of idle peers can't leak tasks/fds
/// unboundedly (the accept loop itself is in the supervisor's `JoinSet`, but the per-connection
/// splices are not): a shared [`Semaphore`](tokio::sync::Semaphore) caps the in-flight count
/// ([`MAX_SERVE_CONNECTIONS`]) and a [`SPLICE_TIMEOUT`] caps each splice's lifetime. At cap, a new
/// connection is dropped (shed, not queued). The `conn_limit` is per-accept-loop (each plain-TCP
/// forward entry gets its own), passed in so the bound is visible at the spawn site.
async fn serve_accept_loop(
    device: std::sync::Arc<tailscale::Device>,
    port: u16,
    target: String,
    conn_limit: std::sync::Arc<tokio::sync::Semaphore>,
) {
    // Bind the node's tailnet IPv4 on the served port. `ipv4_addr` resolves once the netmap assigns
    // an address; an error means we never got one (engine gone) — log + exit the loop.
    let ipv4 = match device.ipv4_addr().await {
        Ok(ip) => ip,
        Err(e) => {
            tracing::error!(error = %e, port, "serve: no tailnet IPv4; listener not started");
            return;
        }
    };
    let listen_addr = std::net::SocketAddr::from((ipv4, port));
    let listener = match device.tcp_listen(listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, %listen_addr, "serve: failed to listen");
            return;
        }
    };
    tracing::info!(%listen_addr, %target, "serve: forwarding inbound tailnet TCP to local target");
    loop {
        // The engine's `TcpListener::accept` yields the inbound `TcpStream` directly (no peer-addr
        // tuple, unlike std/tokio).
        let inbound = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::debug!(error = %e, %listen_addr, "serve: accept loop ended");
                return;
            }
        };
        // Acquire a splice permit BEFORE spawning; if the per-loop cap is exhausted, drop this
        // connection (closing it) rather than queueing unboundedly. The permit is moved into the task
        // and released when the splice ends — so the cap bounds the live splice count, shedding a
        // flood instead of leaking tasks/fds.
        let Ok(permit) = std::sync::Arc::clone(&conn_limit).try_acquire_owned() else {
            tracing::warn!(%target, "serve: connection cap reached; dropping connection");
            continue;
        };
        let target = target.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::net::TcpStream::connect(&target).await {
                Ok(mut local) => {
                    let mut inbound = inbound;
                    // Bidirectional splice inbound(tailnet) <-> local(target), to EOF either side,
                    // bounded by SPLICE_TIMEOUT so an abandoned/dead idle peer can't pin the task (and
                    // its permit + fds) forever. On elapse, drop (the streams close on task exit).
                    match tokio::time::timeout(
                        SPLICE_TIMEOUT,
                        tokio::io::copy_bidirectional(&mut inbound, &mut local),
                    )
                    .await
                    {
                        Ok(_) => {}
                        Err(_) => tracing::debug!(
                            %target,
                            "serve: splice exceeded SPLICE_TIMEOUT; dropping idle/abandoned connection"
                        ),
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, %target, "serve: dial to local target failed");
                }
            }
        });
    }
}

/// LANE 3 of [`spawn_serve`](Backend::spawn_serve) — arm Funnel (Go `tailscale funnel`): expose each
/// funnel-enabled port's web serve to the PUBLIC internet. Extracted as a free fn (it was the deepest
/// nest in the supervisor) — it runs off the backend lock (holds only the device `Arc`) and pushes
/// its accept loops into the supervisor-owned `loops` so abort tears them down, exactly as inline.
///
/// For each funnel port with a web proxy backend it calls the engine's `listen_funnel` (fail-closed:
/// gates on node-attr + funnel-port cap + cert) and — because funnel hands back RAW TLS-terminated
/// streams (NOT internally proxied like LANE 2) — spawns a [`funnel_accept_loop`] that splices each
/// public connection to the local backend. The public ingress data path is live-only/SaaS-only (no
/// relay against a self-hosted control plane), so a fed loop needs a real Funnel-enabled SaaS tailnet;
/// arming + gating is what happens here. Non-fatal throughout — a failure logs and the other lanes
/// (TCP-forward, web) keep running.
async fn arm_funnel_lane(
    device: &std::sync::Arc<tailscale::Device>,
    cfg: &serve::ServeConfig,
    loops: &mut tokio::task::JoinSet<()>,
) {
    let funnel_ports = serve::funnel_ports(cfg);
    if funnel_ports.is_empty() {
        return;
    }
    // Need the node MagicDNS name (the funnel hostname / cert name) + each port's backend.
    let fqdn = match device.self_node().await {
        Ok(node) => node.fqdn(false),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "funnel: could not resolve node MagicDNS name; skipping funnel lane"
            );
            return;
        }
    };
    for port in funnel_ports {
        // Funnel exposes a serve: the port must have a web proxy backend to splice to. (Mirrors Go's
        // "funnel=on but no serve config" warning.) Resolve via `web_proxy_backend`, which consults
        // BOTH the legacy `tcp_forward` AND the Go `Web` map root proxy — the handler-only
        // `is_web_serve(h)` + `h.tcp_forward` path finds nothing for a serve created by the current
        // CLI (which writes the `Web` map with an empty `tcp_forward`), so funnel would never arm.
        let backend = serve::web_proxy_backend(cfg, port);
        let Some(backend) = backend else {
            tracing::warn!(
                port,
                "funnel: enabled for a port with no web proxy backend — skipping \
                 (funnel exposes a serve; configure `serve https <port> <target>` first)"
            );
            continue;
        };
        let fcfg = tailscale::ServeConfig {
            name: fqdn.clone(),
            port,
            target: tailscale::ServeTarget::Proxy {
                to: backend.clone(),
            },
        };
        // `FunnelOptions::default()` = `funnel_only: false`. On this listener that flag is a documented
        // no-op (the ingress data path carries only relay-delivered PUBLIC traffic regardless), so
        // `default()` is intentional — not a security-relevant choice to tighten to `funnel_only: true`.
        match device
            .listen_funnel(&fcfg, ts_control::FunnelOptions::default())
            .await
        {
            Ok(mut rx) => {
                tracing::info!(name = %fqdn, port, "funnel: armed via engine listen_funnel");
                // Funnel hands back RAW TLS-terminated streams (unlike LANE 2's internal proxy), so
                // splice each to the local backend ourselves. The accept loop is spawned as a closure
                // (not a named fn) because the receiver type — `ts_runtime::funnel::FunnelAcceptedReceiver`
                // — is an engine-internal type not re-exported at the facade root, and `ts_runtime` is
                // only a transitive dep here; inferring it in the closure avoids a direct dependency.
                // Holding `rx` keeps the listener alive; the loop ends on receiver close / task abort.
                let backend = backend.clone();
                loops.spawn(async move {
                    // Per-funnel-loop splice cap. Funnel is PUBLIC-internet-facing, so a slow-loris of
                    // idle public connections must not spawn splice tasks (leaking fds) without bound —
                    // at cap a new connection is dropped (shed, not queued). See `MAX_SERVE_CONNECTIONS`.
                    let conn_limit =
                        std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_SERVE_CONNECTIONS));
                    while let Some(accepted) = rx.recv().await {
                        // Acquire a splice permit before spawning; drop the connection if the cap is
                        // exhausted. Moved into the task, released when the splice ends.
                        let Ok(permit) = std::sync::Arc::clone(&conn_limit).try_acquire_owned()
                        else {
                            tracing::warn!(
                                %backend,
                                "funnel: connection cap reached; dropping public connection"
                            );
                            continue;
                        };
                        let backend = backend.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            // `accepted.target`/`src` are the public ingress host:port hit + the public
                            // client's addr (audit/debug trace of who reached the funnel).
                            tracing::debug!(
                                target = %accepted.target,
                                src = %accepted.src,
                                %backend,
                                "funnel: proxying public ingress to local backend"
                            );
                            let mut stream = accepted.stream;
                            match tokio::net::TcpStream::connect(&backend).await {
                                Ok(mut local) => {
                                    // Bounded by SPLICE_TIMEOUT so an abandoned public peer can't pin
                                    // the task/permit/fds forever; on elapse, drop.
                                    match tokio::time::timeout(
                                        SPLICE_TIMEOUT,
                                        tokio::io::copy_bidirectional(&mut stream, &mut local),
                                    )
                                    .await
                                    {
                                        Ok(_) => {}
                                        Err(_) => tracing::debug!(
                                            %backend,
                                            "funnel: splice exceeded SPLICE_TIMEOUT; dropping idle/abandoned connection"
                                        ),
                                    }
                                }
                                Err(e) => tracing::warn!(
                                    error = %e, %backend,
                                    "funnel: dial to local backend failed"
                                ),
                            }
                        });
                    }
                });
            }
            // Fail-closed in the engine: node lacks the https/funnel node-attrs, the port isn't in the
            // funnel-ports cap, or the cert couldn't be issued (acme off / non-SaaS control). Non-fatal
            // — other lanes keep running.
            Err(e) => tracing::warn!(
                error = %e, port,
                "funnel: engine listen_funnel failed (node-attr/port/cert gate — needs \
                 a Funnel-enabled SaaS tailnet + the `acme` feature); skipping this port"
            ),
        }
    }
}

/// Complete and validate `--advertise-tags` values, returning the values as the daemon will store
/// and advertise them.
///
/// **Completion** first, exactly as Go's `prefsFromUpArgs` does before it validates: a value that
/// contains NO colon at all gets the `tag:` prefix added for it, so `--advertise-tags server,ci`
/// means `tag:server,tag:ci`. The no-colon condition is the whole rule — a value that already has a
/// colon is passed through untouched, so a malformed `foo:bar` still reaches the check below and is
/// refused by name instead of being quietly turned into a `tag:foo:bar` nobody asked for.
///
/// **Validation** then runs byte-for-byte against Go's `tailcfg.CheckTag` (which `up`/`set` apply
/// via `Hostinfo.CheckRequestTags`): each must be `tag:<name>` where `<name>` is non-empty,
/// **starts with an ASCII letter**, and contains only `[A-Za-z0-9-]`. Matching Go's gate exactly
/// matters because the engine does NOT re-validate — it ships `requested_tags` straight to control —
/// so this is the *only* client-side check; a too-lax gate lets a malformed tag reach control and be
/// rejected there with a confusing error instead of failing locally with a precise one. Returns the
/// first offender, quoting the COMPLETED value (Go's `tag: %q`) so the operator is shown the tag as
/// the daemon would have seen it rather than the shorthand they typed.
///
/// Go completes in the CLI and validates in `tailcfg`; this fork does both here, daemon-side, so
/// that `up` and `set` keep sharing one notion of what a tag is — a direct LocalAPI caller gets the
/// same completion the CLI does. Pure so it can guard both `begin_up` and `begin_set` before any pref
/// is mutated.
fn complete_and_validate_advertise_tags(tags: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(tags.len());
    for t in tags {
        // Allow operators to omit the `tag:` prefix; if the tag has no colon at all, add it for
        // them (Go `prefsFromUpArgs`).
        let t = if t.contains(':') {
            t.clone()
        } else {
            format!("tag:{t}")
        };
        let name = t.strip_prefix("tag:").ok_or_else(|| {
            anyhow!("invalid tag {t:?}: tags must be of the form tag:<name> (e.g. tag:server)")
        })?;
        match name.bytes().next() {
            None => {
                return Err(anyhow!(
                    "invalid tag {t:?}: the tag name (after 'tag:') is empty"
                ));
            }
            // Go requires the first name char to be a letter.
            Some(b) if !b.is_ascii_alphabetic() => {
                return Err(anyhow!(
                    "invalid tag {t:?}: tag names must start with a letter (after 'tag:')"
                ));
            }
            _ => {}
        }
        // Go restricts name chars to letters, digits, and '-'.
        if name
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && b != b'-')
        {
            return Err(anyhow!(
                "invalid tag {t:?}: tag names may contain only letters, digits, or '-'"
            ));
        }
        out.push(t);
    }
    Ok(out)
}

/// The advertised-route SET a pending `up`/`set` would leave behind, as the pair
/// [`crate::routes::calc_advertise_routes`] asks about: the raw routes, and whether this node
/// advertises itself as an exit node.
///
/// Go needs no such composition — its `AdvertiseRoutes` is ONE pref, and `CalcAdvertiseRoutes` runs
/// on the CLI's two flags before it is written. This fork models the exit-node intent as its own
/// pref, so the two halves of the set can be changed one at a time (`set --advertise-routes` today,
/// `set --advertise-exit-node=false` tomorrow) and the set can only be judged after they are put
/// back together: a named override where the request names one, the persisted pref otherwise.
///
/// `reset` is `up --reset`, where an UNNAMED pref goes back to its default rather than being kept —
/// so the set that request leaves behind is composed against [`Prefs::default`], not against the
/// prefs on disk. Pure, so it can run in `begin_up`/`begin_set` before a single pref is mutated.
fn prospective_route_set(
    named_routes: Option<&Vec<String>>,
    named_advertise_exit_node: Option<bool>,
    current: &Prefs,
    reset: bool,
) -> (Vec<String>, bool) {
    let defaults = Prefs::default();
    let base = if reset { &defaults } else { current };
    (
        named_routes
            .cloned()
            .unwrap_or_else(|| base.advertise_routes.clone()),
        named_advertise_exit_node.unwrap_or(base.advertise_exit_node),
    )
}

/// Reject an `auto:`-prefixed exit-node selector (Go `tailscale up/set --exit-node auto:any`, which
/// enables *automatic* exit-node selection via `ipn.Prefs.AutoExitNode`).
///
/// This build models the exit node as a single concrete selector (`tailscale::ExitNodeSelector`: a
/// bare IP → `Ip`, anything else → `Name`) and has **no** auto-selection machinery. Without this
/// guard, `--exit-node auto:any` would parse — silently — as a request to route through a peer
/// *named* `"auto:any"`, which matches nothing, so exit routing would break with no error (the
/// `FromStr` is infallible). Fail loudly and honestly instead, so the operator isn't left with a
/// silently-broken exit. (Go: `ipn.ParseAutoExitNodeString` / `AnyExitNode = "any"`,
/// `cmd/tailscale/cli/up.go` `prefsFromUpArgs` + `set.go` `runSet`.) Pure, so it can pre-validate
/// both `begin_up` and `begin_set` before any pref is mutated. `None`/cleared and concrete
/// IP/name/MagicDNS selectors pass through unchanged.
fn validate_exit_node_selector(exit_node: Option<&str>) -> Result<()> {
    if let Some(sel) = exit_node
        && sel.starts_with("auto:")
    {
        return Err(anyhow!(
            "exit node {sel:?}: automatic exit-node selection (`auto:`…) is not supported by this \
             build — pass a concrete exit node by tailnet IP, MagicDNS name, or stable node ID"
        ));
    }
    Ok(())
}

/// The netmap facts an operator-supplied `--exit-node` VALUE is resolved against: this fork's
/// stand-in for the `ipnstate.Status` Go's CLI fetches and hands to `Prefs.SetExitNodeIP`
/// (`ipn/prefs.go`) before any pref is written. Projected out of one [`Backend::status`] snapshot by
/// [`ExitNodeFacts::from_status`], so the resolution sees exactly what `tnet status` and
/// `tnet exit-node list` show — one netmap view, no second source of truth.
///
/// [`Default`] is the "nothing known" view (not running, no addresses, no peers), which is what a
/// node that has never come up honestly has; [`resolve_exit_node_arg`] stages its refusals around
/// that, exactly as Go does.
#[derive(Debug, Default, Clone)]
pub(crate) struct ExitNodeFacts {
    /// Whether the node is [`State::Running`] — i.e. whether `peers` is an authoritative netmap
    /// view. Go gates its two netmap-backed refusals on `BackendState == "Running"` for the same
    /// reason: before that, "no peer has this IP" only means "no netmap yet".
    running: bool,
    /// This node's own tailnet addresses (v4 and v6, when a netmap has assigned them).
    self_ips: Vec<std::net::IpAddr>,
    /// The tailnet's MagicDNS suffix (e.g. `tail0123.ts.net`), used to derive a peer's *base* name
    /// from its FQDN — Go's `dnsname.TrimSuffix(ps.DNSName, st.MagicDNSSuffix)`.
    magic_dns_suffix: Option<String>,
    /// The netmap peers, each carrying `is_exit_node` (Go `ipnstate.PeerStatus.ExitNodeOption`) —
    /// the same field `tnet exit-node list` builds its table from.
    peers: Vec<PeerReport>,
}

impl ExitNodeFacts {
    /// Project a [`StatusReport`] into the subset the resolution reads. Consumes the report: it is
    /// built for this call and the peer list is the expensive part, so move rather than clone.
    fn from_status(st: StatusReport) -> Self {
        let self_ips = [st.self_ipv4.as_deref(), st.self_ipv6.as_deref()]
            .into_iter()
            .flatten()
            .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
            .collect();
        Self {
            running: st.state == State::Running.as_str(),
            self_ips,
            magic_dns_suffix: st.magic_dns_suffix,
            peers: st.peers,
        }
    }
}

/// The host-derived inputs [`Backend::check_prefs_gated`] consults, passed IN rather than read from
/// the process environment so every refusal they contribute is unit-testable (`set_var` is `unsafe`
/// in edition 2024 and races the parallel test harness — the same reason
/// [`state_dir_with_source`](crate::state_dir_with_source) takes an injectable environment lookup).
/// One struct rather than two more parameters: they travel together, and the check already carries
/// the caller's five prospective-pref overrides.
struct CheckPrefsEnv<'a> {
    /// [`featureknob::can_run_tailscale_ssh`](crate::featureknob::can_run_tailscale_ssh)'s verdict
    /// for this host. Consulted only when the prospective posture actually runs SSH, matching Go,
    /// which calls it from `checkSSHPrefsLocked` only once `RunSSH` is set.
    ssh_gate: Result<()>,
    /// The netmap view a NAMED exit-node selector is resolved against (see
    /// [`resolve_exit_node_arg`]). [`ExitNodeFacts::default`] when the request names none.
    exit_node_facts: &'a ExitNodeFacts,
}

/// Whether `arg` names `peer`, in any of the three spellings Go's `exitNodeIPOfArg` accepts: the
/// peer's base name, its FQDN, and its FQDN without the trailing root dot — all
/// case-insensitively. A trailing dot on the *argument* is ignored too, so the operator can paste
/// either form of either spelling. This is deliberately the same rule the engine's
/// `Node::matches_name` applies when it later resolves the stored selector, so a value accepted here
/// is a value the engine will route through (and not a value that passes validation and then matches
/// no peer).
fn peer_matches_exit_node_name(
    peer: &PeerReport,
    arg: &str,
    magic_dns_suffix: Option<&str>,
) -> bool {
    let want = arg.strip_suffix('.').unwrap_or(arg);
    let fqdn = peer.name.strip_suffix('.').unwrap_or(peer.name.as_str());
    if want.eq_ignore_ascii_case(fqdn) {
        return true;
    }
    // Base name = FQDN with `.<magic-dns-suffix>` chopped off (case-insensitively, like Go's
    // `dnsname.TrimSuffix`). `str::get` returns `None` rather than panicking if the cut would land
    // inside a multi-byte character, so a non-ASCII peer name can never panic here.
    let Some(suffix) = magic_dns_suffix else {
        return false;
    };
    let suffix = suffix.strip_suffix('.').unwrap_or(suffix);
    let Some(cut) = fqdn.len().checked_sub(suffix.len() + 1) else {
        return false;
    };
    let (Some(base), Some(tail)) = (fqdn.get(..cut), fqdn.get(cut..)) else {
        return false;
    };
    !base.is_empty()
        && tail
            .strip_prefix('.')
            .is_some_and(|t| t.eq_ignore_ascii_case(suffix))
        && want.eq_ignore_ascii_case(base)
}

/// Whether one of `peer`'s tailnet addresses is `ip` (Go compares against every
/// `PeerStatus.TailscaleIPs` entry).
fn peer_has_ip(peer: &PeerReport, ip: std::net::IpAddr) -> bool {
    [Some(peer.ipv4.as_str()), peer.ipv6.as_deref()]
        .into_iter()
        .flatten()
        .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
        .any(|peer_ip| peer_ip == ip)
}

/// Resolve an operator-supplied `--exit-node` VALUE against the netmap — the port of Go's
/// `exitNodeIPOfArg` (`ipn/prefs.go`), which is six refusals in one function.
///
/// The engine's `ExitNodeSelector: FromStr` is **infallible** (a bare IP → `Ip`, anything else →
/// `Name`), so without this every value is accepted, stored, and then silently matches no peer:
/// traffic is not routed through an exit node and nothing ever said why. That is the same trap the
/// `auto:` guard in [`validate_exit_node_selector`] was written to close, left open for every other
/// value.
///
/// Go's refusals, in order, all reproduced here:
///
/// 1. a value that parses as an IP but is **this machine's own** address — `ExitNodeLocalIPError`,
///    "cannot use %s as an exit node as it is a local IP address to this machine", which Go's `up`
///    and `set` both re-wrap as "%w; did you mean --advertise-exit-node?";
/// 2. once Running, an IP **no peer** holds — "no node found in netmap with IP %v";
/// 3. a peer that is **not advertising** an exit node — "node %v is not advertising an exit node";
/// 4. a non-IP value while the **peer list is empty** — "cannot resolve exit node by hostname while
///    Tailscale is starting up; please use its Tailscale IP address instead" (Go refuses rather than
///    attempting a resolution that could only fail);
/// 5. a name **no peer** answers to — "invalid value %q for --exit-node; must be IP or peer
///    hostname";
/// 6. a name **more than one** peer answers to — "ambiguous exit node name %q".
///
/// The **staging** is Go's, not a stricter rule: the local-IP refusal (1) and the empty-value
/// refusal apply always, because they need no netmap; the netmap-backed refusals (2) and (3) apply
/// only once the node is Running, because before that "not in the netmap" only means "no netmap
/// yet"; and a name is refused outright (4) rather than resolved against a peer list that does not
/// exist.
///
/// Two deliberate, documented deviations from Go. (a) Go re-wraps the local-IP error with
/// "did you mean --advertise-exit-node?" in the CLI, for `up` and `set` only; the resolution here is
/// daemon-side and shared, so the hint is part of the one message and `check-prefs` reports it too —
/// the hint is just as true there. (b) Go's empty-value guard returns the opaque `os.ErrInvalid`
/// ("invalid argument"); this says what to pass instead.
///
/// Pure: every fact it reads arrives in `facts`, so it can run before a single pref is mutated, and
/// it is unit-testable without an engine.
fn resolve_exit_node_arg(arg: &str, facts: &ExitNodeFacts) -> Result<()> {
    if arg.trim().is_empty() {
        return Err(anyhow!(
            "--exit-node was given an empty value; pass a tailnet IP address or a peer name, or \
             clear the exit node instead"
        ));
    }
    // The IP branch. A value that parses as an IP is never matched by name (Go returns from this
    // branch unconditionally), so a peer that happens to be *named* after an IP cannot shadow it.
    if let Ok(ip) = arg.parse::<std::net::IpAddr>() {
        // (1) Our own address. Checked whatever the state: a self address we know about is a fact
        // about this machine, not about the netmap's completeness. An operator who types it almost
        // always meant to OFFER egress, hence Go's hint.
        if facts.self_ips.contains(&ip) {
            return Err(anyhow!(
                "cannot use {arg} as an exit node as it is a local IP address to this machine; \
                 did you mean --advertise-exit-node?"
            ));
        }
        // Before Running there is no authoritative peer list, so an unknown IP is accepted (Go
        // does the same): it may well be a peer this node has not learned about yet.
        if !facts.running {
            return Ok(());
        }
        return match facts.peers.iter().find(|p| peer_has_ip(p, ip)) {
            // (2) Running, netmap in hand, and nobody holds this address.
            None => Err(anyhow!("no node found in netmap with IP {ip}")),
            // (3) The peer exists but never advertised a default route, so selecting it would
            // route nothing.
            Some(p) if !p.is_exit_node => Err(anyhow!("node {ip} is not advertising an exit node")),
            Some(_) => Ok(()),
        };
    }

    // The name branch. (4) With no peers there is nothing to resolve against: refuse with the
    // remedy rather than guess.
    if facts.peers.is_empty() {
        return Err(anyhow!(
            "cannot resolve exit node by hostname while Tailscale is starting up; please use its \
             Tailscale IP address instead"
        ));
    }
    let suffix = facts.magic_dns_suffix.as_deref();
    let mut matched = 0usize;
    for peer in &facts.peers {
        if !peer_matches_exit_node_name(peer, arg, suffix) {
            continue;
        }
        matched += 1;
        // (3) again, by name. Go reports it from inside the match loop — i.e. a named peer that
        // offers no exit is refused as such even when the name is ambiguous — and reports the
        // peer's IP, which is the identity the operator has to act on.
        if !peer.is_exit_node {
            return Err(anyhow!(
                "node {} is not advertising an exit node",
                peer.ipv4
            ));
        }
    }
    match matched {
        // (5) A typo, or a peer that has left the tailnet.
        0 => Err(anyhow!(
            "invalid value {arg:?} for --exit-node; must be IP or peer hostname"
        )),
        1 => Ok(()),
        // (6) Two peers answer to the name; picking one silently would be a coin flip over which
        // machine sees the operator's traffic.
        _ => Err(anyhow!("ambiguous exit node name {arg:?}")),
    }
}

/// Per-daemon-process counter that disambiguates two diagnostic markers taken in the same second
/// ([`Backend::bugreport`]). `bugreport --record` prints one marker before the reproduction and one
/// after; the coarse Unix-seconds stamp alone would render both identically when the operator is
/// quick, and a before/after pair that reads as one value brackets nothing. Relaxed ordering is
/// enough: the only requirement is that two markers from one daemon differ, not that the numbers
/// track any other event. Process-local and NOT persisted — a restart re-starts at 0, which is fine
/// because the seconds stamp already separates runs.
static MARKER_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Harden an operator-supplied `bugreport` note for embedding in the diagnostic marker: replace every
/// control character (newlines, tabs, ANSI escapes, etc.) with `_` so the marker stays a single,
/// clean, copy-pasteable token. The note is free text the operator types, so it is untrusted for
/// formatting purposes (a stray newline would split the marker; an escape could corrupt a terminal
/// that later echoes it). All other characters are preserved.
fn sanitize_marker_note(note: &str) -> String {
    note.chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect()
}

/// Max concurrent in-flight splice tasks **per serve/funnel accept loop**. Defense-in-depth against a
/// connection flood: `serve --tcp` is tailnet-facing and funnel is PUBLIC-internet-facing, so a
/// slow-loris of idle connections must not be able to spawn splice tasks (and leak fds) without
/// bound. Matches the LocalAPI server's `MAX_CONNECTIONS` precedent (`server.rs`). A permit is held
/// for a splice's whole lifetime; when the loop is at cap a new connection is dropped (not queued),
/// so a flood is *shed*, not absorbed.
const MAX_SERVE_CONNECTIONS: usize = 128;

/// Hard total cap on a single serve/funnel splice. A `copy_bidirectional`/`copy` runs until either
/// side EOFs, so a peer that connects and then goes silent forever would otherwise pin a task + its
/// permit + fds indefinitely. This is a *total* bound (not idle) — chosen long enough (10 minutes)
/// that it does not cut a legitimately long-lived stream (e.g. an SSH-over-serve session or a slow
/// SSE backend), yet short enough to reap a truly abandoned/dead idle peer and return its permit to
/// the cap. On elapse we log at debug and drop. (A precise *idle* timeout would need read-activity
/// tracking that `copy_bidirectional` does not expose; a generous total bound is the proportionate
/// hardening — it only ever catches connections that are effectively dead.)
const SPLICE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Upper bound on the blocking netmap query inside [`Backend::status`]. The query is held under the
/// backend lock, so this caps how long a `status` can head-of-line block `up`/`down` in the brief
/// Running-but-pre-netmap window (or if a Running engine wedges). On elapse we report `Running`
/// without addresses (the next poll fills them). Generous enough that a healthy converged node
/// always answers well within it.
const STATUS_QUERY_TIMEOUT: Duration = Duration::from_millis(500);

/// An in-progress bring-up handed between [`Backend::begin_up`] (locked, fast) and
/// [`Backend::finish_up`] (locked, fast), across the unlocked [`build_device`] handshake.
///
/// Carries the engine `Config` to construct from and the lifecycle `generation` this attempt was
/// started at, so `finish_up` can tell whether a later `up`/`down` superseded it while the backend
/// lock was released for the slow `Device::new`.
pub struct PendingUp {
    config: tailscale::Config,
    generation: u64,
}

/// Workload-identity-federation / OAuth registration credentials (Go `tailscale up
/// --client-id/--client-secret/--id-token/--audience`), carried from the LocalAPI boundary to the
/// engine handshake. Like the auth key, these are **registration-time-only and never persisted** —
/// they are not part of [`Prefs`] and do not flow through [`config::build_config`]; instead they are
/// set onto the engine [`tailscale::Config`] in [`build_device`] just before the handshake, so the
/// secret window is confined to the construction call (the engine exchanges them for a real auth key
/// when built with the `identity-federation` feature). The two secrets are held in
/// [`secrecy::SecretString`] (zeroized on drop, never logged); `client_id`/`audience` are non-secret
/// identifiers.
pub struct WifCreds {
    client_id: Option<String>,
    client_secret: Option<secrecy::SecretString>,
    id_token: Option<secrecy::SecretString>,
    audience: Option<String>,
}

impl WifCreds {
    /// Build from the four optional wire strings, wrapping the two secret-bearing ones into
    /// [`secrecy::SecretString`]. Returns `None` when every field is absent (the common
    /// authkey/interactive `up`), so callers skip the feature gate and the config plumbing entirely.
    pub fn from_wire(
        client_id: Option<String>,
        client_secret: Option<String>,
        id_token: Option<String>,
        audience: Option<String>,
    ) -> Option<Self> {
        if client_id.is_none()
            && client_secret.is_none()
            && id_token.is_none()
            && audience.is_none()
        {
            return None;
        }
        Some(Self {
            client_id,
            client_secret: client_secret.map(secrecy::SecretString::from),
            id_token: id_token.map(secrecy::SecretString::from),
            audience,
        })
    }

    /// Apply these creds onto the engine [`tailscale::Config`] right before the registration
    /// handshake. This is the daemon→engine trust boundary: the two secrets are exposed once here (the
    /// other, earlier crossing is the CLI's wire-serialize step — the wire type is a plain `String`
    /// because `SecretString` does not serialize, exactly as for the auth key). They are written into
    /// the `Config`'s WIF fields that the engine's `resolve_auth_key` reads under the
    /// `identity-federation` feature, then dropped with `self`; they never enter prefs or the key file.
    fn apply_to_config(&self, config: &mut tailscale::Config) {
        use secrecy::ExposeSecret as _;
        config.client_id = self.client_id.clone();
        config.client_secret = self
            .client_secret
            .as_ref()
            .map(|s| s.expose_secret().to_owned());
        config.id_token = self.id_token.as_ref().map(|s| s.expose_secret().to_owned());
        config.audience = self.audience.clone();
    }
}

/// Whether this daemon binary was compiled with the engine's `identity-federation` feature (the
/// workload-identity / OAuth auth-key exchange). When `false`, the engine treats the WIF `Config`
/// fields as inert, so the LocalAPI layer refuses WIF flags up front rather than letting them
/// silently do nothing.
pub fn identity_federation_built() -> bool {
    cfg!(feature = "identity-federation")
}

/// Project one engine [`StatusNode`](tailscale::StatusNode) into the LocalAPI [`PeerReport`] wire
/// shape — the SINGLE source of truth for that mapping, shared by [`Backend::status`]'s netmap
/// projection and the `watch`-notify stream's `net_map` projection (see
/// [`crate::server`]'s `stream_notify`). Factored out so a one-shot `status` and the streamed
/// notification feed can never describe the same peer differently: both render identical
/// `name`/`ipv4`/`ipv6`/`stable_id`/`online`/`allowed_routes`/`last_seen`/`cur_addr`/`relay` fields
/// from the same engine node.
pub(crate) fn peer_report_from_status_node(p: tailscale::StatusNode) -> PeerReport {
    PeerReport {
        name: p.display_name,
        ipv4: p.ipv4.to_string(),
        is_exit_node: p.is_exit_node,
        // The engine's StableNodeId → the Go `status --json` Peer-map key (see PeerReport::stable_id
        // for the keying-deviation note). `p` is owned, so move the inner String rather than clone.
        stable_id: p.stable_id.0,
        // Engine-reported liveness (Option<bool>) → Go `PeerStatus.Online`.
        online: p.online,
        // IPv6 → Go PeerStatus.TailscaleIPs[1] (rendered as a string).
        ipv6: Some(p.ipv6.to_string()),
        // AllowedIPs → Go PeerStatus.AllowedIPs (CIDR strings).
        allowed_routes: p.allowed_routes.iter().map(|r| r.to_string()).collect(),
        // LastSeen (Go PeerStatus.LastSeen); meaningful when offline. Emit strict RFC3339
        // (`2026-06-11T05:19:14+00:00`) via the chrono `DateTime<Utc>`'s inherent `to_rfc3339` so a
        // JSON consumer parses it like Go's `ipnstate.PeerStatus.LastSeen`. (The Display impl —
        // `2026-06-11 05:19:14 UTC`, space-separated — is NOT RFC3339; `to_rfc3339` is an inherent
        // method on the type, no chrono feature needed.)
        last_seen: p.last_seen.map(|t| t.to_rfc3339()),
        // Direct endpoint vs DERP relay (Go CurAddr/Relay; mutually exclusive).
        cur_addr: p.cur_addr.map(|a| a.to_string()),
        relay: p.relay,
        // The peer's advertised SSH host keys (known_hosts format) → Go PeerStatus.SSH_HostKeys.
        // Carried so `tnet ssh` can pin the host key; empty when control advertised none (the engine
        // never fabricates them).
        ssh_host_keys: p.ssh_host_keys,
    }
}

/// Map an engine [`DeviceState`](tailscale::DeviceState) into the `(state, error)` pair a
/// [`NotifyView`](crate::localapi::NotifyView) carries for the `watch`-notify stream, reusing the
/// SAME [`state_from_device`] mapping [`Backend::status`] uses so the streamed `state`/`error` can
/// never drift from the one-shot `status` view. Only the state-name string and the terminal-failure
/// `error` are returned: the interactive-login URL is carried independently by the engine's
/// [`Notify::browse_to_url`](tailscale::Notify::browse_to_url) (derived there from `NeedsLogin`), so
/// `stream_notify` sources `browse_to_url` from that field, not from this helper's dropped auth-URL
/// component. Exposed at `pub(crate)` because `state_from_device` itself is module-private to `ipn`.
pub(crate) fn notify_state_from_device(ds: tailscale::DeviceState) -> (String, Option<String>) {
    let (state, _auth_url, error) = state_from_device(ds);
    (state.as_str().to_string(), error)
}

/// Perform the slow engine handshake for a [`PendingUp`], **without** holding the backend lock.
/// This is the multi-second, network-bound step (control-plane registration); keeping it off-lock is
/// the whole point of the `begin_up`/`finish_up` split — a concurrent `status` (or any other LocalAPI
/// call) is not blocked behind an in-flight `up`.
///
/// The auth-key flows in as a [`secrecy::SecretString`] and is handed to the engine's
/// [`Device::new_with_secret`](tailscale::Device::new_with_secret) **still wrapped** (engine ask #2 /
/// `tsd-tnv`, shipped in engine v0.8.0). The daemon never exposes it as a plain `String` — the
/// plaintext window is confined to the single `.expose_secret()` inside the engine's own
/// `new_with_secret`, byte-for-byte identical to a direct `new` but with no daemon-side plaintext copy
/// to linger un-zeroized.
pub async fn build_device(
    pending: &PendingUp,
    authkey: Option<secrecy::SecretString>,
) -> Result<tailscale::Device> {
    tailscale::Device::new_with_secret(&pending.config, authkey)
        .await
        .map_err(|e| anyhow!("engine start failed: {e:?}"))
}

/// Gracefully shut down an orphaned device returned by [`Backend::finish_up`] (a device built for a
/// bring-up that was superseded before it could be installed). **Call this with NO backend lock
/// held** — the shutdown awaits up to [`SHUTDOWN_TIMEOUT`], and doing it under the lock would
/// reintroduce the head-of-line stall the begin/finish split removes. A no-op for `None`.
///
/// The orphan arrives as an [`Arc`](std::sync::Arc) (the type [`Backend::device`] and `finish_up`
/// now deal in), but a superseded orphan was **never installed and never SSH-spawned**, so the
/// `Arc` is uniquely owned (refcount 1) and [`Arc::into_inner`](std::sync::Arc::into_inner) always
/// returns the owned `Device` for a graceful, consuming `shutdown`. Should that invariant ever be
/// violated (some other clone outlives this), we fall through to dropping the last `Arc` clone — the
/// engine's `Runtime::drop` still kills its actors — rather than leaking.
pub async fn shutdown_orphan(orphan: Option<std::sync::Arc<tailscale::Device>>) {
    if let Some(dev) = orphan {
        match std::sync::Arc::into_inner(dev) {
            // The normal path: a superseded orphan is uniquely owned, so we reclaim the `Device` and
            // shut it down gracefully (bounded; the engine's `Runtime::drop` also kills its actors if
            // this times out).
            Some(owned) => {
                let _ = owned.shutdown(Some(SHUTDOWN_TIMEOUT)).await;
            }
            // Unreachable for a true orphan (refcount 1, never SSH-spawned). If it ever happens,
            // dropping the last clone still tears the engine down via `Runtime::drop` — never a leak.
            None => {
                tracing::warn!(
                    "orphaned device Arc was not uniquely owned at shutdown; dropping (engine \
                     Runtime::drop will still tear down its actors)"
                );
            }
        }
    }
}

/// Drive a full bring-up against a shared [`Backend`] **without holding the lock across the
/// multi-second `Device::new` handshake** — the concurrency-safe `up` for any caller that holds the
/// `Arc<Mutex<Backend>>` rather than a `&mut Backend`.
///
/// This is the three-phase split the LocalAPI server uses, factored out so the SIGHUP reload path
/// shares it verbatim instead of holding the lock across the handshake (which would reintroduce the
/// exact head-of-line stall the split exists to remove): lock briefly for [`begin_up`](Backend::begin_up)
/// → **drop the lock** for the slow [`build_device`] → lock briefly for [`finish_up`](Backend::finish_up)
/// → drop the lock and settle any superseded orphan off-lock. A concurrent `status`/`down` taken
/// during the handshake is never blocked, and a `down`/`up` that lands mid-flight correctly
/// supersedes this attempt (its device is discarded).
///
/// Returns the [`begin_up`](Backend::begin_up)/[`finish_up`](Backend::finish_up) error if either
/// phase failed (intent stays "up" with no device → `NeedsLogin`, so a later retry can resume).
pub async fn drive_up(
    backend: &std::sync::Arc<tokio::sync::Mutex<Backend>>,
    authkey: Option<secrecy::SecretString>,
    wif: Option<WifCreds>,
    opts: UpOptions,
) -> Result<()> {
    // Phase 1: brief lock — prep + persist prefs, build Config (folding in any transient WIF creds),
    // bump generation.
    let pending = {
        let mut be = backend.lock().await;
        be.begin_up(opts, wif.as_ref()).await
    }?;

    // Phase 2: NO lock held — the slow, network-bound control-plane handshake. Concurrent
    // `status`/`down` proceed freely here; this is the whole point of the split.
    let built = build_device(&pending, authkey).await;

    // Phase 3: brief lock — install iff still current, returning any orphan to shut down off-lock.
    let orphan = {
        let mut be = backend.lock().await;
        let orphan = be.finish_up(pending, built)?;
        // On a successful install (no orphan → this attempt was current, not superseded), `finish_up`
        // flipped `has_logged_in` in memory; persist it so the accidental-revert guard's fresh-node
        // exemption survives a daemon restart. A superseded attempt (orphan present) did NOT install
        // or flip, so there is nothing to persist. Persist failure is non-fatal: the node is up: a
        // lost flag just means the next `up` is unguarded once (the benign migration-default outcome).
        if orphan.is_none()
            && let Err(e) = be.persist_prefs().await
        {
            tracing::warn!(error = %e, "failed to persist has_logged_in after bring-up (node is up; next up may be unguarded once)");
        }
        orphan
    };

    // Lock released — settle the (rare) superseded device off-lock so a supersede never blocks the
    // lock for up to SHUTDOWN_TIMEOUT.
    shutdown_orphan(orphan).await;
    Ok(())
}

/// Rebuild the live engine from the caller's ALREADY-updated-and-persisted prefs, without ever
/// holding the backend lock across the multi-second `Device::new` handshake — the one body shared by
/// every "adopt a rebuild-only change into a running node" path.
///
/// [`drive_set`]'s [`SetAction::Rebuild`] and [`drive_reload_config`]'s [`ReloadAction::Rebuild`] need
/// exactly this sequence, and its lock discipline is load-bearing (a rebuild that holds the lock
/// across the handshake head-of-line blocks every concurrent `status`/`down`; a rebuild that skips the
/// preflight can leave a healthy node offline), so it lives here ONCE — a fix to the sequence cannot
/// land on one caller and miss the other.
///
/// The phases, in order — [`drive_up`]'s phasing plus the preflight:
///
/// 1. **PREFLIGHT under a brief lock** ([`build_config`](Backend::build_config)) — validate the
///    rebuilt config BEFORE tearing the live device down. `begin_up` → `stop_device` drops the running
///    engine, but the SSH root/feature checks (and the control-URL/route parse) live in `build_config`,
///    which `begin_up` only reaches AFTER teardown. If that check fails (e.g. `set --ssh`, or a
///    reloaded config enabling SSH, on a daemon without the `ssh` feature or without root), a naive
///    rebuild would leave a healthy node OFFLINE — a `set`/reload that fails must never drop the
///    tunnel. So validate FIRST; on error, return it with the live device untouched. (The caller
///    already persisted the prefs, so they apply on the next successful `up`/`set` — but the running
///    node stays up now.)
/// 2. **Brief lock** — [`begin_up`](Backend::begin_up) from the (already-updated) prefs. **No authkey
///    and no WIF creds:** a rebuild resumes from the persisted node key; neither `set` nor
///    `reload-config` (re)authenticates. NB `begin_up` sets `want_running = true`, which is a no-op on
///    both callers' rebuild arms — each only reaches one when a device is already up and stays up (the
///    node-down and stop-me-now cases are decided before we get here), so a rebuild can neither flip a
///    down node up nor resurrect one the caller asked to stop.
/// 3. **NO lock held** — the slow, network-bound re-registration handshake ([`build_device`]). This is
///    the whole point of the split: concurrent `status`/`down`/`up` proceed freely here.
/// 4. **Brief lock** — [`finish_up`](Backend::finish_up) installs iff still current (the
///    generation-supersede guard), handing back any superseded device as an orphan. On a successful
///    install (no orphan) `finish_up` flips `has_logged_in` in memory, so we persist it here too (the
///    same contract as `drive_up`/[`Backend::up`]) — otherwise a rebuild after a prior transient
///    persist failure would leave the flag true-in-memory but false-on-disk and lose the
///    accidental-revert guard's fresh-node exemption across a restart. Persist failure is non-fatal:
///    the node is up; a lost flag just means the next `up` is unguarded once.
/// 5. **Lock released** — settle the (rare) superseded orphan off-lock, so a supersede never blocks
///    the lock for up to `SHUTDOWN_TIMEOUT`.
///
/// A `down`/`up` that lands mid-rebuild correctly supersedes it (the rebuilt device is discarded).
///
/// **CAVEAT — this is a brief reconnect:** the live engine is torn down and a fresh one stood up, so
/// the overlay drops and re-registers (a short interruption + a new netmap convergence). Both callers
/// document that on their rebuild arms.
///
/// `cause` names the driving verb (`"set"` / `"reload-config"`) for the non-fatal persist-failure
/// warning, so the log still says which verb's rebuild could not persist the flag.
async fn rebuild_running_device(
    backend: &std::sync::Arc<tokio::sync::Mutex<Backend>>,
    cause: &'static str,
) -> Result<()> {
    // Phase 1: PREFLIGHT the rebuilt config under a brief lock, before anything is torn down (see the
    // doc comment: a bad value must never drop a healthy tunnel).
    {
        let be = backend.lock().await;
        be.build_config().await?;
    }
    // Phase 2: brief lock — begin a bring-up from the (already-updated) prefs. No authkey and no WIF
    // creds: a rebuild resumes from the persisted node key, it never (re)authenticates.
    let pending = {
        let mut be = backend.lock().await;
        be.begin_up(UpOptions::default(), None).await
    }?;
    // Phase 3: NO lock held — the slow, network-bound re-registration handshake.
    let built = build_device(&pending, None).await;
    // Phase 4: brief lock — install iff still current, returning any orphan to settle off-lock.
    let orphan = {
        let mut be = backend.lock().await;
        let orphan = be.finish_up(pending, built)?;
        // Persist the `has_logged_in` flip `finish_up` made on a successful install (see the doc
        // comment). Non-fatal on failure: the node is up.
        if orphan.is_none()
            && let Err(e) = be.persist_prefs().await
        {
            tracing::warn!(
                error = %e,
                cause,
                "failed to persist has_logged_in after a rebuild (node is up; next up may be unguarded once)"
            );
        }
        orphan
    };
    // Phase 5: lock released — settle the (rare) superseded device off-lock.
    shutdown_orphan(orphan).await;
    Ok(())
}

/// Drive a live pref mutation (`tnet set`) against a shared [`Backend`], reconciling the engine
/// without ever holding the backend lock across the multi-second `Device::new` handshake — the
/// concurrency-safe `set` for any caller that holds the `Arc<Mutex<Backend>>`.
///
/// This is the live-mutation analogue of [`drive_up`], and it deliberately splits into the SAME
/// three lock-discipline shapes depending on what changed (decided once, under a brief lock, by
/// [`begin_set`](Backend::begin_set)):
///
/// 1. **Node down** ([`SetAction::PersistedOnly`]) — there is no engine to reconcile; persisting the
///    prefs (already done in `begin_set`) is the whole job. The new prefs apply on the next `up`.
///    Returns immediately, lock already released.
/// 2. **All-live, node up** ([`SetAction::Live`]) — every changed pref has an in-place engine setter
///    (`exit_node`, `hostname`, `accept_routes`, `advertise_routes`, `advertise_exit_node`), so the
///    change applies *live* (no reconnect), matching Go's `set` = one `EditPrefs`. `begin_set` issues
///    the relevant setters under the brief lock it already holds and returns the list of ops; this
///    function has nothing further to do. Each setter takes `&self` (not `&mut`); the device is held
///    behind an `Arc` (shared with the SSH task), so they *could* be cloned and hoisted off-lock —
///    but we deliberately do NOT, because they are quick mailbox round-trips (a local state edit + a
///    control re-push on the established map-poll), not the multi-second registration handshake the
///    begin/finish split exists to keep off-lock. Holding the brief lock keeps the prefs-apply +
///    live-set atomic under one lock. Only NEW flows use the new values; in-flight connections are
///    untouched (no teardown, no reconnect).
/// 3. **A rebuild-only pref changed, node up** ([`SetAction::Rebuild`]) — `shields_up` (the immutable
///    `Config.block_incoming`), `ssh` (a device-lifecycle task), `advertise_tags` (registration-time
///    `Config.requested_tags`), or the wire-advertised `advertise_connector` / `auto_update`
///    (`Hostinfo` fields re-sent on every map request) have no live setter, so the only way to apply
///    them to a running node is to **rebuild the device** from the now-updated prefs. This reuses the
///    exact [`begin_up`](Backend::begin_up) → [`build_device`] → [`finish_up`](Backend::finish_up)
///    machinery as `drive_up` (same off-lock handshake, same generation-supersede guard, same off-lock orphan
///    settle), so it inherits the same lock discipline verbatim. **CAVEAT — this is a brief
///    reconnect:** rebuilding tears down the live engine and stands a fresh one up, so the overlay
///    drops and re-registers (a short interruption + a new netmap convergence). `set` is honest about
///    this: only the live path is truly seamless, and a `set` that mixes live-applicable and
///    rebuild-only prefs takes this rebuild path for the whole change (the rebuild re-applies the live
///    ones from the persisted prefs too). **No `authkey` is involved** (resume uses the persisted node
///    key), and `want_running` is **never** changed — a `set` that rebuilds keeps a running node
///    running and a (paradoxical) `set` on a down node still just persists; `set` is not `up`/`down`.
///
/// This mirrors `drive_up`'s phasing for the rebuild case. The lock is taken briefly for
/// `begin_set` (apply + persist + decide); then, if rebuilding, briefly for `begin_up`; the lock is
/// **dropped** for the slow `build_device`; taken briefly again for `finish_up`; then dropped to
/// settle any superseded orphan off-lock. A concurrent `status`/`down`/`up` is never blocked behind
/// the handshake, and a `down`/`up` that lands mid-rebuild correctly supersedes it (the rebuilt
/// device is discarded).
///
/// A `--nickname` whose login-profile rename failed ([`SetOutcome::rename_error`]) is returned as this
/// function's error — but only AFTER the reconcile above has run, so a `profiles.json` write failure
/// never leaves an already-persisted, live-applicable pref unapplied on the running device.
pub async fn drive_set(
    backend: &std::sync::Arc<tokio::sync::Mutex<Backend>>,
    opts: SetOptions,
) -> Result<()> {
    // Phase 1: brief lock — apply + persist the pref overrides and decide the reconcile path. For
    // the live path we ALSO issue the live engine setters here, under the same brief lock: each is a
    // quick actor message (not the off-lock-worthy registration handshake), so we keep them atomic
    // with the prefs-apply rather than hoisting them off-lock via the device's `Arc`.
    let outcome = {
        let mut be = backend.lock().await;
        be.begin_set(opts).await
    }?;

    match outcome.action {
        // Node down: persisting was the whole job; nothing live to reconcile.
        SetAction::PersistedOnly => {}
        // Every changed pref was live-applicable and applied in place, under the brief lock, inside
        // `begin_set` (`ops` records what was issued). No reconnect. Done.
        SetAction::Live(_) => {}
        // A rebuild-only pref changed on a running node → rebuild from the updated prefs via the
        // preflight → begin_up → (off-lock) build_device → finish_up → off-lock orphan settle
        // sequence, the same off-lock handshake as `drive_up`. That sequence is shared verbatim with
        // `drive_reload_config`'s `ReloadAction::Rebuild`, so it lives in ONE place:
        // `rebuild_running_device` carries the per-phase rationale, and a fix there cannot miss
        // either verb. The brief reconnect is documented on this function and `SetAction::Rebuild`.
        SetAction::Rebuild => rebuild_running_device(backend, "set").await?,
    }

    // The `--nickname` half failed after the prefs were already persisted (see [`SetOutcome`]). The
    // engine is reconciled by now, so report the rename failure as the `set`'s error here rather than
    // letting it skip the reconcile.
    if let Some(e) = outcome.rename_error {
        return Err(e);
    }
    Ok(())
}

/// Drive a `reload-config` against a shared [`Backend`]: re-read the `--config` file and adopt the
/// changed fields into the running node, **without** holding the backend lock across the multi-second
/// `Device::new` handshake — the concurrency-safe `reload-config` for the LocalAPI server (Go
/// `tailscaled`'s `reload-config` route → `LocalBackend.ReloadConfig`).
///
/// It is the reload analogue of [`drive_set`]'s [`SetAction::Rebuild`] path, sharing the SAME
/// three-phase lock discipline verbatim:
///
/// 1. **Brief lock** — [`reload_config`](Backend::reload_config) re-reads + re-parses the config file,
///    merges it over the prefs, persists, and decides the [`ReloadAction`]. A malformed / unsupported
///    file fails HERE with the running node untouched (the fail-fast contract; nothing is left
///    half-applied).
/// 2. **[`ReloadAction::PersistedOnly`]** (node down) — there is no engine to reconcile; persisting the
///    merged prefs was the whole job (they apply on the next `up`/auto-start). Returns immediately.
/// 3. **[`ReloadAction::BringDown`]** (node up, reloaded `Enabled:false`) — Go's config reload always
///    re-applies `WantRunning`, so a reloaded `Enabled:false` means "stop". `apply_config` already
///    persisted `want_running=false`; this calls [`down`](Backend::down) to tear the engine down to
///    match (a teardown, no off-lock build).
/// 4. **[`ReloadAction::Rebuild`]** (node up, reloaded config keeps it up) — the engine `Config` is
///    immutable, so the only way to adopt the changed prefs on a running node is to **rebuild the
///    device** from the now-updated prefs. This reuses the exact [`begin_up`](Backend::begin_up) →
///    [`build_device`] → [`finish_up`](Backend::finish_up) machinery as `drive_up`/`drive_set`'s
///    rebuild — same off-lock handshake, same generation-supersede guard, same off-lock orphan settle.
///    **CAVEAT — this is a brief reconnect** (the overlay drops and re-registers from the persisted node
///    key, then re-converges), identical to a rebuild-only `set`. **No `authkey` is involved** (a reload
///    is not a re-auth; the rebuild resumes from the persisted node key — see
///    [`reload_config`](Backend::reload_config)).
///
/// **`want_running` IS lifecycle-bearing on a reload** (unlike a `set`): Go's `ConfigVAlpha.ToPrefs`
/// re-applies `WantRunning` on every reload (`WantRunningSet` is effectively always set), so a reloaded
/// `Enabled:false` stops a running node ([`ReloadAction::BringDown`]) and an `Enabled`-less/`true`
/// reload keeps/sets up-intent. A reload on a DOWN node does not originate a connection mid-reload
/// (it persists up-intent that the next auto-start/`up` acts on) — so a reload never *surprise-starts*
/// a stopped node from the reload call itself, but it can *stop* a running one.
///
/// Mirrors `drive_set`'s rebuild phasing precisely — in fact it *is* that phasing: the rebuild arm
/// calls the shared [`rebuild_running_device`], so the lock-discipline-critical sequence (brief lock to
/// PREFLIGHT the rebuilt config so a bad value never drops a healthy tunnel; brief lock for `begin_up`;
/// lock **dropped** for the slow `build_device`; brief lock again for `finish_up`; dropped to settle
/// any superseded orphan off-lock) has one source of truth for both verbs. A concurrent
/// `status`/`down`/`up` is never blocked behind the handshake, and a `down`/`up` that lands mid-rebuild
/// correctly supersedes it (the rebuilt device is discarded).
///
/// ## Returns
///
/// `Ok(Some(action))` with the [`ReloadAction`] that was actually reconciled — `Rebuild` (the config
/// is live on a rebuilt engine), `BringDown` (the reloaded `Enabled:false` stopped the node), or
/// `PersistedOnly` (node down; the merged prefs apply on the next `up`). The action is logged by the
/// LocalAPI server; the wire reply carries only Go's `ok` bool, because that is all Go's
/// `serveReloadConfig` returns and the CLI's wording is derived from it.
///
/// `Ok(None)` is Go's `(false, nil)`: the daemon is not in config mode, so there was nothing to
/// reload and nothing was reconciled. It is a refusal, not an error — see
/// [`reload_config`](Backend::reload_config).
pub async fn drive_reload_config(
    backend: &std::sync::Arc<tokio::sync::Mutex<Backend>>,
) -> Result<Option<ReloadAction>> {
    // Phase 1: brief lock — re-read the config, merge + persist, and decide the reconcile action.
    let action = {
        let mut be = backend.lock().await;
        be.reload_config().await
    }?;
    // Not in config mode → no reconcile to run, and nothing was mutated.
    let Some(action) = action else {
        return Ok(None);
    };

    match action {
        // Node down: persisting the merged prefs was the whole job; they apply on the next `up`.
        ReloadAction::PersistedOnly => {}
        // Node up, reloaded `Enabled:false` → tear the engine down to match the already-persisted
        // `want_running=false` (Go applies a reloaded `Enabled:false`). `down` does `stop_device` +
        // bump_generation (so an in-flight bring-up is superseded) + re-persists `want_running=false`
        // (idempotent — `apply_config` already set it). No off-lock build needed for a teardown.
        ReloadAction::BringDown => {
            let mut be = backend.lock().await;
            // `Actor::Daemon`: the daemon reconciling intent `reload_config` has already persisted,
            // not an operator asking to disconnect — so the always-on gate does not apply (see
            // `alwayson::Actor::Daemon` for why refusing here would be the wrong shape).
            be.down(alwayson::Actor::Daemon).await?;
        }
        // Node up, reloaded config keeps it up → rebuild from the now-updated prefs. The
        // preflight → begin_up → (off-lock) build_device → finish_up → off-lock orphan settle
        // sequence is shared verbatim with `drive_set`'s `SetAction::Rebuild`, so it lives in ONE
        // place — see `rebuild_running_device` for the per-phase rationale (and the brief-reconnect
        // caveat, also documented above).
        ReloadAction::Rebuild => rebuild_running_device(backend, "reload-config").await?,
    }

    // Report WHICH reconcile actually ran so the daemon can log it: the wire reply is Go's bare `ok`,
    // but "the engine was rebuilt" vs "the node was brought down" vs "only persisted" is exactly what
    // an operator reading the daemon log after an unexpected disconnect needs.
    Ok(Some(action))
}

/// A single live engine pref-setter that [`Backend::begin_set`] issued (under its brief lock) to
/// apply a `set` change in place — the no-reconnect analogue of rebuilding the device. Each carries
/// the resolved value that was pushed, so [`SetAction::Live`] is a self-describing, comparable record
/// of what the live path did (handy for tests + tracing). Issuing happens in `begin_set`; this type
/// is the receipt, not a deferred instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveSetOp {
    /// `set_exit_node` was issued. Carries the resolved selector *as the pref string*
    /// (`None` = cleared) rather than the engine's `ExitNodeSelector` — the string is what the daemon
    /// persists and is trivially `Eq`, and the engine `FromStr` is infallible, so no fidelity is lost.
    ExitNode(Option<String>),
    /// `set_hostname` was issued with this hostname.
    Hostname(String),
    /// `set_accept_routes` was issued with this value.
    AcceptRoutes(bool),
    /// `set_accept_dns` was issued with this value.
    AcceptDns(bool),
    /// `set_advertise_routes` was issued with these (already-parsed) routes.
    AdvertiseRoutes(Vec<ipnet::IpNet>),
    /// `set_advertise_exit_node` was issued with this value.
    AdvertiseExitNode(bool),
}

/// What [`Backend::begin_set`] decided a `set` must do to reconcile the live engine with the
/// freshly-persisted prefs. The prefs are *already* applied + persisted by the time this is
/// returned; this only describes the remaining engine-side work (and, for [`Live`](Self::Live),
/// records which live setters were already issued under the lock).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetAction {
    /// No device is up: persisting the prefs was the entire job; they take effect on the next `up`.
    PersistedOnly,
    /// Every changed pref is live-applicable and a device is up — the corresponding engine setters
    /// were issued LIVE under the brief `begin_set` lock (`set_exit_node` / `set_hostname` /
    /// `set_accept_routes` / `set_advertise_routes` / `set_advertise_exit_node`). No rebuild, no
    /// reconnect; nothing further for the caller to do. The `Vec` records what was issued (in apply
    /// order) — a `set --exit-node X` is the common single-op case, but a multi-pref all-live `set`
    /// (e.g. `--hostname h --accept-routes`) issues several. Mirrors Go's `set` = one live
    /// `EditPrefs` (no reconnect).
    ///
    /// The `Vec` is EMPTY when the `set` named only CARRIED prefs (`--operator`, `--nickname`,
    /// `--report-posture`, `--webclient`, `--update-check`, `--exit-node-allow-lan-access`): the
    /// pinned engine stores those but never acts on or advertises them, so the persist in `begin_set`
    /// is the whole job even on a running node — there is no setter to issue and no reason to force a
    /// reconnect. (`--nickname` also renames the login profile on disk, as Go's `profiles.go` does,
    /// but that is a local file write, not an engine op — so it too leaves the `Vec` empty.) See
    /// [`SetOptions::needs_rebuild`] for the full three-way classification.
    Live(Vec<LiveSetOp>),
    /// At least one changed pref is one the live engine acts on with NO live setter — `shields_up`
    /// (maps to the immutable `Config.block_incoming`), `ssh` (a device-lifecycle task, not a
    /// `Config` knob), `advertise_tags` (registration-time `requested_tags`), or the wire-advertised
    /// `advertise_connector` / `auto_update` (`Hostinfo.AppConnector` / `Hostinfo.AllowsUpdate`, sent
    /// on every map request from a construction-time field) — so the engine `Config` must be rebuilt
    /// from the updated prefs. The caller ([`drive_set`]) runs the off-lock
    /// `begin_up`/`build_device`/`finish_up` handshake. This is a brief reconnect. (When a `set` mixes
    /// live-applicable and rebuild-only prefs, the whole `set` rebuilds — a rebuild re-applies every
    /// pref from the persisted state anyway, so applying the live ones first would be wasted work.)
    Rebuild,
}

/// What [`Backend::begin_set`] produced: the [`SetAction`] the caller must still carry out, plus a
/// `--nickname` profile rename that FAILED *after* the prefs were already persisted.
///
/// The two ride back together rather than the rename error short-circuiting the return, because by
/// the time the rename runs everything the `set` asked for is already durable in `prefs.json`.
/// Returning early on it would skip the engine reconcile entirely, so a
/// `set --nickname X --exit-node Y` on a running node would leave `Y` in `prefs.json` (and in what
/// `tnet get` reports) while the live device kept the OLD exit node — a mismatch that survives until
/// the next successful `set`/`up`. Instead the reconcile always runs (the live setters inside
/// `begin_set`; [`SetAction::Rebuild`] in [`drive_set`] / [`Backend::set`]) and the caller returns
/// `rename_error` as the command's error afterwards: the operator still learns the rename failed, but
/// no already-durable, live-applicable pref is skipped because a `profiles.json` write failed.
#[derive(Debug)]
pub struct SetOutcome {
    /// How to reconcile the live engine (see [`SetAction`]). Always decided — including when
    /// `rename_error` is set.
    pub action: SetAction,
    /// `Some` when `--nickname` was named and the login-profile rename (`profiles.json`) failed. The
    /// prefs, the `node_nickname` pref included, are already persisted; only the profile's display
    /// name is stale, so `switch --list` keeps showing the old one until a `set --nickname` succeeds.
    /// Callers must surface this as the `set`'s error, but only AFTER performing `action`.
    pub rename_error: Option<anyhow::Error>,
}

/// Optional overrides applied to the persisted [`Prefs`] when bringing the node up.
///
/// Every field is `None` = "leave the persisted pref as-is"; `Some(..)` sets it. This is how a
/// `tnet up --hostname h --tun` request mutates only what the user named, preserving the rest of the
/// stored intent. Built from a [`crate::localapi::Request::Up`] at the server boundary.
#[derive(Debug, Default, Clone)]
pub struct UpOptions {
    /// Override the requested hostname.
    pub hostname: Option<String>,
    /// Override the control server URL.
    pub control_url: Option<String>,
    /// Enable/disable kernel-TUN mode (`None` leaves the pref unchanged).
    pub tun: Option<bool>,
    /// Desired TUN interface name (only applied when TUN is/becomes enabled).
    pub tun_name: Option<String>,
    /// TUN interface MTU (only applied when TUN is/becomes enabled).
    pub tun_mtu: Option<u16>,
    /// Exit-node selector override. The OUTER `Option` is the "leave pref unchanged" sentinel
    /// (`None` = don't touch `prefs.exit_node`); the INNER `Option<String>` is the value to store
    /// (`Some(None)` clears it = stop using an exit node, `Some(Some(sel))` sets it). This double
    /// `Option` is what lets `tnet up --exit-node X` and `tnet up --exit-node=` (clear) and a plain
    /// `tnet up` (unchanged) all be distinct on the wire.
    pub exit_node: Option<Option<String>>,
    /// Advertise-exit-node override (`None` leaves the pref unchanged; `Some(b)` sets it).
    pub advertise_exit_node: Option<bool>,
    /// Advertise-routes override. `None` leaves the pref unchanged; `Some(vec)` replaces the set
    /// (`Some(vec![])` clears it). A `Vec` alone could not express "unchanged", hence the `Option`.
    pub advertise_routes: Option<Vec<String>>,
    /// Advertise-tags override (Go `--advertise-tags`). `None` leaves the pref unchanged; `Some(vec)`
    /// replaces the set (`Some(vec![])` clears it). Each entry must be `tag:<name>`, or a value with
    /// no colon at all, which `complete_and_validate_advertise_tags` completes to `tag:<value>`
    /// before anything is persisted.
    pub advertise_tags: Option<Vec<String>>,
    /// Accept-subnet-routes override (`None` leaves the pref unchanged; `Some(b)` sets it). Go's
    /// `tailscale up --accept-routes`; same tri-state as `set`'s `accept_routes`.
    pub accept_routes: Option<bool>,
    /// Accept-MagicDNS override (`None` leaves the pref unchanged; `Some(b)` sets it). Go's
    /// `tailscale up --accept-dns` (default-on); `Some(false)` ignores the pushed DNS config.
    pub accept_dns: Option<bool>,
    /// Shields-up override (`None` leaves the pref unchanged; `Some(b)` sets it). Go's
    /// `tailscale up --shields-up`; block inbound peer connections terminating on this node.
    pub shields_up: Option<bool>,
    /// Run-SSH-server override (`None` leaves the pref unchanged; `Some(b)` sets it).
    pub ssh: Option<bool>,
    /// Operator override (Go `tailscale up --operator <user>`; `ipn.Prefs.OperatorUser`). Double
    /// `Option` on the same pattern as [`exit_node`](Self::exit_node): OUTER `None` = leave the pref
    /// unchanged, `Some(None)` = clear the operator, `Some(Some(u))` = set it. The CLI maps Go's
    /// clear-by-empty-string form (`--operator=`) onto `Some(None)`.
    pub operator: Option<Option<String>>,
    /// Exit-node-LAN-access override (Go `tailscale up --exit-node-allow-lan-access`). `None`
    /// unchanged; `Some(b)` sets it.
    pub exit_node_allow_lan_access: Option<bool>,
    /// App-connector advertise override (Go `tailscale up --advertise-connector`). `None` unchanged;
    /// `Some(b)` sets it. Crosses the control wire (`Hostinfo.AppConnector`).
    pub advertise_connector: Option<bool>,
    /// Device-posture reporting override (Go `tailscale up --report-posture`). `None` unchanged;
    /// `Some(b)` sets it.
    pub report_posture: Option<bool>,
    /// Reset every up-managed pref this command does not mention back to its default before applying
    /// the named overrides (Go `tailscale up --reset`). The one path where `up` is a true wholesale
    /// REPLACE rather than a PATCH; also bypasses the accidental-revert guard (the operator is
    /// explicitly opting into the revert). See [`Backend::begin_up`] and
    /// [`crate::prefs::Prefs::reset_up_managed_to_default`].
    pub reset: bool,
    /// Force a fresh re-registration (Go `tailscale up --force-reauth`). When set, [`Backend::begin_up`]
    /// discards the persisted node key before the handshake so the engine registers FRESH (surfacing a
    /// new login/auth URL for an interactive up) instead of resuming the old registration. A
    /// **lifecycle action, not a pref**: it mutates no persisted setting, so — like [`reset`](Self::reset)
    /// — it is deliberately NOT part of [`mentions_any_pref`](Self::mentions_any_pref) (a bare
    /// `up --force-reauth` stays a bare up and never trips the accidental-revert guard) and NOT part of
    /// the guard/`--reset` lockstep. Unlike [`Backend::logout`], it keeps the node's up-intent
    /// (`want_running`); it only re-keys.
    pub force_reauth: bool,
    /// Ephemeral-node override (Go `tailscale up --ephemeral`). `None` leaves the pref unchanged;
    /// `Some(b)` sets it. A **registration-time intent** (the engine only acts on it when registering
    /// FRESH), so — like Go and like the prefs-layer treatment — it is deliberately NOT part of the
    /// accidental-revert guard / `--reset` lockstep (changing it on an already-registered node is a
    /// no-op until a fresh register). Default for a fresh node is `false` (persistent).
    pub ephemeral: Option<bool>,
}

impl UpOptions {
    /// Whether this `up` mentions any **pref** flag (anything that would change persisted prefs).
    /// `authkey` is deliberately NOT a pref (it authenticates; it does not alter prefs), so a plain
    /// `tnet up --authkey K` still counts as "mentions no pref" — Go's `simpleUp` (just connect,
    /// change nothing). Used by the accidental-revert guard to exempt a bare `up` (which, with our
    /// PATCH merge, changes nothing and so can revert nothing) and by nothing else.
    ///
    /// `reset` is intentionally excluded: `--reset` is a directive, not a pref, and it has its own
    /// guard-bypass path (the caller skips the guard entirely when `reset` is set), so it never needs
    /// to make a bare `up` look non-bare.
    pub fn mentions_any_pref(&self) -> bool {
        self.hostname.is_some()
            || self.control_url.is_some()
            || self.tun.is_some()
            || self.tun_name.is_some()
            || self.tun_mtu.is_some()
            || self.exit_node.is_some()
            || self.advertise_exit_node.is_some()
            || self.advertise_routes.is_some()
            || self.advertise_tags.is_some()
            || self.accept_routes.is_some()
            || self.accept_dns.is_some()
            || self.ephemeral.is_some()
            || self.shields_up.is_some()
            || self.ssh.is_some()
            || self.operator.is_some()
            || self.exit_node_allow_lan_access.is_some()
            || self.advertise_connector.is_some()
            || self.report_posture.is_some()
    }
}

/// Prefs to patch via [`Backend::set`] (the `tnet set` path) — the live-mutation analogue of
/// [`UpOptions`]. Same "leave unchanged unless named" sentinel semantics, but a deliberately
/// narrower field set: `set` never (re)authenticates (no `authkey`), never changes the control
/// server or TUN transport (those are connection-defining and belong to `up`), and never flips
/// `want_running`. It only adjusts policy prefs on an already-configured node.
///
/// On a running node, most of these apply **live** (no reconnect, matching Go's `set` = one
/// `EditPrefs`) via the engine's runtime setters: `exit_node`, `hostname`, `accept_routes`,
/// `advertise_routes`, `advertise_exit_node`. `shields_up` (the immutable `Config.block_incoming`),
/// `ssh` (a device-lifecycle task), `advertise_tags` (registration-time `requested_tags`) and the two
/// wire-advertised prefs `advertise_connector` / `auto_update` have no live setter and take the
/// device-rebuild path (a brief reconnect). The remaining six are CARRIED prefs the engine never acts
/// on, so they only persist — `nickname` additionally renaming the current login profile, the one
/// local effect among them. See [`SetOptions::needs_rebuild`] and [`SetAction`].
#[derive(Debug, Default, Clone)]
pub struct SetOptions {
    /// Requested hostname (`None` unchanged). Applied LIVE on a running node via
    /// [`tailscale::Device::set_hostname`] (display metadata; no reconnect).
    pub hostname: Option<String>,
    /// Accept subnet routes advertised by peers (`None` unchanged). Applied LIVE via
    /// [`tailscale::Device::set_accept_routes`] (the engine recomputes the route table + source
    /// filter in lock-step; no reconnect).
    pub accept_routes: Option<bool>,
    /// Accept the tailnet's MagicDNS configuration (`None` unchanged). Applied LIVE via
    /// [`tailscale::Device::set_accept_dns`] (the engine re-applies/withdraws the pushed DNS config;
    /// no reconnect).
    pub accept_dns: Option<bool>,
    /// Shields-up: block inbound peer connections terminating on this node (`None` unchanged). Has NO
    /// live engine setter (it maps to the immutable `Config.block_incoming`), so on a running node it
    /// takes the [`SetAction::Rebuild`] path — a brief reconnect.
    pub shields_up: Option<bool>,
    /// Exit-node selector. Double `Option`: `None` unchanged, `Some(None)` clear, `Some(Some(s))`
    /// set. Applied LIVE when a device is up (no reconnect).
    pub exit_node: Option<Option<String>>,
    /// Advertise this node as an exit node (`None` unchanged). Applied LIVE via
    /// [`tailscale::Device::set_advertise_exit_node`] (composes with `advertise_routes` engine-side;
    /// no reconnect).
    pub advertise_exit_node: Option<bool>,
    /// Subnet routes this node advertises (`None` unchanged; `Some(vec)` replaces). Applied LIVE via
    /// [`tailscale::Device::set_advertise_routes`] (no reconnect).
    pub advertise_routes: Option<Vec<String>>,
    /// ACL tags this node advertises (`None` unchanged; `Some(vec)` replaces; `tag:<name>` each, or
    /// a colon-less value completed to `tag:<value>` by `complete_and_validate_advertise_tags`). Has
    /// NO live engine setter (tags are requested at registration via `Config.requested_tags`), so on
    /// a running node it takes the [`SetAction::Rebuild`] path — a brief reconnect.
    pub advertise_tags: Option<Vec<String>>,
    /// Run the Tailscale SSH server (`None` unchanged; `Some(b)` sets it). Toggling SSH is a
    /// device-rebuild change (the SSH server task is tied to the device lifecycle), so it takes the
    /// [`SetAction::Rebuild`] path on a running node — not the live fast path.
    pub ssh: Option<bool>,
    /// App-connector advertise (Go `tailscale set --advertise-connector`; `None` unchanged). The
    /// engine folds this into `Hostinfo.AppConnector` at registration and on every map request, and
    /// it is a construction-time `Config` field with no runtime setter — so applying it to a running
    /// node takes the [`SetAction::Rebuild`] path (a brief reconnect), like `shields_up`.
    pub advertise_connector: Option<bool>,
    /// Admin-console auto-update opt-in (Go `tailscale set --auto-update`; `None` unchanged). Like
    /// `advertise_connector` it reaches control (`Hostinfo.AllowsUpdate`) from a construction-time
    /// `Config` field, so it is a [`SetAction::Rebuild`] pref on a running node.
    pub auto_update: Option<bool>,
    /// Background update-check opt-in (Go `tailscale set --update-check`; `None` unchanged). A
    /// CARRIED pref — nothing reads it at runtime — so it needs no engine reconcile.
    pub update_check: Option<bool>,
    /// Operator user (Go `tailscale set --operator`). Double `Option`: `None` unchanged,
    /// `Some(None)` clears, `Some(Some(u))` sets. A CARRIED pref — no engine reconcile.
    pub operator: Option<Option<String>>,
    /// Login-profile nickname (Go `tailscale set --nickname`). Double `Option`: `None` unchanged,
    /// `Some(None)` clears, `Some(Some(n))` sets. Carried by the ENGINE (no reconcile — see
    /// [`SetOptions::needs_rebuild`]), but not inert locally: like Go's `profiles.go`, applying it
    /// also renames the current login profile
    /// ([`rename_current_profile`](Backend::rename_current_profile)), which is what `switch --list`
    /// shows and what a `switch <name>` target resolves against.
    pub nickname: Option<Option<String>>,
    /// Device-posture reporting (Go `tailscale set --report-posture`; `None` unchanged). A CARRIED
    /// pref — no engine reconcile.
    pub report_posture: Option<bool>,
    /// Local web client (Go `tailscale set --webclient`; `None` unchanged). A CARRIED pref — no
    /// engine reconcile (this daemon starts no web server).
    pub webclient: Option<bool>,
    /// LAN access for peers using this node as an exit node (Go `tailscale set
    /// --exit-node-allow-lan-access`; `None` unchanged). A CARRIED pref — no engine reconcile.
    pub exit_node_allow_lan_access: Option<bool>,
}

impl SetOptions {
    /// Whether any field is set (a `set` with nothing named is a no-op the server can reject early).
    pub fn is_empty(&self) -> bool {
        self.hostname.is_none()
            && self.accept_routes.is_none()
            && self.accept_dns.is_none()
            && self.shields_up.is_none()
            && self.exit_node.is_none()
            && self.advertise_exit_node.is_none()
            && self.advertise_routes.is_none()
            && self.advertise_tags.is_none()
            && self.ssh.is_none()
            && self.advertise_connector.is_none()
            && self.auto_update.is_none()
            && self.update_check.is_none()
            && self.operator.is_none()
            && self.nickname.is_none()
            && self.report_posture.is_none()
            && self.webclient.is_none()
            && self.exit_node_allow_lan_access.is_none()
    }

    /// Whether applying this `set` on a **running** node requires a device REBUILD (a brief
    /// reconnect) — true IFF it names a pref that the live engine ACTS on but offers no setter for:
    /// `shields_up` (the immutable `Config.block_incoming`), `ssh` (a device-lifecycle task, not a
    /// `Config` knob), `advertise_tags` (registration-time `Config.requested_tags`), and the two
    /// wire-advertised prefs `advertise_connector` / `auto_update` (construction-time `Config` fields
    /// the engine folds into `Hostinfo.AppConnector` / `Hostinfo.AllowsUpdate` on every map request —
    /// so a running node keeps advertising the OLD value until the device is rebuilt).
    ///
    /// Three groups, and every `SetOptions` field is in exactly one:
    ///
    /// - **LIVE** — `exit_node`, `hostname`, `accept_routes`, `accept_dns`, `advertise_routes`,
    ///   `advertise_exit_node`: each has an in-place engine setter, so naming only these applies with
    ///   no reconnect.
    /// - **REBUILD** — the five listed above.
    /// - **CARRIED** — `update_check`, `operator`, `nickname`, `report_posture`, `webclient`,
    ///   `exit_node_allow_lan_access`: the pinned engine stores these and never acts on or sends them
    ///   (its own `Config` field docs say so), so a live device holding the old copy behaves
    ///   identically to one holding the new one. There is nothing to reconcile — forcing a reconnect
    ///   for them would be a user-visible outage in exchange for no behavior change — so they neither
    ///   rebuild nor issue a live setter. The persisted pref is the source of truth and the next
    ///   device built (any `up`/rebuild/restart) picks it up. A `set` naming ONLY carried prefs on a
    ///   running node therefore yields `SetAction::Live` with an EMPTY op list. CARRIED is a
    ///   statement about the ENGINE only: `nickname` additionally renames the current login profile
    ///   on disk (Go's `profiles.go` does the same), a purely local effect that needs no reconnect.
    ///
    /// The mixed-change rule: if a single `set` touches BOTH a live-applicable pref and a
    /// rebuild-only one, the whole `set` rebuilds (this returns `true`). A rebuild re-applies every
    /// pref from the persisted state anyway, so applying the live ones first would be wasted work
    /// (and the reconnect is unavoidable the moment a rebuild-only pref is named). Pure inspection of
    /// which fields the REQUEST named (not post-apply state). Only meaningful when a device is up;
    /// the caller checks device-presence separately (a down node is always `PersistedOnly`).
    ///
    /// (`accept_dns` is a live field too — `Device::set_accept_dns` — so it is NOT listed here.)
    pub fn needs_rebuild(&self) -> bool {
        self.shields_up.is_some()
            || self.ssh.is_some()
            || self.advertise_tags.is_some()
            || self.advertise_connector.is_some()
            || self.auto_update.is_some()
    }
}

/// The daemon backend: owns prefs, the key file, and the live engine handle.
pub struct Backend {
    prefs: Prefs,
    /// The daemon's state directory — the root under which all profiles live. Held so the backend
    /// can resolve per-profile paths on a `switch` (see [`profile`]).
    state_dir: PathBuf,
    /// The id of the currently-active profile (`"default"` for the legacy/top-level layout). Switching
    /// profiles swaps `prefs`/`prefs_path`/`key_path` to the target profile's and persists the
    /// `current-profile` pointer.
    current_profile: String,
    prefs_path: PathBuf,
    key_path: PathBuf,
    /// The `--config` SOURCE the daemon was started with (a file path, or the `vm:user-data`
    /// sentinel — see [`crate::conffile::ConfigSource`]), or `None` when it was launched without
    /// `--config`, or when an `optional:` source turned out to be absent and the node booted
    /// unconfigured (there is then no config to re-read, exactly as Go leaves `sys.InitialConfig`
    /// nil in that case). Held so the `reload-config` LocalAPI verb (Go `tailscaled`'s
    /// `reload-config` route → `LocalBackend.ReloadConfig`) can **re-read** the same declarative
    /// config and re-adopt its fields into the running backend. Set once from `tailnetd`'s `main()`
    /// via [`set_config_source`](Backend::set_config_source) right after [`load`](Backend::load) when
    /// a config was actually loaded; `reload_config` errors clearly when it is `None` (there is
    /// nothing to re-read). This is process-local boot configuration — like Go, it is NOT persisted (a
    /// `--config`-less restart has no config to reload), and it is deliberately profile-independent: a
    /// `switch` does not change which `--config` source the daemon was launched with.
    config_source: Option<crate::conffile::ConfigSource>,
    /// The WireGuard/disco UDP listen port (Go `tailscaled --port` / `PORT`), or `None` for an
    /// OS-chosen ephemeral port (the default). Set once from `tailnetd`'s `main()` via
    /// [`set_listen_port`](Backend::set_listen_port) right after [`load`](Backend::load) when `--port`
    /// (or `PORT`) is given, and threaded into the engine [`tailscale::Config`] by
    /// [`build_config`](Backend::build_config). Like `config_source`, this is process-local boot
    /// configuration: NOT a pref, NOT persisted, and profile-independent (a `switch` does not change
    /// the listen port the daemon was launched with). `Some(p)` pins the bind so the node's UDP
    /// endpoint is stable across restarts; the engine falls back to an ephemeral port if `p` is taken.
    listen_port: Option<u16>,
    /// The running engine, if up. `None` when stopped/needs-login.
    ///
    /// Held behind an [`Arc`](std::sync::Arc) (not a bare `Device`) so the engine handle can be
    /// **shared** with the long-lived Tailscale SSH server task ([`ssh_task`](Backend::ssh_task)):
    /// the engine's `Device::listen_ssh` takes `self: Arc<Self>` (it runs an accept loop forever and
    /// internally authorizes each connection against the control-pushed policy). Every existing
    /// `&self` engine call (`ipv4_addr`/`status`/`device_state`/`watch_state`/`set_exit_node`) works
    /// unchanged through `Arc`'s `Deref`; the only owned-`self` consumer is `Device::shutdown`, which
    /// [`stop_device`](Backend::stop_device) reaches by *reclaiming* the unique `Device` from the
    /// `Arc` (via [`Arc::into_inner`](std::sync::Arc::into_inner)) **after** aborting the SSH task so
    /// its `Arc` clone is gone — see `stop_device`. When the `ssh` feature is off no clone is ever
    /// made, so the `Arc` is always uniquely owned and reclaim is infallible.
    device: Option<std::sync::Arc<tailscale::Device>>,
    /// The spawned Tailscale SSH server task, when SSH is running (the node is up **and**
    /// `prefs.ssh_enabled`); `None` otherwise. The task holds an [`Arc`](std::sync::Arc) clone of
    /// [`device`](Backend::device) and runs the engine's `listen_ssh` accept loop, which never
    /// returns under normal operation — so its lifecycle is bound to the device's: it is **spawned**
    /// on install in [`finish_up`](Backend::finish_up) and **aborted** (then awaited) in
    /// [`stop_device`](Backend::stop_device) before the device is reclaimed and shut down. Aborting
    /// drops the task's `Arc` clone, which is what lets `stop_device` reclaim the sole `Device` from
    /// the `Arc` for a graceful `shutdown`. Only ever populated in a daemon built with the `ssh`
    /// cargo feature; without it, spawning is a no-op and this stays `None`.
    ssh_task: Option<tokio::task::JoinHandle<()>>,
    /// The `serve` accept-loop tasks, one per plain-TCP-forward entry in the serve config (Go
    /// `tailscale serve --tcp`). Each holds an [`Arc`](std::sync::Arc) clone of the device and runs a
    /// [`Device::tcp_listen`](tailscale::Device::tcp_listen) accept loop splicing each inbound tailnet
    /// connection to the configured localhost target. Like [`ssh_task`](Backend::ssh_task), they are
    /// bound to the device lifecycle: spawned on install in [`finish_up`](Backend::finish_up) (and
    /// re-armed on a serve-config change while up), and **aborted + awaited** in
    /// [`stop_device`](Backend::stop_device) BEFORE the device `Arc` is reclaimed (their clones must
    /// be gone first). Empty when the node is down or no plain TCP forward is configured.
    serve_tasks: Vec<tokio::task::JoinHandle<()>>,
    /// The link-change monitor task: a poll loop that snapshots the host's interface addresses and
    /// calls [`Device::rebind`](tailscale::Device::rebind) when the network path changes (Wi-Fi
    /// switch / sleep-wake), so magicsock re-homes. Like [`ssh_task`](Backend::ssh_task), it holds an
    /// [`Arc`](std::sync::Arc) clone of the device and is bound to the device lifecycle: spawned on
    /// install in [`finish_up`](Backend::finish_up) and **aborted + awaited** in
    /// [`stop_device`](Backend::stop_device) before the device `Arc` is reclaimed. `None` when down.
    monitor_task: Option<tokio::task::JoinHandle<()>>,
    /// Whether the node has ever been configured (brought `up`/`down`), distinguishing a fresh
    /// `NoState` from an explicit `Stopped`. Persists across restarts: it is derived in
    /// [`Backend::load`] from whether the prefs file exists on disk, not from the live process.
    ever_configured: bool,
    /// Monotonic lifecycle generation, bumped on every `up`/`down`. Used by the concurrent
    /// `begin_up`/`finish_up` split (see [`Backend::begin_up`]): the slow `Device::new` runs without
    /// holding the backend lock, so a second `up`/`down` may land first; the generation lets
    /// `finish_up` detect that its device is stale and discard it instead of clobbering newer intent.
    generation: u64,
    /// Wakes status watchers on every lifecycle change (`up`/`down`), carrying the current
    /// [`generation`](Backend::generation). A streaming `status` watcher selects over this *and* the
    /// current device's state receiver, so when a `down`+`up` replaces the device it re-derives the
    /// new receiver rather than going deaf. Bumped in lockstep with `generation` via
    /// [`bump_generation`](Backend::bump_generation).
    lifecycle_tx: tokio::sync::watch::Sender<u64>,
    /// Wakes prefs watchers (a masked `Watch` with the `prefs` bit) on every prefs change. A tick
    /// channel (`()` payload): a receiver re-reads [`prefs_view`](Backend::prefs_view) on each tick
    /// rather than the value riding the channel — the same "tick, then re-read the source" pattern
    /// the streaming `status` watcher uses for state. Bumped from [`persist_prefs`](Backend::persist_prefs),
    /// the single chokepoint EVERY prefs mutation (`up`/`set`/`logout`/`switch`/`reload-config`)
    /// funnels through, so one send-site covers them all. Daemon-owned (the engine has no prefs cell).
    prefs_tx: tokio::sync::watch::Sender<()>,
    /// Whether **this process** has attempted a boot-time auto-start (set by
    /// [`mark_boot_attempted_up`](Backend::mark_boot_attempted_up)). Process-local and deliberately
    /// NOT persisted: it lets the SIGHUP reload path distinguish "retry a bring-up we already
    /// attempted this run (a transient failure)" from "originate a connection from an out-of-band
    /// `prefs.json` intent flip" — the latter must not silently resurrect a node, so reload only
    /// retries when this is `true`.
    boot_attempted_up: bool,
    /// **Cache** of "is there a persisted node key on disk for the current profile" — the
    /// [`have_node_key`](crate::localapi::StatusReport::have_node_key) fact reported by `status`. It
    /// mirrors what [`has_persisted_node_key`](Backend::has_persisted_node_key) would compute, but
    /// avoids re-reading + JSON-parsing + Ed25519-deriving the key file on every `status` call:
    /// `status` runs under the central backend lock and on the `stream_watch` hot path fires on EVERY
    /// engine connection-state transition — where the node-key-present fact never changes.
    ///
    /// **Invariant**: it MUST stay consistent with the on-disk key file at `key_path`. The fact only
    /// changes on a key persist or wipe — exactly three transitions, plus the active profile changing
    /// out from under it:
    ///   - initialized from an actual disk check ONCE in [`load`](Backend::load) (startup, not hot);
    ///   - set `true` after [`begin_up`](Backend::begin_up)'s `build_config` succeeds (its key load
    ///     create-on-missing-writes the file — true for a plain up *and* a force-reauth up, whose
    ///     wipe-then-rebuild ends with a fresh file present);
    ///   - set `false` in [`discard_node_key`](Backend::discard_node_key) after the wipe succeeds (the
    ///     shared primitive behind both `logout` and a force-reauth up — a force-reauth then flips it
    ///     back to `true` via the `build_config` rebuild above);
    ///   - re-derived for the target profile in [`switch_profile`](Backend::switch_profile), which
    ///     repoints `key_path` at a different profile's key file.
    has_node_key: bool,
    /// Whether the last captive-portal detection pass found a portal (Go's `captivePortalWarnable`
    /// health state, held here because this fork has no health tracker to hold it).
    ///
    /// Written **only** by [`captive_portal_loop`], which owns the whole warning lifecycle: it sets
    /// this on a positive detection and clears it the moment connectivity stops being impacted (Go's
    /// `b.health.SetHealthy(captivePortalWarnable)` branch). Read by [`status`](Backend::status),
    /// which projects it into [`StatusReport::health`](crate::localapi::StatusReport::health).
    ///
    /// Deliberately NOT a lifecycle wake edge: flipping it does not bump the generation, because the
    /// generation is the concurrent-bring-up staleness token (see [`Backend::begin_up`]) and bumping
    /// it from a background probe could make an in-flight `finish_up` discard its own device. A
    /// `status --watch` therefore learns about the warning on its next snapshot rather than being
    /// pushed one — consistent with this fork's `Notify` having no health stream at all.
    captive_portal_detected: bool,
    /// Whether a disconnect the always-on gate PERMITTED is currently standing — Go's
    /// `LocalBackend.overrideAlwaysOn` (`ipn/ipnlocal/local.go`).
    ///
    /// While it is set, [`syspolicy::apply_to_prefs`] skips the `AlwaysOn.Enabled` re-assert, so the
    /// disconnect survives every reconcile point instead of being undone by the next unrelated `tnet
    /// set`. (An `up` is a reconcile point too, but it clears this first — see below, and that is
    /// the point: bringing the node up by hand is not something the policy has to fight.) Without it
    /// the [`ReconnectAfter`][reconnect] timer
    /// would be pointless: the re-assert would put the node back up long before the timer fired.
    ///
    /// Set on a disconnect and cleared on exactly the three events Go clears it on:
    /// - a **connect** — [`begin_up`](Backend::begin_up), where `want_running` goes back to true;
    /// - a **profile switch** — [`activate_profile`](Backend::activate_profile), because the
    ///   exemption was granted against the profile that asked for it;
    /// - an always-on **policy change** — [`sys_policy_changed`](Backend::sys_policy_changed), Go's
    ///   `sysPolicyChanged` clearing it whenever `AlwaysOn.Enabled` or `AlwaysOn.OverrideWithReason`
    ///   moves, so an administrator's edit revokes an outstanding exemption.
    ///
    /// **In-memory, exactly like Go's**, and that is the safe direction: a daemon restart loses the
    /// exemption, the profile load reconciles policy with the flag clear, and an always-on node comes
    /// back up. A policy whose whole purpose is to keep the node connected must not be defeated by
    /// killing the daemon.
    ///
    /// [reconnect]: syspolicy::PKEY_RECONNECT_AFTER
    override_always_on: bool,
    /// The outstanding always-on reconnect timer's arming, or `None` when none is armed — Go's
    /// `LocalBackend.reconnectTimer` (`ipn/ipnlocal/local.go`).
    ///
    /// A [`watch`](tokio::sync::watch) cell rather than a spawned-per-arm task, because the thing
    /// that has to fire it — a bring-up — needs the `Arc<Mutex<Backend>>` the backend cannot hand
    /// itself. [`reconnect_loop`] holds that `Arc`, watches this cell, and sleeps until the deadline
    /// in it; re-arming or cancelling is a `send` that wakes the loop, which is what makes
    /// [`stop_reconnect_timer`](Backend::stop_reconnect_timer) exact rather than advisory. The cell
    /// is the single source of truth for "is a timer armed", so a daemon that never spawns the loop
    /// (a unit test, another binary) still arms and cancels observably — it just never fires.
    ///
    /// See [`ReconnectTimer`] for the two guards the loop re-checks before it acts.
    reconnect_tx: tokio::sync::watch::Sender<Option<ReconnectTimer>>,
    /// Monotonic arming counter behind [`ReconnectTimer::seq`] — Go compares timer *identity*
    /// (`b.reconnectTimer != timer`); this fork compares a number, because the armed value is copied
    /// out of the watch cell rather than being a pointer the loop can hold.
    reconnect_seq: u64,
    /// The always-on policy keys as they were when this backend last looked — the snapshot
    /// [`sys_policy_changed`](Backend::sys_policy_changed) compares against to decide whether an
    /// administrator's edit revoked an outstanding exemption (Go's
    /// `policy.HasChangedAnyOf(pkey.AlwaysOn, pkey.AlwaysOnOverrideWithReason)`).
    ///
    /// Seeded at [`load`](Backend::load) and updated on every comparison, so a change is seen exactly
    /// once no matter how many times the policy ticks.
    always_on_keys: syspolicy::AlwaysOnKeys,
    /// Whether an exit-node choice the policy PERMITTED the operator to make is currently standing —
    /// Go's `LocalBackend.overrideExitNodePolicy` (`ipn/ipnlocal/local.go`).
    ///
    /// It is the exit-node twin of [`override_always_on`](Backend::override_always_on), and it
    /// exists for the same reason: the gate ([`exitnodepolicy`]) can allow an operator to pick a
    /// different exit node under `ExitNode.AllowOverride`, but
    /// [`syspolicy::apply_to_prefs`] re-applies the administrator's `ExitNodeIP` at every reconcile
    /// point, so without this flag the permitted choice would be silently undone by the same
    /// command that made it. While it is set, the exit-node re-apply is skipped.
    ///
    /// Set by [`record_exit_node_edit`](Backend::record_exit_node_edit) when an edit takes the
    /// override, and cleared on exactly the events Go clears it on:
    /// - the operator picking the policy's own node again (the edit itself says so — Go's "switches
    ///   back to the state required by policy");
    /// - a **connect** or **disconnect** — [`begin_up`](Backend::begin_up),
    ///   [`down`](Backend::down)/[`logout`](Backend::logout);
    /// - a **profile switch** — [`activate_profile`](Backend::activate_profile), because the
    ///   exemption was granted against the profile that asked for it;
    /// - an exit-node **policy change** —
    ///   [`exit_node_policy_changed`](Backend::exit_node_policy_changed), Go's `sysPolicyChanged`
    ///   clearing it whenever `ExitNodeID`, `ExitNodeIP` or `ExitNode.AllowOverride` moves.
    ///
    /// **In-memory, exactly like Go's**: a daemon restart forgets the override, the profile-load
    /// reconcile then re-applies the administrator's node, and the operator who still wants theirs
    /// asks for it again. That is the safe direction for a pin whose whole purpose is to decide
    /// where the node egresses.
    override_exit_node_policy: bool,
    /// The exit-node policy keys as they were when this backend last looked — the snapshot
    /// [`exit_node_policy_changed`](Backend::exit_node_policy_changed) compares against, Go's
    /// `policy.HasChangedAnyOf(pkey.ExitNodeID, pkey.ExitNodeIP, pkey.AllowExitNodeOverride)`.
    ///
    /// Seeded and updated exactly like [`always_on_keys`](Backend::always_on_keys).
    exit_node_keys: syspolicy::ExitNodeKeys,
}

/// One arming of the always-on reconnect timer — the state Go's `startReconnectTimerLocked` captures
/// in the closure it hands to `b.clock.AfterFunc` (`ipn/ipnlocal/local.go`).
///
/// Both guards Go re-checks when the timer fires are carried here rather than recomputed, because
/// both are answers about *the moment the timer was armed*:
///
/// - [`seq`](ReconnectTimer::seq) is Go's `b.reconnectTimer != timer` identity check. A timer that
///   was cancelled or replaced while its sleep was in flight must not act — the sleep cannot be
///   un-scheduled once the loop has entered it, so the arming that wakes has to prove it is still
///   the live one.
/// - [`profile`](ReconnectTimer::profile) is Go's captured `profileID`. Without it, a timer armed
///   by a disconnect on one profile would reconnect whichever profile happened to be active when it
///   fired — a different node, on a different tailnet, that nobody asked to be connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectTimer {
    /// Which arming this is; see the type docs. Compared against
    /// [`Backend::reconnect_seq`](Backend::reconnect_seq) at fire time.
    seq: u64,
    /// The profile id that was active when the timer was armed.
    profile: String,
    /// The configured `ReconnectAfter`, kept so the fire-time log can name the window that elapsed
    /// (Go's `after %v`) without re-reading a policy that may have moved since.
    after: std::time::Duration,
    /// When it fires — `armed_at + after`, on the same monotonic clock the loop sleeps against.
    deadline: tokio::time::Instant,
}

impl ReconnectTimer {
    /// When this arming fires.
    pub fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    /// The configured window, rendered the way Go's `%v` renders a `time.Duration` (`30m0s`) — used
    /// in the two log lines `reconnect_loop` writes, so they read exactly like `tailscaled`'s.
    fn after_go(&self) -> String {
        crate::goduration::format_go_duration(
            i64::try_from(self.after.as_nanos()).unwrap_or(i64::MAX),
        )
    }
}

/// What a [`Backend::switch_profile`] call actually did — the daemon-side half of the reporting Go's
/// `switch` does around its `SwitchProfile` LocalAPI call (`cmd/tailscale/cli/switch.go`).
///
/// Go's CLI distinguishes three outcomes and says so in words: the target *was already* the current
/// profile (`Already on account %q`, exit 0, nothing torn down), or the switch happened and the new
/// profile then settles into a state it reports (`Success.` when it reaches `Running`, or
/// `Logged out.` plus `To log in, run: tailscale up` when it reaches `NeedsLogin`). Reducing all
/// three to one "switched" string — as this daemon did — makes the no-op case *claim a switch that
/// never happened*, which is the one report a caller cannot afford to have wrong.
///
/// Go reaches its terminal report by polling `StatusWithoutPeers` until the backend leaves
/// `NoState`/`Starting`. This daemon does not need the poll: `switch_profile` tears the device down
/// and deliberately does not auto-`up` the target (see its docs), so the target's post-switch state
/// is already final and is computed once, here, from the same [`Backend::derive_state`] the wire
/// `status` uses — no second source of truth, no waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwitchOutcome {
    /// `target` resolved to the profile that was **already** active: no teardown, no writes, no
    /// change. Go's `Already on account %q` (which exits 0 — this is a success, not an error).
    AlreadyCurrent {
        /// The canonical id `target` resolved to.
        id: String,
    },
    /// The active profile changed to `id`, whose settled state is `state`. The device is always down
    /// immediately after a switch (this daemon never auto-`up`s the target), so `state` is one of
    /// `NeedsLogin` (logged out / wants running with no engine), `NoState` (never registered — no
    /// node key yet) or `Stopped` (registered, explicitly down).
    Switched {
        /// The canonical id `target` resolved to, now the active profile.
        id: String,
        /// The target profile's state after the switch, from [`Backend::derive_state`].
        state: State,
    },
}

impl SwitchOutcome {
    /// The one-line human report for this outcome, as the LocalAPI `Ok` message.
    ///
    /// Mirrors the three things Go's `switch` tells the user, adapted to this daemon's nouns
    /// (`profile`, not `account`) and to the fact that a switch here never connects:
    /// - already-current → it says so, and does not claim a switch;
    /// - switched to a profile with no usable login (`NeedsLogin`/`NoState`) → Go's "Logged out. To
    ///   log in, run: `tailscale up`" collapsed onto one line;
    /// - switched to a registered-but-down profile (`Stopped`) → run `up` to connect.
    ///
    /// Names the resolved **id** rather than echoing the caller's argument (Go prints `args[0]`):
    /// the argument may have been a display name, and the id is what every follow-up command —
    /// `switch`, `switch remove`, the `--list` output — is keyed by.
    pub fn report(&self) -> String {
        match self {
            SwitchOutcome::AlreadyCurrent { id } => format!("already on profile {id:?}"),
            SwitchOutcome::Switched { id, state } => match state {
                // No usable login on the target: Go's `NeedsLogin` arm tells the user how to fix it.
                State::NeedsLogin | State::NoState => {
                    format!("switched to profile {id:?} (logged out — run `tnet up` to log in)")
                }
                // Registered, just not connected — a switch always leaves the device down.
                _ => format!("switched to profile {id:?} (run `tnet up` to connect)"),
            },
        }
    }
}

/// What a `switch remove` actually did — the analogue of the two exits Go's `removeProfile` takes
/// once it has matched a profile (`cmd/tailscale/cli/switch.go`).
///
/// Go removes the matched profile *unless it is the current one*, and the current-profile case is a
/// plain **success**: `if profID == cp.ID { printf("Already on account %q\n", args[0]); os.Exit(0) }`
/// — nothing is deleted and the command exits 0. (The wording is `switchProfile`'s, reused verbatim
/// there; the behaviour is what matters.) Collapsing that into an error, as this daemon did, breaks
/// every ported caller that walks a list of profiles and removes each: under Go the active one is
/// skipped and the loop finishes, here it exited non-zero. So the "not removed" case is typed and
/// reported rather than raised, exactly like [`SwitchOutcome::AlreadyCurrent`] — the protection Go
/// has (the active profile is never deleted out from under the running device) is kept; only the
/// exit status changes, to Go's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// The profile was removed: its prefs+key files are gone and its `profiles.json` entry with them.
    Removed {
        /// The canonical id `target` resolved to.
        id: String,
    },
    /// `target` resolved to the profile that is **currently active**, so nothing was removed. Go's
    /// `Already on account %q` + `os.Exit(0)` — a success, not a refusal.
    AlreadyCurrent {
        /// The canonical id `target` resolved to, still the active profile and still on disk.
        id: String,
    },
}

impl DeleteOutcome {
    /// The one-line human report for this outcome, as the LocalAPI `Ok` message.
    ///
    /// Names the resolved **id** rather than echoing the caller's argument (Go prints `args[0]`):
    /// the argument may have been a display name, and the id is what `--list` and every follow-up
    /// command are keyed by. The already-current line keeps Go's leading clause but says outright
    /// that nothing was removed — Go's bare `Already on account %q` is `switchProfile`'s message
    /// reused, and after `switch remove` it reads as if the removal had happened.
    pub fn report(&self) -> String {
        match self {
            DeleteOutcome::Removed { id } => format!("removed profile {id:?}"),
            DeleteOutcome::AlreadyCurrent { id } => {
                format!("already on profile {id:?}; not removed — switch away first to remove it")
            }
        }
    }
}

/// Whether the key file at `key_path` holds a usable persisted node key — a **pure, side-effect-free**
/// read (the on-disk source of truth behind both [`Backend::has_persisted_node_key`] and the
/// [`has_node_key`](Backend::has_node_key) cache). One source of truth so the cache's startup seed
/// ([`Backend::load`]), its profile re-derivation ([`Backend::switch_profile`]), and the auto-start
/// probe can never disagree about how the key file is parsed.
///
/// Do NOT call `tailscale::config::load_key_file` here: it create-on-missing-WRITES a fresh key file
/// as a side effect, and merely *checking* must never manufacture a key. We read the bytes and confirm
/// they parse into the engine's own `{ "key_state": <PersistState> }` shape (reusing its
/// `Deserialize`, so this can't drift if the key-state layout changes). A parseable `PersistState`
/// always carries a (32-byte, non-empty) node key, so a successful parse is exactly the "node key
/// present" condition; we derive the public node key both to *use* the parsed state and as a final
/// structural sanity check that the private key material is well-formed. A missing/unreadable/malformed
/// file reads as "no persisted key" (the daemon then falls back to fresh auth rather than trusting
/// garbage).
async fn key_file_has_node_key(key_path: &std::path::Path) -> bool {
    let Ok(bytes) = tokio::fs::read(key_path).await else {
        // Missing (fresh node) or unreadable → treat as "no persisted key".
        return false;
    };
    #[derive(serde::Deserialize)]
    struct KeyFile {
        key_state: tailscale::keys::PersistState,
    }
    match serde_json::from_slice::<KeyFile>(&bytes) {
        Ok(kf) => {
            let _node_public = kf.key_state.node_key.public_key();
            true
        }
        Err(_) => false,
    }
}

impl Backend {
    /// Construct a backend from a state directory, loading the current profile's persisted prefs.
    ///
    /// The active profile is read from the `current-profile` pointer (absent ⇒ `"default"`, which is
    /// the legacy top-level `prefs.json`/`node.key.json` layout — so a pre-profiles state dir loads
    /// exactly as before). Per-profile paths come from [`profile::profile_paths`].
    pub async fn load(state_dir: &std::path::Path) -> Result<Self> {
        let current_profile = profile::load_current_profile(state_dir).await;
        let (prefs_path, key_path) = profile::profile_paths(state_dir, &current_profile);
        // `ever_configured` distinguishes a never-touched node (`NoState`) from one explicitly
        // brought down (`Stopped`), and must survive a daemon restart. It is derived from the
        // *existence* of the prefs file rather than from prefs contents: `down()` persists prefs with
        // `want_running = false` (and not `logged_out`), so a contents-based test
        // (`want_running || logged_out`) would read `false` after an up→down→restart and the node
        // would wrongly fall back to `NoState`. A fresh node has never written prefs, so the file is
        // absent; once `up`/`down` runs, the file exists — exactly the "configured before" signal we
        // need. (`Prefs::load` returns the default for a missing file, so the file's presence, not
        // its contents, is the load-bearing signal — hence we probe it before loading.)
        let ever_configured = tokio::fs::try_exists(&prefs_path).await.unwrap_or(false);
        let prefs = Prefs::load(&prefs_path)
            .await
            .with_context(|| format!("loading prefs from {}", prefs_path.display()))?;
        let (lifecycle_tx, _) = tokio::sync::watch::channel(0u64);
        let (prefs_tx, _) = tokio::sync::watch::channel(());
        let mut backend = Self {
            prefs,
            state_dir: state_dir.to_path_buf(),
            current_profile,
            prefs_path,
            key_path,
            // No `--config` by default; `tailnetd`'s `main()` calls `set_config_source` right after
            // this when a `--config` source actually loaded, so `reload_config` can later re-read it.
            config_source: None,
            // No fixed listen port by default (ephemeral, OS-chosen — Go's port 0); `tailnetd`'s
            // `main()` calls `set_listen_port` right after this when `--port`/`PORT` was given.
            listen_port: None,
            device: None,
            ssh_task: None,
            serve_tasks: Vec::new(),
            monitor_task: None,
            ever_configured,
            generation: 0,
            boot_attempted_up: false,
            lifecycle_tx,
            prefs_tx,
            // Seed the cache once, at startup, from an actual on-disk check — startup is not the hot
            // path, and every later mutation is tracked at its transition (see the field doc's
            // invariant). `has_persisted_node_key` reads only `key_path`, which is already set above.
            has_node_key: false,
            // No detection has run yet; the captive-portal loop is the only writer from here on.
            captive_portal_detected: false,
            // No disconnect has been permitted in THIS process, so no always-on exemption stands and
            // no reconnect is outstanding. Both are deliberately in-memory (see the field docs): a
            // restart forgets an exemption, and the profile-load reconcile below then brings an
            // always-on node back up, which is the direction that keeps the policy's promise.
            override_always_on: false,
            reconnect_tx: tokio::sync::watch::channel(None).0,
            reconnect_seq: 0,
            // Seed the always-on snapshot from the policy as it stands at boot, so the first
            // comparison reports a real change rather than "everything changed".
            always_on_keys: syspolicy::always_on_keys(),
            // No exit-node override has been granted in THIS process either, and for the same
            // reason it is not persisted: the reconcile below puts the administrator's node back.
            override_exit_node_policy: false,
            exit_node_keys: syspolicy::exit_node_keys(),
        };
        backend.has_node_key = backend.has_persisted_node_key().await;
        // Go reconciles system policy on every profile load, and this is one (the daemon's own, at
        // boot). IN MEMORY ONLY — see `reconcile_sys_policy` for why loading must not write.
        backend.reconcile_sys_policy("profile load");
        Ok(backend)
    }

    /// Overwrite this backend's in-memory prefs with whatever the effective system policy (MDM)
    /// says — the Rust analogue of the `applySysPolicy` half of Go's `reconcilePrefs`
    /// (`ipn/ipnlocal/local.go`).
    ///
    /// Called from every place Go reconciles: a **profile load** ([`load`](Backend::load) at daemon
    /// start, [`switch_profile`](Backend::switch_profile)) and every **prefs write**
    /// ([`begin_up`](Backend::begin_up), [`begin_set`](Backend::begin_set),
    /// [`apply_config`](Backend::apply_config)) — always AFTER the caller's own overrides have
    /// landed, which is what makes policy outrank a live `tnet set`, a `tnet up` flag, a `--config`
    /// document and `up --reset` alike. `at` names the call site for the log.
    ///
    /// It mutates prefs and **does not persist**. On the write paths the caller persists a moment
    /// later anyway, so the policy's values are durable. On a profile load there is deliberately
    /// nothing to persist: writing at boot would create a `prefs.json` for a node that has never been
    /// configured, and this daemon derives `ever_configured` from that file's existence — so merely
    /// dropping a policy file on a fresh host would turn its next `NoState` into `Stopped`. The
    /// in-memory values are what `status`, `get` and the next bring-up all read, so nothing is lost
    /// by waiting for a real write.
    ///
    /// It carries the backend's standing exemptions into the apply
    /// ([`syspolicy::PolicyOverrides`]), which is what keeps a change the policy already PERMITTED
    /// from being undone here: while [`override_always_on`](Backend::override_always_on) stands the
    /// `AlwaysOn.Enabled` re-assert is skipped at every one of these call sites, and while
    /// [`override_exit_node_policy`](Backend::override_exit_node_policy) stands the `ExitNodeIP`
    /// re-apply is.
    ///
    /// Silent when the policy is silent (the overwhelmingly common case: no `--syspolicy-file`, or
    /// one whose settings are already in force). A key this build cannot enforce is logged at WARN
    /// *every* time, not once: an administrator who shipped it is owed a message that is still in the
    /// log when they go looking, and the alternative — reporting intent that changes nothing — is the
    /// failure this whole path exists to remove.
    fn reconcile_sys_policy(&mut self, at: &'static str) {
        let applied = syspolicy::apply_to_prefs(
            &mut self.prefs,
            syspolicy::PolicyOverrides {
                always_on: self.override_always_on,
                exit_node: self.override_exit_node_policy,
            },
        );
        for change in &applied.changed {
            tracing::info!(
                at,
                key = change.key,
                pref = change.pref,
                value = %change.value,
                "system policy overrode a pref"
            );
        }
        for refusal in &applied.refused {
            tracing::warn!(
                at,
                key = refusal.key,
                "system policy setting is NOT enforced by this build: {}",
                refusal.reason
            );
        }
    }

    /// Record that a disconnect this daemon **permitted** has just taken `want_running` from true to
    /// false — Go's `onEditPrefsLocked` disconnect arm (`ipn/ipnlocal/local.go`):
    ///
    /// ```text
    /// b.overrideAlwaysOn = true
    /// if reconnectAfter, _ := b.polc.GetDuration(pkey.ReconnectAfter, 0); reconnectAfter > 0 {
    ///     b.startReconnectTimerLocked(reconnectAfter)
    /// }
    /// ```
    ///
    /// Called by [`down`](Backend::down) and [`logout`](Backend::logout) — the two verbs that make
    /// that transition — **after** the gate has allowed the disconnect and the pref has been flipped,
    /// and only when the pref really was true before (Go guards on `oldPrefs.WantRunning()`, so a
    /// `down` on an already-down node neither grants an exemption nor re-arms a timer, and cannot be
    /// used to keep pushing a deadline out).
    ///
    /// `reconnect_after` is [`syspolicy::reconnect_after`]'s answer, passed in rather than read here
    /// so the decision is testable without the process-global policy registry — the same split the
    /// policy module uses throughout. `None` means the administrator set no bound: the exemption is
    /// still granted (that is what makes the disconnect stick), it simply has no expiry, which is
    /// Go's behaviour for an unset or non-positive `ReconnectAfter`.
    fn on_permitted_disconnect(&mut self, reconnect_after: Option<std::time::Duration>) {
        self.override_always_on = true;
        // `None` arms nothing, and — like Go, whose `if reconnectAfter > 0` has no else — does not
        // stop an existing timer either. Nothing can be outstanding here anyway: the transition
        // guard at the call site means the node was up, and coming up cancels any timer.
        if let Some(after) = reconnect_after {
            self.start_reconnect_timer(after);
        }
    }

    /// Arm (or re-arm) the reconnect timer to fire `after` from now — Go
    /// `startReconnectTimerLocked`, which stops any previous timer and captures the current profile
    /// id before scheduling.
    ///
    /// The arming is published to [`reconnect_loop`], which does the sleeping; replacing the value in
    /// the cell IS the "stop any previous timer" half, because the loop re-reads the cell on every
    /// change and the superseded arming can no longer pass [`claim_due_reconnect`] even if its sleep
    /// were somehow still in flight.
    fn start_reconnect_timer(&mut self, after: std::time::Duration) {
        self.reconnect_seq += 1;
        let armed = ReconnectTimer {
            seq: self.reconnect_seq,
            profile: self.current_profile.clone(),
            after,
            deadline: tokio::time::Instant::now() + after,
        };
        tracing::info!(
            profile = %armed.profile,
            after = %armed.after_go(),
            "always-on: disconnect permitted; the node will reconnect itself when ReconnectAfter \
             elapses"
        );
        // `send_replace`, not `send`: `send` REFUSES when there is no receiver, which would leave a
        // daemon that never spawned `reconnect_loop` (a unit test, another binary) silently unarmed.
        // The cell is the source of truth for "is a timer armed", so the value is written either
        // way; with no loop running it simply has nobody to fire it, which is the honest state.
        self.reconnect_tx.send_replace(Some(armed));
    }

    /// Cancel any outstanding reconnect timer — Go's `b.reconnectTimer.Stop()`, reached from every
    /// place Go resets the always-on override.
    ///
    /// Idempotent and silent when nothing is armed, so the reset paths can call it unconditionally.
    fn stop_reconnect_timer(&mut self) {
        if self.is_reconnect_armed() {
            self.reconnect_tx.send_replace(None);
        }
    }

    /// Whether a reconnect timer is currently armed — the cell read, kept in one place so no caller
    /// holds a [`watch`](tokio::sync::watch) borrow across a send (which would deadlock on the
    /// cell's own lock).
    fn is_reconnect_armed(&self) -> bool {
        self.reconnect_tx.borrow().is_some()
    }

    /// Clear a standing always-on exemption and cancel its timer — Go's
    /// `resetAlwaysOnOverrideLocked`. `at` names the event for the log.
    ///
    /// Idempotent: with no exemption standing and no timer armed this does nothing and says nothing,
    /// which is what lets the three reset sites (connect, profile switch, always-on policy change)
    /// call it unconditionally.
    fn reset_always_on_override(&mut self, at: &'static str) {
        let was_armed = self.is_reconnect_armed();
        if self.override_always_on || was_armed {
            tracing::info!(
                at,
                cancelled_reconnect = was_armed,
                "always-on: the permitted-disconnect exemption no longer stands"
            );
        }
        self.override_always_on = false;
        self.stop_reconnect_timer();
    }

    /// React to the effective system policy having moved — Go's `sysPolicyChanged`, narrowed to the
    /// part that owns backend state: `policy.HasChangedAnyOf(pkey.AlwaysOn,
    /// pkey.AlwaysOnOverrideWithReason)` clears the always-on override.
    ///
    /// `current` is [`syspolicy::always_on_keys`]'s answer, passed in by [`reconnect_loop`] (which
    /// holds the policy-change subscription) so the comparison is testable without the process-global
    /// registry. Only a *change* resets: a policy tick that leaves both keys where they were must not
    /// revoke an exemption the administrator did not touch — which matters here because this build's
    /// one policy source captures the file at startup, so `tnet syspolicy reload` ticks the bus
    /// without ever changing a value.
    ///
    /// Returns whether it reset anything, so a caller can log the edge.
    fn sys_policy_changed(&mut self, current: syspolicy::AlwaysOnKeys) -> bool {
        if current == self.always_on_keys {
            return false;
        }
        tracing::info!(
            "always-on: the administrator changed an always-on policy key; revoking any \
             outstanding permitted-disconnect exemption"
        );
        self.always_on_keys = current;
        self.reset_always_on_override("policy change");
        true
    }

    /// Decide whether this prefs edit may change the exit node — Go's `checkEditPrefsAccessLocked`
    /// exit-node arm, reached from [`begin_up`](Backend::begin_up) and
    /// [`begin_set`](Backend::begin_set) **before** a single pref is mutated or persisted, exactly
    /// where the always-on disconnect gate sits for `down`/`logout`.
    ///
    /// `named` is the command's `--exit-node` as its options carry it (see
    /// [`exitnodepolicy::check_exit_node_edit`] for the double `Option`'s meaning). The verdict it
    /// returns is the exemption bookkeeping the caller must hand to
    /// [`record_exit_node_edit`](Backend::record_exit_node_edit) once the edit has landed — one
    /// function decides both, so an edit can never be allowed as an override and then not
    /// remembered as one.
    ///
    /// The refusal is raised as an `anyhow` error, like every other pre-validation refusal on those
    /// paths, so it reaches the operator as the LocalAPI error of the command they ran.
    fn check_exit_node_policy(
        &self,
        named: Option<Option<&str>>,
    ) -> Result<exitnodepolicy::ExitNodeEdit> {
        exitnodepolicy::check_exit_node_edit(named, &syspolicy::exit_node_policy())
            .map_err(|refused| anyhow!(refused))
    }

    /// Record what a **permitted** exit-node edit means for the standing override — Go's
    /// `onEditPrefsLocked` exit-node arm.
    ///
    /// Called by `begin_up`/`begin_set` after the edit has been applied to prefs and *before* the
    /// reconcile, because the reconcile is the thing the flag has to be in place for: an
    /// [`Override`](exitnodepolicy::ExitNodeEdit::Override) that were recorded afterwards would be
    /// overwritten by the very re-apply it exists to suppress. `at` names the call site for the log.
    fn record_exit_node_edit(&mut self, edit: exitnodepolicy::ExitNodeEdit, at: &'static str) {
        match edit {
            // The command said nothing about the exit node, so it says nothing about the exemption.
            exitnodepolicy::ExitNodeEdit::Untouched => {}
            exitnodepolicy::ExitNodeEdit::NoOverride => self.reset_exit_node_policy_override(at),
            exitnodepolicy::ExitNodeEdit::Override => {
                if !self.override_exit_node_policy {
                    tracing::info!(
                        at,
                        "exit node: the policy permits a user override; the \
                         administrator's ExitNodeIP will not be re-applied while it stands"
                    );
                }
                self.override_exit_node_policy = true;
            }
        }
    }

    /// Clear a standing exit-node override — Go's `b.overrideExitNodePolicy = false`. `at` names the
    /// event for the log.
    ///
    /// Idempotent and silent when no override stands, so the reset sites (connect, disconnect,
    /// profile switch, exit-node policy change, and an edit that returns to the policy's own node)
    /// can call it unconditionally.
    fn reset_exit_node_policy_override(&mut self, at: &'static str) {
        if self.override_exit_node_policy {
            tracing::info!(
                at,
                "exit node: the permitted override no longer stands; the policy's exit \
                 node applies again"
            );
        }
        self.override_exit_node_policy = false;
    }

    /// React to the exit-node policy keys having moved — the second half of Go's `sysPolicyChanged`,
    /// `policy.HasChangedAnyOf(pkey.ExitNodeID, pkey.ExitNodeIP, pkey.AllowExitNodeOverride)`, which
    /// clears the exit-node override.
    ///
    /// A sibling of [`sys_policy_changed`](Backend::sys_policy_changed) rather than a branch inside
    /// it, because Go asks two independent `HasChangedAnyOf` questions with two independent answers:
    /// an administrator who edits `AlwaysOn.Enabled` has not said anything about the exit node.
    /// `current` is [`syspolicy::exit_node_keys`]'s answer, passed in by [`reconnect_loop`] for the
    /// same testability reason.
    ///
    /// Returns whether it reset anything, so a caller can log the edge.
    fn exit_node_policy_changed(&mut self, current: syspolicy::ExitNodeKeys) -> bool {
        if current == self.exit_node_keys {
            return false;
        }
        tracing::info!(
            "exit node: the administrator changed an exit-node policy key; revoking any \
             outstanding override"
        );
        self.exit_node_keys = current;
        self.reset_exit_node_policy_override("policy change");
        true
    }

    /// Subscribe to the reconnect-timer arming cell — the handle [`reconnect_loop`] sleeps against.
    pub fn watch_reconnect(&self) -> tokio::sync::watch::Receiver<Option<ReconnectTimer>> {
        self.reconnect_tx.subscribe()
    }

    /// Go's two fire-time guards, taken together and under the same lock: is `armed` still the live
    /// arming, and is the profile it was armed for still the current one?
    ///
    /// ```text
    /// if b.reconnectTimer != timer { return }
    /// b.reconnectTimer = nil
    /// cp := b.pm.CurrentProfile()
    /// if cp.ID() != profileID { return }
    /// ```
    ///
    /// Go clears `b.reconnectTimer` between the two checks, and so does this: a claim that passes
    /// the identity check empties the cell whether or not the profile check then lets the reconnect
    /// through, so a due timer fires at most once either way. The identity check's own refusal
    /// touches nothing — a superseded arming must not cancel the one that replaced it.
    fn claim_due_reconnect(&mut self, armed: &ReconnectTimer) -> bool {
        let live = self.reconnect_tx.borrow().clone();
        if live.as_ref() != Some(armed) {
            // Cancelled or replaced while the sleep was in flight (a manual `up`, a second `down`, a
            // profile switch, a policy change). The newer intent wins.
            return false;
        }
        if armed.profile != self.current_profile {
            // The profile moved out from under the timer. Go returns here WITHOUT reconnecting, and
            // with the timer already cleared above — the exemption belonged to the old profile, and
            // reconnecting this one would connect a node nobody asked for.
            self.reconnect_tx.send_replace(None);
            tracing::info!(
                armed_for = %armed.profile,
                current = %self.current_profile,
                "always-on: dropping a reconnect armed under a different profile"
            );
            return false;
        }
        self.reconnect_tx.send_replace(None);
        true
    }

    /// The state directory this daemon is actually using — the root under which every profile's prefs
    /// and keys live.
    ///
    /// Fixed at [`load`](Backend::load) from `tailnetd`'s `--statedir` (or from the
    /// [`state_dir`](crate::state_dir) cascade as the daemon resolved it *at boot, in the daemon's own
    /// environment*), so this is the only authoritative answer to "where is this node's state?": a CLI
    /// re-running that cascade in a different environment — an unprivileged `tnet` against a root
    /// `tailnetd` whose unit sets the dir — resolves a DIFFERENT path. Read by the
    /// [`DebugStateDir`](crate::localapi::Request::DebugStateDir) LocalAPI verb, the analogue of Go's
    /// `LocalBackend.TailscaleVarRoot()` that its `debug` route's `statedir` action returns.
    pub fn state_dir(&self) -> &std::path::Path {
        &self.state_dir
    }

    /// Record the `--config` source the daemon was started with, so the `reload-config` LocalAPI
    /// verb can later re-read it (see [`config_source`](Backend::config_source) and
    /// [`reload_config`](Backend::reload_config)). Called once from `tailnetd`'s `main()` right after
    /// [`load`](Backend::load) when a `--config` source actually loaded — separate from `load` so the
    /// common (config-less) startup path stays untouched and the rare config path is one explicit
    /// call. NOT called when an `optional:` source was absent: there is nothing to re-read, so
    /// `reload-config` correctly reports that no config is in use. Idempotent (last write wins),
    /// though the daemon only ever calls it once at boot.
    pub fn set_config_source(&mut self, source: crate::conffile::ConfigSource) {
        self.config_source = Some(source);
    }

    /// Record the WireGuard/disco UDP listen port the daemon was started with (Go `tailscaled --port`
    /// / `PORT`), threaded into the engine config by [`build_config`](Backend::build_config). Called
    /// once from `tailnetd`'s `main()` right after [`load`](Backend::load) when `--port`/`PORT` was
    /// given — separate from `load` (like [`set_config_source`](Backend::set_config_source)) so the common
    /// (ephemeral-port) startup path stays untouched. `None` is never passed (the caller only calls
    /// this when a port was given); a `Some(0)` would be honored verbatim by the engine as "pick any",
    /// equivalent to the default. Idempotent (last write wins); the daemon calls it once at boot.
    pub fn set_listen_port(&mut self, port: u16) {
        self.listen_port = Some(port);
    }

    /// List the known profiles (the analogue of Go `tailscale switch --list`). Returns one entry per
    /// profile — the implicit `default` plus every id in `profiles.json` — each with its display name
    /// and whether it is the current profile. Pure read (no device, no lock-sensitive work).
    pub async fn list_profiles(&self) -> Vec<crate::localapi::ProfileEntry> {
        let meta = profile::load_profiles_file(&self.state_dir).await;
        let mut entries = Vec::new();
        // The default profile always exists (it is the legacy top-level layout); include it first.
        entries.push(crate::localapi::ProfileEntry {
            id: profile::DEFAULT_PROFILE_ID.to_string(),
            name: meta
                .profiles
                .get(profile::DEFAULT_PROFILE_ID)
                .map(|m| m.name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| profile::DEFAULT_PROFILE_ID.to_string()),
            current: self.current_profile == profile::DEFAULT_PROFILE_ID,
        });
        for (id, m) in &meta.profiles {
            if id == profile::DEFAULT_PROFILE_ID {
                continue; // already emitted above
            }
            entries.push(crate::localapi::ProfileEntry {
                id: id.clone(),
                name: if m.name.is_empty() {
                    id.clone()
                } else {
                    m.name.clone()
                },
                current: &self.current_profile == id,
            });
        }
        entries
    }

    /// Set the display NAME of the current profile in `profiles.json` — the local half of Go's
    /// `--nickname` (`ipn/ipnlocal/profiles.go`, where `profileManager.SetPrefs` copies
    /// `ipn.Prefs.ProfileName` onto the current `LoginProfile`: `if prefsIn.ProfileName() != "" {
    /// lp.Name = prefsIn.ProfileName() }`). That name is the one user-visible handle a profile has:
    /// [`list_profiles`](Backend::list_profiles) prints it and
    /// [`profile::resolve_target_to_id`] resolves a `switch` target against it, so writing it here is
    /// what makes `tnet set --nickname work-laptop` take effect across the whole `switch` surface
    /// rather than only inside `prefs.json`.
    ///
    /// Go's assignment is TWO-ARMED. `setProfilePrefs` (`ipn/ipnlocal/profiles.go:450` @
    /// `53a0d659afa51835dd7a9283873cca44261454f8`) reads `if prefsIn.ProfileName() != "" { lp.Name =
    /// prefsIn.ProfileName() } else { lp.Name = up.LoginName }`, where `up` is the profile's
    /// persisted `tailcfg.UserProfile`. The first arm is ported exactly; the second arm's VALUE does
    /// not exist on this side. An EMPTY `name` (Go's `--nickname=` clear) therefore stores an empty
    /// display name — the map entry itself stays, so the profile is still listed and still
    /// switchable by id — and both readers fall back to the profile id:
    /// [`list_profiles`](Backend::list_profiles) prints the id, and
    /// [`profile::resolve_target_to_id`] stops resolving the cleared nickname (Go stops resolving it
    /// too: its name pass reads `lp.Name`, which the else arm has just overwritten).
    ///
    /// **The gap is the login name, not the branch.** The daemon tracks no account identity, and the
    /// engine at the pinned rev surfaces none: `Device::status`'s `self_node` is a `StatusNode` with
    /// no owning user, and `Device::whois` resolves PEERS only — the self node is not in the peer db.
    /// The engine holds both halves internally (the control runner's self `Node.user_id`, the peer
    /// tracker's accumulated netmap `UserProfiles` table) but joins them for peers alone, so the ask
    /// is filed as `docs/ENGINE_ASKS.md` §42; when it lands, this function gains Go's else arm and a
    /// cleared nickname restores the account name instead of falling back to the id. For a profile
    /// that never logged in, Go's `up` is the zero value and Go writes the same empty name this does
    /// (Go's `--list` then prints an empty Account column where this fork prints the id — a fork
    /// nicety, not the divergence above). Pinned by
    /// `clearing_the_nickname_blanks_the_name_and_cannot_restore_a_login_name`.
    ///
    /// Registers the current profile in the map if it is not there yet, including the implicit
    /// `default` — [`list_profiles`](Backend::list_profiles) already reads a `default` entry's name
    /// if one exists, so the default profile is renameable like any other. Writes are atomic
    /// (see [`profile::save_profiles_file`]); an unreadable/malformed map is treated as empty by the
    /// loader, so the rename re-establishes it rather than failing.
    async fn rename_current_profile(&self, name: &str) -> Result<()> {
        let mut meta = profile::load_profiles_file(&self.state_dir).await;
        meta.profiles
            .entry(self.current_profile.clone())
            .or_default()
            .name = name.to_string();
        profile::save_profiles_file(&self.state_dir, &meta)
            .await
            .with_context(|| {
                format!(
                    "persisting profiles.json while renaming profile {:?}",
                    self.current_profile
                )
            })?;
        tracing::info!(
            profile = %self.current_profile,
            name = %name,
            "profile: display name updated from --nickname"
        );
        Ok(())
    }

    /// Switch the active profile to `target` (the analogue of Go `tailscale switch <id>`), which must
    /// already exist.
    ///
    /// `target` is resolved by id **or** display name through [`profile::resolve_target_to_id`] (Go's
    /// `matchProfile`), and a target that matches no known profile is **refused** — Go's
    /// `switchProfile` does exactly this: `profID, ok := matchProfile(args[0], all); if !ok { errf("No
    /// profile named %q\n", args[0]); os.Exit(1) }`. This daemon used to treat an unmatched but
    /// syntactically-valid target as a NEW profile id and create it, so a mistyped `tnet switch
    /// wrok-laptop` tore a running node down into a fresh empty profile where Go refuses and leaves
    /// the node alone. Creating a profile is now its own explicit verb — see
    /// [`create_profile`](Backend::create_profile).
    ///
    /// Switching to the already-current profile is a no-op success, reported as
    /// [`SwitchOutcome::AlreadyCurrent`] rather than as a switch that did not happen (Go's
    /// `Already on account %q`); see [`SwitchOutcome`] for why the outcome is typed.
    pub async fn switch_profile(&mut self, target: &str) -> Result<SwitchOutcome> {
        // Resolve `target` (a profile id OR a display name — Go's `switch` accepts either) to a
        // canonical id BEFORE any teardown, so a no-match is rejected with the device untouched.
        let meta = profile::load_profiles_file(&self.state_dir).await;
        let resolved = profile::resolve_target_to_id(target, &meta)
            .ok_or_else(|| anyhow!("no profile named {target:?}"))?;
        self.activate_profile(&resolved).await
    }

    /// Create profile `id` and switch to it — the explicit form of what `switch` used to do by
    /// accident (`tnet switch --new <id>`).
    ///
    /// A **fork extension with no upstream counterpart**: Go creates a profile through an interactive
    /// `tailscale login`, which this fork does not have yet (`docs/PARITY_GAP_ANALYSIS.md` §4.5, bead
    /// `tsd-91w`), and Go's `switch` refuses an unknown target outright. Keeping creation reachable
    /// but making it *asked for* is what separates the two cases a bare `switch <target>` used to
    /// conflate: a typo (refused, node untouched) and a deliberate new account (created).
    ///
    /// Refuses an `id` that is not a usable profile id, and one that already names a profile — by id
    /// **or** by nickname. The nickname case matters because ids win the resolver's first pass: a new
    /// profile whose id equals another profile's nickname would shadow that profile for every later
    /// `switch`/`switch remove`, so it is refused rather than silently created.
    pub async fn create_profile(&mut self, id: &str) -> Result<SwitchOutcome> {
        if !profile::is_valid_profile_id(id) {
            return Err(anyhow!(
                "{id:?} is not a usable profile id (letters, digits, '-' or '_'; 1-64 characters)"
            ));
        }
        let meta = profile::load_profiles_file(&self.state_dir).await;
        if let Some(existing) = profile::resolve_target_to_id(id, &meta) {
            return Err(anyhow!(
                "profile {existing:?} already exists; switch to it without --new"
            ));
        }
        self.activate_profile(id).await
    }

    /// Make profile `target` the active one: tear the current device down, repoint
    /// `prefs`/`prefs_path`/`key_path` at the target, reload its persisted prefs, persist the
    /// `current-profile` pointer, register it in `profiles.json` if new, and bump the generation (so
    /// any in-flight `up` is superseded). It does **not** auto-`up` the target — the caller decides
    /// whether to bring it up (matching Go, where switch changes the profile and the engine
    /// reconciles to the new prefs' `WantRunning`).
    ///
    /// `target` MUST already be a valid profile id ([`profile::is_valid_profile_id`]) — it is joined
    /// as a single path component. Both callers guarantee that: [`switch_profile`](Backend::switch_profile)
    /// passes a [`profile::resolve_target_to_id`] result (which only ever returns validated ids) and
    /// [`create_profile`](Backend::create_profile) validates before calling.
    async fn activate_profile(&mut self, target: &str) -> Result<SwitchOutcome> {
        if target == self.current_profile {
            // Already on it: nothing is torn down and nothing is written. Say so — reporting this as
            // a switch would claim a teardown that never happened (Go: `Already on account %q`).
            return Ok(SwitchOutcome::AlreadyCurrent {
                id: target.to_string(),
            });
        }
        // Tear down the live device + supersede any in-flight up before swapping the active files.
        // (The device is down either way after this — a switch always disconnects; the engine is
        // rebuilt from the new profile on the next `up`.)
        self.stop_device().await;
        self.bump_generation();

        // Compute the target's state into LOCALS first, and do every fallible disk write BEFORE
        // committing anything to `self`. This is the D1 fix: the in-memory active-profile identity
        // (`current_profile`/`prefs`/paths) is mutated only after BOTH persisted writes succeed, so a
        // failed `profiles.json`/pointer write leaves the live backend coherently on the OLD profile
        // (matching the unchanged on-disk pointer) rather than diverging — in-memory ahead of disk.
        let (prefs_path, key_path) = profile::profile_paths(&self.state_dir, target);
        let ever_configured = tokio::fs::try_exists(&prefs_path).await.unwrap_or(false);
        // Re-derive the node-key cache for the TARGET profile (we are about to repoint `key_path` at
        // its key file). Computed here, into a local, alongside the other target state so it is only
        // committed to `self` after every fallible write succeeds (the D1 ordering above).
        let has_node_key = key_file_has_node_key(&key_path).await;
        let prefs = Prefs::load(&prefs_path)
            .await
            .with_context(|| format!("loading prefs for profile {target:?}"))?;

        // (1) Register the target in profiles.json (so `--list` shows it) if it is a new named
        // profile — before the pointer, so a crash between them only leaves a harmless extra entry.
        if target != profile::DEFAULT_PROFILE_ID {
            let mut meta = profile::load_profiles_file(&self.state_dir).await;
            meta.profiles
                .entry(target.to_string())
                .or_insert_with(profile::ProfileMeta::default);
            profile::save_profiles_file(&self.state_dir, &meta)
                .await
                .with_context(|| "persisting profiles.json")?;
        }
        // (2) Persist the pointer. On failure, `self` is still on the old profile (we have not
        // touched it yet) and so is the on-disk pointer — coherent, recoverable by retry.
        profile::save_current_profile(&self.state_dir, target)
            .await
            .with_context(|| "persisting current-profile pointer")?;

        // (3) Only now — every persisted write succeeded — commit the in-memory swap.
        self.prefs = prefs;
        self.prefs_path = prefs_path;
        self.key_path = key_path;
        self.ever_configured = ever_configured;
        self.current_profile = target.to_string();
        // This process has not attempted a boot-up for the newly-active profile.
        self.boot_attempted_up = false;
        // Adopt the target profile's node-key fact (computed above against the new `key_path`).
        self.has_node_key = has_node_key;
        // An always-on exemption belongs to the profile whose operator asked for it, so it does not
        // travel across a switch — and neither does its reconnect timer (Go resets both on a profile
        // change). Cleared BEFORE the reconcile below, so the incoming profile is reconciled against
        // the policy as written rather than under the outgoing profile's exemption.
        self.reset_always_on_override("profile switch");
        // An exit-node override belongs to its profile for the same reason and is cleared on the
        // same edge in Go, so the incoming profile is reconciled under the policy as written.
        self.reset_exit_node_policy_override("profile switch");
        // A profile load, exactly like the one in `load`: system policy applies to the newly-active
        // profile's prefs too, so a switch cannot be used to step out from under it. In memory only
        // (the swap above already persisted everything a switch owes to disk).
        self.reconcile_sys_policy("profile switch");
        // The device is down (we tore it down above and never auto-`up` the target), so the target's
        // state is already final — derive it from the same source `status` uses. `have_self_node` is
        // false for the same reason: no device, hence no netmap.
        Ok(SwitchOutcome::Switched {
            id: self.current_profile.clone(),
            state: self.derive_state(false),
        })
    }

    /// Delete profile `target` (the analogue of Go `tailscale switch remove`), reporting what it did
    /// as a [`DeleteOutcome`].
    ///
    /// `target` is resolved by id **or display name**, exactly like [`switch_profile`](Backend::switch_profile)
    /// — Go shares one `matchProfile` between `switch` and `switch remove`, so a name that can be
    /// switched to can also be removed. A `target` that matches no known profile is **refused**
    /// (Go: `No profile named %q`, exit 1): `remove` has no create-on-use semantics, so a typo that
    /// reported success would tell the operator a profile is gone while it is still on disk. That
    /// makes `remove` non-idempotent, like Go's.
    ///
    /// The **current** profile is never deleted, and — as in Go — that is a success, not an error:
    /// `removeProfile` answers `Already on account %q` and exits 0 without touching it, so a caller
    /// looping over profiles simply skips the active one. This returns
    /// [`DeleteOutcome::AlreadyCurrent`] for that case; see [`DeleteOutcome`] for why it is typed
    /// rather than raised. Checked BEFORE the `default` arm below, so `switch remove default` while
    /// on the default profile takes Go's already-current path rather than a refusal Go never makes.
    ///
    /// The reserved `default` profile is refused when it is *not* current — an extra refusal with no
    /// upstream counterpart, because unlike Go's profiles it is not removable state: it lives at the
    /// legacy top-level `prefs.json`/`node.key.json` paths and always exists (see this module's
    /// layout docs), so there is no "removed" state for it to reach.
    ///
    /// A removal takes the profile's prefs+key files and its `profiles.json` entry.
    pub async fn delete_profile(&mut self, target: &str) -> Result<DeleteOutcome> {
        // Resolve by id or name before anything else — an unknown target must not read as a
        // successful no-op removal. The resolver only ever returns ids that are safe as a single
        // path component, which is what the file removals below rely on.
        let meta = profile::load_profiles_file(&self.state_dir).await;
        let resolved = profile::resolve_target_to_id(target, &meta)
            .ok_or_else(|| anyhow!("no profile named {target:?}"))?;
        let target: &str = &resolved;
        if target == self.current_profile {
            // Go's `if profID == cp.ID`: nothing is removed and the command succeeds.
            return Ok(DeleteOutcome::AlreadyCurrent {
                id: target.to_string(),
            });
        }
        if target == profile::DEFAULT_PROFILE_ID {
            return Err(anyhow!("the default profile cannot be removed"));
        }
        // Remove the profile's files (tolerate already-absent — idempotent).
        let (prefs_path, key_path) = profile::profile_paths(&self.state_dir, target);
        for p in [&prefs_path, &key_path] {
            match tokio::fs::remove_file(p).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(anyhow!("removing {}: {e}", p.display())),
            }
        }
        // Best-effort remove the now-empty profile dir.
        if let Some(dir) = prefs_path.parent() {
            let _ = tokio::fs::remove_dir(dir).await;
        }
        // Drop it from profiles.json. Re-read rather than reusing the map loaded for resolution: the
        // file removals above are `await` points, so the map may be stale by now.
        let mut meta = profile::load_profiles_file(&self.state_dir).await;
        if meta.profiles.remove(target).is_some() {
            profile::save_profiles_file(&self.state_dir, &meta)
                .await
                .with_context(|| "persisting profiles.json after delete")?;
        }
        Ok(DeleteOutcome::Removed {
            id: target.to_string(),
        })
    }

    /// Bump the monotonic [`generation`](Backend::generation) **and** notify lifecycle watchers. The
    /// single place `generation` advances, so the lifecycle signal can never drift from the counter.
    /// A send to zero receivers is a no-op, so this is unconditional.
    fn bump_generation(&mut self) {
        self.generation += 1;
        let _ = self.lifecycle_tx.send(self.generation);
    }

    /// A receiver that wakes on every lifecycle change (`up`/`down`), carrying the current
    /// [`generation`](Backend::generation). A streaming `status` watcher uses this to re-derive the
    /// current device's state receiver when the device is replaced, so a `down`+`up` is *followed*
    /// rather than silently ending the stream. `subscribe()` (not a stored clone) so the caller
    /// starts synced to the current generation and only wakes on genuinely later events.
    pub fn watch_lifecycle(&self) -> tokio::sync::watch::Receiver<u64> {
        self.lifecycle_tx.subscribe()
    }

    /// Whether the persisted intent is to be running (used by the daemon to auto-start on launch).
    pub fn wants_running(&self) -> bool {
        self.prefs.want_running && !self.prefs.logged_out
    }

    /// Record that this process attempted a boot-time auto-start. See
    /// [`boot_attempted_up`](Backend::boot_attempted_up).
    pub fn mark_boot_attempted_up(&mut self) {
        self.boot_attempted_up = true;
    }

    /// Whether this process attempted a boot-time auto-start. The SIGHUP reload path uses this to
    /// retry only a bring-up this run already attempted (a transient failure), never to originate a
    /// connection from an out-of-band `prefs.json` intent flip (which would silently resurrect a node
    /// the operator may have intentionally downed).
    pub fn boot_attempted_up(&self) -> bool {
        self.boot_attempted_up
    }

    /// Whether this node is configured ephemeral (the default). Exposed so the daemon can warn, on a
    /// resume-without-authkey auto-start, that an ephemeral node may have been garbage-collected by
    /// control after its last disconnect — see the ephemeral note in [`Backend::build_config`].
    pub fn prefs_ephemeral(&self) -> bool {
        self.prefs.ephemeral
    }

    /// The persisted control-server URL, or `None` to use the engine default (Tailscale SaaS). Exposed
    /// (alongside [`prefs_ephemeral`](Backend::prefs_ephemeral)) so the daemon can log its effective
    /// posture at boot — which control plane it will talk to.
    pub fn prefs_control_url(&self) -> Option<&str> {
        self.prefs.control_url.as_deref()
    }

    /// Whether the node uses the kernel-TUN data path (vs the userspace netstack). Exposed for the
    /// daemon's boot-posture log line.
    pub fn prefs_tun(&self) -> bool {
        self.prefs.tun_enabled
    }

    /// Whether the Tailscale SSH server is enabled by the persisted pref. Exposed for the daemon's
    /// boot-posture log line.
    pub fn prefs_ssh(&self) -> bool {
        self.prefs.ssh_enabled
    }

    /// Whether a usable persisted node key exists on disk — the signal the daemon uses to decide
    /// whether it can *resume* a prior registration without an auth key (see `tailnetd`'s auto-start).
    ///
    /// ## What "usable" means here (and what it deliberately does NOT mean)
    ///
    /// The key file (`node.key.json`) holds a [`tailscale::keys::PersistState`], whose `node_key` is a
    /// fixed 32-byte `NodePrivateKey` — it is *never* structurally empty, and a fresh
    /// `PersistState::default()` already contains a random one. So "non-empty node key" is **always**
    /// true for any parseable key file and is not, on its own, a fresh-vs-registered discriminator.
    /// The load-bearing signal is therefore the **file's existence**: the daemon only ever writes the
    /// key file inside [`Backend::up`] → [`Backend::build_config`] → `tailscale::config::load_key_file`
    /// (which creates it with fresh keys when absent). A node that has never been brought up has no
    /// key file; once `up` has run at least once, the file exists carrying the very keys that were
    /// sent to control. We read it **without side effects** (a plain parse — *not* `load_key_file`,
    /// which would create-on-missing and so manufacture a key the first time it was merely *checked*),
    /// and confirm it parses into a `PersistState` (so a node key is present). A missing or malformed
    /// file reads as "no persisted key".
    ///
    /// ## This is necessary, not sufficient
    ///
    /// A `true` here means only that *we hold* a node key previously used with control — NOT that
    /// control will still accept it. Control may have expired or garbage-collected the node (see the
    /// ephemeral caveat in [`Backend::build_config`]); in that case resume-without-authkey still
    /// fails at registration and the operator must supply a fresh `TS_AUTH_KEY`. The engine resolves
    /// that authoritatively (re-`POST /machine/register` with this node key; `auth` omitted when no
    /// authkey), so this method is a cheap *pre-flight* to pick the resume path, never a guarantee.
    pub async fn has_persisted_node_key(&self) -> bool {
        // The on-disk source of truth for the [`has_node_key`](Backend::has_node_key) cache. Kept as a
        // method (still called at startup by [`load`](Backend::load) and by `tailnetd`'s auto-start);
        // the per-`status` hot path now reads the cached bool instead. Delegates to the free
        // [`key_file_has_node_key`] so `switch_profile`'s re-derivation shares the exact same logic.
        key_file_has_node_key(&self.key_path).await
    }

    /// Bring the node up in a single call (the auto-start / single-owner path).
    ///
    /// Runs all three phases ([`begin_up`](Backend::begin_up) → [`build_device`] →
    /// [`finish_up`](Backend::finish_up)) inline. Intended for callers that hold no shared lock — the
    /// daemon's boot-time auto-start, where there is no concurrency to protect. The auth key
    /// ([`secrecy::SecretString`], zeroized on drop, never stored on the [`Backend`]) flows through to
    /// [`build_device`], which exposes it exactly once for the `Device::new` engine call.
    ///
    /// For the **concurrent LocalAPI server**, use the explicit `begin_up` / `build_device` /
    /// `finish_up` phases so the slow handshake runs *without* the backend lock and a concurrent
    /// `status` is not head-of-line blocked.
    pub async fn up(
        &mut self,
        authkey: Option<secrecy::SecretString>,
        opts: UpOptions,
    ) -> Result<()> {
        // The single-owner `up` (daemon auto-start / resume at boot) carries no workload-identity
        // creds — it resumes from the persisted node key or a config auth key. WIF registration is
        // driven only through the LocalAPI `up` path (`drive_up`).
        let pending = self.begin_up(opts, None).await?;
        let built = build_device(&pending, authkey).await;
        // Single-owner path: settle the (rare) orphan inline. No external lock is held here, so the
        // off-lock requirement is trivially satisfied — but in practice nothing supersedes a
        // synchronous `up`, so this is virtually always a no-op.
        let orphan = self.finish_up(pending, built)?;
        // On a successful install, `finish_up` flipped `has_logged_in` in memory; persist it (same as
        // the `drive_up` path). Non-fatal on failure — the node is up. (Auto-start resuming an
        // already-logged-in node just re-writes the same flag.)
        if orphan.is_none()
            && let Err(e) = self.persist_prefs().await
        {
            tracing::warn!(error = %e, "failed to persist has_logged_in after bring-up");
        }
        shutdown_orphan(orphan).await;
        Ok(())
    }

    /// Apply a live pref mutation (`tnet set`) in a single call — the simple/owned path for a caller
    /// that holds a `&mut Backend` and has no concurrency to protect (e.g. tests, or a future
    /// single-owner caller). It is the `set` analogue of [`up`](Backend::up).
    ///
    /// Runs the decision ([`begin_set`](Backend::begin_set)) and, for the rebuild sub-case, the full
    /// [`begin_up`](Backend::begin_up) → [`build_device`] → [`finish_up`](Backend::finish_up) inline.
    /// The live setters and the prefs persist are already done by `begin_set`.
    ///
    /// For the **concurrent LocalAPI server**, use [`drive_set`] instead, which keeps the rebuild's
    /// slow `Device::new` handshake **off** the backend lock so a concurrent `status` is not
    /// head-of-line blocked. See [`drive_set`] for the full live-vs-rebuild rationale and the
    /// reconnect caveat.
    ///
    /// `set` never (re)authenticates (no `authkey`), never touches the control URL / TUN transport
    /// (those are connection-defining and belong to `up`), and never flips `want_running`.
    pub async fn set(&mut self, opts: SetOptions) -> Result<()> {
        let outcome = self.begin_set(opts).await?;
        match outcome.action {
            // Node down, or every changed pref applied live under begin_set — nothing further to do.
            SetAction::PersistedOnly | SetAction::Live(_) => {}
            // A rebuild-only pref changed on a running node: rebuild from the updated prefs to apply
            // it (the engine Config is immutable). Brief reconnect; no authkey (resume from the
            // persisted node key); `want_running` unchanged. Inline three-phase like `up`.
            SetAction::Rebuild => {
                // PREFLIGHT before tearing the live device down: `begin_up` → `stop_device` drops
                // the running engine, but the SSH root/feature checks (and control-URL/route parse)
                // live in `build_config`, which `begin_up` only reaches AFTER teardown. If that
                // check fails (e.g. `set --ssh` without the `ssh` feature or without root), a naive
                // rebuild would leave a healthy node OFFLINE — a `set` that fails must never drop the
                // tunnel. So validate the rebuilt config FIRST; on error, return it with the live
                // device untouched. (The pref is already persisted by `begin_set`; it applies on the
                // next successful `up`/`set` — but the running node stays up now.)
                self.build_config().await?;
                // A `set`-driven rebuild never (re)authenticates → no WIF creds.
                let pending = self.begin_up(UpOptions::default(), None).await?;
                let built = build_device(&pending, None).await;
                let orphan = self.finish_up(pending, built)?;
                // On a successful install `finish_up` flipped `has_logged_in` in memory; persist it
                // (same contract as `drive_up`/`Backend::up`/`drive_set`) so a rebuild-`set` after a
                // prior transient persist failure doesn't leave the flag true-in-memory/false-on-disk.
                if orphan.is_none()
                    && let Err(e) = self.persist_prefs().await
                {
                    tracing::warn!(error = %e, "failed to persist has_logged_in after set-rebuild");
                }
                shutdown_orphan(orphan).await;
            }
        }
        // The `--nickname` half failed after the prefs were already persisted (see [`SetOutcome`]).
        // The engine is reconciled by now, so failing the command here reports the rename without
        // having skipped an already-durable, live-applicable pref.
        if let Some(e) = outcome.rename_error {
            return Err(e);
        }
        Ok(())
    }

    /// Phase 1 of a `set` (shared by [`Backend::set`] and [`drive_set`]): apply the [`SetOptions`]
    /// overrides to `self.prefs`, **persist** them, and decide how to reconcile the live engine —
    /// returning a [`SetOutcome`] whose [`SetAction`] the caller carries out (or, for the live
    /// exit-node case, is already carried out here).
    ///
    /// The override block mirrors [`begin_up`](Backend::begin_up) **exactly** for the fields `set`
    /// accepts — same "leave unchanged unless named" sentinel, including the `exit_node` *double*
    /// `Option` where the OUTER `Option` is the unchanged sentinel and the INNER `Option<String>` is
    /// the value to store (so `Some(Some(sel))` sets, `Some(None)` clears, `None` leaves it). Raw
    /// selector/CIDR strings are stored verbatim and parsed only later (in
    /// [`build_config`](Backend::build_config), or just below for the live exit-node set); nothing is
    /// parsed here. Unlike `begin_up`, `set` does **not** touch `want_running` / `logged_out` /
    /// control URL / TUN, and does **not** tear down or rebuild the device itself.
    ///
    /// The reconcile decision (and the live setters, when chosen) is the one place that needs
    /// the live device, so it is done here under the (brief) backend lock the caller already holds:
    /// - **No device up** → [`SetAction::PersistedOnly`]: the persist above is the whole job; the new
    ///   prefs apply on the next `up`.
    /// - **Device up AND every changed pref is live-applicable** (`!opts.needs_rebuild()`) → apply
    ///   each named change **live** here via the engine's runtime setters (`set_exit_node` /
    ///   `set_hostname` / `set_accept_routes` / `set_advertise_routes` / `set_advertise_exit_node`),
    ///   then return [`SetAction::Live`] listing what was issued. No rebuild, no reconnect — the fast
    ///   path that is the whole point of `set`, matching Go's `set` = one live `EditPrefs`. The actor
    ///   messages are awaited under the lock; the device's `Arc` could in principle be cloned to hoist
    ///   them off-lock, but they are quick mailbox round-trips (not the multi-second registration
    ///   handshake), so we keep them atomic with the prefs-apply under the one brief lock.
    /// - **Device up AND a rebuild-only pref changed** (`shields_up` / `ssh` / `advertise_tags` /
    ///   `advertise_connector` / `auto_update`, which have no live setter) → [`SetAction::Rebuild`]:
    ///   the caller must rebuild the device from the
    ///   updated prefs (the engine `Config` is immutable). A brief reconnect. A `set` mixing live and
    ///   rebuild-only prefs rebuilds wholesale (the rebuild re-applies the live ones too).
    ///
    /// `--nickname` additionally renames the current login profile on disk (Go's `profiles.go`), the
    /// one step here that is neither a pref write nor an engine call. It is attempted after the prefs
    /// persist and its failure is **held**, not returned: by then the whole `set` is durable, so
    /// aborting on it would skip the reconcile and leave a live-applicable pref (say `--exit-node`)
    /// persisted-but-not-applied on a running node. The failure comes back in
    /// [`SetOutcome::rename_error`] for the caller to return once the action is done.
    ///
    /// Does **no** network I/O for the `Rebuild` case (the slow `Device::new` is the caller's
    /// off-lock job); the only blocking steps here are the quick live setter mailbox round-trips on
    /// the `Live` path.
    pub async fn begin_set(&mut self, mut opts: SetOptions) -> Result<SetOutcome> {
        // Decide the path BEFORE mutating prefs — `needs_rebuild()` inspects which fields the
        // request named, which the apply below would not change, but reading it first keeps the
        // decision crisply about the *request* rather than post-apply state. Also snapshot which
        // live-applicable fields were named, so after the apply+persist we know which engine setters
        // to issue (the apply below moves the option values into prefs, so capture the booleans now).
        let needs_rebuild = opts.needs_rebuild();
        let named_exit_node = opts.exit_node.is_some();
        let named_hostname = opts.hostname.is_some();
        let named_accept_routes = opts.accept_routes.is_some();
        let named_accept_dns = opts.accept_dns.is_some();
        let named_advertise_routes = opts.advertise_routes.is_some();
        let named_advertise_exit_node = opts.advertise_exit_node.is_some();
        // The rebuild-only fields (no live setter), captured for the reconcile-decision log below —
        // these are what force the `SetAction::Rebuild` (brief-reconnect) path on a running node.
        let opts_shields_up_named = opts.shields_up.is_some();
        let opts_ssh_named = opts.ssh.is_some();
        let opts_advertise_tags_named = opts.advertise_tags.is_some();
        // The two WIRE-advertised prefs: also rebuild-forcing (the engine sends them from a
        // construction-time Config field on every map request, so a running node would keep
        // advertising the old value otherwise).
        let opts_advertise_connector_named = opts.advertise_connector.is_some();
        let opts_auto_update_named = opts.auto_update.is_some();

        // PRE-VALIDATE the advertised route SET BEFORE mutating/persisting prefs. `build_config` is
        // the final authority on the CIDR parse (it re-parses the same way; see its
        // `advertise_routes` block), but it only runs on the rebuild path AFTER `persist_prefs` here
        // — so a malformed CIDR would otherwise be written to `prefs.json` and only rejected later,
        // leaving the persisted prefs inconsistent with the running device (a failed `set` having
        // corrupted state). Validate the set this request would leave behind — the named overrides
        // composed with the persisted prefs, since `set` changes the two halves independently —
        // against Go's `CalcAdvertiseRoutes` rules, and bail with NOTHING yet mutated or persisted.
        // The set-level rules have nowhere else to run on a node that is DOWN, where `set` is
        // persist-only and never reaches `build_config` at all.
        let (prospective_routes, prospective_advertise_exit) = prospective_route_set(
            opts.advertise_routes.as_ref(),
            opts.advertise_exit_node,
            &self.prefs,
            false,
        );
        crate::routes::validate_advertise_routes(&prospective_routes, prospective_advertise_exit)?;
        // Same pre-validate-before-persist discipline for advertise-tags — and the COMPLETION that
        // goes with it: a value with no colon at all becomes `tag:<value>` here, so the shorthand
        // `--advertise-tags server` persists and advertises as `tag:server` (Go completes the same
        // values in its CLI; this fork completes daemon-side so `up` and `set` share one rule). The
        // completed list replaces what was asked for, so everything below — the apply into prefs,
        // the persist, the rebuild — sees the tags exactly as control will.
        if let Some(tags) = opts.advertise_tags.as_mut() {
            *tags = complete_and_validate_advertise_tags(tags)?;
        }
        // The same authority question `begin_up` asks, in the same place and for the same reason
        // (Go's `checkEditPrefsAccessLocked`, which guards every prefs edit): an operator may not
        // move an exit node the administrator pinned, and this is the path on which that used to
        // succeed silently — `set` applied the value, the reconcile below put the policy's node
        // back, and the command reported success.
        let exit_node_edit =
            self.check_exit_node_policy(opts.exit_node.as_ref().map(Option::as_deref))?;
        // And RESOLVE a named `--exit-node` before persisting: the unsupported `auto:` form, then
        // the netmap-backed checks Go runs on the CLI argument (`exitNodeIPOfArg`). Same reason as
        // in `begin_up` — the engine's selector parse is infallible, so an unusable value persists
        // and then routes nothing, with no command saying why. On a RUNNING node this is the one
        // place the check can happen at all: `set` applies the exit node live and never reaches
        // `build_config`.
        if let Some(Some(sel)) = opts.exit_node.as_ref() {
            self.check_exit_node_arg(sel).await?;
        }
        // And refuse an SSH-server enable the host or the operator has ruled out (Go
        // `checkSSHPrefsLocked` → `featureknob.CanRunTailscaleSSH`, run whenever `RunSSH` is being
        // SET). This is the one gate that MUST live here rather than in `build_config`: on a node
        // that is down, `set` is persist-only and never reaches `build_config` at all, so without
        // this `TS_DISABLE_SSH_SERVER=1 tnet set --ssh` would report success and write the pref,
        // and the operator would learn the server is administratively off only at the next `up`.
        if opts.ssh == Some(true) {
            crate::featureknob::can_run_tailscale_ssh()?;
        }
        // Refuse an auto-update OPT-IN this installation could never honour (Go
        // `checkAutoUpdatePrefsLocked`, the fifth child of `checkPrefsLocked` — which in Go guards
        // every prefs write, so the same rule `check_prefs` reports on the dry-run path has to fire
        // on the real one). `--auto-update` is not a local preference: the engine advertises it as
        // `Hostinfo.AllowsUpdate` on registration and on every map request, so setting it tells the
        // tailnet admin that a remote update trigger will be honoured. Same "before a single pref is
        // mutated" discipline as the checks above — a refused `set` leaves prefs.json untouched, and
        // it is asked after the SSH gate so the two refusals report in `check_prefs`'s (4)-then-(5)
        // order.
        if let Some(e) = selfupdate::check_auto_update_pref(
            opts.auto_update,
            selfupdate::auto_update_refusal().as_deref(),
        ) {
            return Err(anyhow!(e));
        }

        // The login-profile rename `--nickname` owes beyond the pref (see the `opts.nickname` arm
        // below): captured here as `Some(name)` / `Some(cleared)` and applied after the prefs persist.
        let mut rename_profile_to: Option<Option<String>> = None;

        // Apply the overrides. Same sentinel semantics as `begin_up`'s override block, restricted to
        // the fields `set` accepts. `exit_node` is the double `Option`: binding `en` (an
        // `Option<String>`) and assigning it through both SETS (`Some(Some(sel))`) and CLEARS
        // (`Some(None)`) in one move; the outer `Some` is "the user named exit_node", `None` leaves
        // `prefs.exit_node` untouched. The advertise overrides are plain set/unchanged (a
        // `Some(vec![])` clears the advertised set). All stored as raw strings; parsed later.
        if let Some(h) = opts.hostname {
            self.prefs.hostname = Some(h);
        }
        if let Some(ar) = opts.accept_routes {
            self.prefs.accept_routes = ar;
        }
        if let Some(ad) = opts.accept_dns {
            self.prefs.accept_dns = ad;
        }
        if let Some(su) = opts.shields_up {
            self.prefs.shields_up = su;
        }
        if let Some(en) = opts.exit_node {
            self.prefs.exit_node = en;
        }
        if let Some(ae) = opts.advertise_exit_node {
            self.prefs.advertise_exit_node = ae;
        }
        if let Some(routes) = opts.advertise_routes {
            self.prefs.advertise_routes = routes;
        }
        if let Some(tags) = opts.advertise_tags {
            self.prefs.advertise_tags = tags;
        }
        // Run-SSH-server override. Toggling SSH is a device-lifecycle change (the server task is
        // bound to the device) with no live engine setter, so on a running node it must take the
        // Rebuild path — `SetOptions::needs_rebuild` returns true whenever `ssh` is named (see its
        // doc), so the reconcile match below routes a device-up `ssh` change to `Rebuild`, which on
        // rebuild re-runs `finish_up` and (re)spawns the SSH task from the now-updated `ssh_enabled`.
        // The brief reconnect is documented on `drive_set`.
        if let Some(ssh) = opts.ssh {
            self.prefs.ssh_enabled = ssh;
        }
        // The eight Go `set` pref flags this fork gained with the engine fields that carry them
        // (`tsd-1m9`). Same "unchanged unless named" sentinel throughout; `operator`/`nickname` are
        // double `Option`s (`Some(None)` clears, mirroring Go's `--operator=` / `--nickname=`).
        // WIRE-advertised (rebuild-forcing, see `needs_rebuild`):
        if let Some(v) = opts.advertise_connector {
            self.prefs.advertise_app_connector = v;
        }
        if let Some(v) = opts.auto_update {
            self.prefs.auto_update_apply = Some(v);
        }
        // CARRIED (persist-only — the engine stores but never acts on or sends these):
        if let Some(v) = opts.update_check {
            self.prefs.auto_update_check = v;
        }
        if let Some(op) = opts.operator {
            self.prefs.operator_user = op;
        }
        if let Some(nick) = opts.nickname {
            self.prefs.node_nickname = nick.clone();
            // `--nickname` is NOT a carried pref in Go: `profileManager.SetPrefs`
            // (`ipn/ipnlocal/profiles.go`) applies `ipn.Prefs.ProfileName` to the LOGIN PROFILE
            // itself — `if prefsIn.ProfileName() != "" { cp.Name = prefsIn.ProfileName() }` — and
            // that name is what `switch --list` prints and what a `switch <target>` resolves
            // against. Renaming only the pref would leave `tnet switch <the name you just chose>`
            // resolving to nothing (worse: to a brand-new empty profile of that id), so the rename
            // lands on `profiles.json` too. Deferred to just after the prefs persist below, so a
            // failed rename cannot leave a renamed profile pointing at unpersisted prefs.
            rename_profile_to = Some(nick);
        }
        if let Some(v) = opts.report_posture {
            self.prefs.posture_checking = v;
        }
        if let Some(v) = opts.webclient {
            self.prefs.run_web_client = v;
        }
        if let Some(v) = opts.exit_node_allow_lan_access {
            self.prefs.exit_node_allow_lan_access = v;
        }
        // `set` is a policy-pref mutation, not a lifecycle change: deliberately do NOT touch
        // `want_running` / `logged_out` (that is `up`/`down`'s job). It still marks the node as
        // configured-at-least-once (a `set` on a never-touched node has now written prefs), matching
        // `up`/`down`, so a `set`-then-restart reads `Stopped`, not `NoState`.
        self.ever_configured = true;
        // Record what the (permitted) exit-node edit means for the standing override, before the
        // reconcile below — which is what the flag has to be in place for: an override recorded
        // after it would be undone by the very re-apply it exists to suppress.
        self.record_exit_node_edit(exit_node_edit, "set");
        // System policy has the last word, applied after this command's overrides and before the
        // persist — so `tnet set --hostname laptop` against a policy that pins `Hostname` persists
        // (and, on the live path below, PUSHES) the pinned name, not the typed one. Policy beating a
        // live `set` is the entire point of policy; a `set` that could quietly win would make the
        // policy file advisory.
        //
        // The live setters below fire on `named_*` — what the REQUEST named — not on what the
        // reconcile changed, which is correct rather than a gap: the only policy source is the JSON
        // file, captured once at startup, and every path that can reach a running device (profile
        // load, then `up`) has already applied it, so a reconcile here can only move a pref the
        // request itself just moved. If a re-readable policy source is ever registered, that
        // reasoning ends with it and the live-setter gating has to be widened to the union.
        self.reconcile_sys_policy("set");
        self.persist_prefs().await?;
        // The other half of `--nickname` (Go's `profiles.go` rename, see the apply arm above): make
        // the display name of the CURRENT profile follow the nickname, so `switch --list` shows it
        // and `switch <nickname>` resolves to this profile immediately. Ordered AFTER the prefs
        // persist so the two agree on disk: a rename that fails leaves the pref already durable (the
        // operator retries `set --nickname`), never the reverse.
        //
        // Its failure is HELD, not propagated with `?`. Everything this `set` asked for is already in
        // `prefs.json` by the time we get here, so returning now would skip the reconcile below and
        // leave a `set --nickname X --exit-node Y` on a running node with `Y` durable (and reported by
        // `tnet get`) but NEVER pushed to the engine — the device keeps the old exit node until the
        // next successful `set`/`up`. So: attempt the rename, keep the error, reconcile the engine,
        // and hand the error back in [`SetOutcome::rename_error`] for the caller to return once the
        // action is carried out. The converse ordering — reconcile first, `?` on the rename — only
        // mirrors the bug (a failing live setter would then skip an otherwise-fine rename): neither
        // half of a `set` whose prefs are already durable may abort the other.
        let rename_error = match rename_profile_to {
            Some(name) => {
                let renamed = self
                    .rename_current_profile(name.as_deref().unwrap_or(""))
                    .await;
                if let Err(e) = &renamed {
                    tracing::warn!(
                        error = %e,
                        "set: profile rename failed; reconciling the already-persisted prefs anyway"
                    );
                }
                renamed.err()
            }
            None => None,
        };

        // Reconcile against the live engine. This is the only step that needs the device, and it runs
        // whether or not the rename above succeeded (see `rename_error`).
        let reconciled: Result<SetAction> = match self.device.as_ref() {
            // No engine to reconcile — persisting above is the whole job; prefs apply on next `up`.
            None => {
                tracing::info!(
                    action = "persisted-only",
                    "set: reconcile decided (node down; prefs apply on next up)"
                );
                Ok(SetAction::PersistedOnly)
            }
            // A rebuild-only pref (shields_up / ssh / advertise_tags / advertise_connector /
            // auto_update — no live setter) changed on a running node: the engine Config is
            // immutable, so the caller must rebuild the device
            // from the updated prefs (a brief reconnect). A `set` that ALSO named live-applicable
            // prefs still rebuilds wholesale — the rebuild re-applies them from the persisted prefs.
            Some(_) if needs_rebuild => {
                // THE "why did my set reconnect?" signal: a rebuild-only pref forces a device rebuild
                // (brief reconnect). Name which one(s) triggered it.
                tracing::info!(
                    action = "rebuild",
                    shields_up = opts_shields_up_named,
                    ssh = opts_ssh_named,
                    advertise_tags = opts_advertise_tags_named,
                    advertise_connector = opts_advertise_connector_named,
                    auto_update = opts_auto_update_named,
                    "set: reconcile decided (rebuild-only pref changed on a running node → brief reconnect)"
                );
                Ok(SetAction::Rebuild)
            }
            // Fast path: every changed pref is live-applicable and a device is up → apply each named
            // change LIVE via the engine's runtime setters, no rebuild, no reconnect (Go's `set` =
            // one live `EditPrefs`). Each call is awaited under the (brief) lock the caller holds: the
            // device's `Arc` could be cloned to hoist these off-lock, but they are quick mailbox
            // round-trips (local state edit + a control re-push on the established map-poll), not the
            // multi-second registration handshake the off-lock split exists for, so we keep them
            // atomic with the prefs-apply under the one lock. Only NEW flows use the new values. A
            // setter error returns `Err` with the device fully INTACT (no teardown) — strictly safer
            // than the rebuild path; the pref is already persisted, so it applies on the next
            // successful reconcile (same persisted-but-not-yet-live semantics as Go).
            Some(dev) => {
                let mut ops = Vec::new();
                // Order: exit_node, hostname, accept_routes, advertise_routes, advertise_exit_node.
                // The advertise pair composes engine-side (each setter re-reads the other's stored
                // contribution behind a shared lock), so the relative order of the two is immaterial.
                if named_exit_node {
                    // `ExitNodeSelector` `FromStr` is infallible (bare IP → `Ip`, else `Name`; the
                    // `Err` is `Infallible`), the same total parse `build_config` relies on — so
                    // `.unwrap()` cannot panic. `None` (cleared) clears the exit node.
                    let sel: Option<tailscale::ExitNodeSelector> =
                        self.prefs.exit_node.as_ref().map(|s| s.parse().unwrap());
                    dev.set_exit_node(sel)
                        .await
                        .map_err(|e| anyhow!("set exit node failed: {e:?}"))?;
                    ops.push(LiveSetOp::ExitNode(self.prefs.exit_node.clone()));
                }
                if named_hostname {
                    let hostname = self.prefs.hostname.clone().unwrap_or_default();
                    dev.set_hostname(hostname.clone())
                        .await
                        .map_err(|e| anyhow!("set hostname failed: {e:?}"))?;
                    ops.push(LiveSetOp::Hostname(hostname));
                }
                if named_accept_routes {
                    dev.set_accept_routes(self.prefs.accept_routes)
                        .await
                        .map_err(|e| anyhow!("set accept-routes failed: {e:?}"))?;
                    ops.push(LiveSetOp::AcceptRoutes(self.prefs.accept_routes));
                }
                if named_accept_dns {
                    dev.set_accept_dns(self.prefs.accept_dns)
                        .await
                        .map_err(|e| anyhow!("set accept-dns failed: {e:?}"))?;
                    ops.push(LiveSetOp::AcceptDns(self.prefs.accept_dns));
                }
                if named_advertise_routes {
                    // Already pre-validated as `ipnet::IpNet` at the top of `begin_set` (before any
                    // mutation/persist), the byte-identical parse `build_config` uses — so this parse
                    // cannot fail here.
                    let routes: Vec<ipnet::IpNet> = self
                        .prefs
                        .advertise_routes
                        .iter()
                        .map(|s| {
                            s.parse()
                                .expect("advertise routes pre-validated in begin_set")
                        })
                        .collect();
                    dev.set_advertise_routes(routes.clone())
                        .await
                        .map_err(|e| anyhow!("set advertise-routes failed: {e:?}"))?;
                    ops.push(LiveSetOp::AdvertiseRoutes(routes));
                }
                if named_advertise_exit_node {
                    dev.set_advertise_exit_node(self.prefs.advertise_exit_node)
                        .await
                        .map_err(|e| anyhow!("set advertise-exit-node failed: {e:?}"))?;
                    ops.push(LiveSetOp::AdvertiseExitNode(self.prefs.advertise_exit_node));
                }
                // Live path: every changed pref applied in place via engine setters — NO reconnect.
                // Record what was issued so the operator can see the set took the seamless path.
                tracing::info!(action = "live", ops = ?ops, "set: reconcile decided (applied live, no reconnect)");
                Ok(SetAction::Live(ops))
            }
        };

        // Both halves attempted. A live-setter failure wins the return (engine state is the more
        // consequential of the two, and it means the engine is in trouble); a rename failure rides
        // back with the action so the caller can carry the action out and only *then* fail the
        // command.
        Ok(SetOutcome {
            action: reconciled?,
            rename_error,
        })
    }

    /// Pure, read-only accidental-revert pre-check for an `up` (the Rust analogue of Go's
    /// `checkForAccidentalSettingReverts`). Returns the list of non-default prefs this `up` would
    /// silently revert because the command did not mention them — empty means the `up` is safe to
    /// proceed. Mutates **nothing**: the server calls this BEFORE [`drive_up`]/[`begin_up`], and on a
    /// non-empty result rejects the `up` outright (returning [`crate::localapi::Response::RevertGuard`])
    /// so a guarded `up` leaves the node exactly as it was.
    ///
    /// The caller must skip this entirely when `opts.reset` is set — a `--reset` up explicitly opts
    /// into reverting unmentioned prefs to their defaults, so it is never guarded. See
    /// [`revert_guard::check_accidental_reverts`] for the two exemptions (fresh node / bare `up`) and
    /// the per-pref logic.
    pub fn up_revert_guard(&self, opts: &UpOptions) -> Vec<crate::localapi::RevertedPref> {
        // The fresh-node exemption keys on `has_logged_in` (the node actually registered), NOT
        // `ever_configured` (prefs-file existence). Go's `checkForAccidentalSettingReverts`
        // early-returns on `curPrefs.ControlURL == ""` — a never-logged-in node — and Go's `set` never
        // writes ControlURL, so a `set`-then-`up` on a fresh node is unguarded there. Keying on
        // `ever_configured` here (flipped true by a bare `tnet set`) would wrongly arm the guard on
        // that exact sequence; `has_logged_in` is the faithful signal. (tsd-i7c)
        //
        // Then drop anything the system policy PINS. `begin_up` re-applies policy over this `up`'s
        // own overrides just before persisting, so a pinned pref is one the `up` provably cannot
        // revert — warning about it would refuse a command that changes nothing and tell the
        // operator to re-mention a setting they are not permitted to change. See
        // `revert_guard::drop_policy_pinned`.
        revert_guard::drop_policy_pinned(
            revert_guard::check_accidental_reverts(&self.prefs, opts, self.prefs.has_logged_in),
            &syspolicy::pinned_prefs(),
        )
    }

    /// Whether this `up` must be refused for changing the control server on a **Running** node
    /// without `--force-reauth` (Go `up`'s `can't change --login-server without --force-reauth`).
    /// A pure, read-only pre-flight check (delegates to [`control_url::change_blocked`]): the current
    /// control URL is `self.prefs.control_url`, the proposed one is `opts.control_url` (`None` =
    /// unmentioned = no change), and `--force-reauth` is the escape hatch (it re-registers, which is
    /// exactly what a control-server change requires).
    ///
    /// "Running" is the node's **actual** reported state — `state_from_device(dev.device_state()) ==
    /// State::Running` — NOT merely "a device is installed". A device can be present while the node
    /// is `Starting`/`NeedsLogin`/`Expired` (e.g. an interactive `up` installs the device before
    /// login completes); Go gates strictly on `backendState == ipn.Running`, and gating on
    /// device-presence would over-fire the guard in those non-Running states. Reading
    /// `device_state()` is a cheap, non-blocking `watch` borrow (the same source `status()` uses).
    pub fn up_control_url_guard(&self, opts: &UpOptions) -> bool {
        let running = matches!(
            self.device
                .as_ref()
                .map(|dev| state_from_device(dev.device_state()).0),
            Some(State::Running)
        );
        control_url::change_blocked(
            self.prefs.control_url.as_deref(),
            opts.control_url.as_deref(),
            running,
            opts.force_reauth,
        )
    }

    /// Phase 1 of the concurrent bring-up: mutate + persist prefs, build the engine `Config`, and
    /// bump the lifecycle [`generation`](Backend::generation). Returns a [`PendingUp`] describing
    /// *this* attempt. Does **no** network I/O — the caller then performs the slow `Device::new` via
    /// [`build_device`] **without** the lock, and re-acquires it for [`finish_up`].
    ///
    /// Tears down any existing device first, so a reconfiguring `up` cleanly replaces the prior one.
    /// Note: that teardown ([`stop_device`](Backend::stop_device)) awaits the prior engine's graceful
    /// shutdown (bounded by [`SHUTDOWN_TIMEOUT`]), so on a *reconfigure* (a device was already live)
    /// this phase is not strictly instantaneous under the lock — only the fresh-up case is. The
    /// common, head-of-line-sensitive case (no prior device) returns immediately.
    pub async fn begin_up(
        &mut self,
        mut opts: UpOptions,
        wif: Option<&WifCreds>,
    ) -> Result<PendingUp> {
        // PRE-VALIDATE the advertised route SET FIRST — before tearing down the device, mutating, or
        // persisting prefs. Same persist-before-validate gap as `begin_set`: `build_config` (below,
        // the final authority on the CIDR parse) only rejects a malformed CIDR AFTER `stop_device` +
        // `persist_prefs` have run, so a bad value would tear down a live engine AND be written to
        // `prefs.json` before being caught. Validate the set this request would leave behind
        // (`prospective_route_set`, which honours `--reset`) with Go's `CalcAdvertiseRoutes` rules —
        // parseable, masked, 4via6-decodable, and no default route advertised in one family only —
        // and bail with the device untouched and nothing persisted. Defense in depth for the parse,
        // and the ONLY place the set-level rules can run for an `up`.
        let (prospective_routes, prospective_advertise_exit) = prospective_route_set(
            opts.advertise_routes.as_ref(),
            opts.advertise_exit_node,
            &self.prefs,
            opts.reset,
        );
        crate::routes::validate_advertise_routes(&prospective_routes, prospective_advertise_exit)?;
        // Same pre-validate-before-teardown discipline for advertise-tags, including the
        // `tag:`-prefix COMPLETION for a value with no colon at all — `up --advertise-tags server`
        // is `tag:server`, as it is in Go. Rewritten in place so the apply/persist below store the
        // completed form; a value that already has a colon is left alone and refused by name if it
        // is not a tag.
        if let Some(tags) = opts.advertise_tags.as_mut() {
            *tags = complete_and_validate_advertise_tags(tags)?;
        }
        // Is this operator ALLOWED to change the exit node at all? Go's `checkEditPrefsAccessLocked`
        // asks first, before any edit is applied, and refuses when the administrator's policy pins
        // the exit node (`exit node cannot be changed: managed by policy`) — see
        // [`exitnodepolicy`]. Asked before the netmap resolution below, and for two reasons: the
        // refusal is about authority rather than about the value (so a pinned node refuses a typo
        // with "managed by policy" rather than with "no such peer"), and it costs no `status`
        // round-trip. The verdict travels to the apply below, where a permitted override is
        // recorded.
        let exit_node_edit =
            self.check_exit_node_policy(opts.exit_node.as_ref().map(Option::as_deref))?;
        // And RESOLVE a named `--exit-node` before teardown/persist: reject the unsupported `auto:`
        // form (no auto-selection in this build), then check the value against the netmap the way Go
        // resolves the CLI argument before writing the pref (`exitNodeIPOfArg`). Both matter for the
        // same reason — the engine's selector parse is infallible, so an unusable value would be
        // stored and then silently route nothing. Refused here, the live device and `prefs.json` are
        // both untouched.
        if let Some(Some(sel)) = opts.exit_node.as_ref() {
            self.check_exit_node_arg(sel).await?;
        }
        // Same discipline for an SSH-server enable: Go's `checkSSHPrefsLocked` runs
        // `featureknob.CanRunTailscaleSSH()` whenever `RunSSH` is being SET, so a host whose
        // operator disabled the server with `TS_DISABLE_SSH_SERVER` (or an OS upstream does not
        // support) refuses the pref rather than accepting it and quietly running no server. Checked
        // here, before teardown/persist, so the refusal costs neither the live device nor a written
        // pref; `build_config` re-checks the MERGED pref (it is the final authority, and it also
        // catches an already-persisted `ssh_enabled` on a host where the knob appeared later).
        if opts.ssh == Some(true) {
            crate::featureknob::can_run_tailscale_ssh()?;
        }

        // Tear down any existing device first so `up` is idempotent / reconfiguring.
        self.stop_device().await;

        // `--reset` (Go `tailscale up --reset`): the one path where `up` is a true wholesale REPLACE.
        // Reset every up-managed pref to its default FIRST, then let the overrides below layer on top
        // — so `up --reset --ssh` ends with only `ssh_enabled` set and every other up-managed pref
        // back at default. Without `--reset`, the merge below is a PATCH (only mentioned prefs change),
        // and the accidental-revert guard (run by the server BEFORE this) is what gives `up` its
        // REPLACE *contract* by refusing to silently drop an unmentioned non-default pref. `--reset`
        // is exactly the operator opting out of that guard. Lifecycle/registration prefs
        // (`want_running`/`logged_out`/`ephemeral`) are deliberately preserved by the reset helper.
        // `--force-reauth` (Go `tailscale up --force-reauth`): discard the persisted node key BEFORE
        // we persist prefs or build the engine, so the rebuilt device cannot resume the old
        // registration and must register FRESH (an interactive up then reaches `NeedsLogin` and the
        // CLI surfaces the new auth URL — `build_config`'s key load re-initializes a fresh key, so
        // the on-disk *content* changes; the file is not left absent). Done after `stop_device` (the
        // device that held the old key is gone) and before `persist_prefs`/`build_config` (so a wipe
        // failure aborts the up before anything is persisted — the live device is already down).
        // Unlike `logout`, this keeps the node's up-intent — `want_running`/`logged_out` are set to up
        // below; force-reauth only re-keys, it does not log out. A wipe failure is FATAL here for the
        // same fail-closed reason as in `logout`: proceeding would bring the node back up on the very
        // key we meant to rotate.
        //
        // ORDER MATTERS: the fallible `discard_node_key` runs BEFORE the in-memory `--reset` mutation
        // below, so a wipe failure aborts (`?`) with `self.prefs` STILL UNTOUCHED — never leaving the
        // live backend's in-memory prefs reset-to-default while nothing was persisted (which a
        // same-process retry / a later `set` would then wrongly read or persist). With this ordering,
        // an aborted `up --reset --force-reauth` is fully no-op on prefs, matching the on-disk state.
        if opts.force_reauth {
            self.discard_node_key()
                .await
                .context("up --force-reauth: bring-up aborted before anything was persisted")?;
        }

        // `--reset`: reset every up-managed pref this command does not mention back to its default
        // before applying the named overrides — the operator opting out of the accidental-revert
        // guard (Go `tailscale up --reset`). Lifecycle/registration prefs
        // (`want_running`/`logged_out`/`ephemeral`) are deliberately preserved by the reset helper.
        // Placed AFTER the force-reauth wipe (above) so a wipe failure can't leave prefs half-reset.
        if opts.reset {
            self.prefs.reset_up_managed_to_default();
        }

        if let Some(h) = opts.hostname {
            self.prefs.hostname = Some(h);
        }
        // Capture an overridden control URL into prefs; it is parsed + applied to the engine config
        // in `build_config` below.
        if opts.control_url.is_some() {
            self.prefs.control_url = opts.control_url;
        }
        // TUN overrides: `Some` sets the persisted pref, `None` leaves it unchanged (so a plain
        // `up` after a `tun`-enabled `up` keeps TUN). The name/mtu only matter when enabled.
        if let Some(tun) = opts.tun {
            self.prefs.tun_enabled = tun;
        }
        if opts.tun_name.is_some() {
            self.prefs.tun_name = opts.tun_name;
        }
        if opts.tun_mtu.is_some() {
            self.prefs.tun_mtu = opts.tun_mtu;
        }
        // Exit-node + route-advertising overrides. Each uses the same "unchanged unless named"
        // sentinel as the rest of `UpOptions`, but `exit_node` is a *double* `Option`: the OUTER
        // `Option` is the unchanged sentinel (`None` = leave `prefs.exit_node` as-is), and the
        // INNER `Option<String>` it carries is the value to store — so binding `en` (itself an
        // `Option<String>`) and assigning it through both SETS (`Some(Some(sel))`) and CLEARS
        // (`Some(None)` = stop using an exit node) in one move. `advertise_exit_node` /
        // `advertise_routes` are plain `Some` = set / `None` = unchanged (a `Some(vec![])` clears
        // the advertised set). These are persisted as raw selector/CIDR strings here and parsed
        // into the engine's typed `ExitNodeSelector` / `ipnet::IpNet` in `build_config`.
        if let Some(en) = opts.exit_node {
            self.prefs.exit_node = en;
        }
        if let Some(ae) = opts.advertise_exit_node {
            self.prefs.advertise_exit_node = ae;
        }
        if let Some(ar) = opts.advertise_routes {
            self.prefs.advertise_routes = ar;
        }
        if let Some(tags) = opts.advertise_tags {
            self.prefs.advertise_tags = tags;
        }
        // Accept-subnet-routes override (Go `up --accept-routes`), same "unchanged unless named"
        // sentinel as `set`'s accept_routes; baked into the engine Config in `build_config`.
        if let Some(ar) = opts.accept_routes {
            self.prefs.accept_routes = ar;
        }
        // Accept-MagicDNS override (Go `up --accept-dns`, default-on), same sentinel; baked into the
        // engine Config in `build_config`.
        if let Some(ad) = opts.accept_dns {
            self.prefs.accept_dns = ad;
        }
        // Ephemeral-node override (Go `up --ephemeral`). Registration-time intent; baked into the
        // engine Config in `build_config` and only acted on at a fresh register.
        if let Some(eph) = opts.ephemeral {
            self.prefs.ephemeral = eph;
        }
        if let Some(su) = opts.shields_up {
            self.prefs.shields_up = su;
        }
        // Run-SSH-server override (same "unchanged unless named" sentinel). The actual SSH server
        // task is spawned on install in `finish_up` when this is set; `build_config` (below) also
        // preflights the feature/root requirements so an impossible `--ssh` fails the bring-up loudly.
        if let Some(ssh) = opts.ssh {
            self.prefs.ssh_enabled = ssh;
        }
        // The four Go pref flags `up` shares with `set` (up.go `newUpFlagSet`). Same
        // "unchanged unless named" sentinel; `operator` is the double `Option` (`Some(None)` clears,
        // mirroring Go's `--operator=`).
        //
        // OPERATOR, vs Go's `applyImplicitPrefs`: Go re-carries an `OperatorUser` that equals the
        // invoking `$USER` across an `up` that did not mention `--operator`, so its REPLACE semantics
        // cannot lock you out of your own daemon. This PATCH merge needs no such carve-out on the
        // ordinary path — an unmentioned pref is simply never touched — and on `--reset` (the one
        // genuine replace) we deliberately DO clear it, because the daemon has no notion of the
        // invoking user at this layer and, today, `operator_user` gates nothing: the LocalAPI write
        // policy is still root/same-euid. Whoever wires the operator authorization matrix must
        // revisit this together with Go's carve-out.
        if let Some(op) = opts.operator {
            self.prefs.operator_user = op;
        }
        if let Some(v) = opts.exit_node_allow_lan_access {
            self.prefs.exit_node_allow_lan_access = v;
        }
        if let Some(v) = opts.advertise_connector {
            self.prefs.advertise_app_connector = v;
        }
        if let Some(v) = opts.report_posture {
            self.prefs.posture_checking = v;
        }
        self.prefs.want_running = true;
        self.prefs.logged_out = false;
        self.ever_configured = true;
        // The node is being connected, so any always-on exemption a previous disconnect earned is
        // spent and its reconnect timer has nothing left to do — Go resets both on the connect edge.
        // Before the reconcile below, so `AlwaysOn.Enabled` is back in force from this moment on.
        self.reset_always_on_override("up");
        // A connect ends an exit-node override too (Go clears both on that edge) — and then THIS
        // command's own verdict applies, so an `up --exit-node <other>` the policy permitted is
        // still a standing override when the reconcile below runs. Order matters: recorded first,
        // the reset would immediately throw it away.
        self.reset_exit_node_policy_override("up");
        self.record_exit_node_edit(exit_node_edit, "up");
        // System policy has the last word — after `--reset`, after every override this command
        // named, and before the persist. That ordering is the whole contract: an `up` cannot be used
        // to step out from under an administrator's policy, and `up --reset` (the one genuine
        // wholesale replace) cannot either.
        self.reconcile_sys_policy("up");
        self.persist_prefs().await?;

        let mut config = self.build_config().await?;
        // Workload-identity-federation creds (Go `--client-id/--client-secret/--id-token/--audience`)
        // are NOT prefs — they are not persisted and never flow through `build_config` (which reads
        // only prefs + the key file). Apply the transient creds onto the freshly-built `Config` here,
        // so the engine's registration handshake (`resolve_auth_key`, under the `identity-federation`
        // feature) can exchange the OAuth secret / OIDC token for a real auth key. `None` (the common
        // authkey/interactive up) leaves the config untouched. The two secrets are exposed once here,
        // inside `apply_to_config`, then dropped with `wif` — they never enter prefs or the key file.
        if let Some(wif) = wif {
            wif.apply_to_config(&mut config);
        }
        // `build_config`'s key load (`load_key_file`) create-on-missing-WROTE the key file, so a node
        // key is now persisted — update the cache. This holds for a plain up AND a force-reauth up:
        // force-reauth wiped the old key above (→ cache false) and this rebuild just minted a fresh
        // one (→ cache true), the correct end state. Set only after `build_config` SUCCEEDS — on its
        // failure (e.g. a bad CIDR or unparseable key on a plain up) no fresh file was written and the
        // cache must not be flipped true. (See the `has_node_key` field invariant.)
        self.has_node_key = true;
        // Bump + capture the generation: `finish_up` installs its device only if this is still the
        // current generation (no later `up`/`down` superseded it while the lock was released). The
        // bump also notifies status watchers (so one watching a replaced device re-derives).
        self.bump_generation();
        Ok(PendingUp {
            config,
            generation: self.generation,
        })
    }

    /// Phase 3 of the concurrent bring-up: install the freshly-built device — but only if no later
    /// `up`/`down` superseded this attempt while the backend lock was released for the handshake.
    ///
    /// `pending` is from [`begin_up`](Backend::begin_up); `device` is the [`build_device`] result.
    ///
    /// Returns the **orphaned device the caller must shut down OFF-LOCK**, if any:
    /// - If a newer generation landed (a later `up`/`down` superseded this attempt while the lock was
    ///   released for the handshake), the just-built device is *not* installed — it is returned as
    ///   `Ok(Some(orphan))` so the caller can `orphan.shutdown(..).await` **after dropping the backend
    ///   lock**. We must NOT await the (up-to-`SHUTDOWN_TIMEOUT`) shutdown here, because `finish_up`
    ///   runs under the lock and that would reintroduce the very head-of-line stall the begin/finish
    ///   split exists to remove. A stale *build error* is simply dropped (nothing to shut down).
    /// - If this attempt is still current and the engine succeeded, the device is installed and
    ///   `Ok(None)` is returned. If the engine failed, the error is returned (intent stays "up" with no
    ///   device → `NeedsLogin`, so auto-start can retry).
    ///
    /// Use [`finish_up_and_settle`](Backend::finish_up_and_settle) if you don't hold the lock yourself
    /// and just want the orphan shut down for you.
    ///
    /// ## SSH server task (spawn-on-install)
    ///
    /// When this attempt is current, the engine succeeded, AND `prefs.ssh_enabled` is set, this also
    /// spawns the long-lived Tailscale SSH server task (a clone of the freshly-installed device's
    /// [`Arc`](std::sync::Arc) running the engine's `listen_ssh` accept loop) and stores its
    /// [`JoinHandle`](tokio::task::JoinHandle) in [`ssh_task`](Backend::ssh_task). The device is
    /// wrapped in the `Arc` **before** the clone, so the task and the backend share one engine. The
    /// spawn is compiled in only with the `ssh` cargo feature; without it, it is a no-op (and
    /// [`build_config`](Backend::build_config) has already failed the bring-up loudly if SSH was
    /// requested, so a feature-less daemon never reaches here with `ssh_enabled`). The task is torn
    /// down (aborted, then the device reclaimed and shut down) by [`stop_device`](Backend::stop_device).
    #[must_use = "the returned orphan device must be shut down off-lock"]
    pub fn finish_up(
        &mut self,
        pending: PendingUp,
        device: Result<tailscale::Device>,
    ) -> Result<Option<std::sync::Arc<tailscale::Device>>> {
        if pending.generation != self.generation {
            // Superseded by a later up/down while we were handshaking. The newer intent is
            // authoritative; hand any built device back (wrapped in the `Arc` the caller settles
            // off-lock) to be torn down. A superseded build was never installed and never
            // SSH-spawned, so its `Arc` is uniquely owned — `shutdown_orphan` reclaims it. A build
            // error on a stale attempt is irrelevant (nothing to return).
            tracing::debug!(
                stale_generation = pending.generation,
                current_generation = self.generation,
                "discarding superseded up() result"
            );
            return Ok(device.ok().map(std::sync::Arc::new));
        }
        // `device` is already an `anyhow::Result` with engine context from `build_device`. Wrap it in
        // the `Arc` BEFORE any SSH-task clone so the task and the backend share one engine handle.
        let device = std::sync::Arc::new(device?);
        self.device = Some(device.clone());
        // Make the device-installed transition its OWN lifecycle wake edge. `begin_up` already bumped
        // the generation while `self.device` was STILL `None` (the device is built off-lock and only
        // installed here), so a `status --watch` parked on `watch_lifecycle()` could wake on THAT
        // bump, re-derive while the device was still absent (emitting another device-less snapshot and
        // taking `stream_watch`'s `None` arm — it never attaches to the device's own state receiver),
        // then re-park. Without this second bump the device-installed edge has no wake signal, and the
        // Connecting→Running transition — which flows ONLY on the device's own (unattached) state
        // receiver — never reaches that watcher: the stream silently hangs on a stale device-less
        // snapshot. Bumping here re-wakes the parked watcher so its outer loop re-derives, takes the
        // `Some` branch, snapshots, and attaches to the device's state receiver.
        //
        // SAFETY (the generation now advances twice per `up`): the stale-check above
        // (`pending.generation != self.generation`) already ran and compared `pending.generation`
        // (captured in `begin_up`) against the generation as it stood ON ENTRY to `finish_up`. This
        // bump happens strictly AFTER that comparison, only on the current (non-superseded) success
        // path, so it cannot cause `finish_up` to reject its own device. (The superseded-orphan
        // early-return above never reaches here, so a discarded stale build never bumps.)
        self.bump_generation();
        // Spawn the SSH server task iff SSH is enabled (and the daemon was built with the `ssh`
        // feature). It outlives this call, running the engine's fail-closed `listen_ssh` accept loop.
        self.spawn_ssh_task(device.clone());
        // Spawn the link-change monitor (Go `tailscaled`'s netmon → rebind): poll the host's
        // interface addresses and re-bind the engine when the network path changes (Wi-Fi switch /
        // sleep-wake). Bound to the device lifecycle like the SSH task (torn down in `stop_device`).
        self.spawn_link_monitor(device.clone());
        // Arm the `serve` accept loops from the persisted serve config (Go `tailscale serve --tcp`).
        // Like the SSH task, these are bound to the device lifecycle (torn down in `stop_device`).
        self.spawn_serve(device);
        // Known lifecycle transition (the IPN state is derived fresh per `status()`, never stored, so
        // transitions are otherwise unlogged): the engine is up and the device is installed. The node
        // converges to Running once the netmap arrives.
        // Mark the node as having logged in: `build_device`'s `Device::new` completed the control
        // registration handshake, so this node has now actually registered (the analogue of Go setting
        // `Persist.UserProfile.LoginName`). The accidental-revert guard's fresh-node exemption keys on
        // this (NOT on prefs-file existence), so a `tnet set` before the first `up` no longer arms the
        // guard. Flip the in-memory flag here, on the non-superseded success path only; the async
        // caller (`drive_up` / `Backend::up`) persists it right after this returns `Ok`. A crash in the
        // gap simply leaves `has_logged_in=false`, so the next `up` is unguarded once — the same benign
        // outcome as the on-upgrade migration default.
        self.prefs.has_logged_in = true;
        tracing::info!(
            generation = self.generation,
            "engine started, device installed"
        );
        Ok(None)
    }

    /// Spawn the long-lived Tailscale SSH server task for a freshly-installed `device`, iff
    /// `prefs.ssh_enabled`. Stores the [`JoinHandle`](tokio::task::JoinHandle) in
    /// [`ssh_task`](Backend::ssh_task) so [`stop_device`](Backend::stop_device) can abort it.
    ///
    /// The task takes the device's [`Arc`](std::sync::Arc) clone and calls the engine's `listen_ssh`,
    /// which binds the node's tailnet IPv4 on port 22 and serves an accept loop **forever**,
    /// authorizing every connection against the control-pushed SSH policy (fail-closed) and dropping
    /// privileges to the policy-mapped local user. `listen_ssh` only returns on a bind/setup error,
    /// which we log; the loop is otherwise terminated by the abort in `stop_device` (which also drops
    /// this task's `Arc` clone, letting `stop_device` reclaim and gracefully shut down the device).
    ///
    /// With the `ssh` cargo feature **off** this is an unconditional no-op: the `device` is dropped
    /// here, no task is spawned, and `ssh_task` stays `None`. That is safe because
    /// [`build_config`](Backend::build_config) fails the bring-up loudly when `ssh_enabled` is set
    /// without the feature, so this is never reached with `ssh_enabled` in a feature-less daemon.
    #[allow(unused_variables)] // `device` is unused when the `ssh` feature is off.
    fn spawn_ssh_task(&mut self, device: std::sync::Arc<tailscale::Device>) {
        // The `ssh_enabled` guard lives INSIDE the feature block so the no-`ssh`-feature build has an
        // empty body (no spawn, no dangling `return`); the device is simply dropped here.
        #[cfg(feature = "ssh")]
        {
            if !self.prefs.ssh_enabled {
                return;
            }
            use tailscale::ssh::russh;
            // A fresh, ephemeral Ed25519 host key per server start (the engine example's recipe).
            // `russh::keys::PrivateKey` is `ssh-key`'s key type and `random` needs a CSPRNG; we use
            // `rand::rng()` (a ChaCha-based `ThreadRng` seeded from OS entropy) exactly as the engine
            // example does. Generation cannot realistically fail for Ed25519, but if it ever did we
            // FAIL CLOSED: log and do NOT spawn (no insecure fallback host key).
            let host_key = match russh::keys::PrivateKey::random(
                &mut rand::rng(),
                russh::keys::Algorithm::Ed25519,
            ) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!(error = ?e, "ssh: failed to generate host key; SSH server NOT started");
                    return;
                }
            };
            let config = russh::server::Config {
                keys: vec![host_key],
                // Authentication is the control-pushed SSH policy enforced inside the engine
                // (`Device::authorize_ssh`), not an SSH userauth method — so the wire offers `none`,
                // exactly like the engine example. The real gate is the fail-closed policy check.
                methods: russh::MethodSet::from(&[russh::MethodKind::None][..]),
                nodelay: true,
                ..Default::default()
            };
            let handle = tokio::spawn(async move {
                // Bind on the node's own tailnet IPv4:22. `ipv4_addr` only resolves once the netmap
                // has assigned an address, so it may briefly wait; an error here means we never got
                // one (engine torn down) — log and exit the task.
                let ipv4 = match device.ipv4_addr().await {
                    Ok(ip) => ip,
                    Err(e) => {
                        tracing::error!(error = %e, "ssh: could not resolve tailnet IPv4; SSH server not started");
                        return;
                    }
                };
                let listen_addr = std::net::SocketAddr::from((ipv4, 22));
                tracing::info!(%listen_addr, "starting Tailscale SSH server");
                // Runs the accept loop forever; only returns on a bind/setup error (or when this task
                // is aborted by `stop_device`, which drops the future). Either way, log the outcome.
                if let Err(e) = device.listen_ssh(config, listen_addr).await {
                    tracing::error!(error = %e, "ssh: server exited with error");
                }
            });
            self.ssh_task = Some(handle);
        }
    }

    /// Spawn the link-change monitor for a freshly-installed `device` (Go `tailscaled`'s netmon →
    /// rebind). Stores the [`JoinHandle`](tokio::task::JoinHandle) in
    /// [`monitor_task`](Backend::monitor_task) so [`stop_device`](Backend::stop_device) can abort it.
    /// Sync (spawns + returns) so it fits the non-async [`finish_up`](Backend::finish_up); the poll
    /// loop runs inside the task. The task holds an [`Arc`](std::sync::Arc) clone of `device` and calls
    /// [`Device::rebind`](tailscale::Device::rebind) on a host network-path change. Always spawned
    /// (unlike the SSH task, this has no pref gate — every up-node wants to re-home on a link change);
    /// torn down in `stop_device` before the device `Arc` is reclaimed.
    fn spawn_link_monitor(&mut self, device: std::sync::Arc<tailscale::Device>) {
        let handle = tokio::spawn(link_monitor_loop(device));
        self.monitor_task = Some(handle);
    }

    /// Spawn the `serve` runtime for the current profile's serve config (Go `tailscale serve`), in
    /// two lanes:
    /// - **Plain TCP forward** (`tcp_forward` set, no HTTPS/HTTP/TerminateTLS — see
    ///   [`serve::is_plain_tcp_forward`]): one accept loop per entry, binding the node's tailnet IPv4
    ///   on the served port via [`Device::tcp_listen`](tailscale::Device::tcp_listen) and splicing
    ///   every inbound connection to the configured localhost target (the `nc` splice, inbound).
    /// - **HTTPS/HTTP web** (see [`serve::is_web_serve`]): delegated to the engine's native serve stack
    ///   via [`Device::set_serve_config`](tailscale::Device::set_serve_config) — the engine terminates
    ///   TLS for the node's MagicDNS name and reverse-proxies each decrypted stream to the backend
    ///   (full-replace; fail-closed on cert error, never a plaintext downgrade). The engine's serve
    ///   loops are owned by the `Device` (torn down on the next `set_serve_config` / device shutdown),
    ///   so this lane needs no entry in [`serve_tasks`](Backend::serve_tasks); a removed last web entry
    ///   is cleared with an empty full-replace.
    ///
    /// `TerminateTLS` raw-TCP entries have no engine analogue at this pin and are logged + skipped.
    ///
    /// The TCP-forward tasks hold `Arc` clones of `device` and are torn down in
    /// [`stop_device`](Backend::stop_device) before the device is reclaimed; the engine web serve is
    /// torn down with the device itself. Stores the supervisor handle in
    /// [`serve_tasks`](Backend::serve_tasks).
    ///
    /// Spawn a single supervisor task that loads the serve config and arms one accept loop per
    /// plain-TCP-forward entry. Sync (spawns + returns) so it can be called from the non-async
    /// [`finish_up`](Backend::finish_up); the async config read happens INSIDE the supervisor task.
    /// The supervisor's [`JoinHandle`](tokio::task::JoinHandle) is stored in
    /// [`serve_tasks`](Backend::serve_tasks); aborting it (in `stop_device`) cancels the supervisor
    /// and — because they are spawned as its children via a `JoinSet` it owns — all per-port loops.
    fn spawn_serve(&mut self, device: std::sync::Arc<tailscale::Device>) {
        let state_dir = self.state_dir.clone();
        let profile = self.current_profile.clone();
        let supervisor = tokio::spawn(async move {
            let cfg = serve::load(&state_dir, &profile).await;
            // Own the per-port loops in a JoinSet so dropping the supervisor (on abort) drops them.
            let mut loops: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
            // LANE 1 — plain TCP-forward: the daemon's own raw accept→dial→splice loops (no TLS).
            for (port_str, handler) in &cfg.tcp {
                let Ok(port) = port_str.parse::<u16>() else {
                    tracing::warn!(port = %port_str, "serve: skipping entry with non-numeric port key");
                    continue;
                };
                if serve::is_plain_tcp_forward(handler) {
                    let target = handler.tcp_forward.clone();
                    let dev = device.clone();
                    // Per-loop splice cap (see `serve_accept_loop` / `MAX_SERVE_CONNECTIONS`).
                    let conn_limit =
                        std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_SERVE_CONNECTIONS));
                    loops.spawn(serve_accept_loop(dev, port, target, conn_limit));
                } else if serve::port_is_web_serve(&cfg, port_str, handler)
                    || serve::is_terminate_tls_serve(handler)
                {
                    // Handled by LANE 2 below (engine delegation): web entries (legacy-bodied OR
                    // Go `Web`-map-bodied) AND servable TLS-terminated raw-TCP forwards (the engine
                    // terminates TLS + splices to the backend — Go's `TerminateTLS`). Nothing here.
                } else if !handler.terminate_tls.is_empty() {
                    // A terminate-tls entry we CAN'T serve via the engine `Proxy` target: either no
                    // `tcp_forward` backend to splice to, or `proxy_protocol != 0` (the engine doesn't
                    // write the PROXY-protocol header, so serving it as a plain splice would silently
                    // drop that semantic). Recognized only — a faithful refusal, not a silent serve.
                    tracing::info!(
                        port,
                        proxy_protocol = handler.proxy_protocol,
                        "serve: TLS-terminated TCP entry not servable (no backend, or proxy-protocol \
                         requested) — recognized only"
                    );
                } else if handler.https || handler.http {
                    // A web flag with no proxy backend — can't be served (LANE 2 needs a target).
                    // Surfaced in `serve status` too; log it so a daemon-log tail sees the skipped port.
                    tracing::info!(
                        port,
                        "serve: web entry with no proxy backend — not served (recognized only)"
                    );
                }
            }
            // LANE 2 — HTTPS/HTTP web: delegate to the engine's native serve stack (full-replace
            // reconcile). The engine's `ServeManager` lives in the `Device` (its per-port accept loops
            // are owned there, torn down on the next `set_serve_config` or on device shutdown — NOT by
            // the returned receiver), and `Proxy` targets are reverse-proxied entirely inside it, so we
            // drop the receiver immediately and the serve stays up regardless of this supervisor.
            // `get_serve_config` is a pure read; reconcile when the new config has web entries OR the
            // engine still has a web serve bound (so removing the last web entry clears it too).
            // Arm LANE 2 for web entries (legacy or Go `Web`-map) AND servable TLS-terminated raw-TCP
            // forwards (both produce engine `ServeState` ports via `build_web_serve_state`).
            let has_web = cfg.tcp.iter().any(|(port_str, h)| {
                serve::port_is_web_serve(&cfg, port_str, h) || serve::is_terminate_tls_serve(h)
            });
            // Arm the web serve (resolve the node MagicDNS name — the shared TLS cert name — and
            // full-replace the engine serve config). `Ok(())` = armed; `Err` = could not arm (device
            // not yet reporting self_node, or a fail-closed cert/serve error: the `acme` feature is
            // off, or the control plane 501s on `set-dns`). Non-fatal either way — the TCP-forward
            // loops keep running.
            let armed = if has_web {
                match device.self_node().await {
                    Ok(node) => {
                        let fqdn = node.fqdn(false);
                        let state = serve::build_web_serve_state(&cfg, &fqdn);
                        match device.set_serve_config(state).await {
                            Ok(_rx) => {
                                tracing::info!(
                                    name = %fqdn,
                                    ports = cfg.tcp.values().filter(|h| serve::is_web_serve(h)).count(),
                                    "serve: armed HTTPS/HTTP web serve via engine delegation"
                                );
                                true
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "serve: engine web serve failed (cert/serve error — needs the `acme` \
                                     feature + a SaaS tailnet that answers set-dns); TCP-forward serve continues"
                                );
                                false
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "serve: could not resolve node MagicDNS name for web serve; skipping web lane"
                        );
                        false
                    }
                }
            } else {
                false
            };
            // Fail-closed reconcile: if we did NOT (re)arm this round but the engine still has a web
            // serve bound from a PRIOR config, clear it with an empty full-replace — otherwise a stale
            // web serve keeps exposing the old backend after the config moved on / a re-arm failed.
            // The engine's `set_serve_config` only swaps in a new config when EVERY port's acceptor
            // built, so a failed re-arm leaves the previous serve live; this clear is what actually
            // tears it down. (No cert/fqdn needed for an empty state.) Covers both "web removed" and
            // "web present but arm failed".
            if !armed
                && !device.get_serve_config().ports.is_empty()
                && let Err(e) = device
                    .set_serve_config(tailscale::ServeState::default())
                    .await
            {
                tracing::warn!(error = %e, "serve: fail-closed clear of stale engine web serve failed");
            }
            // LANE 3 — FUNNEL: expose a port's web serve to the PUBLIC internet (Go `tailscale
            // funnel`). Extracted to `arm_funnel_lane` (it was the deepest nest in this supervisor);
            // it resolves the node's MagicDNS name, arms each funnel-enabled port via the engine's
            // fail-closed `listen_funnel`, and spawns a public-ingress splice loop into `loops`.
            arm_funnel_lane(&device, &cfg, &mut loops).await;
            // Keep the supervisor alive while the TCP/funnel loops run (so aborting it tears them down).
            // Each loop only returns on listener/receiver close or engine teardown. With no loops the
            // supervisor exits here — fine: the engine web serve is Device-bound, not supervisor-bound.
            while loops.join_next().await.is_some() {}
        });
        self.serve_tasks.push(supervisor);
    }

    /// Abort + await all `serve` accept-loop tasks (so their device `Arc` clones are released). Called
    /// by [`stop_device`](Backend::stop_device) before reclaiming the device, and before re-arming on
    /// a serve-config change. Idempotent (empty when no serve tasks run).
    async fn stop_serve_tasks(&mut self) {
        for task in self.serve_tasks.drain(..) {
            task.abort();
            // A cancelled task (the normal abort case above) resolves to a cancellation `JoinError`
            // and stays quiet. But a supervisor that *panicked* before we aborted it would otherwise
            // vanish silently — surface that panic here, on the next teardown/re-arm, so it isn't lost.
            if let Err(e) = task.await
                && e.is_panic()
            {
                tracing::error!(error = ?e, "serve supervisor task panicked");
            }
        }
    }

    /// Translate current [`Prefs`] + the on-disk key file into a [`tailscale::Config`] for the
    /// engine. A thin shim over the free [`config::build_config`] (which reads only prefs + the key
    /// path, no `Backend` `self`), kept so the internal callers (`begin_up` / `begin_set` /
    /// `drive_set` preflight) and the build_config tests are unchanged by the split. See
    /// [`config::build_config`] for the full control-server-precedence / leak-safety / preflight
    /// rationale.
    async fn build_config(&self) -> Result<tailscale::Config> {
        config::build_config(&self.prefs, &self.key_path, self.listen_port).await
    }

    /// The current profile's display NAME — what `tnet switch --list` shows, and Go's
    /// `LoginProfile.Name()`. Falls back to the profile id when the profile has no display name (the
    /// usual case for `default`), which is exactly what [`list_profiles`](Backend::list_profiles)
    /// already decides, so the name in an audit record and the name in `switch --list` cannot drift.
    async fn current_profile_name(&self) -> String {
        self.list_profiles()
            .await
            .into_iter()
            .find(|p| p.current)
            .map(|p| p.name)
            .unwrap_or_else(|| self.current_profile.clone())
    }

    /// The always-on disconnect gate — Go's `checkEditPrefsAccessLocked` calling
    /// `actor.CheckProfileAccess(…, ipnauth.Disconnect, …)`, which lands in
    /// [`alwayson::check_disconnect_policy`].
    ///
    /// Called by [`down`](Backend::down) and [`logout`](Backend::logout) as their first act, so the
    /// two commands that take `WantRunning` from true to false share one rule and neither can be the
    /// only gate. It refuses before any teardown or persist, so a refusal costs nothing.
    ///
    /// Go gates a **transition**, not a state: `mp.WantRunningSet && !mp.WantRunning &&
    /// b.pm.CurrentPrefs().WantRunning()`. A `down` on a node that is already down is therefore not
    /// a disconnect and is not refused — which matters, because the alternative would wedge an
    /// always-on node's operator out of the idempotent `down` that Go lets through.
    ///
    /// Note what "already down" means under an always-on policy: prefs that were *persisted* down do
    /// not qualify, because [`reconcile_sys_policy`](Backend::reconcile_sys_policy) re-asserts
    /// `want_running` at profile load, before any command is evaluated — Go's `reconcilePrefs` does
    /// the same, which is why its `CurrentPrefs().WantRunning()` reads true there too. The state that
    /// does qualify is the window after a disconnect this gate PERMITTED and before the next
    /// reconcile point, where a second `down` is genuinely a no-op.
    ///
    /// A permitted disconnect that the policy *required a reason for* leaves Go's audit record. This
    /// daemon has no transport to ship it to control (engine ask #41), so it goes to the daemon log
    /// under Go's action name — written before the teardown, so a disconnect that then fails is
    /// still explained.
    async fn check_disconnect_policy(&self, actor: alwayson::Actor<'_>) -> Result<()> {
        if !self.prefs.want_running {
            return Ok(());
        }
        // Go's `actor.Username()` is best-effort and, outside Windows, has no implementation — so
        // Go itself takes the no-username branch on every platform this daemon runs on. The LocalAPI
        // peer is identified here by uid rather than by name (see `crate::auth`); resolving that uid
        // to a passwd entry is the one thing a username branch would need, and it is a call-site
        // change when it arrives, not a reshaping of the record.
        let username = None;
        let profile = self.current_profile_name().await;
        if let Some(details) = alwayson::check_disconnect_policy(actor, &profile, username)? {
            tracing::info!(
                action = alwayson::AUDIT_NODE_DISCONNECT,
                details = %details,
                "audit: always-on disconnect permitted by policy"
            );
        }
        Ok(())
    }

    /// Bring the node down (`WantRunning = false`) without logging out; tears down the engine.
    ///
    /// `actor` says who asked, which is what decides whether the always-on policy is consulted — see
    /// [`check_disconnect_policy`](Backend::check_disconnect_policy). A refused disconnect returns
    /// the refusal **before** anything is torn down or persisted, so the node is left exactly as it
    /// was.
    pub async fn down(&mut self, actor: alwayson::Actor<'_>) -> Result<()> {
        self.check_disconnect_policy(actor).await?;
        // Go gates the always-on override + reconnect timer on the *transition*
        // (`mp.WantRunningSet && !mp.WantRunning && oldPrefs.WantRunning()`), so read the old value
        // before the flip below. A `down` on an already-down node is not a disconnect.
        let was_running = self.prefs.want_running;
        self.stop_device().await;
        // Bump the generation so an `up` whose `Device::new` is still in flight (lock released) is
        // recognized as stale by `finish_up` and its device discarded — `down` wins. The bump also
        // notifies status watchers that the device was torn down.
        self.bump_generation();
        self.prefs.want_running = false;
        self.ever_configured = true;
        // The disconnect stands: stop the always-on re-assert from undoing it, and give it the
        // deadline the administrator configured (if any) — Go's `onEditPrefsLocked`.
        if was_running {
            self.on_permitted_disconnect(syspolicy::reconnect_after());
        }
        // Disconnecting ends an exit-node override, on the same edge Go clears it: which node the
        // operator egresses through is not a choice that outlives the connection. Outside the
        // transition guard on purpose — there is no timer to re-arm, so clearing it on a `down` that
        // changes nothing else is simply the honest state.
        self.reset_exit_node_policy_override("down");
        self.persist_prefs().await?;
        Ok(())
    }

    /// Discard the persisted node key so the next bring-up re-registers FRESH instead of resuming the
    /// old registration. The shared re-keying primitive for both [`logout`](Backend::logout) (which
    /// additionally flips intent to logged-out) and a force-reauth [`up`](Backend::begin_up) (which
    /// keeps the node's up-intent and only re-keys). Deleting the key is the daemon's responsibility:
    /// the engine deliberately leaves it on disk (re-`new` with the same key is its *resume/re-login*
    /// path), so neither logout nor force-reauth can be expressed engine-side.
    ///
    /// A **missing key file is success** (never registered / already fresh). Any other IO error is
    /// returned so the caller can fail closed — a path that believed it re-keyed when the old key is
    /// still on disk would silently resume the very registration it meant to end. The error names the
    /// key path; callers add their own action context (so the path is not repeated in the chain).
    async fn discard_node_key(&mut self) -> Result<()> {
        match tokio::fs::remove_file(&self.key_path).await {
            // Key file removed, or it was already absent — either way no node key is on disk now, so
            // the cache is `false`. Set only AFTER a successful wipe (mirrors logout's wipe-before-
            // persist crash-safety: never record "no key" while the file might still be there). A
            // force-reauth up immediately re-mints a key in `build_config` and flips this back to
            // `true`; a `logout` leaves it `false`. (See the `has_node_key` field invariant.)
            Ok(()) => {
                self.has_node_key = false;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.has_node_key = false;
                Ok(())
            }
            // Wipe FAILED: the file may still be present, so leave the cache untouched (the caller
            // fails closed on this error rather than proceeding as if re-keyed).
            Err(e) => Err(anyhow!(
                "could not discard the node key at {}: {e}",
                self.key_path.display()
            )),
        }
    }

    /// Log the node out — the Rust analogue of Go's `tailscale logout`. Distinct from
    /// [`down`](Backend::down): `down` keeps the node key for a seamless resume, whereas `logout`
    /// **ends the registration** and forces the next `up` to re-login from scratch.
    ///
    /// Three things happen, in this order:
    /// 1. **Deregister with control** (if a device is up): call the engine's
    ///    [`Device::logout`](tailscale::Device::logout), a *control-plane* state change that expires
    ///    this node key with control immediately (rather than leaving the node to be GC'd up to ~24h
    ///    later). It is idempotent — logging out an already-gone/ephemeral node is not an error. The
    ///    engine deliberately does NOT tear down the datapath or rotate the on-disk key, so the daemon
    ///    owns steps 2–3. A control round-trip failure here is logged but **not fatal**: a local
    ///    logout (key wipe + intent flip) must still complete so the operator is never wedged "half
    ///    logged in" by a transient control error (Go also proceeds with the local logout).
    /// 2. **Tear down the datapath + flip intent**: [`stop_device`](Backend::stop_device), bump the
    ///    generation (supersede any in-flight `up`), set `want_running = false` **and**
    ///    `logged_out = true` (so daemon auto-start does not silently resurrect the node — see
    ///    [`wants_running`](Backend::wants_running)), and persist.
    /// 3. **Discard the persisted node key**: delete `node.key.json` so the next `up` cannot resume
    ///    the old registration and instead registers fresh (requiring a new auth key / interactive
    ///    login). This is the daemon's responsibility because the engine's `logout` intentionally
    ///    leaves the key on disk (re-`new` with the same key is its *re-login* path — the opposite of
    ///    what `tailscale logout` means). A missing key file is fine (already fresh).
    pub async fn logout(&mut self, actor: alwayson::Actor<'_>) -> Result<()> {
        // 0. The always-on gate, before the control-plane call and before anything is torn down: a
        // logout is a disconnect (Go routes it through the same `editPrefsLocked` with
        // `WantRunning:false`, so the same `ipnauth.Disconnect` check applies), and a refusal must
        // leave the registration intact.
        self.check_disconnect_policy(actor).await?;
        // Read the pre-edit intent for the same transition guard `down` uses: Go routes a logout
        // through the same `WantRunning:false` edit, so `onEditPrefsLocked` fires for it too.
        let was_running = self.prefs.want_running;
        // 1. Best-effort control-plane deregistration while the device is still alive. (Let-chain
        // rather than nested `if let` — clippy::collapsible_if; mirrors the `&&`-let style this
        // module already uses, e.g. the revert-guard arms.)
        if let Some(dev) = self.device.as_ref()
            && let Err(e) = dev.logout().await
        {
            // Non-fatal: proceed with the local logout regardless (never leave the operator wedged
            // half-logged-in on a transient control error). Go behaves the same.
            tracing::warn!(
                error = %e,
                "logout: control-plane deregistration failed; proceeding with local logout \
                 (key wipe + intent flip) anyway"
            );
        }
        // 2. Tear down the datapath.
        self.stop_device().await;
        self.bump_generation();

        // 3. Discard the persisted node key BEFORE flipping intent to logged-out — ordering is
        // load-bearing for crash-safety. Both this `remove_file` and the `persist_prefs` below are
        // separate, non-atomic disk writes; a crash (or kill) between them leaves a partial state. We
        // choose the order whose partial state is SAFE:
        //   - key-wipe THEN persist (this order): a crash after the wipe but before the persist
        //     leaves NO key on disk with `logged_out` not yet set. The next `up` finds no key and
        //     re-registers fresh — exactly the logout intent. Safe.
        //   - persist THEN key-wipe (the reverse): a crash in between leaves `logged_out=true` but the
        //     OLD key still on disk. A later `up` flips `logged_out=false` and `load_key_file` happily
        //     resumes the very registration logout was meant to end — silently resurrecting the old
        //     identity. That is the wrong direction for a logout, so we do NOT use this order.
        // A key-wipe failure is therefore FATAL here, before any intent is persisted: if we cannot
        // discard the key, the logout has not achieved its security goal, so we must not record it as
        // done. The node stays as it was (device down from step 2, but prefs unchanged → a retry of
        // `logout` cleanly re-attempts). A missing key file is success (never registered / already
        // logged out). The control-plane deregister in step 1 already ran, so a retry just re-asserts
        // it (idempotent). The wipe itself is the shared [`discard_node_key`](Self::discard_node_key)
        // primitive (force-reauth re-keys with the same step) so the two paths cannot drift.
        self.discard_node_key().await.context(
            "logout: aborted before recording it — remove the key file or re-run `tnet logout`. \
             Until the key is gone, a later `up` could resume the old registration.",
        )?;

        // 4. Now that the key is gone, flip intent to logged-out and persist. `logged_out` suppresses
        // auto-start (see `wants_running`); `ever_configured` keeps a post-logout restart reporting
        // `NeedsLogin`/`Stopped` rather than `NoState`. Clear `has_logged_in`: logout ends the
        // registration (the node key is gone), so the node is no longer "logged in" — matching Go,
        // which clears `Persist.UserProfile.LoginName` on logout. This keeps the revert-guard's
        // fresh-node exemption faithful: a `set`-then-`up` after a logout is unguarded (the node must
        // re-register first), exactly as it is on a never-logged-in node — the next successful `up`
        // re-sets `has_logged_in` in `finish_up`. (`down`, by contrast, preserves it — `down` keeps
        // the registration, like Go keeping LoginName across a non-logout disconnect.)
        self.prefs.want_running = false;
        self.prefs.logged_out = true;
        self.prefs.has_logged_in = false;
        self.ever_configured = true;
        // Same disconnect bookkeeping as `down` (Go makes no distinction — both are a
        // `WantRunning:false` edit). What the timer can achieve differs, though: a logout has
        // discarded the node key, so the reconnect it fires has no registration to resume and
        // reaches `NeedsLogin` instead of `Running`, which the failure log says out loud.
        if was_running {
            self.on_permitted_disconnect(syspolicy::reconnect_after());
        }
        // A logout is a disconnect, so it ends an exit-node override too — same edge as `down`.
        self.reset_exit_node_policy_override("logout");
        self.persist_prefs().await?;
        Ok(())
    }

    /// A receiver that wakes on every engine connection-state transition, for streaming `status`
    /// (`tnet status --watch`). `None` when no device is up (nothing to watch yet — the caller
    /// should fall back to a one-shot status). The receiver is a cheap `watch` handle; awaiting its
    /// `changed()` does not hold the backend lock, so a watcher never blocks other LocalAPI calls.
    pub fn watch_state_receiver(
        &self,
    ) -> Option<tokio::sync::watch::Receiver<tailscale::DeviceState>> {
        self.device.as_ref().map(|dev| dev.watch_state())
    }

    /// Clone out the live engine handle (the [`Arc<Device>`](std::sync::Arc)) if the node is up, or
    /// `None` if it is not.
    ///
    /// This is the lock-discipline primitive for read/file engine calls that may be **slow or
    /// unbounded** (Taildrop transfers, `ping`'s caller-supplied timeout). The caller locks the
    /// backend only long enough to clone this `Arc`, **drops the lock**, then runs the engine call
    /// off-lock against the borrowed device — the same "clone the work out, drop the lock" discipline
    /// [`drive_up`] uses for the registration handshake. It is sound because every read/file engine
    /// method takes `&self` and the [`device`](Backend::device) is **already** an `Arc` (shared with
    /// the SSH task), so cloning it adds no new aliasing constraint. A concurrent `down` during an
    /// in-flight off-lock call merely makes [`stop_device`](Backend::stop_device)'s `Arc::into_inner`
    /// observe an extra clone (the documented benign drop-the-last-clone path) — the correct trade: a
    /// `down` no longer waits for a multi-minute transfer to finish.
    pub fn device_handle(&self) -> Option<std::sync::Arc<tailscale::Device>> {
        self.device.clone()
    }

    /// Produce a [`StatusReport`] reflecting the live engine + netmap.
    ///
    /// State comes from the engine's **cheap, non-blocking** [`device_state`](tailscale::Device::device_state)
    /// (a `watch` borrow) — it is the authoritative connection state and knows about interactive-login,
    /// expiry, and hard failure. We only issue the **blocking** netmap query
    /// ([`status`](tailscale::Device::status), an actor round-trip) when the device is `Running`.
    /// That is deliberate: while the node is still registering — especially in `NeedsLogin` — the
    /// engine's control runner is still inside its `Actor::on_start` auth-retry loop and processes no
    /// mailbox messages until registration succeeds, so `dev.status().await` would block until then,
    /// hanging every `status` LocalAPI call (and freezing the interactive-login `tnet up` poll). In
    /// non-`Running` states there is no self-node or peer list to report anyway, so skipping the query
    /// loses nothing and keeps status responsive in every state.
    ///
    /// Even in `Running`, the netmap query is bounded by [`STATUS_QUERY_TIMEOUT`]: in the brief
    /// window between the stream attaching (`Running` published) and the first netmap arriving, the
    /// self-node read waits, and we must not hold the backend lock on it unboundedly (that would
    /// head-of-line block `up`/`down`). On timeout we report `Running` with no addresses yet (the
    /// next poll fills them) — the same shape as the error arm.
    pub async fn status(&self) -> StatusReport {
        // Cheap, non-blocking watch borrow → authoritative connection state + any interactive-login
        // URL. `DeviceState::Running` already means "registered, netmap live", so it maps straight to
        // `Running`; the address fill-in below is best-effort on top of that.
        let (state, auth_url, error) = match self.device.as_ref() {
            Some(dev) => state_from_device(dev.device_state()),
            None => (self.derive_state(false), None, None),
        };

        // The address/peer view derived from the netmap. Bundled into one named struct (rather than a
        // 6-positional tuple repeated across the arms below) so the "no netmap yet" arms are a single
        // `NetmapProjection::default()` — one source of truth for "no addresses/peers" — and adding a
        // field can never silently shift a positional value. `Default` gives every field its empty
        // value (`None` / empty `Vec`), exactly the old `(None, …, Vec::new())` tuple.
        #[derive(Default)]
        struct NetmapProjection {
            self_ipv4: Option<String>,
            self_name: Option<String>,
            self_ipv6: Option<String>,
            active_exit_node: Option<String>,
            active_exit_node_id: Option<String>,
            magic_dns_suffix: Option<String>,
            peers: Vec<PeerReport>,
        }

        // Query the (blocking) netmap only when Running — the only state with a self-node/peers.
        // Bounded by a timeout so the backend lock is never held indefinitely (see method doc).
        let NetmapProjection {
            self_ipv4,
            self_name,
            self_ipv6,
            active_exit_node,
            active_exit_node_id,
            magic_dns_suffix,
            peers,
        } = match (state, self.device.as_ref()) {
            (State::Running, Some(dev)) => {
                match tokio::time::timeout(STATUS_QUERY_TIMEOUT, dev.status()).await {
                    Ok(Ok(s)) => {
                        let (self_ipv4, self_name, self_ipv6) = match &s.self_node {
                            Some(n) => (
                                Some(n.ipv4.to_string()),
                                Some(n.display_name.clone()),
                                Some(n.ipv6.to_string()),
                            ),
                            None => (None, None, None),
                        };
                        // The raw StableNodeID of the active exit node — Go's `status --json`
                        // `ExitNodeStatus.ID` (a StableNodeID that keys the `Peer` map), carried as-is.
                        let active_exit_node_id =
                            s.active_exit_node.as_ref().map(|id| id.0.clone());
                        // Resolve the same id → the peer's display name where we can (friendlier than a
                        // raw id, for the human `tnet status` line), falling back to the id.
                        let active_exit_node = s.active_exit_node.as_ref().map(|id| {
                            s.peers
                                .iter()
                                .find(|p| &p.stable_id == id)
                                .map(|p| p.display_name.clone())
                                .unwrap_or_else(|| id.0.clone())
                        });
                        let magic_dns_suffix = s.magic_dns_suffix.clone();
                        let peers = s
                            .peers
                            .into_iter()
                            .map(peer_report_from_status_node)
                            .collect();
                        NetmapProjection {
                            self_ipv4,
                            self_name,
                            self_ipv6,
                            active_exit_node,
                            active_exit_node_id,
                            magic_dns_suffix,
                            peers,
                        }
                    }
                    // Transient engine error: log and report no addresses/peers (state stays Running).
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "engine status query failed");
                        NetmapProjection::default()
                    }
                    // Pre-netmap window (or a wedged Running engine): don't hold the lock waiting.
                    // Report Running with no addresses yet; the next status poll fills them in.
                    Err(_elapsed) => {
                        tracing::debug!(
                            "engine status query exceeded {STATUS_QUERY_TIMEOUT:?}; \
                             reporting Running without addresses (netmap not yet converged)"
                        );
                        NetmapProjection::default()
                    }
                }
            }
            _ => NetmapProjection::default(),
        };

        StatusReport {
            state: state.as_str().to_string(),
            want_running: self.prefs.want_running,
            self_ipv4,
            self_name,
            auth_url,
            error,
            // Project the persisted prefs into the status view so `tnet status` shows the full
            // configured posture (read straight from prefs — no engine round-trip). Shared with
            // `tnet get` via `prefs_view()` so both surfaces report one identical projection.
            prefs: self.prefs_view(),
            self_ipv6,
            active_exit_node,
            active_exit_node_id,
            magic_dns_suffix,
            peers,
            // The daemon's own version (Go `Status.Version`) — the same crate version the `version`
            // request reports, surfaced here so `status --json` carries it too.
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            // Whether a node key is on disk (Go `Status.HaveNodeKey` / `hasNodeKeyLocked`), NOT
            // inferred from `state` (an expired node reports `NeedsLogin` but still holds its key).
            // Read from the cached `has_node_key` rather than re-reading + parsing + Ed25519-deriving
            // the key file on every call: `status` runs under the backend lock and on the
            // `stream_watch` hot path fires on EVERY engine state transition, where this fact never
            // changes (it only moves on key persist/wipe — see the `has_node_key` field invariant).
            have_node_key: self.has_node_key,
            // Go `ipnstate.Status.Health`: the text of every health warning currently raised. Go's
            // `health.Tracker.Strings()` emits one entry per unhealthy warnable; the captive-portal
            // warnable is the only one this fork raises, so the list is either empty or that one
            // message.
            health: self.health_warnings(),
        }
    }

    /// The health-warning texts `status` reports (Go `health.Tracker.Strings()`, whose output lands in
    /// `ipnstate.Status.Health` and is what `tailscale status` prints under `# Health check:`).
    ///
    /// This fork registers exactly one warnable — Go's `captivePortalWarnable` — so the list is empty
    /// on a healthy node and carries that single message when a portal was detected. The string is
    /// Go's verbatim, so `tnet status` and `tailscale status` read identically.
    fn health_warnings(&self) -> Vec<String> {
        let mut health = Vec::new();
        if self.captive_portal_detected {
            health.push(captive::WARNABLE_TEXT.to_string());
        }
        health
    }

    /// Go `LocalBackend.shouldRunCaptivePortalDetection`: may captive-portal detection run at all?
    ///
    /// Go gates on two things: the `DisableCaptivePortalDetection` **control knob** and
    /// `prefs.WantRunning()`. The engine at this pin surfaces no control knobs to the daemon (nor the
    /// `NodeAttrDisableCaptivePortalDetection` node attribute that backs the knob), so only the
    /// want-running half is enforceable here — and no local pref is invented to stand in for a
    /// control-plane switch. That is not a licence to probe freely: the *trigger*
    /// ([`connectivity_impacted`](Backend::connectivity_impacted)) is narrow enough that a node which
    /// is connected, or deliberately down, never probes at all.
    fn should_run_captive_portal_detection(&self) -> bool {
        self.prefs.want_running
    }

    /// Whether this node's connectivity is impacted — the condition that makes a captive portal worth
    /// probing for.
    ///
    /// This is the fork's stand-in for Go's trigger, and it runs in the state Go runs it in:
    /// **`Running`**. Upstream starts `checkCaptivePortalLoop` on the transition *into* `ipn.Running`
    /// and cancels it on the way out (`ipn/ipnlocal/local.go`, `enterStateLocked`), then probes only
    /// while the health tracker reports some *other* `ImpactsConnectivity` warnable unhealthy
    /// (`captivePortalHealthChange`). So the node upstream probes is the connected one that has lost
    /// its path — the ordinary hotel-Wi-Fi case, where a portal appears mid-session — and nothing
    /// else.
    ///
    /// This daemon has no health tracker, so [`captive::ConnectivityWarnable`] enumerates that set
    /// instead, and this method observes each member it has substrate for:
    ///
    /// - `network-status` — the host has no interface that could carry Internet traffic. Go computes
    ///   it in the link monitor (`netmon.State.AnyInterfaceUp`) and pushes it into the tracker via
    ///   `health.Tracker.SetAnyInterfaceUp`; here the daemon's own link monitor answers the same
    ///   question ([`linkmon::any_interface_up`]).
    /// - `no-derp-home` — the net-report ([`netcheck`](tailscale::Device::netcheck)) names no
    ///   reachable DERP region. That is what Go registers as `no-derp-home` (`health/warnings.go`:
    ///   *"Tailscale could not connect to any relay server"*), and the warnable that fires when a
    ///   portal swallows a live node's traffic, since the portal answers the DERP connections instead
    ///   of the relay.
    ///
    /// Reading both matters, and not only for tidiness: the engine's net report is the node's
    /// **last** measurement, so a path that dies under a live session keeps naming its old home
    /// region until something re-measures. On that node `no-derp-home` says nothing is wrong while
    /// the host has plainly lost the network — exactly the case upstream still probes, through
    /// `network-status`. The daemon's own state machine cannot supply either: the engine keeps
    /// publishing `DeviceState::Running` once its netmap stream has attached, so a mid-session portal
    /// never shows up as a state change.
    ///
    /// Deliberately **not** impacted:
    /// - a node that is `Starting`/`NeedsLogin`/`Stopped`/`NoState` — upstream's loop is cancelled
    ///   outside `Running`, so a node still coming up probes zero times;
    /// - a `Running` node with a home relay and a live host network — Go's healthy branch;
    /// - a deliberately-`down` node (`want_running == false`), which
    ///   [`should_run_captive_portal_detection`](Backend::should_run_captive_portal_detection)
    ///   already excludes.
    ///
    /// The net-report read is an engine actor round-trip made under the backend lock, so it is
    /// bounded by [`STATUS_QUERY_TIMEOUT`] exactly like [`status`](Backend::status)'s netmap query,
    /// and is only ever issued in `Running` (where the control runner is past its auth loop and
    /// answers its mailbox). The interface enumeration beside it is the same cheap `if_addrs` call
    /// the link monitor already makes every [`linkmon::POLL_INTERVAL`], with no engine involved. A
    /// timeout, an engine error or a failed enumeration leaves that signal *unknown*, which never
    /// makes the node impacted: an unreadable signal is not evidence of a broken path, and the next
    /// tick asks again.
    async fn connectivity_impacted(&self) -> Option<captive::ConnectivityWarnable> {
        if !self.prefs.want_running {
            return None;
        }
        let state = match self.device.as_ref() {
            Some(dev) => state_from_device(dev.device_state()).0,
            // No engine at all: not `Running`, so upstream's loop would not be alive here.
            None => self.derive_state(false),
        };
        // Observe only in `Running` — the one state where the answers can change the verdict, and the
        // one state where the control runner is past its auth-retry loop and answering its mailbox
        // (see `status`'s note on why it does the same).
        let health = match (state, self.device.as_ref()) {
            (State::Running, Some(dev)) => ConnectivityHealth {
                any_interface_up: linkmon::any_interface_up(),
                derp_home: match tokio::time::timeout(STATUS_QUERY_TIMEOUT, dev.netcheck()).await {
                    Ok(Ok(report)) => Some(report.preferred_derp.is_some()),
                    Ok(Err(e)) => {
                        tracing::debug!(error = %e, "captive: no net report; relay health unknown");
                        None
                    }
                    Err(_) => {
                        tracing::debug!("captive: net report timed out; relay health unknown");
                        None
                    }
                },
            },
            _ => ConnectivityHealth::UNKNOWN,
        };
        connectivity_impacted_from(state, health)
    }

    /// Record the verdict of a captive-portal detection pass (Go's
    /// `b.health.SetUnhealthy`/`SetHealthy(captivePortalWarnable)`). Called only by
    /// [`captive_portal_loop`]; logs the edges, so a portal appearing or clearing is visible in the
    /// daemon log and not only in `status`.
    fn set_captive_portal_detected(&mut self, detected: bool) {
        if self.captive_portal_detected == detected {
            return;
        }
        self.captive_portal_detected = detected;
        if detected {
            tracing::warn!(
                code = captive::WARNABLE_CODE,
                "captive portal detected: {}",
                captive::WARNABLE_TEXT
            );
        } else {
            tracing::info!(
                code = captive::WARNABLE_CODE,
                "captive-portal warning cleared"
            );
        }
    }

    /// Project the persisted [`Prefs`] into the read-only [`PrefsView`] surfaced by both `tnet status`
    /// and `tnet get`. One source of truth so the two commands can never disagree about the node's
    /// configured posture. Reads only `self.prefs` + the SSH task handle — no engine round-trip — so
    /// it is cheap and safe to call under the brief backend lock.
    pub fn prefs_view(&self) -> crate::localapi::PrefsView {
        crate::localapi::PrefsView {
            hostname: self.prefs.hostname.clone(),
            exit_node: self.prefs.exit_node.clone(),
            advertise_exit_node: self.prefs.advertise_exit_node,
            advertise_routes: self.prefs.advertise_routes.clone(),
            advertise_tags: self.prefs.advertise_tags.clone(),
            accept_routes: self.prefs.accept_routes,
            accept_dns: self.prefs.accept_dns,
            shields_up: self.prefs.shields_up,
            ssh: self.prefs.ssh_enabled,
            advertise_connector: self.prefs.advertise_app_connector,
            auto_update: self.prefs.auto_update_apply,
            update_check: self.prefs.auto_update_check,
            operator: self.prefs.operator_user.clone(),
            nickname: self.prefs.node_nickname.clone(),
            report_posture: self.prefs.posture_checking,
            webclient: self.prefs.run_web_client,
            exit_node_allow_lan_access: self.prefs.exit_node_allow_lan_access,
            // SSH *liveness*, distinct from the `ssh_enabled` pref above: the server task is spawned
            // in `finish_up` and can die at bind time (no tailnet IPv4, `listen_ssh` error). Report
            // it as running only when we hold a task handle that has not finished —
            // `JoinHandle::is_finished()` is stable and non-blocking, so this never stalls the brief
            // lock. A missing handle (`None`) — SSH off, node down, or a daemon built without the
            // `ssh` feature where no task is ever spawned — reads as not running. So
            // `ssh: true, ssh_running: false` honestly flags an SSH server that was requested but is
            // not actually accepting connections.
            ssh_running: self
                .ssh_task
                .as_ref()
                .map(|h| !h.is_finished())
                .unwrap_or(false),
            tun: self.prefs.tun_enabled,
        }
    }

    /// Report this node's own tailnet addresses (the `tnet ip` / Go `tailscale ip` path). A thin
    /// `pub` shim over [`diag::ip_report`], kept on `Backend` so the `server.rs` dispatch call site
    /// (`Backend::ip_report(&dev)`) is unchanged by the split. See [`diag::ip_report`] for the
    /// off-lock / best-effort rationale.
    pub async fn ip_report(dev: &tailscale::Device) -> crate::localapi::Response {
        diag::ip_report(dev).await
    }

    /// Snapshot client metrics in Prometheus text (the `tnet metrics` path). Thin `pub` shim over
    /// [`diag::metrics`] so the `server.rs` dispatch call site is uniform with the other diagnostics.
    pub fn metrics(dev: &tailscale::Device) -> crate::localapi::Response {
        diag::metrics(dev)
    }

    /// Build a LOCAL diagnostic marker (the `tnet bugreport` path), optionally with the
    /// `--diagnose` pass attached. Unlike Go's `bugreport`, which uploads logs to logtail and
    /// returns the server-side log id, this fork has no log-upload backend — the marker is a purely
    /// local identifier the operator can quote when reporting an issue. It carries a `BUG-` prefix,
    /// a coarse Unix-seconds stamp, a per-daemon sequence number, the daemon version, the active
    /// profile, and the `want_running` intent. Reads only `self` (no engine round-trip), so it works
    /// whether or not the node is up.
    ///
    /// The sequence number is what makes two markers taken in the same second **distinguishable**,
    /// which `bugreport --record` depends on: it brackets a reproduction with a before/after pair,
    /// and a pair that renders identically brackets nothing. (Go gets this from the random hex
    /// suffix in its own marker; this fork counts instead, so the marker stays deterministic.)
    ///
    /// `note` is the operator's optional free-text note (Go `bugreport [note]`); when present it is
    /// appended as `-note:<note>`. It is sanitized of control characters first — it is operator-/
    /// caller-supplied text and the marker is meant to be copy-pasted into an issue, so a stray
    /// newline/escape must not corrupt it.
    ///
    /// `probe` is `Some` exactly when the request set `--diagnose` (Go
    /// `ipn.BugReportOpts.Diagnose`): the caller gathers it **off** the backend lock — it makes
    /// syscalls and, when the node is up, one engine round-trip — and this method then renders the
    /// checks from it plus the local facts only `self` holds. See [`doctor`] for what the pass
    /// covers and why its output is returned rather than logged.
    pub fn bugreport(
        &self,
        note: Option<&str>,
        probe: Option<&doctor::Probe>,
    ) -> crate::localapi::Response {
        // SystemTime is the real std clock; a coarse seconds stamp makes the marker orderable
        // without adding a uuid dependency, and the counter below disambiguates within one second.
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let seq = MARKER_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut marker = format!(
            "BUG-{secs}-{seq}-v{}-profile:{}-want_running:{}",
            env!("CARGO_PKG_VERSION"),
            self.current_profile,
            self.prefs.want_running,
        );
        if let Some(n) = note {
            // Strip control chars (newlines/escapes) so the appended note keeps the marker a single
            // clean, copy-pasteable token. `sanitize_marker_note` maps any control char to '_'.
            marker.push_str(&format!("-note:{}", sanitize_marker_note(n)));
        }

        // `--diagnose`: the state-of-this-daemon half of the pass. Cheap and non-blocking — the
        // engine state is a `watch` borrow, everything else is already in memory — except the one
        // `faccessat` on the state dir, which is a single syscall on a path we already own.
        let checks = match probe {
            None => Vec::new(),
            Some(probe) => {
                let (state, _auth_url, error) = match self.device.as_ref() {
                    Some(dev) => state_from_device(dev.device_state()),
                    None => (self.derive_state(false), None, None),
                };
                doctor::checks(
                    &doctor::LocalFacts {
                        state: state.as_str(),
                        error: error.as_deref(),
                        want_running: self.prefs.want_running,
                        logged_out: self.prefs.logged_out,
                        node_up: self.device.is_some(),
                        profile: &self.current_profile,
                        have_node_key: self.has_node_key,
                        state_dir: &self.state_dir,
                        state_dir_writable: doctor::dir_writable(&self.state_dir),
                        prefs: &self.prefs,
                    },
                    probe,
                )
            }
        };

        crate::localapi::Response::BugReport { marker, checks }
    }

    /// Gather the out-of-backend half of the `--diagnose` pass (Go's `Doctor` checks that touch the
    /// OS or the engine). A thin `pub` shim over [`doctor::Probe::gather`], kept on `Backend` so the
    /// `server.rs` dispatch call site is uniform with the other off-lock diagnostics: the dispatch
    /// clones the engine handle under a brief lock, drops the lock, calls this, and only then takes
    /// the lock again to build the marker.
    pub async fn diagnose_probe(dev: Option<&tailscale::Device>) -> doctor::Probe {
        doctor::Probe::gather(dev).await
    }

    /// Report Tailnet Lock status (the `tnet lock status` path). Thin `pub` shim over
    /// [`diag::lock_status`]. See it for the `tka_status` → [`LockReport`](crate::localapi::LockReport)
    /// mapping.
    pub async fn lock_status(dev: &tailscale::Device) -> crate::localapi::Response {
        diag::lock_status(dev).await
    }

    /// Read the Tailnet Lock update-chain history (the `tnet lock log` path). Thin `pub` shim over
    /// [`diag::lock_log`]. See it for the `tka_log` → [`LockLogReport`](crate::localapi::LockLogReport)
    /// mapping (and why `tka_status` is queried alongside).
    pub async fn lock_log(dev: &tailscale::Device, limit: usize) -> crate::localapi::Response {
        diag::lock_log(dev, limit).await
    }

    /// Initialize Tailnet Lock (the `tnet lock init` path). Thin `pub` shim over [`diag::lock_init`]
    /// (hex-decodes the disablement secret and calls `Device::tka_init`).
    pub async fn lock_init(dev: &tailscale::Device, secret_hex: &str) -> crate::localapi::Response {
        diag::lock_init(dev, secret_hex).await
    }

    /// Co-sign a node key into Tailnet Lock (the `tnet lock sign` path). Thin `pub` shim over
    /// [`diag::lock_sign`] (parses the `nodekey:<hex>` and calls `Device::tka_sign`).
    pub async fn lock_sign(dev: &tailscale::Device, node_key: &str) -> crate::localapi::Response {
        diag::lock_sign(dev, node_key).await
    }

    /// Disable Tailnet Lock (the `tnet lock disable` path). Thin `pub` shim over
    /// [`diag::lock_disable`] (hex-decodes the secret and calls `Device::tka_disable`).
    pub async fn lock_disable(
        dev: &tailscale::Device,
        secret_hex: &str,
    ) -> crate::localapi::Response {
        diag::lock_disable(dev, secret_hex).await
    }

    /// Report the control-pushed MagicDNS configuration (the `tnet dns status` path). Thin `pub`
    /// shim over [`diag::dns_status`], kept on `Backend` so the `server.rs` dispatch call site
    /// (`Backend::dns_status(&dev)`) is uniform with the other off-lock diagnostics. See
    /// [`diag::dns_status`] for the `dns_config` → [`DnsStatusReport`](crate::localapi::DnsStatusReport)
    /// mapping.
    pub async fn dns_status(dev: &tailscale::Device) -> crate::localapi::Response {
        diag::dns_status(dev).await
    }

    /// Report the Tailscale Services (VIPs) this node can reach (the `tnet service list` path; Go
    /// `tailscale service list` over the `services` LocalAPI verb). Thin `pub` shim over
    /// [`diag::services`], kept on `Backend` so the `server.rs` dispatch call site
    /// (`Backend::services(&dev)`) is uniform with the other off-lock diagnostics. See
    /// [`diag::services`] for the self-node capability map →
    /// [`ServiceReport`](crate::localapi::ServiceReport) decode.
    pub async fn services(dev: &tailscale::Device) -> crate::localapi::Response {
        diag::services(dev).await
    }

    /// Report the effective system policy (the `tnet syspolicy list` path; Go
    /// `GetEffectivePolicy(DefaultScope())`). A **static** associated fn (not `&self`): policy
    /// resolution reads no backend/engine/netmap state — like Go's `rsop.PolicyFor`, it merges the
    /// registered policy stores, which is independent of node lifecycle — so it needs neither the
    /// backend lock nor the node to be up. Thin shim over [`syspolicy::effective_policy`]; kept on
    /// `Backend` so the `server.rs` dispatch reads uniformly with the other diagnostics. On this
    /// platform (no registered policy store) the snapshot is always empty — faithful to Go on Linux.
    pub fn syspolicy_list() -> crate::localapi::Response {
        crate::localapi::Response::Policy(Self::policy_snapshot())
    }

    /// The effective device-scope policy snapshot, as a bare report rather than a
    /// [`Response`](crate::localapi::Response).
    ///
    /// Exists so the notify feed and the one-shot `syspolicy list` read the *same* snapshot through
    /// the *same* renderer: [`syspolicy_list`](Self::syspolicy_list) wraps this, and the masked
    /// `Watch` path's policy frames call it directly. Go's `Notify.Policy` is likewise the very
    /// `setting.Snapshot` `GetEffectivePolicy` returns, not a second rendering of it. Keeping one
    /// producer is what makes any rule the report adopts — redacting a credential-bearing key, say —
    /// apply to the notify stream too, which matters more there: a notify stream is read by more
    /// processes than a CLI is.
    ///
    /// Static for the same reason [`syspolicy_list`](Self::syspolicy_list) is: policy resolution
    /// reads no backend/engine state and needs no lock.
    pub fn policy_snapshot() -> crate::localapi::PolicyReport {
        syspolicy::effective_policy()
    }

    /// Subscribe to policy-change ticks (a masked `Watch` with the `policy` bit) — the analogue of
    /// the `policyclient.RegisterChangeCallback` Go's `WatchNotifications` registers for the life of
    /// a session with `NotifySysPolicyChanges` set. The receiver re-reads
    /// [`policy_snapshot`](Self::policy_snapshot) on each tick.
    ///
    /// Static (no backend state, no lock): the policy registry is process-global, like Go's `rsop`
    /// store list. See `syspolicy::watch_policy` for exactly which events tick it in this build —
    /// notably, an edit to the policy file behind the daemon's back does **not**, because nothing
    /// re-reads the file until a `syspolicy reload`.
    pub fn watch_policy() -> tokio::sync::watch::Receiver<()> {
        syspolicy::watch_policy()
    }

    /// Force a re-read of the effective system policy (the `tnet syspolicy reload` path; Go
    /// `ReloadEffectivePolicy(DefaultScope())`). Static like [`syspolicy_list`](Self::syspolicy_list)
    /// (no backend state, no lock, node-up-independent). Thin shim over
    /// [`syspolicy::reload_effective_policy`]; observationally identical to `syspolicy_list` while no
    /// policy store is registered (the forced re-read re-merges zero sources). Never errors.
    ///
    /// It deliberately does **not** re-apply the policy to prefs, and stays `&self`-free and
    /// lock-free as a result. Two reasons, both structural rather than convenient: the only store
    /// this daemon registers is the JSON file, which Go captures at construction and never re-reads,
    /// so a reload cannot resolve anything the daemon has not already applied; and the reconcile runs
    /// on every prefs write ([`Backend::reconcile_sys_policy`]), so there is no drift for a reload to
    /// correct. Re-applying would turn a read-only verb — classified `PermitRead` in
    /// [`crate::auth`] precisely because reading policy has no side effects — into a prefs write, for
    /// no observable gain. A store that can genuinely change under the daemon would change that
    /// calculus and the auth classification with it (see the invariant on
    /// `syspolicy::registered_store_settings`).
    pub fn syspolicy_reload() -> crate::localapi::Response {
        crate::localapi::Response::Policy(syspolicy::reload_effective_policy())
    }

    /// Resolve `name`/`qtype` through the node's MagicDNS path (the `tnet dns query` path). Thin `pub`
    /// shim over [`diag::dns_query`], kept on `Backend` so the `server.rs` dispatch call site is
    /// uniform with the other off-lock diagnostics. See [`diag::dns_query`] for the
    /// `Device::query_dns` → [`DnsQueryReport`](crate::localapi::DnsQueryReport) mapping.
    pub async fn dns_query(
        dev: &tailscale::Device,
        name: &str,
        qtype: u16,
    ) -> crate::localapi::Response {
        diag::dns_query(dev, name, qtype).await
    }

    /// Report the node's network-conditions report (the `tnet netcheck` path). Thin `pub` shim over
    /// [`diag::netcheck`], kept on `Backend` so the `server.rs` dispatch call site
    /// (`Backend::netcheck(&dev)`) is uniform with the other off-lock diagnostics. See
    /// [`diag::netcheck`] for the `netcheck()` → [`NetcheckReport`](crate::localapi::NetcheckReport)
    /// mapping (and the honest DERP-latency-only scope note).
    pub async fn netcheck(dev: &tailscale::Device) -> crate::localapi::Response {
        diag::netcheck(dev).await
    }

    /// Suggest the best available exit node (the `tnet exit-node suggest` path). Thin `pub` shim over
    /// [`diag::suggest_exit_node`], uniform with the other off-lock diagnostics. See it for the
    /// `suggest_exit_node()` → [`Response::ExitNodeSuggestion`](crate::localapi::Response) mapping
    /// (`Ok(None)` = no eligible candidate, an honest empty result, not an error) and for the
    /// `AllowedSuggestedExitNodes` allow-list the engine's answer is filtered through.
    pub async fn suggest_exit_node(dev: &tailscale::Device) -> crate::localapi::Response {
        diag::suggest_exit_node(dev).await
    }

    /// Validate a prospective prefs change WITHOUT applying it (the `check-prefs` LocalAPI / Go
    /// `LocalBackend.CheckPrefs`). Returns `Ok(())` if the resulting posture is valid, else an error
    /// naming every violation (Go joins them; we do too). MUTATES NOTHING — it composes the named
    /// overrides over a *clone* of the current prefs and runs the same validation the bring-up path
    /// would, so a CLI can fail fast before an `up`/`set`.
    ///
    /// This fork mirrors the subset of Go's `checkPrefsLocked` rule chain that maps to its pref model:
    /// (1) the exit-node selector is concrete (no unsupported `auto:`) and, when the request names
    /// one, RESOLVES against the netmap (Go `exitNodeIPOfArg`: not this machine's own address, a
    /// peer that exists, a peer that actually advertises an exit node, an unambiguous name);
    /// (2) **exit-node-vs-advertise
    /// conflict** — cannot use an exit node and advertise as one simultaneously (Go
    /// `checkExitNodePrefsLocked`); (3) the advertised-route SET is one Go would send: every entry a
    /// masked CIDR, every 4via6 prefix decodable, and a default route present in both families or in
    /// neither (Go `netutil.CalcAdvertiseRoutes`, via [`crate::routes`]); (4) SSH-server enable requires the `ssh` build feature (the local
    /// analogue of Go's capability gate — a faithful, build-time check) **and** must clear the
    /// host/operator gate Go's `checkSSHPrefsLocked` applies,
    /// [`featureknob::can_run_tailscale_ssh`](crate::featureknob::can_run_tailscale_ssh) — chiefly
    /// its `TS_DISABLE_SSH_SERVER` administrative off-switch, which is how an image build or a
    /// configuration-managed host holds the SSH server down whatever the tailnet or the user asks
    /// for; (5) an auto-update **opt-in** requires an installation that can replace its own binary
    /// (Go `checkAutoUpdatePrefsLocked` → `feature.CanAutoUpdate()`, decided here by
    /// [`selfupdate::auto_update_refusal`]). Go's operator/profile-name/config-lock/Funnel-shields
    /// rules reference prefs this fork does not model, so they are correctly N/A.
    pub async fn check_prefs(
        &self,
        exit_node: Option<Option<String>>,
        advertise_exit_node: Option<bool>,
        advertise_routes: Option<Vec<String>>,
        ssh: Option<bool>,
        auto_update: Option<bool>,
    ) -> Result<()> {
        // Only pay for the netmap snapshot when the request actually NAMES a selector — that is the
        // only input rule (1b) reads, and `status` on a Running node is an engine round-trip taken
        // under the backend lock.
        let facts = match exit_node.as_ref() {
            Some(Some(_)) => self.exit_node_facts().await,
            _ => ExitNodeFacts::default(),
        };
        self.check_prefs_gated(
            exit_node,
            advertise_exit_node,
            advertise_routes,
            ssh,
            auto_update,
            CheckPrefsEnv {
                ssh_gate: crate::featureknob::can_run_tailscale_ssh(),
                exit_node_facts: &facts,
            },
        )
    }

    /// One [`status`](Backend::status) snapshot, projected into the facts an exit-node selector is
    /// resolved against. The single place the daemon reads the netmap for this purpose, so `up`,
    /// `set` and `check-prefs` all resolve against the same view `tnet status` reports.
    async fn exit_node_facts(&self) -> ExitNodeFacts {
        ExitNodeFacts::from_status(self.status().await)
    }

    /// Full validation of an operator-supplied `--exit-node` VALUE, before any pref is mutated: the
    /// `auto:` form this build cannot honour ([`validate_exit_node_selector`]), then Go's
    /// `exitNodeIPOfArg` resolution against the live netmap ([`resolve_exit_node_arg`]).
    ///
    /// Go runs the resolution in the CLI, because that is where the status round-trip is. It runs
    /// here instead so `up`, `set` and `check-prefs` share ONE implementation reading ONE netmap
    /// view — the daemon already holds the netmap, and a CLI-side copy would be a second rule to
    /// keep in step with the first. The cost is one bounded `status` query per named selector.
    async fn check_exit_node_arg(&self, sel: &str) -> Result<()> {
        validate_exit_node_selector(Some(sel))?;
        resolve_exit_node_arg(sel, &self.exit_node_facts().await)
    }

    /// [`check_prefs`](Self::check_prefs) with the host-derived inputs passed IN rather than read
    /// from the process environment or the engine — see [`CheckPrefsEnv`] for why they are injected.
    /// `auto_update` stays a plain override (rule (5) reads the host's update provenance through
    /// [`selfupdate::auto_update_refusal`], which needs no injection to be testable — its own pure
    /// predicate takes the facts as arguments).
    fn check_prefs_gated(
        &self,
        exit_node: Option<Option<String>>,
        advertise_exit_node: Option<bool>,
        advertise_routes: Option<Vec<String>>,
        ssh: Option<bool>,
        auto_update: Option<bool>,
        env: CheckPrefsEnv<'_>,
    ) -> Result<()> {
        // Compose the prospective posture: the named override wins, else the current pref.
        let prospective_exit_node = match &exit_node {
            Some(v) => v.clone(),
            None => self.prefs.exit_node.clone(),
        };
        let prospective_advertise_exit =
            advertise_exit_node.unwrap_or(self.prefs.advertise_exit_node);
        let prospective_routes = advertise_routes
            .clone()
            .unwrap_or_else(|| self.prefs.advertise_routes.clone());
        let prospective_ssh = ssh.unwrap_or(self.prefs.ssh_enabled);
        let prospective_auto_update = match auto_update {
            Some(v) => Some(v),
            None => self.prefs.auto_update_apply,
        };

        let mut errors: Vec<String> = Vec::new();

        // (1) exit-node selector must be concrete (reuse the bring-up validator's rule), and
        // (1b) a selector the request NAMES must additionally RESOLVE against the netmap, exactly as
        // the real `up`/`set` paths now resolve it (Go `exitNodeIPOfArg`) — a dry run that cannot
        // report the refusal the real command is about to give is not a dry run. Only the named
        // value is resolved: an already-persisted selector is not re-litigated by a `check-prefs`
        // about some unrelated pref, and `check_prefs` is a question about the change being
        // proposed. (1b) runs only when (1) passed, so an `auto:` value reports once, as itself,
        // rather than also as an unresolvable name.
        match validate_exit_node_selector(prospective_exit_node.as_deref()) {
            Err(e) => errors.push(e.to_string()),
            Ok(()) => {
                if let Some(Some(sel)) = exit_node.as_ref()
                    && let Err(e) = resolve_exit_node_arg(sel, env.exit_node_facts)
                {
                    errors.push(e.to_string());
                }
            }
        }
        // (2) exit-node-vs-advertise conflict (Go: "Cannot advertise an exit node and use an exit
        // node at the same time."). A `Some(sel)` exit node means "use one".
        if prospective_exit_node.is_some() && prospective_advertise_exit {
            errors.push(
                "Cannot advertise an exit node and use an exit node at the same time.".into(),
            );
        }
        // (3) the advertised-route SET (Go `netutil.CalcAdvertiseRoutes`): every entry is a parseable,
        // MASKED CIDR, every 4via6 prefix actually decodes, and a default route is advertised in BOTH
        // families or in neither. Asked of the set the two inputs COMPOSE — `prospective_advertise_exit`
        // contributes the two default routes, exactly as Go's `advertiseDefaultRoute` argument does —
        // because the set is what this node will offer control, and a lone default route there is a
        // half exit node whichever input produced it. See [`crate::routes`] for each rule.
        if let Err(errs) =
            crate::routes::calc_advertise_routes(&prospective_routes, prospective_advertise_exit)
        {
            errors.extend(errs.iter().map(ToString::to_string));
        }
        // (4) SSH-server enable requires the `ssh` build feature (local analogue of Go's
        // capability gate — a faithful build-time check; the netmap-capability check is engine-gated)
        // AND must clear the host/operator gate (Go `checkSSHPrefsLocked` → `CanRunTailscaleSSH`).
        // Both are reported when both fail: this call exists to tell the caller everything that is
        // wrong with the posture in one answer, and "rebuild with the feature" alone would send an
        // operator off to rebuild a daemon that the administrative knob would still refuse.
        if prospective_ssh {
            if cfg!(not(feature = "ssh")) {
                errors.push(
                    "Unable to enable Tailscale SSH server: this build was compiled without the \
                     `ssh` feature."
                        .into(),
                );
            }
            if let Err(e) = env.ssh_gate {
                errors.push(e.to_string());
            }
        }

        // (5) an auto-update opt-in on an installation that can never apply one (Go
        // `checkAutoUpdatePrefsLocked`). `AutoUpdate.Apply` is advertised to control as
        // `Hostinfo.AllowsUpdate`, so accepting it here would let the node tell the tailnet admin
        // that a remote update trigger will be honoured when nothing could honour it.
        if let Some(e) = selfupdate::check_auto_update_pref(
            prospective_auto_update,
            selfupdate::auto_update_refusal().as_deref(),
        ) {
            errors.push(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(errors.join("\n")))
        }
    }

    /// Force the engine to rebind its UDP sockets (the `tnet debug rebind` path). Thin `pub` shim over
    /// [`diag::rebind`], kept on `Backend` so the `server.rs` dispatch call site is uniform with the
    /// other off-lock device operations. A **write** (mutates live datapath state).
    pub async fn rebind(dev: &tailscale::Device) -> crate::localapi::Response {
        diag::rebind(dev).await
    }

    /// Force an immediate STUN re-probe without rebinding the socket (the `tnet debug restun` path).
    /// Thin `pub` shim over [`diag::re_stun`], uniform with [`Backend::rebind`]. A **write** (mutates
    /// live datapath endpoint state) — strictly lighter than `rebind` (no socket churn).
    pub async fn re_stun(dev: &tailscale::Device) -> crate::localapi::Response {
        diag::re_stun(dev).await
    }

    /// Provision a TLS cert+key for `domain` via the tailnet ACME flow (the `tnet cert` path). Thin
    /// `pub` shim over [`diag::cert_pair`], kept on `Backend` so the `server.rs` dispatch call site is
    /// uniform with the other off-lock device operations. Fail-closed: a non-`acme` build, or any ACME
    /// failure, returns a clear [`Response::Error`] — never a self-signed cert. `min_validity` is the
    /// caller's `--min-validity` (Go's flag), passed through to the engine. See [`diag::cert_pair`].
    pub async fn cert_pair(
        dev: &tailscale::Device,
        domain: &str,
        min_validity: Option<std::time::Duration>,
    ) -> crate::localapi::Response {
        diag::cert_pair(dev, domain, min_validity).await
    }

    /// Load the current profile's serve config (the `tnet serve status` / GetServeConfig path).
    /// Missing/malformed → empty (no serve). Reads only the profile's serve-config file.
    pub async fn serve_config(&self) -> serve::ServeConfig {
        serve::load(&self.state_dir, &self.current_profile).await
    }

    /// Persist a new serve config for the current profile (the SetServeConfig path), then re-arm the
    /// serve runtime to match if the node is up. `&mut self` because re-arming mutates the task list.
    /// If the node is down, persisting is the whole job — the config applies on the next `up` (via
    /// `finish_up`). The re-arm tears down the old supervisor + spawns a fresh one from the new config
    /// ([`spawn_serve`](Backend::spawn_serve)), so across BOTH lanes a removed entry stops serving and
    /// an added one starts: plain TCP-forward accept loops are torn down + respawned, and the engine
    /// web serve is full-replaced (an emptied web config is cleared) — all without disturbing the
    /// device.
    ///
    /// **Refuses** (before persisting, leaving the live serve untouched), in Go's order:
    ///
    /// 1. an incoming config that turns Funnel on while `shields_up` is set — Go
    ///    `setServeConfigLocked`'s first statement (`config.IsFunnelOn() && prefs.ShieldsUp()`);
    /// 2. an incoming config that would change the serve type of a port the current config already
    ///    serves — Go `validateServeConfigUpdate`; see [`serve::validate_serve_config_update`].
    pub async fn set_serve_config(&mut self, cfg: &serve::ServeConfig) -> Result<()> {
        // Funnel publishes a port to the PUBLIC internet; shields-up blocks every inbound connection
        // (it is `Config.block_incoming`). A node with both accepts nothing on the endpoint it just
        // advertised, and neither `tnet serve status` nor `tnet status` shows the contradiction — so
        // the only honest answer is a refusal at the moment the pair would be created. Go refuses it
        // as the FIRST statement of `setServeConfigLocked`, ahead of its own serve-type validation,
        // and this guard keeps that order: under shields-up, a funnel-enabled config is refused for
        // being funnel-enabled, whatever else is also wrong with it. The message is Go's verbatim —
        // it reaches the operator as the `SetServeConfig` error body.
        //
        // `serve::funnel_ports` is the analogue of Go's `ServeConfig.IsFunnelOn` (the ports with a
        // `true` AllowFunnel entry), so this fires for EVERY road into the daemon's single setter:
        // the `set-serve-config` LocalAPI verb, `tnet funnel <port> on`, the `funnel --https=…` flag
        // grammar, and the foreground serve path restoring a previous config on exit — a restore
        // that would re-arm Funnel under shields-up fails exactly like a fresh `funnel` would.
        if !serve::funnel_ports(cfg).is_empty() && self.prefs.shields_up {
            anyhow::bail!("Unable to turn on Funnel while shields-up is enabled");
        }
        // Refuse a change that would silently destroy a live serve BEFORE anything is written: an
        // incoming config may not change the serve type of a port the current config already serves
        // (Go `validateServeConfigUpdate`). Every CLI write is a read-modify-write of the current
        // config and SetServeConfig replaces it wholesale, so `serve --tcp 443` aimed at a port
        // already terminating HTTPS used to be a plain map insert: success reported, previous serve
        // gone, operator told nothing. The existing config is the one on disk for this profile —
        // exactly what the CLI fetched and mutated. See `serve::validate_serve_config_update` for
        // the rule and for which of Go's neighbouring rules have no state here yet.
        let existing = self.serve_config().await;
        if let Err(conflict) = serve::validate_serve_config_update(&existing, cfg) {
            anyhow::bail!(conflict);
        }
        // Heads-up if a funnel-enabled port forwards to a NON-loopback backend: funnel publishes to
        // the PUBLIC internet, so a non-loopback target means inbound internet traffic is spliced to
        // something other than this host's loopback (another LAN host, a metadata endpoint, a public
        // IP). This is allowed (the operator asked for it; the security boundary is SetServeConfig's
        // write authorization), so it is a WARN, not a refusal — exposing an internal service to the
        // internet should not be silent. (tsd-6nk)
        for (port, backend) in serve::funnel_nonloopback_backends(cfg) {
            tracing::warn!(
                port,
                backend = %backend,
                "funnel: port {port} is published to the PUBLIC internet and forwards to a \
                 non-loopback backend {backend} — inbound internet traffic will reach it"
            );
        }
        serve::save(cfg, &self.state_dir, &self.current_profile)
            .await
            .with_context(|| "persisting serve-config")?;
        // Re-arm live if a device is up; otherwise the config applies on the next `up`.
        if let Some(dev) = self.device.clone() {
            self.stop_serve_tasks().await;
            self.spawn_serve(dev);
        }
        Ok(())
    }

    /// Resolve a tailnet IP to the peer that owns it (the `tnet whois` / Go `tailscale whois` path).
    /// A thin `pub` shim over [`diag::whois`], kept on `Backend` so the `server.rs` dispatch call
    /// site (`Backend::whois(&dev, ..)`) is unchanged. See [`diag::whois`] for the full mapping.
    pub async fn whois(
        dev: &tailscale::Device,
        ip: &str,
        port: Option<u16>,
        proto: Option<crate::localapi::WhoisProto>,
    ) -> crate::localapi::Response {
        diag::whois(dev, ip, port, proto).await
    }

    /// Fetch an OIDC id-token for this node scoped to `audience` (the `tnet id-token` / Go
    /// `tailscale id-token` path). A thin `pub` shim over the engine's
    /// [`Device::fetch_id_token`](tailscale::Device::fetch_id_token), which mints a signed JWT via
    /// control over the live Noise connection. Kept on `Backend` so the `server.rs` dispatch call
    /// site is uniform with the other off-lock device calls (`Backend::whois`/`ping`). Any issuance
    /// failure surfaces as [`Response::Error`](crate::localapi::Response::Error), never a panic. NOTE:
    /// the engine maps every non-2xx control response (including a too-old control server that can't
    /// issue id-tokens) to one coarse "unsuccessful HTTP request" error, so the message identifies
    /// *that the request failed*, not always *why* — distinguishing a 403/cap-too-old from a transient
    /// 5xx would need a finer-grained engine error (a candidate engine ask).
    pub async fn id_token(dev: &tailscale::Device, audience: &str) -> crate::localapi::Response {
        match dev.fetch_id_token(audience).await {
            Ok(token) => crate::localapi::Response::IdToken { token },
            Err(e) => crate::localapi::Response::Error {
                message: format!("id-token request failed: {e}"),
            },
        }
    }

    /// Ping a tailnet peer over the overlay and report the round-trip time (the `tnet ping` / Go
    /// `tailscale ping` path). A thin `pub` shim over [`diag::ping`], kept on `Backend` so the
    /// `server.rs` dispatch call site (`Backend::ping(&dev, ..)`) is unchanged. See [`diag::ping`].
    pub async fn ping(
        dev: &tailscale::Device,
        ip: &str,
        timeout_ms: Option<u64>,
    ) -> crate::localapi::Response {
        diag::ping(dev, ip, timeout_ms).await
    }

    /// Capture the dataplane to a pcap file for `seconds` (the `tnet debug capture` / Go `tailscale
    /// debug capture` path). A thin `pub` shim over [`diag::debug_capture`], kept on `Backend` so the
    /// `server.rs` dispatch call site (`Backend::debug_capture(&dev, ..)`) matches the other
    /// off-lock diagnostics. See [`diag::debug_capture`] for the path-hardening + flush-on-stop logic.
    pub async fn debug_capture(
        dev: &tailscale::Device,
        path: &str,
        seconds: u64,
    ) -> crate::localapi::Response {
        diag::debug_capture(dev, path, seconds).await
    }

    /// Send a local file to a tailnet peer via Taildrop (the `tnet file cp` / Go `tailscale file cp`
    /// path). A thin `pub` shim over [`diag::file_cp`], kept on `Backend` so the `server.rs`
    /// dispatch call site (`Backend::file_cp(&dev, ..)`) is unchanged. See [`diag::file_cp`] for the
    /// off-lock transfer + same-host-open + path-hardening rationale.
    pub async fn file_cp(
        dev: &tailscale::Device,
        path: &str,
        peer: &str,
        name: Option<&str>,
    ) -> crate::localapi::Response {
        diag::file_cp(dev, path, peer, name).await
    }

    /// List the Taildrop files waiting in this node's receive directory (the `tnet file list` / Go
    /// `tailscale file get` no-arg path). A thin `pub` shim over [`diag::file_list`], kept on
    /// `Backend` so the `server.rs` dispatch call site (`Backend::file_list(&dev)`) is unchanged.
    pub fn file_list(dev: &tailscale::Device) -> crate::localapi::Response {
        diag::file_list(dev)
    }

    /// List the tailnet peers this node can Taildrop *to* (the `tnet file cp --targets` / Go
    /// `tailscale file cp --targets` path). A thin `pub` shim over [`diag::file_targets`], kept on
    /// `Backend` so the `server.rs` dispatch call site matches the other off-lock diagnostics.
    pub async fn file_targets(dev: &tailscale::Device) -> crate::localapi::Response {
        diag::file_targets(dev).await
    }

    /// Fetch a waiting Taildrop file by name, writing it to `dest` (the `tnet file get <name>` / Go
    /// `tailscale file get <name>` path). A thin `pub` shim over [`diag::file_get`], kept on
    /// `Backend` so the `server.rs` dispatch call site (`Backend::file_get(&dev, ..)`) is unchanged.
    /// See [`diag::file_get`] for the off-lock copy + dest-hardening + delete-after rationale.
    pub async fn file_get(
        dev: &tailscale::Device,
        name: &str,
        dest: &str,
        delete_after: bool,
    ) -> crate::localapi::Response {
        diag::file_get(dev, name, dest, delete_after).await
    }

    /// Drain the whole Taildrop inbox into a directory under a conflict policy (the `tnet file get
    /// <dir>` / Go `tailscale file get <target-directory>` path). A thin `pub` shim over
    /// [`diag::file_get_dir`], kept on `Backend` so the `server.rs` dispatch call site matches the
    /// other off-lock Taildrop methods. See [`diag::file_get_dir`] for the drain loop + conflict
    /// policy + quarantine + delete-after rationale.
    pub async fn file_get_dir(
        dev: &tailscale::Device,
        dir: &str,
        conflict: crate::localapi::ConflictPolicy,
    ) -> crate::localapi::Response {
        diag::file_get_dir(dev, dir, conflict).await
    }

    /// Derive the reported state from device presence, netmap arrival, and prefs.
    ///
    /// The decision is delegated to the pure [`derive_state_from`] helper so it can be unit-tested
    /// without a live `Backend`/engine (see the test module).
    ///
    // LIMITATION (tsd-dcf): this never returns [`State::NeedsMachineAuth`]. That state means
    // "registered, but a tailnet admin has not yet approved this machine" — and the engine's
    // `Status`/`StatusNode` carry no "machine authorized" / "needs approval" signal to derive it
    // from (the engine's `ts_runtime::status` docs themselves note several wire fields the domain
    // node model drops; node *online*/user/cap are likewise always absent). Worse, the engine's
    // control runner handles `MachineNotAuthorized` by silently retrying every 5s inside a
    // fire-and-forget actor (see `ts_runtime::control_runner`, with its own `TODO(tsr-kqj)`), so a
    // machine awaiting approval simply presents as `Starting` here (device up, no self-node yet) —
    // indistinguishable from a node that is merely still converging. Rather than fabricate the
    // distinction, we surface `Starting` honestly. `NeedsMachineAuth` would become reachable only if
    // [`Backend::up`] is reworked to call the engine's typed registration error and branch on it
    // (if/when the engine grows one, per its `tsr-kqj` TODO); today `up` maps every engine error to a
    // string `Response::Error`, so no code path produces `NeedsMachineAuth` — nor
    // [`State::InUseOtherUser`], unreachable in this single-user, auth-key-only daemon. Both exist
    // purely for `ipn.State` parity.
    fn derive_state(&self, have_self_node: bool) -> State {
        derive_state_from(
            self.device.is_some(),
            have_self_node,
            self.prefs.want_running,
            self.prefs.logged_out,
            // Go gates `Stopped` on `hasNodeKeyLocked()` (a persisted key), not on "ever configured".
            // `has_node_key` is the cached on-disk-key signal (see the field doc); using it makes a
            // configured-but-never-upped node report `NoState` like Go, not `Stopped`.
            self.has_node_key,
        )
    }

    /// Gracefully shut down the engine on daemon exit.
    ///
    // NOTE (tsd-tcq): the teardown order here is already correct and is *not* the source of the
    // netstack's "possible socket leak: the remote end of the channel has closed" warning seen on
    // SIGTERM. `shutdown` → [`stop_device`] takes the `Device` out of the `Backend` and fully
    // `await`s [`tailscale::Device::shutdown`] (which *consumes* the device and awaits the engine's
    // graceful shutdown) before returning, and the daemon awaits this before the process exits. The
    // `Backend` holds no clone or handle to the device that could outlive it — `device:
    // Option<tailscale::Device>` is the sole owner, and `Device::shutdown(self, …)` moves it. The
    // warning originates *inside* the engine's own netstack shutdown sequence (a command-channel
    // receiver dropped slightly before its last sender during the engine's internal teardown) and
    // is not daemon-controllable from this crate. Deliberately no cargo-cult `sleep` is added to
    // paper over it: the shutdown is already awaited to completion, and a sleep would only slow exit
    // without changing the engine-internal ordering.
    pub async fn shutdown(&mut self) {
        self.stop_device().await;
    }

    /// Tear down the live engine (and its SSH server task, if any), gracefully and bounded.
    ///
    /// ## Order matters (abort SSH, *then* reclaim the device)
    ///
    /// The SSH server task holds an [`Arc`](std::sync::Arc) clone of the device, so the backend is
    /// NOT the sole owner while it runs. We therefore tear down in two steps:
    ///
    /// 1. **Abort the SSH task and `await` the aborted handle.** `abort()` requests cancellation;
    ///    awaiting the handle blocks until the task has actually stopped (it resolves to a
    ///    `JoinError` reporting the cancel, which we ignore). This `await` is the load-bearing
    ///    guarantee: once it returns, the task — and thus its `Arc` clone of the device — is gone.
    /// 2. **Reclaim the sole `Device` from the `Arc`** via [`Arc::into_inner`](std::sync::Arc::into_inner)
    ///    and call the consuming `Device::shutdown` (bounded by [`SHUTDOWN_TIMEOUT`] so a wedged
    ///    engine can't hang the daemon). The abort+await in step 1 makes `into_inner` return `Some`
    ///    in the normal path; if it somehow returns `None` (a clone unexpectedly outlived the abort),
    ///    we log and drop — the engine's `Runtime::drop` still kills its actors — rather than leak.
    ///    With the `ssh` feature off there is never a clone, so reclaim is trivially infallible.
    async fn stop_device(&mut self) {
        // Bounded teardown: the engine shutdown below is capped at SHUTDOWN_TIMEOUT (5s), so a caller
        // holding the backend lock across this (e.g. the Down/Logout dispatch arms) blocks at most that.
        // Step 1: stop the SSH server task first so its `Arc` clone of the device is released before
        // we try to reclaim sole ownership. Aborting an already-finished task is harmless.
        if let Some(task) = self.ssh_task.take() {
            task.abort();
            // Await the aborted handle so the task (and its `Arc` clone) is truly gone before we
            // reclaim the device. The result is the expected cancellation `JoinError` — ignore it.
            let _ = task.await;
        }
        // Step 1b: likewise stop the link-change monitor — it holds a device `Arc` clone too, so it
        // must be gone before `into_inner` can reclaim the sole `Device`.
        if let Some(task) = self.monitor_task.take() {
            task.abort();
            let _ = task.await;
        }
        // Step 1c: likewise stop every `serve` accept-loop task — they also hold device `Arc` clones,
        // so they must be gone before `into_inner` can reclaim the sole `Device`.
        self.stop_serve_tasks().await;
        // Step 2: reclaim and gracefully shut down the engine. After the abort+await above, the
        // backend holds the only `Arc`, so `into_inner` yields the owned `Device` for `shutdown`.
        if let Some(dev) = self.device.take() {
            match std::sync::Arc::into_inner(dev) {
                Some(owned) => {
                    // `shutdown` consumes the device; bounded so a wedged engine can't hang the daemon.
                    let _ = owned.shutdown(Some(SHUTDOWN_TIMEOUT)).await;
                    // Known lifecycle transition: a live device was just torn down (the node left
                    // Running/Starting). Logged only when a device was actually present, so a no-op
                    // teardown (already-down node) stays quiet.
                    tracing::info!("engine stopped, device torn down");
                }
                None => {
                    // Should not happen after the SSH task was aborted and awaited above (the backend
                    // is then the sole owner). Drop the last clone rather than leak — the engine's
                    // `Runtime::drop` tears down its actors — but flag the unexpected sharing.
                    tracing::warn!(
                        "device Arc still shared at stop_device after aborting the SSH task; \
                         dropping (engine Runtime::drop will tear down its actors)"
                    );
                }
            }
        }
    }

    async fn persist_prefs(&self) -> Result<()> {
        self.prefs
            .save(&self.prefs_path)
            .await
            .with_context(|| format!("saving prefs to {}", self.prefs_path.display()))?;
        // Wake any prefs watchers (a masked `Watch` with the `prefs` bit) — this is the single
        // chokepoint every prefs mutation funnels through, so one tick here covers up/set/logout/
        // switch/reload-config. A failed send (no subscribers) is fine — `watch::Sender::send` errors
        // only when there are zero receivers, which is the common case (no one is watching prefs).
        let _ = self.prefs_tx.send(());
        Ok(())
    }

    /// Subscribe to prefs-change ticks (a masked `Watch` with the `prefs` bit). The receiver re-reads
    /// [`prefs_view`](Backend::prefs_view) on each tick. `subscribe()` starts synced (no spurious
    /// initial tick), so a watcher emits its first prefs frame from its own initial snapshot, not from
    /// this channel.
    pub fn watch_prefs(&self) -> tokio::sync::watch::Receiver<()> {
        self.prefs_tx.subscribe()
    }

    /// Apply `tailnetd --tun` to the loaded prefs, persisting only if it actually changed something.
    /// Returns whether it did, so the caller can say so in the boot log.
    ///
    /// Go carries the tunnel interface as a launch argument and hands it straight to
    /// `wgengine.Config`; this fork carries it as a pref ([`Prefs::tun_enabled`] / [`Prefs::tun_name`],
    /// set by `tnet up --tun`/`--tun-name`), so the flag has to land somewhere, and the pref is the
    /// only place that reaches the engine. Mapping it here — rather than into a second, flag-only
    /// override — keeps ONE answer to "what data path is this node using": `tnet status`, the boot
    /// posture line, the exit-node leak warning and `check-ip-forwarding` all read the same pref, and
    /// a later `tnet up --tun` changes the node the way it always did instead of being silently
    /// outranked by an invisible launch value.
    ///
    /// Persisting matches how [`apply_config`](Backend::apply_config) treats `--config`: the flag is
    /// part of the node's configured intent, so it survives a restart. Two deliberate narrowings:
    ///
    /// * **Nothing is written when nothing changed.** The overwhelmingly common case is a unit file
    ///   passing `--tun=userspace-networking` to a daemon already on the netstack; that must not
    ///   create a `prefs.json` for a node that was never configured, because the file's existence is
    ///   itself state (the daemon derives `ever_configured` from it).
    /// * **`ever_configured` is not set** even when it does write. Choosing a data path on the
    ///   command line is not the deliberate "this node is configured" act that `up` or `--config` is.
    ///
    /// A resolved netstack transport leaves `tun_name`/`tun_mtu` alone — both are documented as ignored
    /// while TUN is off, so clearing them would throw away a name the operator set for the next time
    /// they enable it.
    pub async fn apply_tun_flag(
        &mut self,
        transport: &crate::tunflag::TunTransport,
    ) -> Result<bool> {
        let (tun_enabled, tun_name) = match transport {
            crate::tunflag::TunTransport::Netstack => (false, self.prefs.tun_name.clone()),
            // `None` (Go's bare `utun` on darwin) means "let the platform default choose", which is
            // exactly what a `None` `tun_name` already means to `build_config`.
            crate::tunflag::TunTransport::Tun { name } => (true, name.clone()),
        };
        if self.prefs.tun_enabled == tun_enabled && self.prefs.tun_name == tun_name {
            return Ok(false);
        }
        self.prefs.tun_enabled = tun_enabled;
        self.prefs.tun_name = tun_name;
        self.persist_prefs().await?;
        Ok(true)
    }

    /// Apply a declarative `--config` document over the loaded prefs and persist the result, returning
    /// the registration auth key the config supplied (if any) for the caller to feed into bring-up.
    ///
    /// The merge is layered (a field unset in the config leaves the corresponding pref untouched —
    /// see [`crate::conffile::Config::apply_to_prefs`]), so the config refines the persisted prefs
    /// rather than wholesale-replacing them. Persisting here means the merged intent survives a
    /// restart even if the daemon is later launched without `--config` (matching Go, where a config
    /// applied at boot becomes the node's prefs). Marks `ever_configured` so the node is treated as
    /// explicitly configured (a `--config` boot is a deliberate configuration, like `up`). The auth
    /// key is returned, never persisted into prefs — it is a credential, not intent.
    pub async fn apply_config(
        &mut self,
        config: &crate::conffile::Config,
    ) -> Result<Option<secrecy::SecretString>> {
        let authkey = config.apply_to_prefs(&mut self.prefs)?;
        self.ever_configured = true;
        // System policy is applied AFTER the config merge, so a declarative config cannot outrank an
        // administrator's policy either. This is also the answer to the config's `Locked` field,
        // which this fork parses and warns about but does not honour (see `conffile`): `Locked` asks
        // for the config to be immune to out-of-band `tnet set`, which is a weaker claim than the one
        // policy already makes — and if it is ever honoured it must be honoured BELOW policy, not
        // above it.
        self.reconcile_sys_policy("config apply");
        self.persist_prefs().await?;
        Ok(authkey)
    }

    /// Re-read the `--config` file the daemon was started with and re-adopt its fields into the running
    /// backend — the Rust analogue of Go `tailscaled`'s `reload-config` LocalAPI route
    /// (`ipn/localapi.go` `serveReloadConfig` → `LocalBackend.ReloadConfig` → `setConfigLocked`,
    /// v1.100.0). Used when an operator edits the declarative config and wants the changes adopted
    /// without restarting the daemon.
    ///
    /// Returns `Ok(Some(action))` with the [`ReloadAction`] the caller — [`drive_reload_config`] — must
    /// run to reconcile the live engine with the now-updated prefs, and `Ok(None)` when the daemon is
    /// **not in config mode** (no `--config` source in use). That `Option` is Go's `(ok bool, err
    /// error)` shape: `LocalBackend.ReloadConfig` returns `(false, nil)` — a refusal, not an error —
    /// when `b.conf == nil`, and the CLI turns that into its own "config mode not in use" line. The
    /// `Some` half mirrors the `begin_set` → [`SetAction`] split: a brief lock applies + persists +
    /// decides, and the off-lock rebuild (if any) is the caller's job so the multi-second `Device::new`
    /// never runs under the backend lock.
    ///
    /// ## Faithful behavior
    ///
    /// - **No `--config` in use** → `Ok(None)`, never an `Err`. Go's `ReloadConfig` returns
    ///   `(false, nil)` here, and only its CLI decides what that means to an operator (a printed line
    ///   plus exit 1). Reporting it as a daemon error would put the refusal on the wrong layer and
    ///   give it the wrong wording.
    /// - **Malformed / unsupported-version file** → fails HARD (the error is propagated, NOTHING is
    ///   mutated or persisted). This is the same fail-fast contract as boot ([`conffile::load`] +
    ///   `apply_to_prefs`, which validates every field BEFORE touching `prefs`), so a bad reload can
    ///   never half-corrupt the running node — it is rejected with the live prefs and device intact.
    /// - **The merge is layered** (a field unset in the config leaves the corresponding pref untouched),
    ///   identical to the boot-time `--config` apply — so reload refines the prefs, never wholesale-
    ///   resets them.
    ///
    /// ## The auth key from a reloaded config
    ///
    /// A reloaded config's `AuthKey` is deliberately **dropped** here (logged, never used): a
    /// `reload-config` is a re-configuration, not a re-authentication. If the node is up, the rebuild
    /// resumes from the persisted node key (no re-register); if it is down, the merged prefs apply on
    /// the next `up`, which already resolves auth from the config/`TS_AUTH_KEY` at that point. Adopting a
    /// changed authkey on a live node would force a surprise re-registration — strictly more than a
    /// "reload my settings" verb should do, so we do not. (This is the one deliberate narrowing vs. Go's
    /// boot path, where the key is consumed at first bring-up; flagged in the type docs.)
    pub async fn reload_config(&mut self) -> Result<Option<ReloadAction>> {
        let source = match &self.config_source {
            Some(s) => s.clone(),
            // Not in config mode — the daemon was started without `--config` (or with an `optional:`
            // source that was not found). Go's `ReloadConfig` returns `(false, nil)` here: there is
            // nothing to reload, but nothing FAILED either. The refusal is logged once, by the
            // LocalAPI server's `Ok(None)` arm, beside the log of the reconcile that the other arm
            // ran; the CLI owns the user-facing wording and the exit code.
            None => return Ok(None),
        };
        // Re-read + re-parse + version-gate the file, with context on failure (a malformed or
        // unsupported-version file is rejected here, before any mutation — the same fail-hard contract
        // as boot). `apply_config` then validates every field BEFORE mutating prefs (all-or-nothing),
        // so a bad reload leaves the running node's prefs untouched.
        let config = crate::conffile::load(&source)
            .with_context(|| format!("reloading --config {source}"))?;
        tracing::info!(source = %source, version = %config.version, "reloading --config");
        // Merge + persist (and capture, only to drop) the config's auth key — a reload is not a
        // re-auth (see the doc comment). `apply_config` already persists the merged prefs.
        let authkey = self.apply_config(&config).await?;
        if authkey.is_some() {
            tracing::info!(
                "reload-config: the reloaded config carried an AuthKey; ignoring it (a reload is not a \
                 re-registration — a running node resumes from its persisted node key)"
            );
        }
        // Decide the reconcile path from the now-updated prefs + the live device. Go's
        // `ConfigVAlpha.ToPrefs` ALWAYS re-applies `WantRunning` on a reload (`WantRunningSet` is
        // effectively always true: `mp.WantRunning = !Enabled.EqualBool(false)`,
        // `mp.WantRunningSet = WantRunning || Enabled != ""`), so a reload is lifecycle-bearing — the
        // reloaded `Enabled` decides up/down, NOT just "rebuild if it was up":
        //   * device up + want_running now true  → REBUILD (adopt the new prefs into a fresh engine).
        //   * device up + want_running now false (reloaded `Enabled:false`) → BRING DOWN (Go applies
        //     it; the operator asked the node to stop). `apply_config` already persisted
        //     `want_running=false`, so the caller only tears the engine down to match.
        //   * device down → persisting above was the whole job (a `want_running=true` reload on a
        //     down node sets intent up; it comes up on the next auto-start/`up`, NOT mid-reload —
        //     matching how a down node treats a re-applied up-intent, and avoiding a reload silently
        //     originating a connection).
        Ok(Some(
            match (self.device.is_some(), self.prefs.want_running) {
                (true, true) => ReloadAction::Rebuild,
                (true, false) => ReloadAction::BringDown,
                (false, _) => ReloadAction::PersistedOnly,
            },
        ))
    }
}

/// What [`Backend::reload_config`] decided a `reload-config` must do to reconcile the live engine with
/// the freshly-merged-and-persisted config prefs. The prefs are ALREADY applied + persisted by the
/// time this is returned (including `want_running`, which Go's config reload always re-applies); this
/// only tells [`drive_reload_config`] how to bring the live engine into line.
///
/// It is DAEMON-side detail, not an operator-facing outcome: Go's `reload-config` LocalAPI route
/// returns a bare `ok` bool and its CLI prints one fixed line, so this action is logged (with the
/// reconcile it drove) rather than rendered into the reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadAction {
    /// Node down → nothing live to reconcile; the persisted prefs apply on the next `up`/auto-start.
    PersistedOnly,
    /// Node up and the reloaded config keeps it up → rebuild the engine from the new prefs (the
    /// engine `Config` is immutable), via the off-lock begin_up/build_device/finish_up handshake.
    Rebuild,
    /// Node up but the reloaded config set `Enabled:false` (`want_running=false`) → tear the engine
    /// down to match the already-persisted intent (Go applies a reloaded `Enabled:false`).
    BringDown,
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: the pure state-machine tests (`derive_state_from` input matrix, `state_as_str_is_stable`,
    // `state_from_device` mapping) and the macOS TUN-name tests moved to `ipn::state` alongside the
    // functions they exercise; the read-only-diagnostics / Taildrop path-hardening predicate tests
    // moved to `ipn::diag`. See those modules' `#[cfg(test)] mod tests`.

    // --- has_persisted_node_key ---------------------------------------------------------------
    //
    // The auto-start "resume vs. fresh-auth" decision hinges on this probe: it must read `false` for
    // a never-configured node (no key file) and `true` once a key file with a node key exists, all
    // with NO side effect (checking must never create a key file). These tests roll their own temp
    // dir via `process::id()` + the test name (the prefs-module idiom) so no `tempfile` dep is added.

    /// A throwaway `Backend` pointed at `dir`, used only to exercise `has_persisted_node_key`. We
    /// construct it directly rather than via `Backend::load` so the test is independent of prefs I/O.
    fn backend_for(dir: &std::path::Path) -> Backend {
        Backend {
            prefs: Prefs::default(),
            state_dir: dir.to_path_buf(),
            current_profile: profile::DEFAULT_PROFILE_ID.to_string(),
            prefs_path: dir.join("prefs.json"),
            key_path: dir.join("node.key.json"),
            // No `--config` by default; the reload-config tests set this explicitly when exercising
            // the re-read path (`set_config_source`).
            config_source: None,
            // No fixed listen port by default (ephemeral); tests that exercise it set it explicitly.
            listen_port: None,
            device: None,
            ssh_task: None,
            serve_tasks: Vec::new(),
            monitor_task: None,
            ever_configured: false,
            generation: 0,
            boot_attempted_up: false,
            lifecycle_tx: tokio::sync::watch::channel(0u64).0,
            prefs_tx: tokio::sync::watch::channel(()).0,
            // Cache starts `false` (a fresh backend, no key checked yet). Tests that need a key
            // present drive the real wipe/build paths, which keep the cache consistent on their own.
            has_node_key: false,
            captive_portal_detected: false,
            // No disconnect has happened yet, so no exemption stands and nothing is armed. No
            // `reconnect_loop` runs in a unit test, which is deliberate: the arming cell is the
            // observable state, and the tests below assert on it rather than on a fired timer.
            override_always_on: false,
            reconnect_tx: tokio::sync::watch::channel(None).0,
            reconnect_seq: 0,
            always_on_keys: syspolicy::AlwaysOnKeys::default(),
            override_exit_node_policy: false,
            exit_node_keys: syspolicy::ExitNodeKeys::default(),
        }
    }

    // --- captive-portal detection (tsd-iqq.5) -----------------------------------------------------

    #[tokio::test]
    async fn captive_detection_is_gated_on_wanting_to_be_up() {
        // Go `shouldRunCaptivePortalDetection`: detection only ever runs for a node the operator
        // actually wants connected. A `down` node must probe nothing at all.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-captive-gate-{}", std::process::id()));
        let mut be = backend_for(&dir);

        be.prefs.want_running = false;
        assert!(
            !be.should_run_captive_portal_detection(),
            "a node that does not want to be running must never probe"
        );
        assert_eq!(
            be.connectivity_impacted().await,
            None,
            "a deliberately-down node is not 'impacted'; it is doing what was asked"
        );

        be.prefs.want_running = true;
        assert!(be.should_run_captive_portal_detection());
    }

    /// A `ConnectivityHealth` with every signal observed: `true` = healthy, `false` = the warnable
    /// that watches it is unhealthy.
    fn health(any_interface_up: bool, derp_home: bool) -> ConnectivityHealth {
        ConnectivityHealth {
            any_interface_up: Some(any_interface_up),
            derp_home: Some(derp_home),
        }
    }

    #[test]
    fn captive_detection_triggers_in_the_state_go_triggers_it_in() {
        // Go starts `checkCaptivePortalLoop` on entry to `ipn.Running` and cancels it on the way out
        // (`ipn/ipnlocal/local.go`, `enterStateLocked`), then probes only while a warnable that
        // impacts connectivity is unhealthy. So the one node that probes is the connected one that
        // lost its path.
        assert_eq!(
            connectivity_impacted_from(State::Running, health(true, false)),
            Some(captive::ConnectivityWarnable::NoDerpHome),
            "a Running node with no reachable relay is exactly what Go probes: a portal appeared \
             under a live session"
        );
        assert_eq!(
            connectivity_impacted_from(State::Running, health(true, true)),
            None,
            "a Running node that reaches a relay is healthy; Go's healthy branch clears the warning"
        );
        for state in [
            State::NoState,
            State::NeedsLogin,
            State::NeedsMachineAuth,
            State::InUseOtherUser,
            State::Starting,
            State::Stopped,
        ] {
            assert_eq!(
                connectivity_impacted_from(state, health(false, false)),
                None,
                "{}: upstream's loop is cancelled outside Running, so this state probes zero times \
                 however broken the network is",
                state.as_str()
            );
        }
    }

    #[test]
    fn captive_detection_triggers_on_any_connectivity_warnable_not_only_no_derp_home() {
        // Go walks the whole health tracker: `for _, w := range state.Warnings { if
        // w.ImpactsConnectivity && w.WarnableCode != captivePortalWarnable.Code }`
        // (feature/captiveportal/captiveportal.go, `Extension.onHealthChange`). `no-derp-home` is one
        // member of that set, not the set.
        //
        // The case that makes this more than tidiness: the engine's net report is the node's LAST
        // measurement, so a host that loses the network mid-session keeps naming the home region it
        // measured before. `no-derp-home` then says nothing is wrong while the host has no usable
        // interface at all — and that node is one upstream probes, via `network-status`.
        assert_eq!(
            connectivity_impacted_from(State::Running, health(false, true)),
            Some(captive::ConnectivityWarnable::NetworkStatus),
            "a Running node whose host network is down is impacted even while the stale net report \
             still names a home relay"
        );

        // Both unhealthy: the one that becomes visible soonest is the one whose settle time the loop
        // owes, which is the health change that would have reached Go's loop first.
        assert_eq!(
            connectivity_impacted_from(State::Running, health(false, false)),
            Some(captive::ConnectivityWarnable::NetworkStatus),
            "network-status becomes visible in 5s and no-derp-home in 10s, so the first probe of \
             this episode is owed the shorter wait"
        );

        // An unobserved signal is not an unhealthy one. Go's tracker only raises
        // `NetworkStatusWarnable` for an `anyInterfaceUp` it was actually told about, and a net
        // report the engine could not produce says nothing about the relay.
        assert_eq!(
            connectivity_impacted_from(State::Running, ConnectivityHealth::UNKNOWN),
            None,
            "signals we could not read are unknown, not broken; an unreadable signal must never \
             raise a captive-portal probe"
        );
        assert_eq!(
            connectivity_impacted_from(
                State::Running,
                ConnectivityHealth {
                    any_interface_up: Some(false),
                    derp_home: None,
                },
            ),
            Some(captive::ConnectivityWarnable::NetworkStatus),
            "one observed-unhealthy signal is enough, whatever the others could not tell us"
        );
    }

    #[test]
    fn each_connectivity_warnable_carries_gos_settle_time() {
        // The first pass of an episode waits the triggering warnable's own `TimeToVisible` plus Go's
        // `captivePortalDetectionInterval` — per warnable, because upstream hears about a warnable
        // only once the tracker makes it visible, and the two do not become visible at the same time
        // (health/warnings.go: `network-status` 5s, `no-derp-home` 10s).
        use captive::ConnectivityWarnable::{NetworkStatus, NoDerpHome};
        assert_eq!(NetworkStatus.code(), "network-status");
        assert_eq!(NoDerpHome.code(), "no-derp-home");
        assert_eq!(
            NetworkStatus.settle_time(),
            std::time::Duration::from_secs(7),
            "network-status: 5s TimeToVisible + Go's 2s detection interval"
        );
        assert_eq!(
            NoDerpHome.settle_time(),
            std::time::Duration::from_secs(12),
            "no-derp-home: 10s TimeToVisible + Go's 2s detection interval"
        );
    }

    #[tokio::test]
    async fn a_node_that_never_came_up_does_not_probe() {
        // The inverse of the case above, and the one this fork used to get backwards: a node whose
        // engine is not up is NOT the node Go probes. Upstream's loop only exists between entering
        // and leaving `ipn.Running`, so `Starting`/`NeedsLogin` must make no requests at all.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-captive-trigger-{}", std::process::id()));
        let mut be = backend_for(&dir);
        be.prefs.want_running = true;

        assert_ne!(
            be.derive_state(false),
            State::Running,
            "no device installed, so the node cannot be Running"
        );
        assert_eq!(
            be.connectivity_impacted().await,
            None,
            "a node still coming up is not the node upstream probes"
        );
    }

    #[tokio::test]
    async fn a_detected_portal_becomes_the_go_health_warning_on_status() {
        // The verdict has to reach the operator, and in Go's words. `status().health` is what
        // `tnet status` prints under `# Health check:` and what `status --json` puts in `Health`.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-captive-health-{}", std::process::id()));
        let mut be = backend_for(&dir);

        assert!(
            be.status().await.health.is_empty(),
            "a node with no warning raised reports no health problems"
        );

        be.set_captive_portal_detected(true);
        assert_eq!(
            be.status().await.health,
            vec!["This network requires you to log in using your web browser.".to_string()],
            "the reported text must be Go's captivePortalWarnable text, verbatim"
        );

        // Go's healthy branch drops the warning again; `status` must stop reporting it.
        be.set_captive_portal_detected(false);
        assert!(
            be.status().await.health.is_empty(),
            "clearing the warning must clear the health list"
        );
    }

    #[tokio::test]
    async fn check_prefs_validates_without_mutating() {
        // check-prefs (Go CheckPrefs): validate a prospective posture, mutate NOTHING.
        let dir = std::env::temp_dir().join(format!("tailnetd-checkprefs-{}", std::process::id()));
        let be = backend_for(&dir);

        // Clean prospective change → Ok.
        assert!(
            be.check_prefs(
                Some(Some("100.64.0.9".into())),
                Some(false),
                None,
                None,
                None
            )
            .await
            .is_ok(),
            "a concrete exit node with advertise-exit off is valid"
        );

        // Exit-node-vs-advertise conflict → error naming the Go message.
        let err = be
            .check_prefs(
                Some(Some("100.64.0.9".into())),
                Some(true),
                None,
                None,
                None,
            )
            .await
            .expect_err("using + advertising an exit node must conflict");
        assert!(
            err.to_string()
                .contains("Cannot advertise an exit node and use an exit node at the same time"),
            "got {err:#}"
        );

        // An unmasked advertised route → error naming the masked form.
        let err = be
            .check_prefs(None, None, Some(vec!["10.0.0.5/24".into()]), None, None)
            .await
            .expect_err("an unmasked CIDR must be rejected");
        assert!(
            err.to_string().contains("has non-address bits set")
                && err.to_string().contains("10.0.0.0/24"),
            "got {err:#}"
        );

        // `auto:` exit node → rejected (reuses the bring-up validator).
        assert!(
            be.check_prefs(Some(Some("auto:any".into())), None, None, None, None)
                .await
                .is_err(),
            "auto: exit-node selection is not supported"
        );

        // An auto-update OPT-IN is refused on an installation that could never apply an update (Go
        // `checkAutoUpdatePrefsLocked`), and a DECLINE is legal everywhere. Which branch this host
        // takes is a property of the host, so assert against the same predicate the rule consults;
        // the rule's own two outcomes are pinned, host-independently, in `ipn::selfupdate`'s tests.
        let opt_in = be.check_prefs(None, None, None, None, Some(true)).await;
        match selfupdate::auto_update_refusal() {
            None => assert!(
                opt_in.is_ok(),
                "this installation can replace its own binary, so opting in is valid: {opt_in:?}"
            ),
            Some(_) => {
                let err = opt_in.expect_err("an installation that can never update must refuse");
                let msg = format!("{err:#}");
                assert!(msg.contains("Auto-updates are not supported"), "got {msg}");
                assert!(
                    msg.contains("Hostinfo.AllowsUpdate"),
                    "the refusal must say what the pref claims to the tailnet: {msg}"
                );
            }
        }
        assert!(
            be.check_prefs(None, None, None, None, Some(false))
                .await
                .is_ok(),
            "declining auto-update is legal on every installation"
        );

        // The check must not have persisted or mutated prefs — the backend's exit_node is still unset.
        assert!(
            be.prefs.exit_node.is_none() && be.prefs.advertise_routes.is_empty(),
            "check_prefs must mutate nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_prefs_reports_an_administratively_disabled_ssh_server() {
        // Go's `checkSSHPrefsLocked` gate: with `TS_DISABLE_SSH_SERVER` set, enabling the SSH server
        // is refused with the upstream sentence, and the refusal comes from the production gate —
        // the verdict handed in below is `featureknob`'s own, not one this test writes out.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-checkprefs-ssh-{}", std::process::id()));
        let be = backend_for(&dir);
        let disabled = || crate::featureknob::can_run_tailscale_ssh_in("linux", Some("1"));
        let allowed = || crate::featureknob::can_run_tailscale_ssh_in("linux", None);

        // Asking for the SSH server on a host that has it disabled → refused, in Go's words.
        let err = be
            .check_prefs_gated(
                None,
                None,
                None,
                Some(true),
                None,
                CheckPrefsEnv {
                    ssh_gate: disabled(),
                    exit_node_facts: &ExitNodeFacts::default(),
                },
            )
            .expect_err("TS_DISABLE_SSH_SERVER must refuse an SSH-server enable");
        assert!(
            err.to_string()
                .contains("The Tailscale SSH server has been administratively disabled."),
            "got {err:#}"
        );

        // The gate is consulted only for a posture that actually runs SSH: turning it OFF (and
        // leaving it alone, which on a fresh backend means off) stays valid on the same host, so a
        // disabled machine can still edit every other pref. Go refuses only when `RunSSH` is set.
        assert!(
            be.check_prefs_gated(
                None,
                None,
                None,
                Some(false),
                None,
                CheckPrefsEnv {
                    ssh_gate: disabled(),
                    exit_node_facts: &ExitNodeFacts::default(),
                },
            )
            .is_ok(),
            "disabling SSH on a host with the knob set must still be a valid posture"
        );
        assert!(
            be.check_prefs_gated(
                None,
                None,
                None,
                None,
                None,
                CheckPrefsEnv {
                    ssh_gate: disabled(),
                    exit_node_facts: &ExitNodeFacts::default(),
                },
            )
            .is_ok(),
            "an unrelated prefs check must not be refused by the SSH knob"
        );

        // And with the knob clear, the same request is valid on an `ssh`-feature build. (Without the
        // feature the build-time gate refuses it on its own — that arm is asserted below.)
        let ok = be.check_prefs_gated(
            None,
            None,
            None,
            Some(true),
            None,
            CheckPrefsEnv {
                ssh_gate: allowed(),
                exit_node_facts: &ExitNodeFacts::default(),
            },
        );
        if cfg!(feature = "ssh") {
            assert!(ok.is_ok(), "an unrestricted host must accept --ssh: {ok:?}");
        } else {
            let err = ok.expect_err("a build without the `ssh` feature cannot enable the server");
            let msg = err.to_string();
            assert!(
                msg.contains("`ssh` feature") && !msg.contains("administratively disabled"),
                "only the build-feature refusal applies when the knob is clear, got {msg:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn up_control_url_guard_reads_actual_state_not_device_presence() {
        // The Backend-level wiring of the control-URL guard. `backend_for` has `device: None`, so the
        // node is NOT Running → the guard must NEVER fire, even for a genuine control-server change.
        // This pins that `up_control_url_guard` keys on the node's actual reported state (here:
        // device absent → not Running), the fix for the device-presence-over-fires divergence — the
        // pure precedence (synonyms / force-reauth / proposed-None) is covered by control_url's own
        // unit tests; the device-present-AND-Running path needs a live tailnet (the gated e2e).
        let dir = std::env::temp_dir().join(format!("tailnetd-ctrlurl-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        be.prefs.control_url = Some("https://hs.example.com".to_string());

        // A genuine change to a different server, but the node is down (device: None) → not blocked.
        let opts = UpOptions {
            control_url: Some("https://other.example.com".to_string()),
            ..UpOptions::default()
        };
        assert!(
            !be.up_control_url_guard(&opts),
            "a down (non-Running) node must not be guarded, even for a real control-server change"
        );

        // A bare up (no --control-url) is never a change regardless of state.
        assert!(!be.up_control_url_guard(&UpOptions::default()));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn bugreport_marker_appends_sanitized_note() {
        // `bugreport [note]` (Go parity): the marker carries the operator note when given, omits the
        // `-note:` segment when not, and strips control chars from the note (it's free operator text
        // and the marker must stay one clean, copy-pasteable token).
        let dir = std::env::temp_dir().join(format!("tailnetd-bugreport-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let be = backend_for(&dir);

        // No note → no `-note:` segment.
        let crate::localapi::Response::BugReport { marker, checks } = be.bugreport(None, None)
        else {
            panic!("expected BugReport");
        };
        assert!(
            marker.starts_with("BUG-"),
            "marker has the BUG- prefix: {marker}"
        );
        assert!(
            !marker.contains("-note:"),
            "no note segment when omitted: {marker}"
        );
        assert!(
            checks.is_empty(),
            "no --diagnose probe means no checks: {checks:?}"
        );

        // Two markers taken back-to-back (the `--record` pair) must be DISTINGUISHABLE, even though
        // the seconds stamp is the same — otherwise the before/after bracket is a single value
        // printed twice.
        let crate::localapi::Response::BugReport { marker: second, .. } = be.bugreport(None, None)
        else {
            panic!("expected BugReport");
        };
        assert_ne!(
            marker, second,
            "two markers from one daemon must differ (the --record pair brackets a reproduction)"
        );

        // A note → appended as `-note:<note>`.
        let crate::localapi::Response::BugReport { marker, .. } =
            be.bugreport(Some("dns broke"), None)
        else {
            panic!("expected BugReport");
        };
        assert!(
            marker.contains("-note:dns broke"),
            "note appended: {marker}"
        );

        // A hostile note (newline + ESC + BEL) → control chars replaced with '_', marker stays one
        // line/token.
        let crate::localapi::Response::BugReport { marker, .. } =
            be.bugreport(Some("evil\n\x1b[2J\x07x"), None)
        else {
            panic!("expected BugReport");
        };
        assert!(
            !marker.contains('\n'),
            "newline stripped from the note: {marker:?}"
        );
        assert!(
            !marker.contains('\x1b'),
            "ESC stripped from the note: {marker:?}"
        );
        assert!(
            !marker.contains('\x07'),
            "BEL stripped from the note: {marker:?}"
        );
        assert!(
            marker.contains("-note:evil"),
            "readable part survives: {marker}"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn bugreport_diagnose_attaches_the_check_pass_without_changing_the_marker() {
        // `bugreport --diagnose` (Go `BugReportOpts.Diagnose` → `LocalBackend.Doctor`): the flag adds
        // checks and touches nothing else. Driven through the real dispatch path — the probe is
        // gathered exactly as `server.rs` gathers it, with no engine (the node is down), which is
        // also the state an operator most often runs this in.
        let dir = std::env::temp_dir().join(format!("tailnetd-diagnose-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let be = backend_for(&dir);

        let probe = Backend::diagnose_probe(None).await;
        let crate::localapi::Response::BugReport { marker, checks } =
            be.bugreport(Some("dns broke"), Some(&probe))
        else {
            panic!("expected BugReport");
        };

        // The marker is the same shape as without the flag: Go's `--diagnose` changes what is
        // logged, never the identifier the operator quotes.
        assert!(
            marker.starts_with("BUG-"),
            "marker unchanged in shape: {marker}"
        );
        assert!(
            marker.contains("-note:dns broke"),
            "the note still rides: {marker}"
        );

        let joined = checks.join("\n");
        for expected in [
            "state: ",
            "profile: ",
            "prefs: ",
            "permissions: ",
            "dns-resolvers: ",
            "interfaces: ",
            "not-checked: ",
        ] {
            assert!(
                checks.iter().any(|l| l.starts_with(expected)),
                "the pass should report {expected:?}; got:\n{joined}"
            );
        }
        assert!(
            joined.contains("dns-resolvers: not checked — the node is not up"),
            "a down node must say the DNS check had nothing to judge; got:\n{joined}"
        );
        assert!(
            joined.contains(&format!("state_dir={}", dir.display())),
            "the permissions check names the real state dir; got:\n{joined}"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn logout_wipes_key_and_sets_logged_out_but_down_keeps_key() {
        // The parity-defining distinction between `logout` and `down`: both bring the node down, but
        // `logout` ALSO discards the on-disk node key and sets `logged_out` (forcing a fresh login
        // next `up`), while `down` keeps the key (resume). Driven with no live device (device: None),
        // so `logout` skips the control-plane deregister and exercises the local mechanics — which is
        // exactly the behavior that differs from `down`.
        let dir = std::env::temp_dir().join(format!("tailnetd-logout-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        // --- `down` keeps the key file ---
        let mut be = backend_for(&dir);
        be.prefs.want_running = true;
        be.prefs.has_logged_in = true; // a registered node
        // Simulate a prior registration: a node key file on disk.
        tokio::fs::write(&be.key_path, b"{\"key_state\":{}}")
            .await
            .unwrap();
        be.down(alwayson::Actor::Operator { reason: None })
            .await
            .expect("down");
        assert!(!be.prefs.want_running, "down clears want_running");
        assert!(!be.prefs.logged_out, "down must NOT set logged_out");
        assert!(
            be.prefs.has_logged_in,
            "down must PRESERVE has_logged_in (down keeps the registration, like Go keeps LoginName)"
        );
        assert!(
            tokio::fs::try_exists(&be.key_path).await.unwrap(),
            "down must KEEP the node key file (resume path)"
        );

        // --- `logout` wipes the key file + sets logged_out + clears has_logged_in ---
        let mut be = backend_for(&dir);
        be.prefs.want_running = true;
        be.prefs.has_logged_in = true; // a registered node
        // key file still present from the `down` case above.
        assert!(tokio::fs::try_exists(&be.key_path).await.unwrap());
        be.logout(alwayson::Actor::Operator { reason: None })
            .await
            .expect("logout");
        assert!(!be.prefs.want_running, "logout clears want_running");
        assert!(
            be.prefs.logged_out,
            "logout MUST set logged_out (suppresses auto-start; forces fresh login)"
        );
        assert!(
            !be.prefs.has_logged_in,
            "logout MUST clear has_logged_in (ends the registration; matches Go clearing LoginName) \
             — so a post-logout set-then-up is unguarded until the node re-registers"
        );
        assert!(
            !be.wants_running(),
            "a logged-out node must not auto-start even though it was want_running before"
        );
        assert!(
            !tokio::fs::try_exists(&be.key_path).await.unwrap(),
            "logout MUST discard the node key file (fresh-login path)"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    // --- the always-on override + its `ReconnectAfter` timer (Go `onEditPrefsLocked`,
    // `startReconnectTimerLocked`, `sysPolicyChanged`) ------------------------------------------
    //
    // These drive the backend's own decisions directly. The policy READ that feeds them
    // (`syspolicy::reconnect_after`) is tested in `syspolicy`, over a resolved document, because the
    // policy registry is process-global and registering into it would leak into every other test in
    // this binary — the same split every other policy consumer here uses.

    /// A permitted disconnect, as `down`/`logout` report it, with the administrator's bound.
    fn permitted_disconnect(be: &mut Backend, after: Option<std::time::Duration>) {
        be.on_permitted_disconnect(after);
    }

    #[tokio::test]
    async fn a_permitted_disconnect_stands_and_carries_the_administrators_deadline() {
        let dir =
            std::env::temp_dir().join(format!("tailnetd-alwayson-arm-{}", std::process::id()));
        let mut be = backend_for(&dir);
        assert!(!be.override_always_on);
        assert_eq!(
            *be.reconnect_tx.borrow(),
            None,
            "nothing armed on a fresh backend"
        );

        let before = tokio::time::Instant::now();
        permitted_disconnect(&mut be, Some(std::time::Duration::from_secs(30 * 60)));

        assert!(
            be.override_always_on,
            "without the override the re-assert would undo the disconnect at the next reconcile"
        );
        let armed = be
            .reconnect_tx
            .borrow()
            .clone()
            .expect("a positive ReconnectAfter must arm a timer");
        assert_eq!(
            armed.profile, be.current_profile,
            "Go captures the profile id at arming time"
        );
        assert_eq!(armed.after, std::time::Duration::from_secs(30 * 60));
        assert!(
            armed.deadline() >= before + std::time::Duration::from_secs(30 * 60),
            "the deadline is measured from the disconnect, not from some later event"
        );
        assert_eq!(
            armed.after_go(),
            "30m0s",
            "Go renders the window with Duration.String()"
        );
    }

    #[tokio::test]
    async fn a_disconnect_with_no_configured_bound_stands_but_never_expires() {
        // Go's `if reconnectAfter > 0`: with no bound configured the exemption is still granted (that
        // is what makes the permitted disconnect stick), it simply has no expiry.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-alwayson-nobound-{}", std::process::id()));
        let mut be = backend_for(&dir);
        permitted_disconnect(&mut be, None);
        assert!(be.override_always_on);
        assert_eq!(
            *be.reconnect_tx.borrow(),
            None,
            "an unset/zero/negative ReconnectAfter must not arm a timer"
        );
    }

    #[tokio::test]
    async fn re_arming_supersedes_the_previous_timer() {
        // Go's `startReconnectTimerLocked` stops any previous timer before scheduling, and its
        // callback re-checks `b.reconnectTimer != timer`. Both halves matter: a superseded arming
        // whose sleep is already in flight must not reconnect on the newer one's behalf.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-alwayson-rearm-{}", std::process::id()));
        let mut be = backend_for(&dir);
        permitted_disconnect(&mut be, Some(std::time::Duration::from_secs(60)));
        let first = be.reconnect_tx.borrow().clone().expect("armed");
        permitted_disconnect(&mut be, Some(std::time::Duration::from_secs(7200)));
        let second = be.reconnect_tx.borrow().clone().expect("re-armed");

        assert_ne!(
            first.seq, second.seq,
            "a re-arm is a different timer, not the same one moved"
        );
        assert!(second.deadline() > first.deadline());
        assert!(
            !be.claim_due_reconnect(&first),
            "the superseded arming must refuse to fire"
        );
        assert_eq!(
            be.reconnect_tx.borrow().clone(),
            Some(second.clone()),
            "and refusing must not cancel the arming that replaced it"
        );
        assert!(be.claim_due_reconnect(&second), "the live arming fires");
        assert_eq!(
            *be.reconnect_tx.borrow(),
            None,
            "Go clears `b.reconnectTimer` before reconnecting, so a fire cannot happen twice"
        );
        assert!(
            !be.claim_due_reconnect(&second),
            "and a second attempt with the same arming is refused"
        );
    }

    #[tokio::test]
    async fn a_reconnect_armed_under_one_profile_never_connects_another() {
        // Go captures `profileID` at arming time and re-checks it in the callback. Without that
        // guard, a timer armed by a disconnect on one profile brings up whichever profile happens to
        // be active when it fires — a different node, on a different tailnet, that nobody asked for.
        // (A switch also cancels the timer outright; this pins the guard itself, which is what
        // protects the window between the deadline and the lock.)
        let dir =
            std::env::temp_dir().join(format!("tailnetd-alwayson-profile-{}", std::process::id()));
        let mut be = backend_for(&dir);
        permitted_disconnect(&mut be, Some(std::time::Duration::from_secs(60)));
        let armed = be.reconnect_tx.borrow().clone().expect("armed");

        be.current_profile = "work".to_string();
        assert!(
            !be.claim_due_reconnect(&armed),
            "a timer armed for another profile must not reconnect this one"
        );
        assert_eq!(
            *be.reconnect_tx.borrow(),
            None,
            "and it is discarded rather than left to fire again"
        );
    }

    #[tokio::test]
    async fn down_grants_the_exemption_only_on_the_true_to_false_transition() {
        // Go gates on `oldPrefs.WantRunning()`, so an idempotent `down` on an already-down node is
        // not a disconnect: it must neither grant an exemption nor push an existing deadline out.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-alwayson-down-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        // A node that was up: `down` grants the exemption (no policy file is registered in this test
        // process, so there is no bound to arm — that read is tested in `syspolicy`).
        let mut be = backend_for(&dir);
        be.prefs.want_running = true;
        be.down(alwayson::Actor::Operator {
            reason: Some("laptop returned to IT"),
        })
        .await
        .expect("an unmanaged node may always disconnect");
        assert!(!be.prefs.want_running);
        assert!(
            be.override_always_on,
            "a permitted disconnect must suppress the always-on re-assert"
        );

        // A node that was already down: nothing to permit, so nothing is granted.
        let mut be = backend_for(&dir);
        be.prefs.want_running = false;
        be.down(alwayson::Actor::Operator { reason: None })
            .await
            .expect("a down on a down node is a no-op success");
        assert!(
            !be.override_always_on,
            "a `down` on an already-down node is not a disconnect and grants no exemption"
        );

        // A logout is the same edit in Go, and takes the same road here.
        let mut be = backend_for(&dir);
        be.prefs.want_running = true;
        be.logout(alwayson::Actor::Operator { reason: None })
            .await
            .expect("logout");
        assert!(be.override_always_on, "a logout is a disconnect too");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn connecting_the_node_ends_the_exemption_and_cancels_the_reconnect() {
        // Go resets `overrideAlwaysOn` (and stops the timer) on the connect edge: the window a
        // disconnect bought is spent the moment the node is brought back up by hand.
        let dir = std::env::temp_dir().join(format!("tailnetd-alwayson-up-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        permitted_disconnect(&mut be, Some(std::time::Duration::from_secs(30 * 60)));
        assert!(be.reconnect_tx.borrow().is_some());

        be.begin_up(UpOptions::default(), None)
            .await
            .expect("a device-less begin_up mints a fresh key and prepares the config");
        assert!(
            !be.override_always_on,
            "`up` re-arms the policy: from here on AlwaysOn.Enabled is back in force"
        );
        assert_eq!(
            *be.reconnect_tx.borrow(),
            None,
            "and the reconnect it would have performed has already happened"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn switching_profile_ends_the_exemption_and_cancels_the_reconnect() {
        // The exemption was granted to the profile whose operator asked for it, so it does not
        // travel — Go resets it on a profile change.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-alwayson-switch-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        permitted_disconnect(&mut be, Some(std::time::Duration::from_secs(30 * 60)));
        be.create_profile("work").await.expect("create + switch");

        assert!(
            !be.override_always_on,
            "the exemption does not follow the switch"
        );
        assert_eq!(
            *be.reconnect_tx.borrow(),
            None,
            "and neither does its timer"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn only_a_real_always_on_policy_change_revokes_an_outstanding_exemption() {
        // Go's `sysPolicyChanged` resets the override on
        // `HasChangedAnyOf(AlwaysOn, AlwaysOnOverrideWithReason)`. The "HasChanged" part is
        // load-bearing here: this build's policy source captures its file at startup, so a `tnet
        // syspolicy reload` ticks the change bus without a single value having moved — and a tick
        // that revoked the exemption would cut a permitted disconnect short for no reason.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-alwayson-policy-{}", std::process::id()));
        let mut be = backend_for(&dir);
        be.always_on_keys = syspolicy::AlwaysOnKeys {
            enabled: Some(true),
            override_with_reason: Some(true),
        };
        permitted_disconnect(&mut be, Some(std::time::Duration::from_secs(30 * 60)));

        assert!(
            !be.sys_policy_changed(syspolicy::AlwaysOnKeys {
                enabled: Some(true),
                override_with_reason: Some(true),
            }),
            "an unchanged policy is not a change"
        );
        assert!(be.override_always_on, "so the exemption still stands");
        assert!(
            be.reconnect_tx.borrow().is_some(),
            "and its timer is still armed"
        );

        // The administrator withdraws the override key: the exemption it granted goes with it.
        assert!(be.sys_policy_changed(syspolicy::AlwaysOnKeys {
            enabled: Some(true),
            override_with_reason: None,
        }));
        assert!(!be.override_always_on);
        assert_eq!(*be.reconnect_tx.borrow(), None);

        // The snapshot is updated, so the same change is not re-reported on the next tick.
        assert!(!be.sys_policy_changed(syspolicy::AlwaysOnKeys {
            enabled: Some(true),
            override_with_reason: None,
        }));
    }

    // --- the exit-node edit gate's bookkeeping (Go `onEditPrefsLocked` / `sysPolicyChanged`) -----

    /// The exemption a permitted override buys, and the two ways an edit can end it — Go's
    /// `onEditPrefsLocked` exit-node arm, driven through the production recorder.
    #[tokio::test]
    async fn a_permitted_exit_node_override_stands_until_an_edit_ends_it() {
        let dir =
            std::env::temp_dir().join(format!("tailnetd-exitnode-override-{}", std::process::id()));
        let mut be = backend_for(&dir);
        assert!(
            !be.override_exit_node_policy,
            "a fresh backend stands on no exemption, so the policy's exit node applies"
        );

        // An edit that names no exit node says nothing about the exemption, in either direction.
        be.record_exit_node_edit(exitnodepolicy::ExitNodeEdit::Untouched, "set");
        assert!(!be.override_exit_node_policy);

        be.record_exit_node_edit(exitnodepolicy::ExitNodeEdit::Override, "set");
        assert!(
            be.override_exit_node_policy,
            "an override the policy permitted must suppress the re-apply that would undo it"
        );
        be.record_exit_node_edit(exitnodepolicy::ExitNodeEdit::Untouched, "set");
        assert!(
            be.override_exit_node_policy,
            "an unrelated `set` is not an exit-node edit and must not revoke the exemption"
        );

        // The operator picking the policy's own node again is Go's "switches back to the state
        // required by policy": there is nothing left to exempt.
        be.record_exit_node_edit(exitnodepolicy::ExitNodeEdit::NoOverride, "set");
        assert!(!be.override_exit_node_policy);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// Connecting, disconnecting and switching profile all end an exit-node override — the three
    /// lifecycle edges Go clears `overrideExitNodePolicy` on.
    #[tokio::test]
    async fn every_lifecycle_edge_ends_an_exit_node_override() {
        let dir = std::env::temp_dir().join(format!(
            "tailnetd-exitnode-lifecycle-{}",
            std::process::id()
        ));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        // A disconnect: which node the operator egresses through does not outlive the connection.
        let mut be = backend_for(&dir);
        be.prefs.want_running = true;
        be.record_exit_node_edit(exitnodepolicy::ExitNodeEdit::Override, "set");
        be.down(alwayson::Actor::Operator { reason: None })
            .await
            .expect("an unmanaged node may always disconnect");
        assert!(!be.override_exit_node_policy, "a `down` ends the override");

        // A logout is the same edit in Go, and takes the same road here.
        let mut be = backend_for(&dir);
        be.prefs.want_running = true;
        be.record_exit_node_edit(exitnodepolicy::ExitNodeEdit::Override, "set");
        be.logout(alwayson::Actor::Operator { reason: None })
            .await
            .expect("logout");
        assert!(!be.override_exit_node_policy, "a logout ends it too");

        // A connect: `up` puts the administrator's policy back in force.
        let mut be = backend_for(&dir);
        be.record_exit_node_edit(exitnodepolicy::ExitNodeEdit::Override, "set");
        be.begin_up(UpOptions::default(), None)
            .await
            .expect("a device-less begin_up mints a fresh key and prepares the config");
        assert!(
            !be.override_exit_node_policy,
            "`up` re-arms the policy: from here on the pinned ExitNodeIP is back in force"
        );

        // A profile switch: the exemption was granted against the profile that asked for it.
        let mut be = backend_for(&dir);
        be.record_exit_node_edit(exitnodepolicy::ExitNodeEdit::Override, "set");
        be.create_profile("work").await.expect("create + switch");
        assert!(
            !be.override_exit_node_policy,
            "the exemption does not follow the switch"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// Go's second `HasChangedAnyOf` in `sysPolicyChanged`: an exit-node key moving revokes a
    /// standing override, and a tick that moved nothing does not.
    #[tokio::test]
    async fn only_a_real_exit_node_policy_change_revokes_an_outstanding_override() {
        let dir =
            std::env::temp_dir().join(format!("tailnetd-exitnode-policy-{}", std::process::id()));
        let mut be = backend_for(&dir);
        let pinned_with_override = syspolicy::ExitNodeKeys {
            id: None,
            ip: Some("100.64.0.9".to_string()),
            allow_override: Some(true),
        };
        be.exit_node_keys = pinned_with_override.clone();
        be.record_exit_node_edit(exitnodepolicy::ExitNodeEdit::Override, "set");

        assert!(
            !be.exit_node_policy_changed(pinned_with_override),
            "an unchanged policy is not a change — this build's source captures its file at \
             startup, so a `syspolicy reload` ticks the bus without a value having moved"
        );
        assert!(be.override_exit_node_policy, "so the override still stands");

        // The administrator withdraws the override key: the exemption it granted goes with it.
        let withdrawn = syspolicy::ExitNodeKeys {
            id: None,
            ip: Some("100.64.0.9".to_string()),
            allow_override: None,
        };
        assert!(be.exit_node_policy_changed(withdrawn.clone()));
        assert!(!be.override_exit_node_policy);

        // The snapshot is updated, so the same change is not re-reported on the next tick.
        assert!(!be.exit_node_policy_changed(withdrawn));

        // Moving the PINNED NODE is a change too, even to a value this build cannot apply: Go
        // compares the keys, not their effect.
        be.record_exit_node_edit(exitnodepolicy::ExitNodeEdit::Override, "set");
        assert!(be.exit_node_policy_changed(syspolicy::ExitNodeKeys {
            id: Some("nABC123CNTRL".to_string()),
            ip: Some("100.64.0.9".to_string()),
            allow_override: None,
        }));
        assert!(!be.override_exit_node_policy);
    }

    /// The gate itself, reached the way `up` and `set` reach it: with no policy registered in this
    /// test process the exit node is nobody's but the operator's, and every edit is permitted.
    #[tokio::test]
    async fn an_unmanaged_node_reaches_the_gate_and_is_waved_through() {
        let dir =
            std::env::temp_dir().join(format!("tailnetd-exitnode-gate-{}", std::process::id()));
        let be = backend_for(&dir);
        for named in [None, Some(None), Some(Some("100.64.0.3"))] {
            assert_eq!(
                be.check_exit_node_policy(named).ok(),
                Some(match named {
                    None => exitnodepolicy::ExitNodeEdit::Untouched,
                    Some(_) => exitnodepolicy::ExitNodeEdit::NoOverride,
                }),
                "{named:?}"
            );
        }
        // And the refusal itself, over a registered policy file, is `tests/exit_node_policy.rs` —
        // the registry is process-global, so it owns a test binary of its own.
    }

    #[tokio::test]
    async fn the_reconnect_wait_is_the_deadline_and_nothing_when_unarmed() {
        // The loop's two waiting states, over the production future it selects on: an armed timer
        // sleeps until its deadline and no earlier, and an unarmed backend waits forever (a task
        // that returned instead would spin, retaking the backend lock at full speed).
        //
        // Real time, not a paused clock (this crate does not carry tokio's `test-util`), so the
        // margins are chosen to be robust rather than tight: "must not fire early" is asserted 10
        // seconds short of the deadline, and the firing case uses a window long enough that a
        // loaded machine still reaches it inside the timeout.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-alwayson-wait-{}", std::process::id()));
        let mut be = backend_for(&dir);

        permitted_disconnect(&mut be, Some(std::time::Duration::from_secs(10)));
        let armed = be.reconnect_tx.borrow().clone().expect("armed");
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                sleep_until_armed(Some(&armed))
            )
            .await
            .is_err(),
            "a timer must not fire before its deadline"
        );

        // The same future, armed for a window that does elapse: it completes, and only then.
        permitted_disconnect(&mut be, Some(std::time::Duration::from_millis(30)));
        let armed = be.reconnect_tx.borrow().clone().expect("re-armed");
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            sleep_until_armed(Some(&armed)),
        )
        .await
        .expect("a timer must fire once its deadline passes");

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                sleep_until_armed(None)
            )
            .await
            .is_err(),
            "with nothing armed the loop must park rather than wake"
        );
    }

    #[tokio::test]
    async fn serve_config_persists_and_no_device_means_no_loops() {
        // set_serve_config persists the config and reads back; with no device up, it does NOT spawn
        // any accept loops (they arm on the next `up` via finish_up). serve_config round-trips.
        let dir = std::env::temp_dir().join(format!("tailnetd-serve-be-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        // Initially empty.
        assert!(be.serve_config().await.tcp.is_empty());

        let mut cfg = serve::ServeConfig::default();
        serve::set_tcp_forward(&mut cfg, 8443, "127.0.0.1:5000".into());
        be.set_serve_config(&cfg).await.unwrap();

        // Round-trips through the backend.
        let back = be.serve_config().await;
        assert_eq!(back, cfg);
        assert_eq!(
            back.tcp.get("8443").map(|h| h.tcp_forward.as_str()),
            Some("127.0.0.1:5000")
        );
        // No device up → no accept loops were spawned (they arm on the next `up`).
        assert!(
            be.serve_tasks.is_empty(),
            "set_serve_config on a down node must not spawn serve loops"
        );

        // A funnel-enabled config likewise persists + round-trips and arms NO loops while down
        // (the funnel listener + accept loop arm on the next `up`, in spawn_serve LANE 3).
        let mut cfg = serve::ServeConfig::default();
        cfg.tcp.insert(
            "443".into(),
            crate::localapi::TcpPortHandler {
                https: true,
                tcp_forward: "127.0.0.1:3000".into(),
                ..Default::default()
            },
        );
        serve::set_funnel(&mut cfg, "host.example.ts.net", 443, true);
        be.set_serve_config(&cfg).await.unwrap();
        let back = be.serve_config().await;
        assert_eq!(back, cfg);
        assert_eq!(
            serve::funnel_ports(&back),
            std::collections::BTreeSet::from([443])
        );
        assert!(
            be.serve_tasks.is_empty(),
            "set_serve_config with funnel on a down node must not spawn loops"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn a_second_serve_on_a_busy_port_is_refused_not_silently_swapped() {
        // A serve config is replaced wholesale, and the CLI builds each one by fetching the current
        // config and inserting into its port map. Aiming a `--tcp` serve at a port that already
        // terminates HTTPS therefore used to overwrite the handler, report success, and leave the
        // operator to discover the loss when the old backend stopped receiving traffic. Go refuses
        // it (`validateServeConfigUpdate`), so this must too — and must leave the live serve alone.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-serve-conflict-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        // Port 443 terminates HTTPS and reverse-proxies to a local backend.
        let mut https = serve::ServeConfig::default();
        https.tcp.insert(
            "443".into(),
            crate::localapi::TcpPortHandler {
                https: true,
                ..Default::default()
            },
        );
        https.web.insert(
            "host.example.ts.net:443".into(),
            crate::localapi::WebServerConfig {
                handlers: std::collections::BTreeMap::from([(
                    "/".to_string(),
                    crate::localapi::HttpHandler {
                        proxy: "127.0.0.1:3000".into(),
                        ..Default::default()
                    },
                )]),
            },
        );
        be.set_serve_config(&https).await.expect("first serve");

        // Now a plain TCP forward on the same port, the way `tnet serve --tcp 443` builds it.
        let mut tcp = be.serve_config().await;
        tcp.tcp.insert(
            "443".into(),
            crate::localapi::TcpPortHandler {
                tcp_forward: "127.0.0.1:8000".into(),
                ..Default::default()
            },
        );
        tcp.web.retain(|k, _| !k.ends_with(":443"));
        let err = be
            .set_serve_config(&tcp)
            .await
            .expect_err("a serve-type change on a busy port must be refused");
        assert_eq!(
            format!("{err:#}"),
            r#"want to serve "tcp", but port 443 is already serving "https""#,
            "the refusal reaches the operator as the SetServeConfig error body, so it is Go's \
             message and nothing else"
        );

        // The refusal is total: the HTTPS serve is still the persisted config.
        assert_eq!(
            be.serve_config().await,
            https,
            "a refused update must not have been written"
        );

        // Re-targeting the SAME serve type is still allowed (this is not a freeze on the port).
        let mut retarget = https.clone();
        retarget.web.insert(
            "host.example.ts.net:443".into(),
            crate::localapi::WebServerConfig {
                handlers: std::collections::BTreeMap::from([(
                    "/".to_string(),
                    crate::localapi::HttpHandler {
                        proxy: "127.0.0.1:9000".into(),
                        ..Default::default()
                    },
                )]),
            },
        );
        be.set_serve_config(&retarget).await.expect("re-target");
        assert_eq!(be.serve_config().await, retarget);

        // And taking the port down, then serving `--tcp` on it, is the supported way through.
        let mut off = retarget.clone();
        off.tcp.remove("443");
        off.web.retain(|k, _| !k.ends_with(":443"));
        be.set_serve_config(&off).await.expect("serve 443 off");
        let mut tcp = off.clone();
        serve::set_tcp_forward(&mut tcp, 443, "127.0.0.1:8000".into());
        be.set_serve_config(&tcp).await.expect("tcp after off");
        assert_eq!(be.serve_config().await, tcp);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn funnel_under_shields_up_is_refused_on_every_road() {
        // Shields-up blocks every inbound connection; Funnel publishes a port to the public
        // internet. A node with both advertises an endpoint that accepts nothing, and no status
        // output says so — so the setter refuses the pair at the moment it would be created, with
        // Go's message (`setServeConfigLocked`'s first statement). Every road into the daemon (the
        // LocalAPI verb, `tnet funnel`, the flag grammar, the foreground restore) lands on this one
        // function, so one guard covers them all — including the restore, exercised below.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-funnel-shields-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        be.prefs.shields_up = true;

        // Port 443 terminates HTTPS to a local backend, with Funnel on — what `tnet funnel
        // --https=443 http://127.0.0.1:3000` (or `tnet funnel 443 on`) writes.
        let mut funnel = serve::ServeConfig::default();
        funnel.tcp.insert(
            "443".into(),
            crate::localapi::TcpPortHandler {
                https: true,
                tcp_forward: "127.0.0.1:3000".into(),
                ..Default::default()
            },
        );
        serve::set_funnel(&mut funnel, "host.example.ts.net", 443, true);

        let err = be
            .set_serve_config(&funnel)
            .await
            .expect_err("funnel-on under shields-up must be refused");
        assert_eq!(
            format!("{err:#}"),
            "Unable to turn on Funnel while shields-up is enabled",
            "Go's message verbatim — it is what the operator is shown"
        );
        assert_eq!(
            be.serve_config().await,
            serve::ServeConfig::default(),
            "a refused update must not have been persisted"
        );

        // The guard is Funnel-specific: a funnel-free serve is tailnet-only, so shields-up does not
        // refuse it (Go gates on `IsFunnelOn`, not on serving at all).
        let mut plain = serve::ServeConfig::default();
        serve::set_tcp_forward(&mut plain, 8443, "127.0.0.1:5000".into());
        be.set_serve_config(&plain)
            .await
            .expect("a funnel-free serve is untouched by the guard");
        assert_eq!(be.serve_config().await, plain);

        // Shields down → the same funnel config goes through.
        be.prefs.shields_up = false;
        be.set_serve_config(&funnel)
            .await
            .expect("funnel with shields down");
        assert_eq!(
            serve::funnel_ports(&be.serve_config().await),
            std::collections::BTreeSet::from([443])
        );

        // Enabling shields-up behind the daemon's back must not trap the operator: turning Funnel
        // OFF is a config with no funnel port, so it still goes through and the bad pair can be
        // undone from either side.
        be.prefs.shields_up = true;
        let mut off = funnel.clone();
        serve::set_funnel(&mut off, "host.example.ts.net", 443, false);
        be.set_serve_config(&off)
            .await
            .expect("turning funnel off under shields-up must still be allowed");
        assert!(
            serve::funnel_ports(&be.serve_config().await).is_empty(),
            "funnel must actually be off"
        );

        // The restore road: a foreground serve re-sends the config it captured on entry when it
        // exits. If shields-up arrived in between, that restore would re-arm Funnel — and it is
        // refused exactly like a fresh `funnel` is, leaving the persisted config alone.
        let err = be
            .set_serve_config(&funnel)
            .await
            .expect_err("a restore that re-arms funnel under shields-up must be refused too");
        assert_eq!(
            format!("{err:#}"),
            "Unable to turn on Funnel while shields-up is enabled"
        );
        assert_eq!(
            be.serve_config().await,
            off,
            "the refused restore left the live config untouched"
        );

        // Go's ORDER: the shields-up refusal is the first statement of the setter, ahead of the
        // serve-type validation. A config that is wrong in both ways is refused for the Funnel, …
        let mut both_wrong = off.clone();
        both_wrong.tcp.insert(
            "443".into(),
            crate::localapi::TcpPortHandler {
                tcp_forward: "127.0.0.1:8000".into(),
                ..Default::default()
            },
        );
        serve::set_funnel(&mut both_wrong, "host.example.ts.net", 443, true);
        let err = be
            .set_serve_config(&both_wrong)
            .await
            .expect_err("refused for the funnel, ahead of the serve-type conflict");
        assert_eq!(
            format!("{err:#}"),
            "Unable to turn on Funnel while shields-up is enabled"
        );
        // … and the serve-type conflict really was there, which is what makes the order observable.
        be.prefs.shields_up = false;
        let err = be
            .set_serve_config(&both_wrong)
            .await
            .expect_err("the same config still trips the serve-type rule with shields down");
        assert_eq!(
            format!("{err:#}"),
            r#"want to serve "tcp", but port 443 is already serving "https""#
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn logout_is_idempotent_with_no_key_file() {
        // Logging out a never-registered node (no key file) is not an error — the remove is a
        // tolerated NotFound. Mirrors Go's idempotent logout.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-logout-nokey-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        assert!(!tokio::fs::try_exists(&be.key_path).await.unwrap());
        be.logout(alwayson::Actor::Operator { reason: None })
            .await
            .expect("logout with no key file must succeed");
        assert!(be.prefs.logged_out);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_up_force_reauth_discards_key_before_build_but_keeps_up_intent() {
        // `up --force-reauth` (Go parity): the bring-up must DISCARD the on-disk node key (so the
        // engine re-registers fresh / surfaces a new login) while KEEPING the node's up-intent —
        // unlike `logout`, it does NOT set `logged_out` or clear `want_running`.
        //
        // The test exploits the load-bearing ORDER: the force-reauth wipe runs BEFORE `build_config`
        // (which reads the key). We plant an UNPARSEABLE key file and show the two paths diverge on
        // exactly that file:
        //   - a PLAIN `begin_up` reaches `build_config`, which tries to parse the key and FAILS
        //     (`load key file ... KeyFileRead`) — proving the plain path does NOT wipe (it resumes).
        //   - a force-reauth `begin_up` WIPES the key first, so `build_config` then sees no key and
        //     registers fresh — succeeding on the very file that broke the plain path.
        // This both pins the wipe AND its ordering relative to build_config. Driven device-less, like
        // the logout tests; `begin_up` returns the slow handshake's `PendingUp` (not `Debug`) → match.
        let dir = std::env::temp_dir().join(format!("tailnetd-reauth-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let bogus_key = b"this is not a valid key file";

        // --- a PLAIN `begin_up` reaches build_config, which chokes on the bogus key (no wipe) ---
        let mut be = backend_for(&dir);
        tokio::fs::write(&be.key_path, bogus_key).await.unwrap();
        match be.begin_up(UpOptions::default(), None).await {
            Ok(_) => panic!("a plain up must reach build_config and fail to parse the bogus key"),
            Err(e) => {
                let msg = format!("{e:#}");
                assert!(
                    msg.contains("load key file"),
                    "the plain up must fail in build_config's key load (proving it did NOT wipe the \
                     key first), got {msg:?}"
                );
            }
        }
        assert!(
            tokio::fs::try_exists(&be.key_path).await.unwrap(),
            "a plain `up` must KEEP the node key (seamless resume — only force-reauth/logout wipe it)"
        );

        // --- `begin_up { force_reauth: true }` WIPES the key first, so build_config registers fresh ---
        let mut be = backend_for(&dir);
        // bogus key still present from the plain-up case above.
        assert!(tokio::fs::try_exists(&be.key_path).await.unwrap());
        match be
            .begin_up(
                UpOptions {
                    force_reauth: true,
                    ..UpOptions::default()
                },
                None,
            )
            .await
        {
            Ok(_) => {}
            Err(e) => panic!(
                "force-reauth must wipe the key BEFORE build_config reads it, so the same bogus key \
                 that broke the plain path is gone and the up succeeds; got {e:#}"
            ),
        }
        // The OLD (bogus) registration is gone. `build_config`'s key load then re-initializes a
        // FRESH default key file (the engine's load-or-init writes one when none is present), so the
        // faithful post-condition is "the old key content was discarded", not "no file exists" — the
        // node now holds a brand-new, unregistered key (a fresh login).
        let after = tokio::fs::read(&be.key_path).await.unwrap_or_default();
        assert_ne!(
            after.as_slice(),
            bogus_key.as_slice(),
            "force-reauth MUST discard the OLD node key (the bogus content is gone — registered fresh)"
        );
        assert!(
            be.prefs.want_running,
            "force-reauth keeps up-intent: want_running stays true (it is an `up`, not a `down`)"
        );
        assert!(
            !be.prefs.logged_out,
            "force-reauth must NOT set logged_out (it re-logs-in; it does not log out)"
        );
        assert!(
            be.wants_running(),
            "a force-reauth'd node is still want-running (unlike a logged-out one)"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_up_force_reauth_wipe_failure_aborts_before_persisting() {
        // Fail-closed parity with `logout_key_wipe_failure_aborts_before_flipping_logged_out`: if the
        // force-reauth key wipe FAILS, `begin_up` must abort BEFORE persisting prefs or flipping
        // `want_running` — never come up on the very key it meant to rotate. Same un-removable-key
        // trick: make `key_path` a non-empty directory so `remove_file` errors (not NotFound).
        let dir =
            std::env::temp_dir().join(format!("tailnetd-reauth-wipefail-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        tokio::fs::create_dir_all(&be.key_path).await.unwrap();
        tokio::fs::write(be.key_path.join("blocker"), b"x")
            .await
            .unwrap();

        let result = be
            .begin_up(
                UpOptions {
                    force_reauth: true,
                    ..UpOptions::default()
                },
                None,
            )
            .await;
        // PendingUp is not Debug, so check by hand rather than `.is_err()`/`expect_err`.
        if result.is_ok() {
            panic!("a force-reauth whose key wipe fails must make begin_up fail");
        }
        // The critical invariant: the wipe is BEFORE the prefs mutate/persist, so a failed wipe left
        // `want_running` un-flipped and nothing on disk.
        assert!(
            !be.prefs.want_running,
            "a wipe-failed force-reauth must NOT have flipped want_running (the wipe precedes it)"
        );
        assert!(
            !tokio::fs::try_exists(dir.join("prefs.json")).await.unwrap(),
            "a wipe-failed force-reauth must not have persisted prefs.json"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_up_reset_force_reauth_wipe_failure_leaves_in_memory_prefs_untouched() {
        // The fallible `discard_node_key` runs BEFORE the in-memory `--reset` mutation, so a combined
        // `up --reset --force-reauth` whose key wipe fails must abort with `self.prefs` STILL the
        // pre-command values — never half-reset in memory while nothing was persisted (which a
        // same-process retry, a `status` read, or a later bare `set` would then wrongly observe or
        // persist). Same un-removable-key trick as the plain wipe-failure test.
        let dir = std::env::temp_dir().join(format!(
            "tailnetd-reset-reauth-wipefail-{}",
            std::process::id()
        ));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        tokio::fs::create_dir_all(&be.key_path).await.unwrap();
        tokio::fs::write(be.key_path.join("blocker"), b"x")
            .await
            .unwrap();

        // A non-default up-managed pref that `reset_up_managed_to_default` would clear to None.
        be.prefs.hostname = Some("preset-host".to_string());

        let result = be
            .begin_up(
                UpOptions {
                    reset: true,
                    force_reauth: true,
                    ..UpOptions::default()
                },
                None,
            )
            .await;
        if result.is_ok() {
            panic!("a `--reset --force-reauth` whose key wipe fails must make begin_up fail");
        }
        // The load-bearing invariant: the reset never ran (the wipe aborted first), so the in-memory
        // pref is untouched — matching the on-disk state (nothing persisted).
        assert_eq!(
            be.prefs.hostname.as_deref(),
            Some("preset-host"),
            "a wipe-failed `--reset --force-reauth` must NOT have reset in-memory prefs (the fallible \
             wipe precedes the reset mutation, so an abort leaves prefs fully untouched)"
        );
        assert!(
            !be.prefs.want_running,
            "a wipe-failed `--reset --force-reauth` must NOT have flipped want_running"
        );
        assert!(
            !tokio::fs::try_exists(dir.join("prefs.json")).await.unwrap(),
            "a wipe-failed `--reset --force-reauth` must not have persisted prefs.json"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn up_options_force_reauth_is_not_a_mentioned_pref() {
        // `force_reauth` is a LIFECYCLE action, not a pref — so (like `reset`) it must NOT count as a
        // "mentioned pref". This is load-bearing: if it counted, a bare `up --force-reauth` on a node
        // with any non-default pref would wrongly trip the accidental-revert guard (RevertGuard)
        // instead of just re-authenticating. Pin that it stays exempt.
        assert!(
            !UpOptions {
                force_reauth: true,
                ..UpOptions::default()
            }
            .mentions_any_pref(),
            "force_reauth must NOT be a mentioned pref (a bare `up --force-reauth` stays a bare up)"
        );
    }

    #[tokio::test]
    async fn revert_guard_exempts_never_logged_in_node_then_guards_after_login() {
        // tsd-i7c: the accidental-revert guard's fresh-node exemption must key on `has_logged_in`
        // (the node actually registered), NOT prefs-file existence / `ever_configured` (which a bare
        // `tnet set` flips true). So a `set`-then-`up` on a node that never logged in must NOT trip the
        // guard — matching Go (whose `set` never writes ControlURL, so `checkForAccidentalSettingReverts`
        // still early-returns on the subsequent `up`).
        let dir = std::env::temp_dir().join(format!("tailnetd-i7c-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let mut be = backend_for(&dir);
        // Simulate `tnet set --accept-routes` on a never-logged-in node: a non-default pref is set and
        // a prefs.json exists (ever_configured true), but the node has NOT registered.
        be.prefs.accept_routes = true;
        be.ever_configured = true;
        be.prefs.has_logged_in = false;

        // A later `tnet up --ssh` mentions ssh but not accept_routes. Under the OLD (ever_configured)
        // keying this WRONGLY tripped the guard; under has_logged_in it is correctly exempt.
        let up_ssh = UpOptions {
            ssh: Some(true),
            ..UpOptions::default()
        };
        assert!(
            be.up_revert_guard(&up_ssh).is_empty(),
            "set-then-up on a never-logged-in node must NOT trip the revert guard (tsd-i7c)"
        );

        // Once the node HAS logged in, the guard arms normally: the same `up --ssh` would now silently
        // revert the non-default accept_routes, so it is flagged.
        be.prefs.has_logged_in = true;
        let reverts = be.up_revert_guard(&up_ssh);
        assert!(
            reverts.iter().any(|r| r.key == "accept_routes"),
            "after login, an unmentioned non-default accept_routes must be guarded: {reverts:?}"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn profile_switch_isolates_prefs_and_lists_with_current_marker() {
        // The load-bearing profile guarantee: switching profiles isolates each profile's prefs (and,
        // by the same path layout, its node key) — profile A's settings must never bleed into B.
        // Driven via Backend::load against a temp state dir (no engine; switch only swaps files +
        // pointer when no device is up).
        let dir = std::env::temp_dir().join(format!("tailnetd-prof-sw-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        // Fresh daemon → default profile, legacy top-level paths (backward compatible).
        let mut be = Backend::load(&dir).await.unwrap();
        assert_eq!(be.current_profile, profile::DEFAULT_PROFILE_ID);
        assert_eq!(be.prefs_path, dir.join("prefs.json"));
        // Configure the default profile distinctively + persist.
        be.prefs.hostname = Some("default-host".into());
        be.prefs.accept_routes = true;
        be.ever_configured = true;
        be.persist_prefs().await.unwrap();

        // Create a new profile "work" and switch to it: its prefs start at default (NOT the default
        // profile's). Creation is explicit — a bare `switch work` refuses an unknown target, as Go's
        // `switchProfile` does.
        be.create_profile("work").await.unwrap();
        assert_eq!(be.current_profile, "work");
        assert_eq!(
            be.prefs_path,
            dir.join("profiles").join("work").join("prefs.json")
        );
        assert!(
            be.prefs.hostname.is_none() && !be.prefs.accept_routes,
            "a fresh profile must NOT inherit the default profile's prefs (isolation)"
        );
        // Configure "work" distinctively + persist.
        be.prefs.hostname = Some("work-host".into());
        be.ever_configured = true;
        be.persist_prefs().await.unwrap();

        // Switch back to default: its prefs are intact (work's changes didn't bleed in).
        be.switch_profile(profile::DEFAULT_PROFILE_ID)
            .await
            .unwrap();
        assert_eq!(be.prefs.hostname.as_deref(), Some("default-host"));
        assert!(be.prefs.accept_routes);

        // Switch to work again: work's prefs are intact too.
        be.switch_profile("work").await.unwrap();
        assert_eq!(be.prefs.hostname.as_deref(), Some("work-host"));
        assert!(!be.prefs.accept_routes);

        // list_profiles shows both, with the current marker on "work".
        let list = be.list_profiles().await;
        let work = list.iter().find(|e| e.id == "work").unwrap();
        let def = list
            .iter()
            .find(|e| e.id == profile::DEFAULT_PROFILE_ID)
            .unwrap();
        assert!(work.current && !def.current);

        // The pointer persists across a reload (a restart resumes the same profile).
        drop(be);
        let be2 = Backend::load(&dir).await.unwrap();
        assert_eq!(be2.current_profile, "work");
        assert_eq!(be2.prefs.hostname.as_deref(), Some("work-host"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn switch_profile_pointer_write_failure_keeps_old_profile_in_memory() {
        // D1 fix: if persisting the current-profile pointer fails, switch_profile must return Err
        // WITHOUT having committed the in-memory swap — the live backend stays coherently on the old
        // profile (matching the unchanged on-disk pointer), not diverged ahead of disk. We force the
        // pointer write to fail by making `current-profile` an un-removable DIRECTORY (write to a path
        // that is a dir errors with non-NotFound).
        let dir = std::env::temp_dir().join(format!("tailnetd-prof-d1-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = Backend::load(&dir).await.unwrap();
        be.prefs.hostname = Some("default-host".into());
        be.persist_prefs().await.unwrap();

        // Sabotage: make the pointer path a directory so `save_current_profile` fails.
        tokio::fs::create_dir_all(profile::current_profile_path(&dir))
            .await
            .unwrap();

        let before = be.current_profile.clone();
        let result = be.create_profile("work").await;
        assert!(
            result.is_err(),
            "a failed pointer write must surface as Err"
        );
        // The in-memory state must NOT have advanced past the failed commit.
        assert_eq!(
            be.current_profile, before,
            "current_profile must stay on the old profile when the pointer write failed"
        );
        assert_eq!(
            be.prefs.hostname.as_deref(),
            Some("default-host"),
            "prefs must not have been swapped to the target's"
        );
        assert_eq!(
            be.prefs_path,
            dir.join("prefs.json"),
            "paths must not have swapped"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn profile_delete_skips_the_current_profile_as_a_success_and_removes_others() {
        // Go's `removeProfile` never deletes the profile that is current, and says so as a SUCCESS:
        // `if profID == cp.ID { printf("Already on account %q\n", args[0]); os.Exit(0) }`. This
        // daemon used to raise an error there, so a ported script that walks a profile list and
        // removes each one finished under Go and exited non-zero here. The profile is still not
        // deleted — only the report and the exit status change.
        let dir = std::env::temp_dir().join(format!("tailnetd-prof-del-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = Backend::load(&dir).await.unwrap();

        // Create + populate "work" and stay on it.
        be.create_profile("work").await.unwrap();
        be.prefs.hostname = Some("work-host".into());
        be.persist_prefs().await.unwrap();

        // While on "work": the reserved `default` profile is refused. That refusal has no upstream
        // counterpart — Go has no such profile — and stands because `default` is not removable
        // state: it lives at the legacy top-level paths and always exists.
        assert!(
            be.delete_profile(profile::DEFAULT_PROFILE_ID)
                .await
                .is_err()
        );

        // Naming the CURRENT profile removes nothing and SUCCEEDS (Go's already-current exit).
        let (work_prefs, _) = profile::profile_paths(&dir, "work");
        assert!(tokio::fs::try_exists(&work_prefs).await.unwrap());
        assert_eq!(
            be.delete_profile("work").await.unwrap(),
            DeleteOutcome::AlreadyCurrent { id: "work".into() },
            "removing the current profile must be a no-op success, as in Go"
        );
        assert!(
            tokio::fs::try_exists(&work_prefs).await.unwrap(),
            "the current profile's prefs must survive the no-op removal"
        );
        assert!(
            be.list_profiles().await.iter().any(|e| e.id == "work"),
            "the current profile must still be listed after the no-op removal"
        );

        // Switch away, then the same target is really removed — files and listing entry both.
        be.switch_profile(profile::DEFAULT_PROFILE_ID)
            .await
            .unwrap();
        // The current-profile check runs BEFORE the `default` one, so naming the current profile
        // takes Go's already-current path even when it is `default` (which is otherwise refused).
        assert_eq!(
            be.delete_profile(profile::DEFAULT_PROFILE_ID)
                .await
                .unwrap(),
            DeleteOutcome::AlreadyCurrent {
                id: profile::DEFAULT_PROFILE_ID.into()
            }
        );
        assert_eq!(
            be.delete_profile("work").await.unwrap(),
            DeleteOutcome::Removed { id: "work".into() }
        );
        assert!(!tokio::fs::try_exists(&work_prefs).await.unwrap());
        // It's gone from the list (only default remains).
        let list = be.list_profiles().await;
        assert!(!list.iter().any(|e| e.id == "work"));
        // Removing it AGAIN is refused, not silently reported as success (Go: `No profile named
        // %q`). `remove` never creates, so an unmatched target is always an operator error — most
        // often a typo — and answering "removed" would say a profile is gone while it is still there.
        let err = be
            .delete_profile("work")
            .await
            .expect_err("removing an unknown profile must be refused, not a silent no-op");
        assert!(
            format!("{err:#}").contains("no profile named"),
            "unexpected error: {err:#}"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn profile_delete_resolves_display_names_like_switch_does() {
        // Go shares one `matchProfile` between `switch` and `switch remove`, so anything you can
        // switch to by display name you can also remove by display name. This daemon resolves the
        // target through the same `resolve_target_to_id`, so the two agree by construction — pinned
        // here because `delete_profile` used to require a literal id and would have refused a name.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-prof-delname-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = Backend::load(&dir).await.unwrap();

        // Create "work" and give it a display name, then switch away so it is removable.
        be.create_profile("work").await.unwrap();
        be.persist_prefs().await.unwrap();
        let mut meta = profile::load_profiles_file(&dir).await;
        meta.profiles.insert(
            "work".to_string(),
            profile::ProfileMeta {
                name: "Work tailnet".to_string(),
            },
        );
        profile::save_profiles_file(&dir, &meta).await.unwrap();
        be.switch_profile(profile::DEFAULT_PROFILE_ID)
            .await
            .unwrap();

        // Remove by DISPLAY NAME: resolves to the id, and the id is what comes back.
        assert_eq!(
            be.delete_profile("Work tailnet").await.unwrap(),
            DeleteOutcome::Removed { id: "work".into() }
        );
        assert!(!be.list_profiles().await.iter().any(|e| e.id == "work"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn switch_resolves_a_display_name_two_profiles_share_instead_of_conjuring_a_third() {
        // Go's `matchProfile` name pass returns the FIRST profile whose `Name` matches, so a
        // nickname two profiles share is a usable target. This daemon's resolver answered `None` for
        // it, and `switch_profile`'s no-match arm treats a syntactically valid target as a NEW
        // profile id — so `tnet switch shared` did not even refuse: it created a third profile
        // literally called "shared" and switched to that. Now the name resolves, like Go's.
        let dir = std::env::temp_dir().join(format!("tailnetd-prof-dup-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = Backend::load(&dir).await.unwrap();

        // Two profiles that both carry the nickname "shared" (Go's `LoginProfile.Name`, what
        // `set --nickname` writes here). `alpha` sorts first in `profiles.json`'s map.
        for id in ["alpha", "beta"] {
            be.create_profile(id).await.unwrap();
            be.persist_prefs().await.unwrap();
        }
        let mut meta = profile::load_profiles_file(&dir).await;
        for id in ["alpha", "beta"] {
            meta.profiles.insert(
                id.to_string(),
                profile::ProfileMeta {
                    name: "shared".to_string(),
                },
            );
        }
        profile::save_profiles_file(&dir, &meta).await.unwrap();
        be.switch_profile(profile::DEFAULT_PROFILE_ID)
            .await
            .unwrap();

        // The shared name switches to the first match rather than being refused or creating anew.
        match be.switch_profile("shared").await.unwrap() {
            SwitchOutcome::Switched { id, .. } => assert_eq!(
                id, "alpha",
                "a shared nickname must resolve to the first matching profile, as Go's pass does"
            ),
            other => panic!("expected a real switch, got {other:?}"),
        }
        assert!(
            !be.list_profiles().await.iter().any(|e| e.id == "shared"),
            "the shared name must not be taken for a new profile id"
        );

        // `switch remove` shares the resolver, so it agrees: the name names `alpha`, which is now
        // current — Go's already-current success, not a removal and not a refusal.
        assert_eq!(
            be.delete_profile("shared").await.unwrap(),
            DeleteOutcome::AlreadyCurrent { id: "alpha".into() }
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn switch_reports_already_current_separately_from_a_real_switch() {
        // The no-op switch must not claim a switch: Go answers `Already on account %q` and exits 0.
        // Also pins the settled state each outcome carries — the daemon never auto-`up`s the target,
        // so a fresh (never-registered) profile lands in `NoState` and a registered-but-down one in
        // `Stopped`, which is what the report's "log in" vs "connect" wording keys off.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-prof-outcome-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = Backend::load(&dir).await.unwrap();

        // Switching to the profile that is already current changes nothing.
        let outcome = be
            .switch_profile(profile::DEFAULT_PROFILE_ID)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            SwitchOutcome::AlreadyCurrent {
                id: profile::DEFAULT_PROFILE_ID.to_string()
            }
        );
        assert_eq!(outcome.report(), "already on profile \"default\"");
        assert_eq!(be.current_profile, profile::DEFAULT_PROFILE_ID);

        // A real switch to a brand-new profile: never registered → NoState → "log in" wording.
        let outcome = be.create_profile("work").await.unwrap();
        assert_eq!(
            outcome,
            SwitchOutcome::Switched {
                id: "work".to_string(),
                state: State::NoState,
            }
        );
        assert!(
            outcome.report().contains("log in"),
            "a profile with no node key must be reported as needing a login: {}",
            outcome.report()
        );

        // A profile that HAS a persisted node key and is explicitly down settles in `Stopped`, and
        // is reported as connectable rather than as logged out. Fake the key file the same way the
        // `has_node_key` cache reads it (a real key, minted by the engine's own keypair type).
        let (_, key_path) = profile::profile_paths(&dir, "keyed");
        tokio::fs::create_dir_all(key_path.parent().unwrap())
            .await
            .unwrap();
        // Mint a realistic key file with the engine's own loader (it create-on-missing-writes one),
        // the same way `has_persisted_node_key_true_after_key_file_written` does — so the on-disk
        // shape cannot drift from what the switch's node-key re-derivation parses.
        tailscale::config::load_key_file(&key_path, Default::default())
            .await
            .expect("mint a key file for the target profile");

        let outcome = be.create_profile("keyed").await.unwrap();
        assert_eq!(
            outcome,
            SwitchOutcome::Switched {
                id: "keyed".to_string(),
                state: State::Stopped,
            }
        );
        assert!(
            outcome.report().contains("connect") && !outcome.report().contains("log in"),
            "a registered, downed profile must be reported as connectable: {}",
            outcome.report()
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn switch_refuses_an_unmatched_target_instead_of_creating_a_profile() {
        // Go's `switchProfile` refuses a target that matches nothing and leaves the node alone:
        // `profID, ok := matchProfile(args[0], all); if !ok { errf("No profile named %q\n",
        // args[0]); os.Exit(1) }`. This daemon used to adopt any syntactically valid target as a NEW
        // profile id, so `tnet switch wrok-laptop` — a typo for the `work-laptop` nickname — tore the
        // live device down into a fresh empty profile and reported success. The typo is the whole
        // point of the test: it is the case where the two behaviours differ by a disconnect.
        let dir = std::env::temp_dir().join(format!("tailnetd-prof-typo-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = Backend::load(&dir).await.unwrap();

        // A configured default profile carrying the nickname the typo aims at.
        be.prefs.hostname = Some("default-host".into());
        be.ever_configured = true;
        be.persist_prefs().await.unwrap();
        be.rename_current_profile("work-laptop").await.unwrap();

        let generation_before = be.generation;
        let err = be
            .switch_profile("wrok-laptop")
            .await
            .expect_err("a target that matches no profile must be refused, not created");
        assert!(
            format!("{err:#}").contains("no profile named"),
            "unexpected error: {err:#}"
        );

        // Nothing moved: not the active profile, not its prefs, not the active paths.
        assert_eq!(be.current_profile, profile::DEFAULT_PROFILE_ID);
        assert_eq!(be.prefs.hostname.as_deref(), Some("default-host"));
        assert_eq!(be.prefs_path, dir.join("prefs.json"));
        // The generation is the teardown's fingerprint (`switch` bumps it to supersede an in-flight
        // `up`), so an unchanged one is the proof the refusal happened before any of that.
        assert_eq!(
            be.generation, generation_before,
            "a refused switch must not tear the device down"
        );
        // And nothing was created — no per-profile directory, no listing entry.
        assert!(
            !tokio::fs::try_exists(dir.join("profiles").join("wrok-laptop"))
                .await
                .unwrap(),
            "a refused switch must not create the target's state directory"
        );
        assert!(
            !be.list_profiles()
                .await
                .iter()
                .any(|e| e.id == "wrok-laptop"),
            "a refused switch must not register the target in profiles.json"
        );

        // The nickname the typo missed still resolves through the same call — this refuses unknown
        // targets, it does not stop resolving known ones. It is the current profile, so Go's
        // already-current success is what comes back.
        assert_eq!(
            be.switch_profile("work-laptop").await.unwrap(),
            SwitchOutcome::AlreadyCurrent {
                id: profile::DEFAULT_PROFILE_ID.to_string()
            }
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn create_profile_refuses_an_unusable_id_or_one_that_is_already_taken() {
        // `create_profile` (`tnet switch --new`) is where creating a profile moved to once `switch`
        // stopped doing it by accident. It has no upstream counterpart — Go creates profiles through
        // an interactive `tailscale login` — so its refusals are this fork's to state: an id that is
        // not a safe single path component, and one that already names a profile by id OR nickname
        // (an id shadows a nickname in the resolver's first pass, so allowing that would hide the
        // profile it collides with from every later `switch`/`switch remove`).
        let dir = std::env::temp_dir().join(format!("tailnetd-prof-new-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = Backend::load(&dir).await.unwrap();

        // The happy path: a fresh id is created, becomes current, and is listed.
        assert_eq!(
            be.create_profile("work").await.unwrap(),
            SwitchOutcome::Switched {
                id: "work".to_string(),
                state: State::NoState,
            }
        );
        assert!(be.list_profiles().await.iter().any(|e| e.id == "work"));

        // Asking to create it again is refused rather than quietly switching to it.
        let err = be
            .create_profile("work")
            .await
            .expect_err("--new must not adopt an existing profile");
        assert!(
            format!("{err:#}").contains("already exists"),
            "unexpected error: {err:#}"
        );

        // Give the current profile the nickname "shared": the id `shared` is now taken too, because
        // creating it would shadow this profile for every later lookup.
        be.rename_current_profile("shared").await.unwrap();
        let err = be
            .create_profile("shared")
            .await
            .expect_err("an id that collides with an existing nickname must be refused");
        assert!(
            format!("{err:#}").contains("already exists"),
            "unexpected error: {err:#}"
        );

        // The reserved `default` profile always exists, so it can never be created.
        assert!(
            be.create_profile(profile::DEFAULT_PROFILE_ID)
                .await
                .is_err(),
            "the always-present default profile must not be creatable"
        );

        // Ids that are not safe single path components are refused before anything is written — the
        // same rule `is_valid_profile_id` enforces, now stated at the only place that adopts a
        // caller-supplied id verbatim.
        for bad in ["", "..", "a/b", "a.b", "../../etc"] {
            let err = be
                .create_profile(bad)
                .await
                .expect_err("an id that is not a safe path component must be refused");
            assert!(
                format!("{err:#}").contains("not a usable profile id"),
                "unexpected error for {bad:?}: {err:#}"
            );
        }

        // None of the refusals moved the active profile or left state behind.
        assert_eq!(be.current_profile, "work");
        assert!(
            !tokio::fs::try_exists(dir.join("profiles").join("shared"))
                .await
                .unwrap()
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn logout_key_wipe_failure_aborts_before_flipping_logged_out() {
        // M3/M4 crash-safety: the key MUST be discarded BEFORE `logged_out` is persisted, so the two
        // can never disagree (logged_out set + old key resurrectable). If the key-wipe fails, logout
        // must return Err WITHOUT having flipped intent — so a retry cleanly re-attempts and a later
        // `up` can't resume the old registration on a "logged out" node. We force a non-NotFound
        // remove_file error by making `key_path` a NON-EMPTY directory (remove_file on a populated
        // dir fails with an error that is not NotFound on both Linux and macOS).
        let dir =
            std::env::temp_dir().join(format!("tailnetd-logout-wipefail-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        be.prefs.want_running = true;
        // Make the key_path an un-removable directory (non-empty → remove_file errors, not NotFound).
        tokio::fs::create_dir_all(&be.key_path).await.unwrap();
        tokio::fs::write(be.key_path.join("blocker"), b"x")
            .await
            .unwrap();

        let result = be.logout(alwayson::Actor::Operator { reason: None }).await;
        assert!(
            result.is_err(),
            "a key-wipe failure must make logout fail, not silently half-complete"
        );
        // The critical invariant: intent was NOT flipped, so on-disk/in-memory state stays coherent.
        assert!(
            !be.prefs.logged_out,
            "logout must NOT set logged_out when it could not discard the key (else a later `up` \
             resumes the old identity on a 'logged out' node)"
        );
        assert!(
            be.prefs.want_running,
            "logout must not flip want_running before the key is gone either"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn boot_attempted_up_defaults_false_and_flips() {
        // The SIGHUP reload path gates "retry auto-start" on this flag, so a fresh backend must
        // report `false` (a reload must NOT originate a connection from an out-of-band intent flip),
        // and `mark_boot_attempted_up` must flip it (so a transient boot failure CAN be retried).
        let dir = std::env::temp_dir().join(format!("tailnetd-bootflag-{}", std::process::id()));
        let mut backend = backend_for(&dir);
        assert!(
            !backend.boot_attempted_up(),
            "a fresh backend has not attempted a boot-time up"
        );
        backend.mark_boot_attempted_up();
        assert!(
            backend.boot_attempted_up(),
            "mark_boot_attempted_up must record the boot attempt"
        );
    }

    #[tokio::test]
    async fn has_persisted_node_key_false_for_fresh_dir() {
        // Fresh state dir, no key file → no persisted key (the daemon must take the fresh-auth path).
        let dir =
            std::env::temp_dir().join(format!("tailnetd-haskey-fresh-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let backend = backend_for(&dir);
        assert!(
            !backend.has_persisted_node_key().await,
            "a node that has never been brought up has no key file → no persisted key"
        );
        // The probe must be side-effect-free: it must NOT have created the key file just by checking.
        assert!(
            !tokio::fs::try_exists(dir.join("node.key.json"))
                .await
                .unwrap(),
            "has_persisted_node_key must not create the key file as a side effect"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn has_persisted_node_key_true_after_key_file_written() {
        // A key file carrying a `PersistState` node key (exactly what `up` persists) → resume is
        // possible. We serialize a real engine `PersistState` so the on-disk shape can never drift
        // from what `has_persisted_node_key` parses.
        let dir = std::env::temp_dir().join(format!("tailnetd-haskey-set-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let key_path = dir.join("node.key.json");
        // This is the side-effecting engine loader (it create-on-missing-writes the file) — used
        // here precisely to MINT a realistic key file for the assertion, not as the probe itself.
        tailscale::config::load_key_file(&key_path, Default::default())
            .await
            .expect("mint a key file");

        let backend = backend_for(&dir);
        assert!(
            backend.has_persisted_node_key().await,
            "a key file with a node key must read as a usable persisted key"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn restart_with_persisted_key_and_wantrunning_false_loads_as_stopped() {
        // The up→down→RESTART leg of the `has_node_key` gate, end-to-end through the REAL `load` path
        // (not the synthetic `derive_state_from` args). `up` persists a node key + leaves
        // want_running=true; `down` keeps the key and flips want_running=false; the daemon then
        // restarts. We reconstruct exactly that on-disk state (a real minted key file + a saved
        // want_running=false prefs in the default-profile paths), `Backend::load` it fresh, and assert
        // the node re-seeds `has_node_key=true` from disk and derives `Stopped` (Go's hasNodeKeyLocked
        // gate) — NOT `NoState`. This pins the `load`→`has_persisted_node_key` reseed that only the
        // synthetic unit test covered before; a regression in the load-path key re-read would flip
        // this to NoState and be caught here.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-restart-stopped-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        // Default-profile layout: <dir>/node.key.json + <dir>/prefs.json.
        let key_path = dir.join("node.key.json");
        tailscale::config::load_key_file(&key_path, Default::default())
            .await
            .expect("mint a persisted node key (what `up` writes)");
        // What `down` leaves behind: a persisted prefs with want_running=false, not logged out.
        let prefs = Prefs {
            want_running: false,
            logged_out: false,
            ..Prefs::default()
        };
        prefs
            .save(&dir.join("prefs.json"))
            .await
            .expect("persist the down prefs");

        // Restart: a fresh load from the same state dir (no engine, device-less).
        let be = Backend::load(&dir).await.expect("reload the daemon state");
        assert!(
            be.has_node_key,
            "load must re-seed has_node_key=true from the persisted key file"
        );
        assert!(!be.prefs.want_running, "down left want_running=false");
        assert!(!be.prefs.logged_out, "down did not log out");
        assert_eq!(
            be.derive_state(false),
            State::Stopped,
            "a restarted node with a persisted key + want_running=false must derive Stopped (Go's \
             hasNodeKeyLocked gate), not NoState"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn has_persisted_node_key_false_for_malformed_file() {
        // A truncated/corrupt key file must read as "no persisted key" so the daemon falls back to
        // fresh auth rather than trusting garbage (mirrors prefs' malformed-file fail-safe).
        let dir = std::env::temp_dir().join(format!("tailnetd-haskey-bad-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("node.key.json"), b"not json at all")
            .await
            .unwrap();

        let backend = backend_for(&dir);
        assert!(
            !backend.has_persisted_node_key().await,
            "a malformed key file must not be treated as a usable persisted key"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    // --- concurrent bring-up generation guard (tsd-jvn) --------------------------------------------

    #[tokio::test]
    async fn begin_up_then_down_supersedes_a_stale_finish_up() {
        // Models the race the begin_up/finish_up split exists to handle: an `up` starts (begin_up),
        // its slow handshake runs with the lock RELEASED, and a `down` lands first. The stale
        // `finish_up` must DISCARD its result (return Ok, install nothing) rather than clobber the
        // newer `down` intent. Driven without a real engine: begin_up + down are pure-ish (fs only),
        // and we hand finish_up an `Err` device so no real `Device` is needed for the stale path.
        let dir = std::env::temp_dir().join(format!("tailnetd-gen-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        let gen0 = be.generation;
        // Phase 1 of an `up`: prep config + bump generation (no engine call).
        let pending = be
            .begin_up(UpOptions::default(), None)
            .await
            .expect("begin_up");
        assert_eq!(
            pending.generation,
            gen0 + 1,
            "begin_up must bump the generation"
        );
        assert!(be.prefs.want_running, "begin_up sets want_running");

        // A `down` lands while the (hypothetical) handshake is still in flight → supersedes.
        be.down(alwayson::Actor::Operator { reason: None })
            .await
            .expect("down");
        assert!(!be.prefs.want_running, "down clears want_running");
        assert!(
            be.generation > pending.generation,
            "down must bump the generation past the in-flight up"
        );

        // The stale finish_up returns Ok(None) (no orphan to settle, since the stale build was an
        // Err) and installs NO device — the `down` intent wins. We pass an Err device so the
        // stale-path needs no real engine.
        let orphan = be
            .finish_up(
                pending,
                Err(anyhow!("handshake result is irrelevant once superseded")),
            )
            .expect("a superseded finish_up is a successful no-op");
        assert!(
            orphan.is_none(),
            "a stale build error yields no orphan device to shut down"
        );
        assert!(
            be.device.is_none(),
            "a superseded up must not install a device over the newer down intent"
        );
        // State reflects the down, not the stale up.
        assert_eq!(be.derive_state(false), State::Stopped);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn finish_up_with_current_generation_surfaces_engine_error() {
        // The non-stale path: when this attempt is still current and the engine build failed, the
        // error must propagate (so intent stays "up" with no device → NeedsLogin, and auto-start can
        // retry) — it must NOT be swallowed like the superseded case.
        let dir = std::env::temp_dir().join(format!("tailnetd-gen-err-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        let pending = be
            .begin_up(UpOptions::default(), None)
            .await
            .expect("begin_up");
        // No superseding call → pending.generation == be.generation. A build error must surface.
        let result = be.finish_up(pending, Err(anyhow!("simulated engine start failure")));
        assert!(
            result.is_err(),
            "a current (non-superseded) finish_up must propagate the engine error"
        );
        assert!(be.device.is_none(), "no device installed on engine failure");
        // want_running stayed true (begin_up set it) but no device → NeedsLogin, the retry state.
        assert_eq!(be.derive_state(false), State::NeedsLogin);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    // --- exit-node / advertise-routes config wiring (tsd) ----------------------------------------
    //
    // `build_config` parses the raw selector/CIDR strings prefs persist into the engine's typed
    // `ExitNodeSelector` / `ipnet::IpNet`. These tests pin the daemon's assumptions about the
    // engine API (so a facade bump that changed the `FromStr`/parse contract would trip here) and
    // the fail-loud-on-bad-CIDR behavior — all pure/offline, no live engine or network.

    #[test]
    fn exit_node_selector_parses_ip_vs_name() {
        // Confirms the daemon's assumption that the engine's `ExitNodeSelector: FromStr` is
        // infallible and discriminates a bare IP (→ `Ip`) from anything else (→ `Name`) — exactly
        // what `build_config`'s `s.parse().unwrap()` relies on. The `Err` is `Infallible`, so
        // `.unwrap()` is total here, not a swallowed fallible parse.
        let ip: tailscale::ExitNodeSelector = "100.64.0.9".parse().unwrap();
        assert!(
            matches!(ip, tailscale::ExitNodeSelector::Ip(_)),
            "a bare IP must parse to the Ip variant, got {ip:?}"
        );
        let name: tailscale::ExitNodeSelector = "mynode".parse().unwrap();
        assert!(
            matches!(name, tailscale::ExitNodeSelector::Name(_)),
            "a non-IP selector must parse to the Name variant, got {name:?}"
        );
    }

    #[test]
    fn advertise_route_cidr_parse_ok_and_fails_loud() {
        // Pins the fail-loud contract `build_config` depends on: a valid CIDR parses to
        // `ipnet::IpNet`, and a malformed one is an `Err` (which `build_config` turns into a
        // loud `anyhow` error naming the value, never a silent drop).
        assert!(
            "192.168.1.0/24".parse::<ipnet::IpNet>().is_ok(),
            "a valid CIDR must parse"
        );
        assert!(
            "nope".parse::<ipnet::IpNet>().is_err(),
            "a malformed CIDR must be an Err so build_config can fail loudly"
        );
    }

    #[tokio::test]
    async fn build_config_maps_exit_node_and_advertise_prefs() {
        // End-to-end (but offline) round-trip: prefs → `build_config` → engine `Config`. Exercises
        // the exit-node selector parse, the `advertise_exit_node` passthrough, and the
        // CIDR→`IpNet` collection in one place. `build_config` touches only the key file (created
        // on demand by the engine's `load_key_file`); it stands up NO engine and does NO network.
        let dir = std::env::temp_dir().join(format!("tailnetd-bc-ok-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        be.prefs.exit_node = Some("100.64.0.9".to_string());
        be.prefs.advertise_exit_node = true;
        be.prefs.advertise_routes = vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()];

        let cfg = be.build_config().await.expect("build_config");
        assert!(
            matches!(cfg.exit_node, Some(tailscale::ExitNodeSelector::Ip(_))),
            "a bare-IP exit_node pref must map to Config.exit_node = Some(Ip(..))"
        );
        assert!(
            cfg.advertise_exit_node,
            "advertise_exit_node pref must flow straight into Config"
        );
        assert_eq!(
            cfg.advertise_routes,
            vec![
                "192.168.1.0/24".parse::<ipnet::IpNet>().unwrap(),
                "10.0.0.0/8".parse::<ipnet::IpNet>().unwrap(),
            ],
            "every advertised CIDR must parse into Config.advertise_routes in order"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn wif_creds_from_wire_is_none_when_all_absent() {
        // The common case (plain authkey / interactive `up`): no WIF flag → `None`, so the daemon
        // skips the feature gate and the config plumbing entirely.
        assert!(
            WifCreds::from_wire(None, None, None, None).is_none(),
            "all-absent WIF must collapse to None"
        );
        // Any single field present → `Some` (so e.g. a lone `--audience` still triggers the gate).
        assert!(WifCreds::from_wire(None, None, None, Some("aud".into())).is_some());
        assert!(WifCreds::from_wire(Some("cid".into()), None, None, None).is_some());
    }

    #[tokio::test]
    async fn wif_creds_apply_to_config_sets_engine_fields() {
        // The WIF creds are NOT prefs: `build_config` (prefs-only) must leave the engine Config's WIF
        // fields empty, and `apply_to_config` is what writes them — the exact fields the engine's
        // `resolve_auth_key` reads under the `identity-federation` feature. Proves the secrets reach
        // the Config (exposed once) rather than being silently dropped.
        let dir = std::env::temp_dir().join(format!("tailnetd-wif-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let be = backend_for(&dir);
        let mut cfg = be.build_config().await.expect("build_config");
        // Prefs-only build leaves WIF fields empty (they are not prefs).
        assert!(cfg.client_id.is_none() && cfg.client_secret.is_none());
        assert!(cfg.id_token.is_none() && cfg.audience.is_none());

        let wif = WifCreds::from_wire(
            Some("oauth-client".into()),
            Some("tskey-client-secret".into()),
            None,
            Some("sts.example".into()),
        )
        .expect("some WIF");
        wif.apply_to_config(&mut cfg);
        assert_eq!(cfg.client_id.as_deref(), Some("oauth-client"));
        assert_eq!(cfg.client_secret.as_deref(), Some("tskey-client-secret"));
        assert_eq!(cfg.audience.as_deref(), Some("sts.example"));
        assert!(cfg.id_token.is_none(), "unset id_token stays None");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn identity_federation_built_matches_cfg() {
        // The runtime gate must track the compile-time feature exactly (the LocalAPI layer relies on
        // it to refuse WIF flags on a build that would ignore them).
        assert_eq!(
            identity_federation_built(),
            cfg!(feature = "identity-federation")
        );
    }

    #[tokio::test]
    async fn build_config_no_exit_node_leaves_config_default() {
        // The unchanged/clear path: a `None` exit_node pref must leave `Config.exit_node` at its
        // default (`None` = direct egress), and an empty advertise set yields an empty Vec.
        let dir = std::env::temp_dir().join(format!("tailnetd-bc-none-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let be = backend_for(&dir); // Prefs::default → exit_node None, advertise_routes empty.

        let cfg = be.build_config().await.expect("build_config");
        assert!(
            cfg.exit_node.is_none(),
            "no exit_node pref must leave Config.exit_node = None (direct egress)"
        );
        assert!(
            !cfg.advertise_exit_node,
            "default prefs do not advertise this node as an exit node"
        );
        assert!(
            cfg.advertise_routes.is_empty(),
            "no advertised routes → empty Config.advertise_routes"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn build_config_rejects_malformed_advertise_route() {
        // A bad CIDR must FAIL LOUDLY (not be silently dropped), with the offending value named in
        // the error — pinning the fail-loud contract end-to-end through `build_config`.
        let dir = std::env::temp_dir().join(format!("tailnetd-bc-bad-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        be.prefs.advertise_routes = vec!["192.168.1.0/24".to_string(), "not-a-cidr".to_string()];

        // `tailscale::Config` is not `Debug`, so `expect_err` (which would format the `Ok` value)
        // won't compile — match on the result and panic on the unexpected-`Ok` arm by hand.
        let err = match be.build_config().await {
            Ok(_) => panic!("a malformed advertise route must make build_config fail"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not-a-cidr"),
            "the error must name the offending CIDR value, got {msg:?}"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_set_rejects_malformed_advertise_route_without_persisting() {
        // FIX (set-persist-order): a malformed advertise-route CIDR must be rejected by `begin_set`
        // UP-FRONT, before any pref is mutated or persisted — so a failed `set` never writes a value
        // to prefs.json that the rebuild's `build_config` preflight would then reject, leaving
        // prefs inconsistent with the running device. Assert the error names the bad value AND that
        // NO pref moved (the named-alongside `accept_routes` must NOT have been applied) AND that
        // nothing was persisted to disk.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-set-badroute-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        // Seed a known-good baseline that must survive a rejected set untouched.
        be.prefs.advertise_routes = vec!["192.168.1.0/24".to_string()];

        let err = be
            .begin_set(SetOptions {
                // A valid route paired with a malformed one, plus an unrelated pref change — the
                // whole apply must be rejected atomically before any of it is persisted.
                advertise_routes: Some(vec!["10.0.0.0/8".to_string(), "not-a-cidr".to_string()]),
                accept_routes: Some(true),
                ..SetOptions::default()
            })
            .await
            .expect_err("a malformed advertise route must make begin_set fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not-a-cidr"),
            "the error must name the offending CIDR value, got {msg:?}"
        );
        // NOT mutated: neither the routes nor the co-named accept_routes moved (validate-before-apply).
        assert_eq!(
            be.prefs.advertise_routes,
            vec!["192.168.1.0/24".to_string()],
            "a rejected set must leave the advertise_routes pref untouched"
        );
        assert!(
            !be.prefs.accept_routes,
            "a rejected set must not have applied the co-named accept_routes change"
        );
        // NOT persisted: the validation fails before `persist_prefs`, so no prefs file was written.
        assert!(
            !tokio::fs::try_exists(dir.join("prefs.json")).await.unwrap(),
            "a set rejected for a bad CIDR must not have persisted prefs.json"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_set_completes_bare_advertise_tags() {
        // Go's `prefsFromUpArgs` lets an operator omit the `tag:` prefix — `--advertise-tags
        // server,ci` is `tag:server,tag:ci` — and every piece of upstream documentation an operator
        // copies from says so. This fork validates tags daemon-side so `up` and `set` share one
        // rule, so the completion has to live there too: a bare name must be ACCEPTED and stored in
        // its completed form, since `requested_tags` goes to control exactly as persisted.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-set-baretags-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        be.begin_set(SetOptions {
            // One shorthand, one already-prefixed: the completion is per-value.
            advertise_tags: Some(vec!["server".to_string(), "tag:ci".to_string()]),
            ..SetOptions::default()
        })
        .await
        .expect("a bare tag name must be accepted, as `tailscale set --advertise-tags server` is");
        assert_eq!(
            be.prefs.advertise_tags,
            vec!["tag:server".to_string(), "tag:ci".to_string()],
            "the COMPLETED tags must be what lands in prefs — control sees these verbatim"
        );
        // And the completed form is what was persisted, so the next boot advertises the same tags.
        let persisted = tokio::fs::read_to_string(dir.join("prefs.json"))
            .await
            .unwrap();
        assert!(
            persisted.contains("tag:server") && !persisted.contains("\"server\""),
            "prefs.json must hold the completed tag, got {persisted}"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_set_refuses_colon_bearing_non_tag_without_completing_it() {
        // The colon rule is the half of Go's completion that does the refusing: it applies ONLY to a
        // value with no colon at all, so a malformed `foo:bar` still reaches the `CheckTag` port and
        // is refused by name instead of being silently turned into `tag:foo:bar` — a tag nobody
        // asked for, advertised to control. Refused before anything is mutated or persisted.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-set-colontag-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        be.prefs.advertise_tags = vec!["tag:baseline".to_string()];

        let err = be
            .begin_set(SetOptions {
                advertise_tags: Some(vec!["foo:bar".to_string()]),
                accept_routes: Some(true),
                ..SetOptions::default()
            })
            .await
            .expect_err("a colon-bearing value that is not a tag must still be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("\"foo:bar\"") && !msg.contains("tag:foo:bar"),
            "the refusal must name the value as typed and must not show a completed one, got {msg:?}"
        );
        assert_eq!(
            be.prefs.advertise_tags,
            vec!["tag:baseline".to_string()],
            "a refused set must leave the tags pref untouched"
        );
        assert!(
            !be.prefs.accept_routes,
            "a refused set must not have applied the co-named accept_routes change"
        );
        assert!(
            !tokio::fs::try_exists(dir.join("prefs.json")).await.unwrap(),
            "a set refused for a bad tag must not have persisted prefs.json"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_up_completes_bare_advertise_tags() {
        // The same shorthand on the `up` path — this is the command in upstream's own docs
        // (`tailscale up --advertise-tags server`), and it used to be refused here by a rule an
        // operator copying that documentation has no reason to expect.
        let dir = std::env::temp_dir().join(format!("tailnetd-up-baretags-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        be.begin_up(
            UpOptions {
                advertise_tags: Some(vec!["server".to_string()]),
                ..UpOptions::default()
            },
            None,
        )
        .await
        .expect("a bare tag name must be accepted, as `tailscale up --advertise-tags server` is");
        assert_eq!(
            be.prefs.advertise_tags,
            vec!["tag:server".to_string()],
            "`up` must persist the completed tag, exactly as `set` does"
        );

        // And an illegal name is still refused — quoting the COMPLETED value, as Go's `tag: %q`
        // does, so the operator is shown the tag as the daemon would have seen it.
        let mut be = backend_for(&dir);
        // `PendingUp` is not `Debug`, so match rather than `expect_err` (as the other `begin_up`
        // tests do).
        match be
            .begin_up(
                UpOptions {
                    advertise_tags: Some(vec!["9server".to_string()]),
                    ..UpOptions::default()
                },
                None,
            )
            .await
        {
            Ok(_) => panic!("a completed tag with an illegal name must still be refused"),
            Err(e) => {
                let msg = format!("{e:#}");
                assert!(
                    msg.contains("\"tag:9server\""),
                    "the refusal must quote the completed value, got {msg:?}"
                );
            }
        }

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn validate_exit_node_selector_rejects_auto_passes_concrete() {
        // Go `--exit-node auto:any` enables automatic exit-node selection (ipn.AutoExitNode); this
        // build has no such machinery, so an `auto:`-prefixed value must be REJECTED loudly rather
        // than silently parsed as a peer named "auto:any" (which matches nothing → broken exit).
        // Concrete selectors (IP / MagicDNS name / stable id) and None/cleared pass through.
        assert!(
            validate_exit_node_selector(Some("auto:any")).is_err(),
            "`auto:any` (automatic selection) must be rejected — this build has no auto-selection"
        );
        assert!(
            validate_exit_node_selector(Some("auto:foo")).is_err(),
            "any `auto:`-prefixed selector must be rejected"
        );
        let msg = format!(
            "{:#}",
            validate_exit_node_selector(Some("auto:any")).unwrap_err()
        );
        assert!(
            msg.contains("auto:any") && msg.to_lowercase().contains("not supported"),
            "the error must name the value + say it's unsupported, got {msg:?}"
        );
        // Concrete selectors are fine.
        assert!(validate_exit_node_selector(Some("100.64.0.9")).is_ok());
        assert!(validate_exit_node_selector(Some("exit-node.example.ts.net")).is_ok());
        assert!(validate_exit_node_selector(Some("nABC123")).is_ok());
        // None (unchanged / cleared) is fine.
        assert!(validate_exit_node_selector(None).is_ok());
    }

    // --- `--exit-node` value resolution (Go `exitNodeIPOfArg`, ipn/prefs.go) ----------------------
    //
    // The engine's selector parse is infallible, so every one of these values would otherwise be
    // accepted, persisted, and silently route nothing. Each test calls the production
    // `resolve_exit_node_arg` (or a `Backend` path that calls it) — the expected refusals are Go's,
    // reproduced, not rebuilt in the test body.

    /// One netmap peer, named + addressed, advertising an exit node or not. Every other
    /// [`PeerReport`] field is irrelevant to resolution, so it stays at its default.
    fn exit_peer(name: &str, ipv4: &str, is_exit_node: bool) -> PeerReport {
        PeerReport {
            name: name.to_string(),
            ipv4: ipv4.to_string(),
            is_exit_node,
            ..PeerReport::default()
        }
    }

    /// A converged netmap: this node is `100.64.0.1` on the `tail0123.ts.net` tailnet, with `peers`
    /// visible. The shape [`Backend::exit_node_facts`] builds from a Running `status`.
    fn running_facts(peers: Vec<PeerReport>) -> ExitNodeFacts {
        ExitNodeFacts {
            running: true,
            self_ips: vec!["100.64.0.1".parse().unwrap()],
            magic_dns_suffix: Some("tail0123.ts.net".to_string()),
            peers,
        }
    }

    #[test]
    fn resolve_exit_node_arg_refuses_this_machines_own_address() {
        // Go `ExitNodeLocalIPError`, which `up` and `set` both re-wrap with the hint. Routing this
        // node's traffic through this node is not a thing; the operator meant to OFFER egress.
        let facts = running_facts(vec![exit_peer("exit.tail0123.ts.net", "100.64.0.7", true)]);
        let err = resolve_exit_node_arg("100.64.0.1", &facts)
            .expect_err("this machine's own address cannot be its exit node");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(
                "cannot use 100.64.0.1 as an exit node as it is a local IP address to this machine"
            ),
            "the refusal must be Go's sentence, got {msg:?}"
        );
        assert!(
            msg.contains("--advertise-exit-node"),
            "the refusal must carry Go's hint, got {msg:?}"
        );

        // The check needs no netmap, so it also fires before the node is Running: a self address is
        // a fact about this machine, not about the netmap's completeness.
        let not_running = ExitNodeFacts {
            running: false,
            ..facts
        };
        assert!(
            resolve_exit_node_arg("100.64.0.1", &not_running).is_err(),
            "the local-IP refusal is not gated on Running"
        );
    }

    #[test]
    fn resolve_exit_node_arg_checks_the_netmap_only_once_running() {
        // Go stages this: before `BackendState == "Running"` an unknown IP is accepted, because
        // "no peer holds it" only means "no netmap yet". Once Running it is a real refusal.
        let peers = vec![exit_peer("exit.tail0123.ts.net", "100.64.0.7", true)];
        let starting = ExitNodeFacts {
            running: false,
            peers: peers.clone(),
            ..ExitNodeFacts::default()
        };
        assert!(
            resolve_exit_node_arg("100.64.0.42", &starting).is_ok(),
            "a not-yet-Running node must not refuse an IP it simply has not learned about"
        );

        let err = resolve_exit_node_arg("100.64.0.42", &running_facts(peers))
            .expect_err("a Running node with a netmap must refuse an IP no peer holds");
        assert!(
            format!("{err:#}").contains("no node found in netmap with IP 100.64.0.42"),
            "got {err:#}"
        );
    }

    #[test]
    fn resolve_exit_node_arg_refuses_a_peer_advertising_no_exit_node() {
        // The peer exists and is reachable — it just never advertised a default route, so selecting
        // it would route nothing. Go refuses by IP and by name alike, naming the peer's IP.
        let facts = running_facts(vec![exit_peer(
            "plain.tail0123.ts.net",
            "100.64.0.8",
            false,
        )]);
        for arg in ["100.64.0.8", "plain", "plain.tail0123.ts.net"] {
            let err = format!(
                "{:#}",
                resolve_exit_node_arg(arg, &facts)
                    .expect_err("a peer that advertises no exit node must be refused")
            );
            assert!(
                err.contains("node 100.64.0.8 is not advertising an exit node"),
                "{arg:?} must be refused in Go's words, got {err:?}"
            );
        }
    }

    #[test]
    fn resolve_exit_node_arg_matches_a_peer_name_in_gos_three_spellings() {
        // Base name, FQDN, and FQDN without the trailing root dot — case-insensitively, the same
        // rule the engine's `Node::matches_name` applies to the stored selector afterwards.
        let facts = running_facts(vec![
            exit_peer("exit.tail0123.ts.net", "100.64.0.7", true),
            exit_peer("other.tail0123.ts.net", "100.64.0.8", false),
        ]);
        for arg in [
            "exit",
            "EXIT",
            "exit.tail0123.ts.net",
            "exit.tail0123.ts.net.",
            "Exit.Tail0123.TS.NET",
        ] {
            assert!(
                resolve_exit_node_arg(arg, &facts).is_ok(),
                "{arg:?} names the exit-advertising peer and must resolve"
            );
        }
        // The peer's own IP resolves too, and a *different* tailnet's FQDN does not.
        assert!(resolve_exit_node_arg("100.64.0.7", &facts).is_ok());
        assert!(
            resolve_exit_node_arg("exit.other.ts.net", &facts).is_err(),
            "the suffix is part of the name: a foreign FQDN must not match"
        );
    }

    #[test]
    fn resolve_exit_node_arg_refuses_a_name_before_the_peer_list_exists() {
        // Go refuses rather than attempting a resolution that could only fail, and says what to
        // pass instead. This is also why a bring-up on a node that has never seen a netmap can only
        // take an IP.
        let err = resolve_exit_node_arg("exit", &ExitNodeFacts::default())
            .expect_err("a name cannot be resolved against an empty peer list");
        assert!(
            format!("{err:#}").contains(
                "cannot resolve exit node by hostname while Tailscale is starting up; please use \
                 its Tailscale IP address instead"
            ),
            "got {err:#}"
        );
    }

    #[test]
    fn resolve_exit_node_arg_refuses_an_unknown_or_ambiguous_name() {
        // A typo (or a peer that has left) → Go's "invalid value"; two peers answering to one name
        // → Go's "ambiguous", because picking one would be a coin flip over which machine sees the
        // operator's traffic.
        let facts = running_facts(vec![exit_peer("exit.tail0123.ts.net", "100.64.0.7", true)]);
        let err = resolve_exit_node_arg("exti", &facts).expect_err("a typo must be refused");
        assert!(
            format!("{err:#}")
                .contains("invalid value \"exti\" for --exit-node; must be IP or peer hostname"),
            "got {err:#}"
        );

        let twins = running_facts(vec![
            exit_peer("exit.tail0123.ts.net", "100.64.0.7", true),
            exit_peer("exit.tail0123.ts.net", "100.64.0.9", true),
        ]);
        let err = resolve_exit_node_arg("exit", &twins)
            .expect_err("two peers answering to one name must be refused");
        assert!(
            format!("{err:#}").contains("ambiguous exit node name \"exit\""),
            "got {err:#}"
        );
    }

    #[test]
    fn resolve_exit_node_arg_refuses_an_empty_value() {
        // Go's `os.ErrInvalid` guard at the top of `exitNodeIPOfArg`, said usefully: an empty
        // `--exit-node` would otherwise be stored as a selector matching no peer.
        for arg in ["", "   "] {
            let err = resolve_exit_node_arg(arg, &running_facts(vec![]))
                .expect_err("an empty selector must be refused");
            assert!(
                format!("{err:#}").contains("empty value"),
                "got {err:#} for {arg:?}"
            );
        }
    }

    #[tokio::test]
    async fn begin_up_refuses_an_exit_node_it_cannot_resolve() {
        // The `up` wiring: an unresolvable `--exit-node` is refused BEFORE teardown/persist, so the
        // failed up leaves neither the device nor prefs.json touched. This backend has no device
        // (not Running), so a name has no peer list to resolve against.
        let dir = std::env::temp_dir().join(format!("tailnetd-up-badexit-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        // `PendingUp` is not `Debug`, so `expect_err` would not compile — match by hand.
        let err = match be
            .begin_up(
                UpOptions {
                    exit_node: Some(Some("no-such-peer".to_string())),
                    accept_routes: Some(true),
                    ..UpOptions::default()
                },
                None,
            )
            .await
        {
            Ok(_) => panic!("an unresolvable exit node must fail begin_up"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            err.contains("cannot resolve exit node by hostname"),
            "got {err:?}"
        );
        assert!(
            be.prefs.exit_node.is_none() && !be.prefs.accept_routes,
            "a refused up must not have applied the exit node or the co-named accept_routes"
        );
        assert!(
            !tokio::fs::try_exists(dir.join("prefs.json")).await.unwrap(),
            "a refused up must not have persisted prefs.json"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_set_refuses_an_exit_node_it_cannot_resolve() {
        // Same wiring on the `set` path, which is where it matters most on a live node: `set`
        // applies the exit node LIVE and never reaches `build_config`, so this is the only place an
        // unusable selector can be caught before it is persisted and silently routes nothing.
        let dir = std::env::temp_dir().join(format!("tailnetd-set-badexit-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        be.prefs.exit_node = Some("100.64.0.9".to_string());

        let err = be
            .begin_set(SetOptions {
                exit_node: Some(Some("no-such-peer".to_string())),
                accept_routes: Some(true),
                ..SetOptions::default()
            })
            .await
            .expect_err("an unresolvable exit node must fail begin_set");
        assert!(
            format!("{err:#}").contains("cannot resolve exit node by hostname"),
            "got {err:#}"
        );
        assert_eq!(
            be.prefs.exit_node.as_deref(),
            Some("100.64.0.9"),
            "a refused set must leave the previously-working exit node in place"
        );
        assert!(
            !be.prefs.accept_routes,
            "a refused set must not have applied the co-named accept_routes change"
        );
        assert!(
            !tokio::fs::try_exists(dir.join("prefs.json")).await.unwrap(),
            "a refused set must not have persisted prefs.json"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn check_prefs_reports_an_unresolvable_exit_node_once() {
        // The dry-run verb answers with the same refusal the real `up`/`set` would give — a
        // `check-prefs` that cannot report it is not a dry run. And an `auto:` value reports ONCE,
        // as itself, rather than also as a name that resolves against nothing.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-checkprefs-exit-{}", std::process::id()));
        let be = backend_for(&dir);
        let facts = running_facts(vec![exit_peer(
            "plain.tail0123.ts.net",
            "100.64.0.8",
            false,
        )]);

        let err = be
            .check_prefs_gated(
                Some(Some("100.64.0.8".into())),
                None,
                None,
                None,
                None,
                CheckPrefsEnv {
                    ssh_gate: Ok(()),
                    exit_node_facts: &facts,
                },
            )
            .expect_err("a peer advertising no exit node must be reported");
        assert!(
            format!("{err:#}").contains("node 100.64.0.8 is not advertising an exit node"),
            "got {err:#}"
        );

        // A selector that resolves is accepted.
        let ok = be.check_prefs_gated(
            Some(Some("100.64.0.7".into())),
            None,
            None,
            None,
            None,
            CheckPrefsEnv {
                ssh_gate: Ok(()),
                exit_node_facts: &running_facts(vec![exit_peer(
                    "exit.tail0123.ts.net",
                    "100.64.0.7",
                    true,
                )]),
            },
        );
        assert!(ok.is_ok(), "a real exit node must be accepted: {ok:?}");

        // `auto:` is refused by rule (1) alone; the resolution must not pile a second sentence on.
        let err = format!(
            "{:#}",
            be.check_prefs_gated(
                Some(Some("auto:any".into())),
                None,
                None,
                None,
                None,
                CheckPrefsEnv {
                    ssh_gate: Ok(()),
                    exit_node_facts: &facts,
                },
            )
            .expect_err("auto: selection is unsupported")
        );
        assert!(err.contains("not supported"), "got {err:?}");
        assert!(
            !err.contains("invalid value") && !err.contains("starting up"),
            "an auto: value must report once, as itself, got {err:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn begin_up_rejects_auto_exit_node_without_persisting() {
        // `up --exit-node auto:any` must be rejected up-front (before teardown/persist), so a failed
        // up never tears down the device or writes prefs.json for an unsupported auto-selection.
        let dir = std::env::temp_dir().join(format!("tailnetd-up-autoexit-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        // `begin_up` returns `Result<PendingUp>` and `PendingUp` is not `Debug`, so `expect_err`
        // (which would format the `Ok` value) won't compile — match by hand.
        let err = match be
            .begin_up(
                UpOptions {
                    exit_node: Some(Some("auto:any".to_string())),
                    ..UpOptions::default()
                },
                None,
            )
            .await
        {
            Ok(_) => panic!("up --exit-node auto:any must fail (no auto-selection in this build)"),
            Err(e) => e,
        };
        assert!(
            format!("{err:#}").contains("auto:any"),
            "the error must name the rejected selector"
        );
        assert!(
            be.prefs.exit_node.is_none(),
            "a rejected auto: exit node must not have been applied to prefs"
        );
        assert!(
            !tokio::fs::try_exists(dir.join("prefs.json")).await.unwrap(),
            "an up rejected for auto: exit node must not have persisted prefs.json"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_set_rejects_auto_exit_node_without_persisting() {
        // `set --exit-node auto:any` must be rejected up-front, leaving prefs untouched + unpersisted.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-set-autoexit-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        let err = be
            .begin_set(SetOptions {
                exit_node: Some(Some("auto:any".to_string())),
                accept_routes: Some(true),
                ..SetOptions::default()
            })
            .await
            .expect_err("set --exit-node auto:any must fail");
        assert!(format!("{err:#}").contains("auto:any"));
        assert!(
            be.prefs.exit_node.is_none() && !be.prefs.accept_routes,
            "a rejected set must not have applied exit_node OR the co-named accept_routes"
        );
        assert!(
            !tokio::fs::try_exists(dir.join("prefs.json")).await.unwrap(),
            "a set rejected for auto: exit node must not have persisted prefs.json"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_up_rejects_malformed_advertise_route_without_persisting() {
        // FIX (set-persist-order), the `up`/`begin_up` half: a malformed advertise-route CIDR must be
        // rejected up-front, before the device is torn down, prefs mutated, or persisted — so a
        // failed `up` neither drops a live engine nor writes a doomed value to prefs.json. Assert the
        // error names the value and that nothing was persisted.
        let dir = std::env::temp_dir().join(format!("tailnetd-bu-badroute-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        // `begin_up` returns `Result<PendingUp>` and `PendingUp` is not `Debug`, so `expect_err`
        // (which would format the `Ok` value) won't compile — match by hand like
        // `build_config_rejects_malformed_advertise_route`.
        let err = match be
            .begin_up(
                UpOptions {
                    advertise_routes: Some(vec!["10.0.0.0/8".to_string(), "nope/33".to_string()]),
                    ..UpOptions::default()
                },
                None,
            )
            .await
        {
            Ok(_) => panic!("a malformed advertise route must make begin_up fail"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("nope/33"),
            "the error must name the offending CIDR value, got {msg:?}"
        );
        // begin_up sets want_running before persist, but the early CIDR reject is BEFORE that — so a
        // rejected up must not have flipped want_running nor persisted prefs.
        assert!(
            !be.prefs.want_running,
            "a CIDR-rejected up must not have flipped want_running (reject is before that)"
        );
        assert!(
            !tokio::fs::try_exists(dir.join("prefs.json")).await.unwrap(),
            "an up rejected for a bad CIDR must not have persisted prefs.json"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_up_refuses_a_lone_default_route_without_persisting() {
        // The half-exit-node leak on the `up` path (Go `netutil.CalcAdvertiseRoutes`): advertising
        // `0.0.0.0/0` alone takes clients' v4 traffic while their v6 leaves out their own link. Refused
        // before the device is torn down or a pref is written, naming the counterpart to add.
        let dir = std::env::temp_dir().join(format!("tailnetd-bu-halfexit-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        let err = match be
            .begin_up(
                UpOptions {
                    advertise_routes: Some(vec![
                        "0.0.0.0/0".to_string(),
                        "192.0.2.0/24".to_string(),
                    ]),
                    ..UpOptions::default()
                },
                None,
            )
            .await
        {
            Ok(_) => panic!("a lone v4 default route must make begin_up fail"),
            Err(e) => e,
        };
        assert_eq!(
            format!("{err:#}"),
            "0.0.0.0/0 advertised without its IPv6 counterpart, please also advertise ::/0"
        );
        assert!(
            !be.prefs.want_running && be.prefs.advertise_routes.is_empty(),
            "the refusal is before any pref moves"
        );
        assert!(
            !tokio::fs::try_exists(dir.join("prefs.json")).await.unwrap(),
            "an up refused for a half-advertised default route must not have persisted prefs.json"
        );

        // Naming BOTH defaults is an exit node spelled the long way, and is accepted.
        be.begin_up(
            UpOptions {
                advertise_routes: Some(vec!["0.0.0.0/0".to_string(), "::/0".to_string()]),
                ..UpOptions::default()
            },
            None,
        )
        .await
        .expect("both default routes together are a whole exit node");
        assert_eq!(
            be.prefs.advertise_routes,
            vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
            "the operator's own list is what is stored — the check is a validation, not a rewrite"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_set_judges_the_route_set_the_two_prefs_compose() {
        // `--advertise-routes` and `--advertise-exit-node` are separate prefs here, so the pairing rule
        // has to be asked of what they produce TOGETHER — on `set`, which changes them one at a time.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-set-halfexit-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        // (a) The v4 default alongside the exit-node advertisement: both families are advertised, so
        // this is accepted — the rule is about the set, not about the flag's literal argument.
        be.begin_set(SetOptions {
            advertise_routes: Some(vec!["0.0.0.0/0".to_string()]),
            advertise_exit_node: Some(true),
            ..SetOptions::default()
        })
        .await
        .expect("a v4 default plus the exit-node advertisement advertises both defaults");
        assert!(be.prefs.advertise_exit_node);

        // (b) Dropping the exit-node advertisement now LEAVES that lone v4 default behind — the same
        // leak, arrived at from the other side — so it is refused, and nothing moves.
        let err = be
            .begin_set(SetOptions {
                advertise_exit_node: Some(false),
                ..SetOptions::default()
            })
            .await
            .expect_err("dropping the exit-node advertisement must not leave a lone default route");
        assert_eq!(
            format!("{err:#}"),
            "0.0.0.0/0 advertised without its IPv6 counterpart, please also advertise ::/0"
        );
        assert!(
            be.prefs.advertise_exit_node,
            "a refused set leaves the pref it was refusing to change"
        );

        // (c) Dropping BOTH together is coherent, and accepted.
        be.begin_set(SetOptions {
            advertise_routes: Some(vec![]),
            advertise_exit_node: Some(false),
            ..SetOptions::default()
        })
        .await
        .expect("clearing the routes and the exit-node advertisement together is coherent");
        assert!(!be.prefs.advertise_exit_node && be.prefs.advertise_routes.is_empty());

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn check_prefs_reports_the_route_set_rules() {
        // The dry-run verb reports exactly what `up`/`set` would refuse, including both new set-level
        // rules, and still reports every reason in one answer.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-checkprefs-routes-{}", std::process::id()));
        let be = backend_for(&dir);

        let err = be
            .check_prefs(None, None, Some(vec!["::/0".into()]), None, None)
            .await
            .expect_err("a lone v6 default route must be reported");
        assert_eq!(
            err.to_string(),
            "::/0 advertised without its IPv4 counterpart, please also advertise 0.0.0.0/0"
        );

        // A 4via6 prefix that cannot carry a site id is reported as the malformed via route it is,
        // not accepted as an ordinary IPv6 route (Go `netutil.ValidateViaPrefix`).
        let err = be
            .check_prefs(
                None,
                None,
                Some(vec!["fd7a:115c:a1e0:b1a::/64".into()]),
                None,
                None,
            )
            .await
            .expect_err("a 4via6 prefix shorter than /96 must be reported");
        assert_eq!(
            err.to_string(),
            "fd7a:115c:a1e0:b1a::/64 4-in-6 prefix must be at least a /96"
        );

        // The exit-node advertisement supplies both defaults, so the v4 default is fine beside it —
        // and a plain subnet route was never in question.
        assert!(
            be.check_prefs(None, Some(true), Some(vec!["0.0.0.0/0".into()]), None, None)
                .await
                .is_ok(),
            "advertising as an exit node advertises both default routes"
        );
        assert!(
            be.check_prefs(None, None, Some(vec!["192.0.2.0/24".into()]), None, None)
                .await
                .is_ok(),
            "an ordinary subnet route is unaffected"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn begin_up_applies_exit_node_and_advertise_overrides() {
        // The `UpOptions` sentinel semantics, end-to-end through `begin_up`: a `Some(Some(sel))`
        // sets exit_node, a `Some(None)` clears it, and the advertise overrides set/clear. Driven
        // without an engine (begin_up only mutates + persists prefs and builds Config).
        let dir =
            std::env::temp_dir().join(format!("tailnetd-bu-overrides-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        // SET via overrides. The exit node is given as an IP: this backend has no device, so it is
        // not Running, and `begin_up` now refuses to resolve a *name* against a peer list that does
        // not exist yet (Go's "cannot resolve exit node by hostname while Tailscale is starting up"
        // — pinned by `resolve_exit_node_arg_refuses_a_name_before_the_peer_list_exists`). This test
        // is about the override sentinels, not about resolution.
        let _ = be
            .begin_up(
                UpOptions {
                    exit_node: Some(Some("100.64.0.9".to_string())),
                    advertise_exit_node: Some(true),
                    advertise_routes: Some(vec!["10.0.0.0/8".to_string()]),
                    ..UpOptions::default()
                },
                None,
            )
            .await
            .expect("begin_up set");
        assert_eq!(be.prefs.exit_node.as_deref(), Some("100.64.0.9"));
        assert!(be.prefs.advertise_exit_node);
        assert_eq!(be.prefs.advertise_routes, vec!["10.0.0.0/8".to_string()]);

        // A plain follow-up `up` (all None) must leave the prefs UNCHANGED.
        let _ = be
            .begin_up(UpOptions::default(), None)
            .await
            .expect("begin_up unchanged");
        assert_eq!(
            be.prefs.exit_node.as_deref(),
            Some("100.64.0.9"),
            "an unchanged (None) override must preserve the stored exit_node"
        );
        assert!(
            be.prefs.advertise_exit_node,
            "unchanged override preserves it"
        );
        assert_eq!(be.prefs.advertise_routes, vec!["10.0.0.0/8".to_string()]);

        // CLEAR exit_node via `Some(None)`, clear the advertised set via `Some(vec![])`.
        let _ = be
            .begin_up(
                UpOptions {
                    exit_node: Some(None),
                    advertise_exit_node: Some(false),
                    advertise_routes: Some(vec![]),
                    ..UpOptions::default()
                },
                None,
            )
            .await
            .expect("begin_up clear");
        assert!(
            be.prefs.exit_node.is_none(),
            "Some(None) must clear the exit_node pref"
        );
        assert!(!be.prefs.advertise_exit_node);
        assert!(be.prefs.advertise_routes.is_empty());

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_up_reset_wipes_unmentioned_prefs_to_default_then_applies_overrides() {
        // `up --reset --ssh` is the one true wholesale-REPLACE path: every up-managed pref the
        // command does NOT mention is reset to default FIRST, then the named overrides layer on top.
        // So a node with routes+accept+exit-node+hostname set, given `--reset --ssh`, ends with ONLY
        // ssh_enabled set and everything else back at default. Lifecycle prefs (want_running) survive.
        let dir = std::env::temp_dir().join(format!("tailnetd-bu-reset-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        // Seed a richly-configured node.
        let _ = be
            .begin_up(
                UpOptions {
                    hostname: Some("node-a".to_string()),
                    exit_node: Some(Some("100.64.0.9".to_string())),
                    advertise_exit_node: Some(true),
                    advertise_routes: Some(vec!["10.0.0.0/8".to_string()]),
                    accept_routes: Some(true),
                    ..UpOptions::default()
                },
                None,
            )
            .await
            .expect("begin_up seed");
        assert_eq!(be.prefs.advertise_routes, vec!["10.0.0.0/8".to_string()]);

        // `up --reset --accept-routes`: reset everything unmentioned, set only accept_routes. (We
        // mention `accept_routes` rather than `ssh` so the assertion holds in BOTH feature configs —
        // a mentioned `ssh: Some(true)` would trip `build_config`'s SSH-feature/root preflight in the
        // default no-`ssh` build, which is a separate, already-tested behavior; this test is about the
        // reset mechanics, not the SSH preflight.)
        let _ = be
            .begin_up(
                UpOptions {
                    accept_routes: Some(true),
                    reset: true,
                    ..UpOptions::default()
                },
                None,
            )
            .await
            .expect("begin_up reset");

        assert!(
            be.prefs.accept_routes,
            "the mentioned --accept-routes override applies"
        );
        assert!(
            be.prefs.exit_node.is_none(),
            "--reset wipes the unmentioned exit_node back to default"
        );
        assert!(
            !be.prefs.advertise_exit_node,
            "--reset wipes advertise_exit_node"
        );
        assert!(
            be.prefs.advertise_routes.is_empty(),
            "--reset wipes the advertised route set"
        );
        assert!(
            be.prefs.hostname.is_none(),
            "--reset wipes the unmentioned hostname"
        );
        assert!(
            !be.prefs.ssh_enabled,
            "--reset wipes ssh_enabled (it was never set here, but proves the reset covers it)"
        );
        assert!(
            be.prefs.want_running,
            "--reset must NOT touch the lifecycle pref want_running"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_up_reset_keeps_a_mentioned_pref_value() {
        // `--reset` resets unmentioned prefs but a pref the command DOES mention keeps its new value
        // (the override layers on AFTER the reset). `up --reset --advertise-routes=192.168.0.0/16`
        // on a node advertising 10/8 ends advertising ONLY 192.168/16, not the wiped 10/8.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-bu-reset-keep-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        let _ = be
            .begin_up(
                UpOptions {
                    advertise_routes: Some(vec!["10.0.0.0/8".to_string()]),
                    accept_routes: Some(true),
                    ..UpOptions::default()
                },
                None,
            )
            .await
            .expect("begin_up seed");

        let _ = be
            .begin_up(
                UpOptions {
                    advertise_routes: Some(vec!["192.168.0.0/16".to_string()]),
                    reset: true,
                    ..UpOptions::default()
                },
                None,
            )
            .await
            .expect("begin_up reset+mention");

        assert_eq!(
            be.prefs.advertise_routes,
            vec!["192.168.0.0/16".to_string()],
            "the mentioned override replaces the set even under --reset"
        );
        assert!(
            !be.prefs.accept_routes,
            "the unmentioned accept_routes is still wiped by --reset"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_up_applies_accept_routes_override() {
        // `UpOptions.accept_routes` (Go `up --accept-routes`) uses the same "unchanged unless named"
        // sentinel as the other up overrides: `Some(true)` enables, `Some(false)` disables, `None`
        // leaves the pref untouched. Driven without an engine (begin_up only mutates + persists prefs
        // and builds Config; default prefs have accept_routes false so no SSH/TUN preflight fires).
        let dir = std::env::temp_dir().join(format!("tailnetd-bu-accept-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        assert!(
            !be.prefs.accept_routes,
            "default prefs do not accept routes"
        );

        // ENABLE via the override.
        let _ = be
            .begin_up(
                UpOptions {
                    accept_routes: Some(true),
                    ..UpOptions::default()
                },
                None,
            )
            .await
            .expect("begin_up accept_routes enable");
        assert!(
            be.prefs.accept_routes,
            "Some(true) must enable accept_routes"
        );

        // A plain follow-up `up` (None) must leave it enabled (unchanged).
        let _ = be
            .begin_up(UpOptions::default(), None)
            .await
            .expect("begin_up unchanged");
        assert!(
            be.prefs.accept_routes,
            "a None accept_routes override must preserve the stored value"
        );

        // DISABLE via the override.
        let _ = be
            .begin_up(
                UpOptions {
                    accept_routes: Some(false),
                    ..UpOptions::default()
                },
                None,
            )
            .await
            .expect("begin_up accept_routes disable");
        assert!(
            !be.prefs.accept_routes,
            "Some(false) must disable accept_routes"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    // --- `set` (tnet set) — SetOptions truth table + offline prefs reconciliation (tsd) ----------
    //
    // The live (`set_exit_node`) and rebuild paths need a real engine, so they are NOT unit-tested
    // here (that is integration territory); these tests pin the PURE decision surface — the
    // `SetOptions` predicates the server gates on, and the `begin_set` prefs-apply + sentinel
    // semantics on a device-less backend (which returns `PersistedOnly`, doing no engine I/O). All
    // offline: no `Device::new`, no network.

    #[test]
    fn set_options_is_empty_truth_table() {
        // A `set` with nothing named is a no-op the server rejects early → `is_empty` must be true
        // ONLY for the all-`None` default, and false the instant any single field is named (incl.
        // the exit_node CLEAR form `Some(None)`, which is a real change, not "empty").
        assert!(
            SetOptions::default().is_empty(),
            "an all-None SetOptions is empty"
        );
        assert!(
            !SetOptions {
                hostname: Some("h".into()),
                ..SetOptions::default()
            }
            .is_empty(),
            "a named hostname is not empty"
        );
        assert!(
            !SetOptions {
                accept_routes: Some(true),
                ..SetOptions::default()
            }
            .is_empty(),
            "a named accept_routes is not empty"
        );
        assert!(
            !SetOptions {
                exit_node: Some(None),
                ..SetOptions::default()
            }
            .is_empty(),
            "an exit_node CLEAR (Some(None)) is a real change, not empty"
        );
        assert!(
            !SetOptions {
                advertise_exit_node: Some(false),
                ..SetOptions::default()
            }
            .is_empty(),
            "a named advertise_exit_node is not empty"
        );
        assert!(
            !SetOptions {
                advertise_routes: Some(vec![]),
                ..SetOptions::default()
            }
            .is_empty(),
            "a named advertise_routes (even the clearing empty vec) is not empty"
        );
        // An ssh-only `set` (toggle the SSH server) is a real change → NOT empty (so the server does
        // not reject `tnet set --ssh` as a no-op).
        assert!(
            !SetOptions {
                ssh: Some(true),
                ..SetOptions::default()
            }
            .is_empty(),
            "a named ssh toggle is not empty"
        );
    }

    #[test]
    fn set_options_needs_rebuild_truth_table() {
        // The path discriminator on a RUNNING node: `needs_rebuild` is true IFF the request names a
        // pref with NO live engine setter — `shields_up`, `ssh`, or `advertise_tags`. The five
        // live-applicable fields (exit_node / hostname / accept_routes / advertise_routes /
        // advertise_exit_node) each apply in place, so naming ONLY those is a no-reconnect live set.

        // Each live-applicable pref ALONE → live (no rebuild). Both exit_node forms (SET + CLEAR).
        assert!(
            !SetOptions {
                exit_node: Some(Some("100.64.0.9".into())),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "exit_node SET alone is live"
        );
        assert!(
            !SetOptions {
                exit_node: Some(None),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "exit_node CLEAR alone is live"
        );
        assert!(
            !SetOptions {
                hostname: Some("h".into()),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "hostname alone is live (set_hostname)"
        );
        assert!(
            !SetOptions {
                accept_routes: Some(true),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "accept_routes alone is live (set_accept_routes)"
        );
        assert!(
            !SetOptions {
                advertise_routes: Some(vec!["10.0.0.0/24".into()]),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "advertise_routes alone is live (set_advertise_routes)"
        );
        assert!(
            !SetOptions {
                advertise_exit_node: Some(true),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "advertise_exit_node alone is live (set_advertise_exit_node)"
        );

        // An all-live MIX → still live (no rebuild): the whole point of the generalized path.
        assert!(
            !SetOptions {
                hostname: Some("h".into()),
                accept_routes: Some(true),
                advertise_exit_node: Some(true),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "a mix of only live-applicable prefs stays live"
        );

        // Each rebuild-only pref ALONE → rebuild (no live setter exists).
        assert!(
            SetOptions {
                shields_up: Some(true),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "shields_up has no live setter (immutable block_incoming) → rebuild"
        );
        assert!(
            SetOptions {
                ssh: Some(true),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "ssh is a device-lifecycle task → rebuild"
        );
        assert!(
            SetOptions {
                advertise_tags: Some(vec!["tag:server".into()]),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "advertise_tags is registration-time → rebuild"
        );

        // The mixed-change rule: a live-applicable pref paired with ANY rebuild-only pref → rebuild
        // the whole set (the rebuild re-applies the live one anyway). One case per rebuild-forcer.
        assert!(
            SetOptions {
                hostname: Some("h".into()),
                shields_up: Some(true),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "hostname + shields_up → rebuild (shields_up forces it)"
        );
        assert!(
            SetOptions {
                exit_node: Some(Some("100.64.0.9".into())),
                ssh: Some(true),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "exit_node + ssh → rebuild (ssh forces it)"
        );
        assert!(
            SetOptions {
                accept_routes: Some(true),
                advertise_tags: Some(vec!["tag:ci".into()]),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "accept_routes + advertise_tags → rebuild (tags force it)"
        );

        // The two WIRE-advertised prefs alone → rebuild: the engine sends them from a
        // construction-time Config field on every map request, so a live node would otherwise keep
        // advertising the old value until the next restart (the silent persists-without-effect trap).
        assert!(
            SetOptions {
                advertise_connector: Some(true),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "advertise_connector reaches Hostinfo.AppConnector from an immutable Config → rebuild"
        );
        assert!(
            SetOptions {
                auto_update: Some(true),
                ..SetOptions::default()
            }
            .needs_rebuild(),
            "auto_update reaches Hostinfo.AllowsUpdate from an immutable Config → rebuild"
        );

        // The six CARRIED prefs alone → NO rebuild: the pinned engine stores each and never acts on
        // or advertises it, so the persisted pref is the whole change and a reconnect would buy
        // nothing. Naming one must still make the request non-empty (the server would otherwise
        // reject it as "no preferences specified").
        type CarriedCase = (&'static str, fn(&mut SetOptions));
        let carried: Vec<CarriedCase> = vec![
            ("update_check", |o| o.update_check = Some(false)),
            ("operator", |o| o.operator = Some(Some("alice".into()))),
            ("nickname", |o| o.nickname = Some(Some("laptop".into()))),
            ("report_posture", |o| o.report_posture = Some(true)),
            ("webclient", |o| o.webclient = Some(true)),
            ("exit_node_allow_lan_access", |o| {
                o.exit_node_allow_lan_access = Some(true)
            }),
        ];
        for (name, apply) in &carried {
            let mut opts = SetOptions::default();
            apply(&mut opts);
            assert!(
                !opts.is_empty(),
                "{name}: a named set must not be is_empty()"
            );
            assert!(
                !opts.needs_rebuild(),
                "{name} is a CARRIED pref (the engine never acts on or sends it) — it must NOT force \
                 a reconnect"
            );
        }

        // An empty set names no rebuild-only pref → needs_rebuild is false (the server rejects an
        // empty set earlier via is_empty; needs_rebuild is only consulted for a non-empty, device-up
        // set).
        assert!(
            !SetOptions::default().needs_rebuild(),
            "an empty set needs no rebuild"
        );
    }

    #[test]
    fn set_options_live_vs_rebuild_classification_no_silent_drift() {
        // Structural drift tripwire — the `SetOptions` analogue of the `Prefs`/`UpOptions` lockstep
        // tests in `revert_guard`. EXHAUSTIVELY destructure `SetOptions` with NO `..`, so adding a
        // field is a COMPILE error until it is consciously classified LIVE (an in-place engine setter
        // is called in `begin_set`, so a `set` naming only it applies with no reconnect), REBUILD
        // (the engine acts on it but has no live setter → `needs_rebuild()` must return true so the
        // device is rebuilt), or CARRIED (the engine stores it and never acts on or sends it, so
        // there is nothing to reconcile — neither a setter nor a rebuild). Without this,
        // a new field defaults to the Live path and SILENTLY persists-without-effect on a running node
        // until the next restart — the exact exit_node/has_logged_in/funnel bug-class this repo has
        // been burned by. The runtime half below proves each field's classification actually holds.
        let SetOptions {
            // --- LIVE (has a Device::set_* called in begin_set; needs_rebuild=false alone) ---
            hostname: _,
            accept_routes: _,
            accept_dns: _,
            exit_node: _,
            advertise_exit_node: _,
            advertise_routes: _,
            // --- REBUILD (the engine ACTS on it with no live setter → MUST be in needs_rebuild()) ---
            shields_up: _,
            advertise_tags: _,
            ssh: _,
            // `advertise_connector`/`auto_update` reach control from a construction-time `Config`
            // field (`Hostinfo.AppConnector` / `Hostinfo.AllowsUpdate`, re-sent on every map
            // request), so a running node keeps advertising the OLD value until it is rebuilt.
            advertise_connector: _,
            auto_update: _,
            // --- CARRIED (the pinned engine stores it but never acts on or sends it, so a live
            //     device holding the stale copy is indistinguishable from one holding the new value:
            //     nothing to reconcile, and forcing a reconnect would be an outage for no behavior
            //     change. needs_rebuild() must stay FALSE and no live setter is issued.) ---
            update_check: _,
            operator: _,
            nickname: _,
            report_posture: _,
            webclient: _,
            exit_node_allow_lan_access: _,
        } = SetOptions::default();

        // Runtime half: a `set` naming ONLY a LIVE field must NOT need a rebuild; naming ONLY a
        // REBUILD field MUST. (Drives the same `needs_rebuild` the dispatch consults.) If a field is
        // misclassified above, the matching assertion below fails.
        type Case = (&'static str, bool, fn(&mut SetOptions)); // (name, expect_rebuild, set-only-it)
        let cases: Vec<Case> = vec![
            ("hostname", false, |o| o.hostname = Some("h".into())),
            ("accept_routes", false, |o| o.accept_routes = Some(true)),
            ("accept_dns", false, |o| o.accept_dns = Some(false)),
            ("exit_node", false, |o| {
                o.exit_node = Some(Some("100.64.0.9".into()))
            }),
            ("advertise_exit_node", false, |o| {
                o.advertise_exit_node = Some(true)
            }),
            ("advertise_routes", false, |o| {
                o.advertise_routes = Some(vec!["10.0.0.0/8".into()])
            }),
            ("shields_up", true, |o| o.shields_up = Some(true)),
            ("advertise_tags", true, |o| {
                o.advertise_tags = Some(vec!["tag:server".into()])
            }),
            ("ssh", true, |o| o.ssh = Some(true)),
            ("advertise_connector", true, |o| {
                o.advertise_connector = Some(true)
            }),
            ("auto_update", true, |o| o.auto_update = Some(true)),
            // CARRIED: naming one makes the request non-empty, but there is nothing to reconcile.
            ("update_check", false, |o| o.update_check = Some(false)),
            ("operator", false, |o| {
                o.operator = Some(Some("alice".into()))
            }),
            ("nickname", false, |o| {
                o.nickname = Some(Some("laptop".into()))
            }),
            ("report_posture", false, |o| o.report_posture = Some(true)),
            ("webclient", false, |o| o.webclient = Some(true)),
            ("exit_node_allow_lan_access", false, |o| {
                o.exit_node_allow_lan_access = Some(true)
            }),
        ];
        for (name, expect_rebuild, set_only) in &cases {
            let mut opts = SetOptions::default();
            set_only(&mut opts);
            assert!(
                !opts.is_empty(),
                "{name}: a named set must not be is_empty()"
            );
            assert_eq!(
                opts.needs_rebuild(),
                *expect_rebuild,
                "{name}: live-vs-rebuild misclassified — a LIVE pref must apply in place (no rebuild) \
                 and a REBUILD pref (no engine live setter) must force a rebuild; update \
                 `needs_rebuild()` + `begin_set` for this field"
            );
        }
    }

    #[tokio::test]
    async fn begin_set_applies_named_prefs_and_leaves_rest_unchanged() {
        // With NO device up, `begin_set` returns `PersistedOnly` (the persist is the whole job) and
        // mutates EXACTLY the named prefs, preserving every unnamed one. Drives the full sentinel
        // surface in one place: SET each field, then a no-op `set` that must change nothing, then a
        // CLEAR. Offline: a device-less backend does no engine I/O.
        let dir = std::env::temp_dir().join(format!("tailnetd-set-apply-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        // A baseline unnamed pref that must survive every `set` below untouched.
        be.prefs.hostname = Some("baseline-host".to_string());

        // SET accept_routes + exit_node + advertise_* (but NOT hostname) → only those move.
        let outcome = be
            .begin_set(SetOptions {
                accept_routes: Some(true),
                exit_node: Some(Some("100.64.0.9".to_string())),
                advertise_exit_node: Some(true),
                advertise_routes: Some(vec!["10.0.0.0/8".to_string()]),
                ..SetOptions::default()
            })
            .await
            .expect("begin_set");
        assert_eq!(
            outcome.action,
            SetAction::PersistedOnly,
            "no device up → set just persists; prefs apply on next up"
        );
        assert!(be.prefs.accept_routes, "accept_routes was set");
        assert_eq!(be.prefs.exit_node.as_deref(), Some("100.64.0.9"));
        assert!(be.prefs.advertise_exit_node);
        assert_eq!(be.prefs.advertise_routes, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(
            be.prefs.hostname.as_deref(),
            Some("baseline-host"),
            "an unnamed hostname must be left untouched by set"
        );
        assert!(
            !be.prefs.want_running,
            "set must NOT flip want_running (it is not up)"
        );
        assert!(
            be.ever_configured,
            "set marks the node configured-at-least-once"
        );

        // A no-op `set` (all None) must leave EVERY pref exactly as-is.
        let outcome = be
            .begin_set(SetOptions::default())
            .await
            .expect("begin_set");
        assert_eq!(outcome.action, SetAction::PersistedOnly);
        assert!(be.prefs.accept_routes, "no-op set preserves accept_routes");
        assert_eq!(
            be.prefs.exit_node.as_deref(),
            Some("100.64.0.9"),
            "a None exit_node override must preserve the stored selector"
        );
        assert!(be.prefs.advertise_exit_node);
        assert_eq!(be.prefs.advertise_routes, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(be.prefs.hostname.as_deref(), Some("baseline-host"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_up_applies_the_four_shared_go_pref_flags() {
        // Go registers `--operator`, `--exit-node-allow-lan-access`, `--advertise-connector` and
        // `--report-posture` on `up` as well as `set` (`up.go` `newUpFlagSet`). Drive them through
        // `begin_up` (offline — no engine handshake happens until `build_device`) and pin: each named
        // flag lands on its own pref, a following BARE `up` leaves them alone (the PATCH merge), and
        // `--operator=` clears.
        let dir = std::env::temp_dir().join(format!("tailnetd-up-goflags-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        be.begin_up(
            UpOptions {
                operator: Some(Some("alice".to_string())),
                exit_node_allow_lan_access: Some(true),
                advertise_connector: Some(true),
                report_posture: Some(true),
                ..UpOptions::default()
            },
            None,
        )
        .await
        .expect("begin_up");
        assert_eq!(be.prefs.operator_user.as_deref(), Some("alice"));
        assert!(be.prefs.exit_node_allow_lan_access);
        assert!(be.prefs.advertise_app_connector);
        assert!(be.prefs.posture_checking);

        // A bare `up` must not revert any of them (this daemon's `up` is a PATCH merge; the
        // accidental-revert guard, not a silent default, is what enforces Go's REPLACE contract).
        be.begin_up(UpOptions::default(), None)
            .await
            .expect("bare begin_up");
        assert_eq!(be.prefs.operator_user.as_deref(), Some("alice"));
        assert!(be.prefs.exit_node_allow_lan_access);
        assert!(be.prefs.advertise_app_connector);
        assert!(be.prefs.posture_checking);

        // `--operator=` (the empty-value form Go clears with) removes the operator.
        be.begin_up(
            UpOptions {
                operator: Some(None),
                ..UpOptions::default()
            },
            None,
        )
        .await
        .expect("begin_up clear");
        assert_eq!(be.prefs.operator_user, None);

        // `up --reset` resets the four `up`-managed flags but must NOT touch the four Go registers on
        // `set` only — an `up` has no flag that could mention them.
        be.prefs.advertise_app_connector = true;
        be.prefs.posture_checking = true;
        be.prefs.node_nickname = Some("laptop".to_string());
        be.prefs.run_web_client = true;
        be.prefs.auto_update_apply = Some(true);
        be.begin_up(
            UpOptions {
                reset: true,
                ..UpOptions::default()
            },
            None,
        )
        .await
        .expect("begin_up --reset");
        assert!(!be.prefs.advertise_app_connector, "--reset clears up flags");
        assert!(!be.prefs.posture_checking);
        assert_eq!(
            be.prefs.node_nickname.as_deref(),
            Some("laptop"),
            "--reset must not clear a `set`-only pref"
        );
        assert!(be.prefs.run_web_client);
        assert_eq!(be.prefs.auto_update_apply, Some(true));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn set_nickname_renames_the_login_profile_switch_resolves_against() {
        // Go's `--nickname` is not a carried pref: `profileManager.SetPrefs` copies
        // `ipn.Prefs.ProfileName` onto the current login profile, so the new name is immediately what
        // `switch --list` prints and what a `switch <target>` resolves against. Drive the real
        // `begin_set` and read the rename back through the two production surfaces that consume it.
        let dir = std::env::temp_dir().join(format!("tailnetd-nick-rename-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = Backend::load(&dir).await.unwrap();

        // Before: the default profile is listed under its id, because nothing has named it.
        let before = be.list_profiles().await;
        let def = before
            .iter()
            .find(|e| e.id == profile::DEFAULT_PROFILE_ID)
            .expect("default profile is always listed");
        assert_eq!(def.name, profile::DEFAULT_PROFILE_ID);

        be.begin_set(SetOptions {
            nickname: Some(Some("work-laptop".to_string())),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set --nickname");

        // The pref still holds it (Go writes `Prefs.ProfileName` too)...
        assert_eq!(be.prefs.node_nickname.as_deref(), Some("work-laptop"));
        // ...and the LISTING now shows the chosen name against the current profile.
        let listed = be.list_profiles().await;
        let def = listed
            .iter()
            .find(|e| e.id == profile::DEFAULT_PROFILE_ID)
            .expect("default profile is always listed");
        assert_eq!(
            def.name, "work-laptop",
            "`switch --list` must show the nickname just set"
        );
        assert!(def.current);
        // The rename is DURABLE (it is the on-disk profiles.json a restart reads), not in-memory.
        let meta = profile::load_profiles_file(&dir).await;
        assert_eq!(
            meta.profiles
                .get(profile::DEFAULT_PROFILE_ID)
                .map(|m| m.name.as_str()),
            Some("work-laptop")
        );

        // And `switch work-laptop` now resolves to THIS profile. Without the rename the name is not
        // a known profile, and — being a syntactically valid id — it would be taken as a request to
        // create a brand-new empty profile called `work-laptop` and switch to it.
        match be.switch_profile("work-laptop").await.expect("switch") {
            SwitchOutcome::AlreadyCurrent { id } => {
                assert_eq!(id, profile::DEFAULT_PROFILE_ID);
            }
            other => panic!("nickname must resolve to the current profile, got {other:?}"),
        }
        assert_eq!(be.current_profile, profile::DEFAULT_PROFILE_ID);

        // Clearing (Go's `--nickname=`) drops the display name; the listing falls back to the id.
        // Where Go restores the account's login name instead — the deviation and why it stands are
        // in `clearing_the_nickname_blanks_the_name_and_cannot_restore_a_login_name`.
        be.begin_set(SetOptions {
            nickname: Some(None),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set --nickname=");
        assert_eq!(be.prefs.node_nickname, None);
        let cleared = be.list_profiles().await;
        let def = cleared
            .iter()
            .find(|e| e.id == profile::DEFAULT_PROFILE_ID)
            .expect("default profile is always listed");
        assert_eq!(def.name, profile::DEFAULT_PROFILE_ID);

        // A `set` that does NOT name a nickname leaves the profile name alone.
        be.begin_set(SetOptions {
            nickname: Some(Some("renamed".to_string())),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set --nickname");
        be.begin_set(SetOptions {
            hostname: Some("some-host".to_string()),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set --hostname");
        let after = be.list_profiles().await;
        let def = after
            .iter()
            .find(|e| e.id == profile::DEFAULT_PROFILE_ID)
            .expect("default profile is always listed");
        assert_eq!(def.name, "renamed", "an unnamed nickname must not rename");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn clearing_the_nickname_blanks_the_name_and_cannot_restore_a_login_name() {
        // Go assigns the profile name in TWO arms — `setProfilePrefs`, `ipn/ipnlocal/profiles.go:450`
        // @ `53a0d659afa51835dd7a9283873cca44261454f8`:
        //
        //     if prefsIn.ProfileName() != "" { lp.Name = prefsIn.ProfileName() }
        //     else                           { lp.Name = up.LoginName }
        //
        // This port has the first arm exactly. The second arm's VALUE — the account's login name out
        // of the profile's persisted `tailcfg.UserProfile` — does not exist here: the daemon tracks
        // no account identity and the engine at the pinned rev surfaces none (`Device::status`'s
        // `self_node` carries no owning user; `Device::whois` resolves peers only). So a cleared
        // nickname blanks the name and the readers fall back to the profile id, where Go would show
        // the account. Filed as `docs/ENGINE_ASKS.md` §42 and pinned here, so the shape of the
        // deviation is a decision rather than a drift — and so the day the engine can answer
        // "who owns this node", this test is what has to change.
        let dir = std::env::temp_dir().join(format!("tailnetd-nick-clear-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = Backend::load(&dir).await.unwrap();

        // A non-default profile, so "fell back to the id" is visibly distinct from "is the default".
        be.create_profile("work").await.expect("create work");
        be.begin_set(SetOptions {
            nickname: Some(Some("work-laptop".to_string())),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set --nickname");

        // Go's `--nickname=` clear, through the real `set` path.
        be.begin_set(SetOptions {
            nickname: Some(None),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set --nickname=");
        assert_eq!(be.prefs.node_nickname, None, "the pref must clear too");

        // The map ENTRY survives with an empty name — the clear blanks a name, it does not delete a
        // profile. (Go's else arm likewise overwrites `lp.Name` in place; it never drops the
        // profile.) This is what keeps the profile listed and switchable below.
        let meta = profile::load_profiles_file(&dir).await;
        assert_eq!(
            meta.profiles.get("work").map(|m| m.name.as_str()),
            Some(""),
            "clearing the nickname must blank the name in place, not remove the profile entry"
        );

        // The listing falls back to the id. Go prints the account's login name here.
        let listed = be.list_profiles().await;
        let work = listed
            .iter()
            .find(|e| e.id == "work")
            .expect("the profile must still be listed after its name is cleared");
        assert_eq!(
            work.name, "work",
            "with no login name to restore, the listing falls back to the profile id"
        );
        assert!(work.current);

        // The cleared nickname stops resolving — Go's name pass reads the same field its else arm
        // has just overwritten, so it stops resolving there too. Refused, not adopted as a new id.
        let err = be
            .switch_profile("work-laptop")
            .await
            .expect_err("a cleared nickname must no longer name a profile");
        assert!(
            format!("{err:#}").contains("no profile named"),
            "unexpected error: {err:#}"
        );
        // And the id still does, on the profile whose name was cleared.
        assert_eq!(
            be.switch_profile("work").await.unwrap(),
            SwitchOutcome::AlreadyCurrent {
                id: "work".to_string()
            }
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn set_nickname_renames_the_profile_it_is_issued_on_not_the_default() {
        // The rename follows the CURRENT profile — Go renames the current login profile, not a fixed
        // one — so a nickname set after `switch work` names `work` and leaves `default` untouched.
        let dir = std::env::temp_dir().join(format!("tailnetd-nick-cur-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = Backend::load(&dir).await.unwrap();
        be.create_profile("work").await.expect("create work");

        be.begin_set(SetOptions {
            nickname: Some(Some("Work tailnet".to_string())),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set --nickname");

        let listed = be.list_profiles().await;
        let work = listed.iter().find(|e| e.id == "work").expect("work listed");
        let def = listed
            .iter()
            .find(|e| e.id == profile::DEFAULT_PROFILE_ID)
            .expect("default listed");
        assert_eq!(work.name, "Work tailnet");
        assert_eq!(
            def.name,
            profile::DEFAULT_PROFILE_ID,
            "another profile must not be renamed"
        );

        // A display name with a space is unreachable as an id, so the name arm of the resolver is the
        // only thing that can find it — exactly Go's `switch "Work tailnet"`.
        be.switch_profile(profile::DEFAULT_PROFILE_ID)
            .await
            .expect("switch default");
        match be.switch_profile("Work tailnet").await.expect("switch") {
            SwitchOutcome::Switched { id, .. } => assert_eq!(id, "work"),
            other => panic!("expected a switch to `work`, got {other:?}"),
        }

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn set_nickname_rename_failure_still_reconciles_the_persisted_prefs() {
        // A `--nickname` whose login-profile rename FAILS must not swallow the rest of the `set`. By
        // the time the rename runs, every pref the request named is already durable in `prefs.json`,
        // so returning early on it would skip the engine reconcile — and a
        // `set --nickname X --exit-node Y` on a running node would end with `Y` on disk (and in what
        // `tnet get` reports) while the live device kept the OLD exit node, until the next successful
        // `set`/`up`. `begin_set` must therefore still decide + carry out the reconcile and hand the
        // rename failure back in `SetOutcome::rename_error`.
        //
        // The rename is forced to fail by making `profiles.json` a DIRECTORY: `save_profiles_file`
        // writes atomically (temp file in the same dir, then rename over the target), and renaming a
        // file over a directory fails on every platform this daemon builds for. Offline: no device,
        // so the reconcile decision is `PersistedOnly` — the observable is that a decision was
        // reached at all.
        let dir = std::env::temp_dir().join(format!("tailnetd-nick-fail-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::create_dir_all(profile::profiles_file_path(&dir))
            .await
            .unwrap();
        let mut be = backend_for(&dir);

        let outcome = be
            .begin_set(SetOptions {
                nickname: Some(Some("work-laptop".to_string())),
                exit_node: Some(Some("100.64.0.9".to_string())),
                ..SetOptions::default()
            })
            .await
            .expect("a failed profile rename must not abort begin_set before the reconcile");

        // The reconcile decision was still REACHED. Without the fix `begin_set` returned the rename
        // error here and never looked at the device at all.
        assert_eq!(
            outcome.action,
            SetAction::PersistedOnly,
            "the reconcile must run even when the profile rename failed"
        );
        // ...and the failure is reported, not swallowed.
        let err = outcome
            .rename_error
            .expect("the failed rename must be reported, not dropped");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("renaming profile"),
            "the rename failure must name what failed, got {msg:?}"
        );

        // The live-applicable pref the reconcile exists to apply is durable — in memory and on disk.
        assert_eq!(be.prefs.exit_node.as_deref(), Some("100.64.0.9"));
        let persisted = crate::prefs::Prefs::load(&be.prefs_path)
            .await
            .expect("prefs.json");
        assert_eq!(
            persisted.exit_node.as_deref(),
            Some("100.64.0.9"),
            "the exit node was already persisted before the rename was attempted"
        );
        assert_eq!(persisted.node_nickname.as_deref(), Some("work-laptop"));
        // Only the profile DISPLAY name is stale: the unwritable map reads as empty, so the listing
        // falls back to the profile id.
        let listed = be.list_profiles().await;
        let def = listed
            .iter()
            .find(|e| e.id == profile::DEFAULT_PROFILE_ID)
            .expect("default profile is always listed");
        assert_eq!(def.name, profile::DEFAULT_PROFILE_ID);

        // The owned `set` path reports the same failure — but only AFTER carrying the action out, so
        // the rest of the request still lands.
        let err = be
            .set(SetOptions {
                nickname: Some(Some("work-laptop".to_string())),
                hostname: Some("renamed-host".to_string()),
                ..SetOptions::default()
            })
            .await
            .expect_err("a failed profile rename must still fail the command");
        assert!(format!("{err:#}").contains("renaming profile"));
        let persisted = crate::prefs::Prefs::load(&be.prefs_path)
            .await
            .expect("prefs.json");
        assert_eq!(
            persisted.hostname.as_deref(),
            Some("renamed-host"),
            "the rest of the set must be applied even though the rename failed"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn set_auto_update_opt_in_needs_an_installation_that_can_update() {
        // Go `checkAutoUpdatePrefsLocked` on the WRITE path. `AutoUpdate.Apply` is not a local
        // preference: the engine advertises it as `Hostinfo.AllowsUpdate` on registration and on
        // every map request, so opting in tells the tailnet admin a remote update trigger will be
        // honoured. A node whose binary can never be replaced must not be allowed to say that.
        //
        // Whether THIS host can update is a host property, so the test asks the same predicate
        // `begin_set` consults and checks the branch that applies — both branches assert durable
        // state, and the rule's own two outcomes are pinned host-independently in `ipn::selfupdate`.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-set-autoupdate-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        let opt_in = be
            .begin_set(SetOptions {
                auto_update: Some(true),
                ..SetOptions::default()
            })
            .await;
        match selfupdate::auto_update_refusal() {
            None => {
                opt_in.expect("an installation that can replace its own binary may opt in");
                assert_eq!(be.prefs.auto_update_apply, Some(true));
            }
            Some(_) => {
                let err = opt_in.expect_err(
                    "opting in on an installation that can never apply an update must be refused",
                );
                let msg = format!("{err:#}");
                assert!(msg.contains("Auto-updates are not supported"), "got {msg}");
                assert!(
                    msg.contains("Hostinfo.AllowsUpdate"),
                    "the refusal must say what the pref claims to the tailnet: {msg}"
                );
                // Refused BEFORE a single pref is mutated or persisted — a rejected `set` must not
                // leave prefs.json carrying the claim it just refused.
                assert_eq!(
                    be.prefs.auto_update_apply, None,
                    "a refused set must leave the pref never-stated"
                );
                assert!(
                    !tokio::fs::try_exists(&be.prefs_path).await.unwrap(),
                    "a refused set must not have persisted anything"
                );
            }
        }

        // Declining, and never stating one, are legal on every installation — neither claims
        // anything to the tailnet (Go acts on `Apply.EqualBool(true)` alone).
        be.begin_set(SetOptions {
            auto_update: Some(false),
            ..SetOptions::default()
        })
        .await
        .expect("declining auto-update is legal on every installation");
        assert_eq!(be.prefs.auto_update_apply, Some(false));
        be.begin_set(SetOptions {
            hostname: Some("unrelated".to_string()),
            ..SetOptions::default()
        })
        .await
        .expect("a set that never names auto-update is unaffected by the rule");
        assert_eq!(be.prefs.auto_update_apply, Some(false));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_set_applies_the_go_parity_pref_flags() {
        // The eight Go `set` pref flags added alongside their engine `Config` fields, end to end
        // through `begin_set`: each named flag lands on its OWN pref, an unnamed one is untouched,
        // and the two string prefs CLEAR (`Some(None)`) distinctly from unchanged (`None`).
        let dir = std::env::temp_dir().join(format!("tailnetd-set-goflags-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        // A baseline unnamed pref that must survive untouched.
        be.prefs.hostname = Some("baseline-host".to_string());

        be.begin_set(SetOptions {
            advertise_connector: Some(true),
            // The DECLINE, not the opt-in: `--auto-update` claims `Hostinfo.AllowsUpdate` and is
            // refused on an installation that could never apply an update, which is a property of
            // whatever host runs this test (see
            // `set_auto_update_opt_in_needs_an_installation_that_can_update`). Declining is legal
            // everywhere and still proves the flag lands on its OWN pref, distinct from the
            // never-stated default.
            auto_update: Some(false),
            update_check: Some(false),
            operator: Some(Some("alice".to_string())),
            nickname: Some(Some("laptop".to_string())),
            report_posture: Some(true),
            webclient: Some(true),
            exit_node_allow_lan_access: Some(true),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set");

        assert!(be.prefs.advertise_app_connector);
        assert_eq!(be.prefs.auto_update_apply, Some(false));
        assert!(!be.prefs.auto_update_check);
        assert_eq!(be.prefs.operator_user.as_deref(), Some("alice"));
        assert_eq!(be.prefs.node_nickname.as_deref(), Some("laptop"));
        assert!(be.prefs.posture_checking);
        assert!(be.prefs.run_web_client);
        assert!(be.prefs.exit_node_allow_lan_access);
        assert_eq!(
            be.prefs.hostname.as_deref(),
            Some("baseline-host"),
            "an unnamed pref must be left untouched"
        );

        // `--no-auto-update` is an explicit DECLINE, distinct from never having stated one.
        be.begin_set(SetOptions {
            auto_update: Some(false),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set");
        assert_eq!(be.prefs.auto_update_apply, Some(false));

        // A no-op `set` leaves every one of them alone (the "unchanged" sentinel).
        be.begin_set(SetOptions {
            hostname: Some("other-host".to_string()),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set");
        assert_eq!(be.prefs.operator_user.as_deref(), Some("alice"));
        assert_eq!(be.prefs.node_nickname.as_deref(), Some("laptop"));
        assert!(be.prefs.advertise_app_connector);
        assert_eq!(be.prefs.auto_update_apply, Some(false));

        // CLEAR: `--operator=` / `--nickname=` remove the value (Go's empty-value form).
        be.begin_set(SetOptions {
            operator: Some(None),
            nickname: Some(None),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set");
        assert_eq!(be.prefs.operator_user, None);
        assert_eq!(be.prefs.node_nickname, None);

        // The persist actually reached disk (a `set` is durable, not in-memory only).
        let persisted = Prefs::load(&be.prefs_path).await.expect("load prefs");
        assert!(persisted.advertise_app_connector);
        assert_eq!(persisted.auto_update_apply, Some(false));
        assert!(!persisted.auto_update_check);
        assert_eq!(persisted.operator_user, None);
        assert!(persisted.posture_checking);
        assert!(persisted.run_web_client);
        assert!(persisted.exit_node_allow_lan_access);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_set_device_less_persists_regardless_of_live_vs_rebuild() {
        // With NO device up, the live-vs-rebuild classification is moot: `begin_set` always returns
        // `PersistedOnly` and persists the named prefs (they apply on the next `up`). Verify this for
        // a request that MIXES a live-applicable pref (hostname) and a rebuild-only one (shields_up) —
        // a device-up version would take `Rebuild`, but device-less it just persists both. This pins
        // that the new classification never leaks into the device-less path. Offline (no engine I/O).
        let dir = std::env::temp_dir().join(format!("tailnetd-set-devless-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        // Sanity: this request WOULD rebuild on a running node (shields_up has no live setter)...
        let opts = SetOptions {
            hostname: Some("mixed-host".to_string()),
            shields_up: Some(true),
            ..SetOptions::default()
        };
        assert!(
            opts.needs_rebuild(),
            "hostname + shields_up classifies as rebuild (precondition)"
        );
        // ...but device-less it just persists, returning PersistedOnly and applying BOTH prefs.
        let outcome = be.begin_set(opts).await.expect("begin_set");
        assert_eq!(
            outcome.action,
            SetAction::PersistedOnly,
            "device-less set persists regardless of live/rebuild classification"
        );
        assert_eq!(be.prefs.hostname.as_deref(), Some("mixed-host"));
        assert!(
            be.prefs.shields_up,
            "the rebuild-only pref was persisted too"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_set_exit_node_clear_vs_unchanged_distinction() {
        // The double-`Option` crux AT THE PREFS LAYER: `Some(None)` CLEARS `prefs.exit_node`, while
        // `None` (the outer sentinel) leaves it UNCHANGED. These must be distinguishable end-to-end
        // through `begin_set`, exactly as for `up`. Offline (no device).
        let dir = std::env::temp_dir().join(format!("tailnetd-set-clear-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        be.prefs.exit_node = Some("seed-exit".to_string());

        // `None` outer sentinel: a `set` that names other fields but NOT exit_node must leave it.
        be.begin_set(SetOptions {
            accept_routes: Some(true),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set unchanged exit");
        assert_eq!(
            be.prefs.exit_node.as_deref(),
            Some("seed-exit"),
            "a None (unchanged) exit_node override must preserve the stored exit node"
        );

        // `Some(None)`: explicit CLEAR.
        be.begin_set(SetOptions {
            exit_node: Some(None),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set clear exit");
        assert!(
            be.prefs.exit_node.is_none(),
            "Some(None) must clear the exit_node pref (distinct from None = unchanged)"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn status_prefs_view_projects_every_pref_field() {
        // `status()` projects the persisted `Prefs` into the wire `PrefsView`. That projection is
        // hand-written field-by-field, so a transposition (e.g. `ssh: tun_enabled`) would silently
        // misreport the node's posture with nothing to catch it. Drive a device-less backend (so
        // `status()` does no engine I/O) with NON-DEFAULT, mutually-distinguishable values for every
        // field and assert each lands in the matching `PrefsView` field. `accept_routes` (false) is
        // set OPPOSITE `advertise_exit_node`/`tun` (true) so a swap between same-typed bool fields is
        // caught, not masked by equal values.
        let dir = std::env::temp_dir().join(format!("tailnetd-status-view-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        be.prefs.hostname = Some("node-a".to_string());
        be.prefs.exit_node = Some("100.64.0.9".to_string());
        be.prefs.advertise_exit_node = true;
        be.prefs.advertise_routes = vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()];
        be.prefs.accept_routes = false;
        be.prefs.ssh_enabled = true;
        be.prefs.tun_enabled = true;

        let view = be.status().await.prefs;
        assert_eq!(
            view.hostname.as_deref(),
            Some("node-a"),
            "hostname pref must project into PrefsView.hostname verbatim"
        );
        assert_eq!(
            view.exit_node.as_deref(),
            Some("100.64.0.9"),
            "exit_node pref must project into PrefsView.exit_node verbatim"
        );
        assert!(
            view.advertise_exit_node,
            "advertise_exit_node pref must project into PrefsView.advertise_exit_node"
        );
        assert_eq!(
            view.advertise_routes,
            vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()],
            "advertise_routes pref must project into PrefsView.advertise_routes in order"
        );
        assert!(
            !view.accept_routes,
            "accept_routes pref (false) must project into PrefsView.accept_routes (not swapped)"
        );
        assert!(
            view.ssh,
            "ssh_enabled pref must project into PrefsView.ssh (not tun_enabled)"
        );
        assert!(view.tun, "tun_enabled pref must project into PrefsView.tun");
        // No device is up, so the SSH server task was never spawned → not running, even though the
        // `ssh` pref is enabled. This is exactly the `ssh: true, ssh_running: false` honest signal.
        assert!(
            !view.ssh_running,
            "a device-less backend spawns no SSH task → ssh_running is false even with ssh enabled"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn set_exit_node_selector_parse_is_infallible_for_names() {
        // The live exit-node path in `begin_set` does `self.prefs.exit_node.parse().unwrap()`, which
        // relies on `ExitNodeSelector: FromStr` being INFALLIBLE — a "malformed" selector cannot
        // panic because there is no parse failure to unwrap. Assert that even an arbitrary,
        // not-an-IP string parses (to the `Name` variant), so the `.unwrap()` is total, not a
        // swallowed fallible parse. (The IP-vs-Name split itself is pinned by
        // `exit_node_selector_parses_ip_vs_name`; this guards the NO-PANIC invariant `set` depends on.)
        let weird = "this is definitely not an ip address !@#";
        let sel: tailscale::ExitNodeSelector = weird.parse().unwrap();
        assert!(
            matches!(sel, tailscale::ExitNodeSelector::Name(_)),
            "any non-IP exit-node selector must parse to Name (never panic), got {sel:?}"
        );
    }

    // --- SSH server pref wiring + build_config preflight (tsd-46c) --------------------------------
    //
    // The SSH server is opt-in twice (build feature + runtime pref). These tests pin the PURE,
    // offline surface: the `ssh` override sentinel through `begin_up`/`begin_set` (set/unchanged/
    // clear, like every other pref), and the `build_config` preflight that fails the bring-up loudly
    // when SSH is impossible. The actual spawn/abort lifecycle needs a live engine (integration
    // territory), so it is NOT unit-tested here. All offline: a device-less backend does no engine I/O.

    #[tokio::test]
    async fn begin_up_applies_ssh_override() {
        // The `UpOptions.ssh` sentinel through `begin_up`, exercised in the directions that do NOT
        // require the `ssh` feature + root: `None` leaves `ssh_enabled` unchanged, and `Some(false)`
        // disables it. (The ENABLE direction is NOT tested through `begin_up` here because `begin_up`
        // builds Config internally, and `build_config`'s SSH preflight correctly fails an
        // `ssh_enabled = true` bring-up without the feature/root — that preflight is pinned by its own
        // tests, and the ENABLE *override semantics* are pinned via `begin_set` in
        // `begin_set_applies_ssh_override_and_persisted_only_when_down`, which does no Config build.)
        // Offline in every feature config: with `ssh_enabled` staying false, no SSH preflight fires.
        let dir = std::env::temp_dir().join(format!("tailnetd-bu-ssh-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        assert!(
            !be.prefs.ssh_enabled,
            "default prefs do not run the SSH server"
        );

        // A plain `up` (ssh: None) must leave ssh_enabled at its default (false).
        let _ = be
            .begin_up(UpOptions::default(), None)
            .await
            .expect("begin_up unchanged");
        assert!(
            !be.prefs.ssh_enabled,
            "a None ssh override must leave ssh_enabled unchanged"
        );

        // Seed ssh_enabled = true directly (bypassing the override path) so we can prove the
        // `Some(false)` override DISABLES it — without needing the feature/root an ENABLE would.
        be.prefs.ssh_enabled = true;
        let _ = be
            .begin_up(
                UpOptions {
                    ssh: Some(false),
                    ..UpOptions::default()
                },
                None,
            )
            .await
            .expect("begin_up disable ssh");
        assert!(
            !be.prefs.ssh_enabled,
            "Some(false) must disable ssh_enabled"
        );

        // And a follow-up `None` override must preserve the now-disabled state.
        let _ = be
            .begin_up(UpOptions::default(), None)
            .await
            .expect("begin_up unchanged after disable");
        assert!(
            !be.prefs.ssh_enabled,
            "a None ssh override must preserve the disabled ssh_enabled"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn begin_set_applies_ssh_override_and_persisted_only_when_down() {
        // `begin_set` applies the `ssh` override with the same sentinel and, with NO device up,
        // returns `PersistedOnly` (the persist is the whole job; the toggle takes effect on the next
        // `up`). `begin_set` does NOT build Config, so this is safe in every feature config (no root
        // needed). Drives ENABLE → no-op (unchanged) → DISABLE.
        let dir = std::env::temp_dir().join(format!("tailnetd-set-ssh-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        assert!(!be.prefs.ssh_enabled);

        // ENABLE.
        let outcome = be
            .begin_set(SetOptions {
                ssh: Some(true),
                ..SetOptions::default()
            })
            .await
            .expect("begin_set enable ssh");
        assert_eq!(
            outcome.action,
            SetAction::PersistedOnly,
            "no device up → an ssh toggle just persists; it applies on next up"
        );
        assert!(be.prefs.ssh_enabled, "Some(true) must enable ssh_enabled");

        // A no-op set (ssh: None) must leave it ENABLED.
        be.begin_set(SetOptions {
            accept_routes: Some(true),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set unrelated change");
        assert!(
            be.prefs.ssh_enabled,
            "a None ssh override must preserve the stored ssh_enabled"
        );

        // DISABLE.
        be.begin_set(SetOptions {
            ssh: Some(false),
            ..SetOptions::default()
        })
        .await
        .expect("begin_set disable ssh");
        assert!(
            !be.prefs.ssh_enabled,
            "Some(false) must disable ssh_enabled"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    // `build_config`'s SSH preflight fails the bring-up LOUDLY when SSH is impossible. The error
    // depends on the build: WITHOUT the `ssh` feature, *any* `ssh_enabled` is an error (there is no
    // server to spawn); WITH it, the error is gated on running as non-root (the engine must drop
    // privileges). We split into two feature-gated tests so each is meaningful in its own config.

    #[cfg(not(feature = "ssh"))]
    #[tokio::test]
    async fn build_config_ssh_requested_without_feature_errors() {
        // Default build (no `ssh` feature): `ssh_enabled = true` must make `build_config` fail with a
        // message naming the missing feature — never a silent no-SSH node.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-bc-ssh-nofeat-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        be.prefs.ssh_enabled = true;

        // `tailscale::Config` is not `Debug`, so match by hand (cannot use `expect_err`).
        let err = match be.build_config().await {
            Ok(_) => panic!("ssh_enabled without the `ssh` feature must make build_config fail"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("ssh") && msg.contains("feature"),
            "the error must name the missing `ssh` feature, got {msg:?}"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[cfg(all(feature = "ssh", unix))]
    #[tokio::test]
    async fn build_config_ssh_requires_root() {
        // With the `ssh` feature on unix, `ssh_enabled` requires root (the engine drops privileges to
        // the policy-mapped local user). Under a non-root test runner this must FAIL LOUDLY naming
        // the root requirement; if the runner happens to be root, the preflight passes — assert the
        // matching outcome for whichever euid the test runs under so it is correct either way.
        let dir = std::env::temp_dir().join(format!("tailnetd-bc-ssh-root-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        be.prefs.ssh_enabled = true;

        // SAFETY: geteuid() is infallible (no args, no preconditions).
        let is_root = unsafe { libc::geteuid() } == 0;
        match be.build_config().await {
            Ok(_) => assert!(
                is_root,
                "build_config may only succeed with ssh_enabled when running as root"
            ),
            Err(e) => {
                assert!(
                    !is_root,
                    "as root, the SSH root-preflight must not fail; got error {e:#}"
                );
                let msg = format!("{e:#}");
                assert!(
                    msg.contains("root"),
                    "the non-root SSH preflight error must name the root requirement, got {msg:?}"
                );
            }
        }

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    // --- read-only diagnostics + Taildrop: off-lock device handle -------------------------------
    //
    // After the lock-across-await fix (tsd), the `ip_report`/`whois`/`ping`/`file_cp`/`file_list`/
    // `file_get` free fns take `&tailscale::Device` (see `ipn::diag`) and the LocalAPI server runs
    // them OFF the backend lock: it clones the engine handle via `device_handle()` under a brief
    // lock, drops the lock, and only calls the method when that handle is `Some`. The "node is not
    // up" branch therefore lives in the dispatch arm, keyed on `device_handle()` being `None` — so
    // the device-less precondition is unit-tested here as `device_handle().is_none()` (the single
    // fact every "not up" reply derives from). The bad-IP-parse and path-hardening predicate tests
    // moved to `ipn::diag` alongside the diagnostics they pin.

    #[tokio::test]
    async fn device_handle_is_none_without_device() {
        // The shared precondition for every "node is not up" LocalAPI reply: with no engine up, the
        // server's brief-lock `device_handle()` clone yields `None`, and the dispatch arm turns that
        // into the "not up" Error WITHOUT calling the (now `&Device`-taking) engine method. One
        // assertion covers ip/whois/ping/file_cp/file_list/file_get, which all gate on this same bit.
        let dir = std::env::temp_dir().join(format!("tailnetd-diag-nodev-{}", std::process::id()));
        let be = backend_for(&dir);
        assert!(
            be.device_handle().is_none(),
            "a device-less backend must hand the server no engine handle → dispatch replies \"not up\""
        );
    }

    #[tokio::test]
    async fn link_monitor_not_running_without_device() {
        // The link-change monitor is bound to the device lifecycle: a device-less (down/fresh)
        // backend has no monitor task. It is spawned in `finish_up` (on up) and aborted in
        // `stop_device` (on down) — the spawn-and-rebind path needs a live engine, so it is exercised
        // by the gated headscale e2e; here we pin the down-state half (no device ⇒ no monitor).
        let dir =
            std::env::temp_dir().join(format!("tailnetd-linkmon-nodev-{}", std::process::id()));
        let be = backend_for(&dir);
        assert!(
            be.monitor_task.is_none(),
            "a device-less backend must run no link-change monitor (it arms on the next `up`)"
        );
    }

    // NOTE: the bad-IP-parse predicate test and the Taildrop file_cp/file_get path-hardening
    // predicate tests moved to `ipn::diag` alongside the diagnostics they pin. See that module's
    // `#[cfg(test)] mod tests`.

    // --- Taildrop build_config mapping — offline (no Device::new, no network) ----------------------

    #[tokio::test]
    async fn build_config_maps_taildrop_dir_some_and_none() {
        // The receive-enable seam: a `Some(dir)` pref must flow into `Config.taildrop_dir` as the
        // matching `PathBuf` (the engine then stands up the receive store under it), and the default
        // `None` pref must leave `Config.taildrop_dir = None` (receiving off, engine fail-closed).
        // `build_config` touches only the key file (created on demand); it stands up NO engine and
        // does NO network.
        let dir = std::env::temp_dir().join(format!("tailnetd-bc-taildrop-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        // None (default prefs) → receiving off.
        let cfg = be
            .build_config()
            .await
            .expect("build_config (taildrop none)");
        assert!(
            cfg.taildrop_dir.is_none(),
            "a None taildrop_dir pref must leave Config.taildrop_dir = None (receiving off)"
        );

        // Some(dir) → that exact path is the engine's receive dir.
        be.prefs.taildrop_dir = Some("/var/lib/tailnetd/taildrop".to_string());
        let cfg = be
            .build_config()
            .await
            .expect("build_config (taildrop some)");
        assert_eq!(
            cfg.taildrop_dir,
            Some(std::path::PathBuf::from("/var/lib/tailnetd/taildrop")),
            "a Some(dir) taildrop_dir pref must map to Config.taildrop_dir = Some(PathBuf)"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn apply_config_merges_persists_and_marks_configured() {
        // `Backend::apply_config` is the seam that turns a `--config` document into the node's
        // intent: it merges the config over the loaded prefs, PERSISTS the result (so the intent
        // survives a `--config`-less restart), marks `ever_configured`, and returns the AuthKey
        // out-of-band (never persisting it). The pure merge (`conffile::apply_to_prefs`) is unit-
        // tested in `conffile`; this pins the Backend wrapper's persist + ever_configured + the
        // auth-key-not-persisted contract end to end.
        use secrecy::ExposeSecret;
        let dir = std::env::temp_dir().join(format!("tailnetd-applycfg-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        assert!(!be.ever_configured, "fresh backend is not yet configured");

        // Parse a config that sets a few prefs + carries an auth key.
        let cfg_path = dir.join("c.json");
        tokio::fs::write(
            &cfg_path,
            br#"{"version":"alpha0","Hostname":"cfg-host","acceptDNS":false,"AuthKey":"tskey-secret"}"#,
        )
        .await
        .unwrap();
        let config = crate::conffile::load(&crate::conffile::ConfigSource::File(cfg_path.clone()))
            .expect("load config");

        let authkey = be.apply_config(&config).await.expect("apply_config");

        // (1) The auth key is returned (for bring-up), as a SecretString.
        assert_eq!(
            authkey.as_ref().map(|k| k.expose_secret().to_string()),
            Some("tskey-secret".to_string()),
            "apply_config returns the config auth key"
        );
        // (2) The merge landed on the in-memory prefs (Hostname set; Enabled unset → up; acceptDNS off).
        assert_eq!(be.prefs.hostname.as_deref(), Some("cfg-host"));
        assert!(
            be.prefs.want_running,
            "unset Enabled defaults the node up (Go)"
        );
        assert!(!be.prefs.accept_dns, "acceptDNS:false applied");
        // (3) ever_configured flipped (a --config boot is a deliberate configuration).
        assert!(be.ever_configured, "apply_config marks the node configured");
        // (4) The merged prefs were PERSISTED to disk — re-load and confirm.
        let reloaded = Prefs::load(&be.prefs_path)
            .await
            .expect("reload persisted prefs");
        assert_eq!(reloaded.hostname.as_deref(), Some("cfg-host"));
        assert!(reloaded.want_running);
        assert!(!reloaded.accept_dns);
        // (5) The auth key MUST NOT be in the persisted file (it's a credential, not intent).
        let raw = tokio::fs::read_to_string(&be.prefs_path).await.unwrap();
        assert!(
            !raw.contains("tskey-secret"),
            "the auth key must never be persisted into prefs.json: {raw}"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn apply_tun_flag_maps_the_daemon_flag_onto_the_prefs_and_writes_only_on_change() {
        // `Backend::apply_tun_flag` is the seam that turns `tailnetd --tun` into this node's data
        // path. Go hands its `--tun` to `wgengine.Config`; here the pref is what reaches the engine,
        // so the flag has to land there — and because prefs.json's mere existence is state, a flag
        // that changes nothing must write nothing. Both halves are pinned here.
        let dir = std::env::temp_dir().join(format!("tailnetd-tunflag-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        // (1) `--tun=userspace-networking` on a daemon already on the netstack (the default, and the
        //     overwhelmingly common unit-file case): nothing changed, so nothing is written — a
        //     never-configured node must not acquire a prefs.json just by being started.
        let changed = be
            .apply_tun_flag(&crate::tunflag::TunTransport::Netstack)
            .await
            .expect("applying the netstack transport cannot fail");
        assert!(!changed, "an unchanged transport must report no change");
        assert!(
            !be.prefs_path.exists(),
            "an unchanged --tun must not create {}",
            be.prefs_path.display()
        );

        // (2) `--tun=tailscale0`: TUN on, with that interface name, persisted — the launch flag is
        //     part of the node's intent, so it survives a restart like a `--config` boot does.
        let changed = be
            .apply_tun_flag(&crate::tunflag::TunTransport::Tun {
                name: Some("tailscale0".to_string()),
            })
            .await
            .expect("applying a TUN transport cannot fail");
        assert!(changed, "switching to TUN is a change");
        assert!(be.prefs.tun_enabled);
        assert_eq!(be.prefs.tun_name.as_deref(), Some("tailscale0"));
        let reloaded = Prefs::load(&be.prefs_path)
            .await
            .expect("reload persisted prefs");
        assert!(
            reloaded.tun_enabled && reloaded.tun_name.as_deref() == Some("tailscale0"),
            "the resolved transport must be persisted: {reloaded:?}"
        );
        // Choosing a data path on the command line is not the deliberate "this node is configured"
        // act that `up` or `--config` is, so it must not flip `ever_configured`.
        assert!(
            !be.ever_configured,
            "--tun must not mark the node configured"
        );

        // (3) Back to `--tun=userspace-networking`: TUN off, but the interface NAME is kept. It is
        //     documented as ignored while TUN is off, so clearing it would silently throw away a
        //     name the operator set for the next time they enable it.
        let changed = be
            .apply_tun_flag(&crate::tunflag::TunTransport::Netstack)
            .await
            .expect("applying the netstack transport cannot fail");
        assert!(changed, "switching off TUN is a change");
        assert!(!be.prefs.tun_enabled);
        assert_eq!(
            be.prefs.tun_name.as_deref(),
            Some("tailscale0"),
            "an off transport must not clear the configured interface name"
        );

        // (4) `--tun=utun` on macOS resolves to "no name" (Go's any-free-unit magic value), which is
        //     already this daemon's spelling for "let the platform default choose".
        let changed = be
            .apply_tun_flag(&crate::tunflag::TunTransport::Tun { name: None })
            .await
            .expect("applying a TUN transport cannot fail");
        assert!(changed, "TUN with no name is a change from netstack");
        assert!(be.prefs.tun_enabled && be.prefs.tun_name.is_none());

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn reload_config_without_config_source_refuses_without_erroring() {
        // `reload_config` re-reads the `--config` file the daemon was started with. A daemon launched
        // WITHOUT `--config` has nothing to reload (`config_source` is None). Go's
        // `LocalBackend.ReloadConfig` returns `(false, nil)` for exactly this case — a REFUSAL, not a
        // failure — and leaves the wording and the exit code to its CLI. So this must be `Ok(None)`:
        // an `Err` here would be a daemon-authored error string on the wire, which is both the wrong
        // layer and the wrong words.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-reloadcfg-none-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        assert!(
            be.config_source.is_none(),
            "a backend with no --config has config_source None"
        );

        let outcome = be.reload_config().await.expect(
            "not being in config mode is a refusal, not an error (Go returns (false, nil))",
        );
        assert_eq!(
            outcome, None,
            "no --config in use → None (Go's ok=false), never a reconcile action"
        );
        // And it stayed a no-op: nothing was configured or persisted by the refusal.
        assert!(
            !be.ever_configured,
            "a refused reload must not mark the node configured"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn reload_config_rereads_and_applies_the_config_file() {
        // The happy path on a down node (device: None): `reload_config` re-reads the recorded `--config`
        // file, merges its fields over the prefs, persists, and reports `Ok(false)` (no device up → no
        // rebuild needed; the merged prefs apply on the next `up`). This pins the re-read + merge +
        // persist + decision wiring end to end; the live-rebuild leg needs a real tailnet (the gated
        // e2e). It also proves an EDITED file is re-read (reload picks up the change), the whole point
        // of the verb vs. a one-shot boot apply.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-reloadcfg-apply-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        // Record a config path (as `tailnetd`'s main() would after `--config`), then write a config to
        // it and reload.
        let cfg_path = dir.join("daemon-config.json");
        be.set_config_source(crate::conffile::ConfigSource::File(cfg_path.clone()));
        tokio::fs::write(
            &cfg_path,
            br#"{"version":"alpha0","Hostname":"reloaded-host","ShieldsUp":true}"#,
        )
        .await
        .unwrap();

        let action = be.reload_config().await.expect("reload_config succeeds");
        assert_eq!(
            action,
            Some(ReloadAction::PersistedOnly),
            "a down node (device: None) needs no live reconcile — the merged prefs apply on the next up"
        );
        // The config's fields landed on the in-memory prefs.
        assert_eq!(be.prefs.hostname.as_deref(), Some("reloaded-host"));
        assert!(be.prefs.shields_up, "ShieldsUp:true was adopted");
        // ever_configured flipped (reload goes through apply_config).
        assert!(be.ever_configured, "reload marks the node configured");
        // And the merged prefs were PERSISTED — re-load from disk and confirm.
        let persisted = Prefs::load(&be.prefs_path)
            .await
            .expect("reload persisted prefs from disk");
        assert_eq!(persisted.hostname.as_deref(), Some("reloaded-host"));
        assert!(persisted.shields_up);

        // Now EDIT the file and reload again — the change must be picked up (the verb re-reads the file
        // every time, it is not cached from boot).
        tokio::fs::write(
            &cfg_path,
            br#"{"version":"alpha0","Hostname":"edited-host","ShieldsUp":false}"#,
        )
        .await
        .unwrap();
        be.reload_config().await.expect("second reload succeeds");
        assert_eq!(
            be.prefs.hostname.as_deref(),
            Some("edited-host"),
            "an edited config is re-read on reload"
        );
        assert!(
            !be.prefs.shields_up,
            "the edited ShieldsUp:false was adopted"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn reload_config_applies_enabled_false_as_stop_intent() {
        // Go's config reload ALWAYS re-applies WantRunning (ToPrefs: WantRunningSet effectively always
        // set), so a reloaded `Enabled:false` is a STOP intent — unlike a `set`, a reload IS lifecycle
        // -bearing. On a down node (device: None) this can't reach the live BringDown teardown (that
        // needs a real engine — the gated e2e), but it MUST: (a) persist want_running=false, and (b)
        // map to PersistedOnly (down node → no live reconcile), NOT silently keep up-intent.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-reloadcfg-stop-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        // Pretend the node was up-intent before the reload (a real up would also have a device).
        be.prefs.want_running = true;
        let cfg_path = dir.join("daemon-config.json");
        be.set_config_source(crate::conffile::ConfigSource::File(cfg_path.clone()));

        // A config that keeps the node enabled → want_running stays true; down node → PersistedOnly.
        tokio::fs::write(
            &cfg_path,
            br#"{"version":"alpha0","Hostname":"up-host","Enabled":true}"#,
        )
        .await
        .unwrap();
        assert_eq!(
            be.reload_config().await.unwrap(),
            Some(ReloadAction::PersistedOnly),
            "down node → PersistedOnly regardless of Enabled"
        );
        assert!(
            be.prefs.want_running,
            "Enabled:true keeps want_running true"
        );

        // Now reload a config with Enabled:false → want_running must flip to false (Go applies it).
        tokio::fs::write(
            &cfg_path,
            br#"{"version":"alpha0","Hostname":"up-host","Enabled":false}"#,
        )
        .await
        .unwrap();
        assert_eq!(
            be.reload_config().await.unwrap(),
            Some(ReloadAction::PersistedOnly),
            "still a down node → PersistedOnly (the live BringDown path needs a real device)"
        );
        assert!(
            !be.prefs.want_running,
            "a reloaded Enabled:false MUST set want_running=false (Go re-applies WantRunning on reload)"
        );
        let persisted = Prefs::load(&be.prefs_path).await.unwrap();
        assert!(
            !persisted.want_running,
            "the stop intent must be persisted, not just in-memory"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn reload_config_rejects_a_malformed_file_without_corrupting_prefs() {
        // Fail-fast contract: a now-malformed / unsupported-version `--config` file must be rejected by
        // `reload_config` HARD, leaving the running node's prefs UNTOUCHED (a bad reload must never
        // half-corrupt a live node). `conffile::load` + `apply_to_prefs` validate before mutating; this
        // pins that the Backend wrapper preserves that all-or-nothing behavior.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-reloadcfg-bad-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        be.prefs.hostname = Some("original-host".to_string());

        let cfg_path = dir.join("daemon-config.json");
        be.set_config_source(crate::conffile::ConfigSource::File(cfg_path.clone()));
        // Unsupported version → `conffile::load` rejects it.
        tokio::fs::write(
            &cfg_path,
            br#"{"version":"beta9","Hostname":"should-not-apply"}"#,
        )
        .await
        .unwrap();

        let err = be
            .reload_config()
            .await
            .expect_err("a malformed/unsupported config must be rejected");
        // `reload_config` wraps `conffile::load`'s error with `.with_context`, so the version detail
        // lives in the SOURCE of the chain — assert on the FULL chain (`{:#}`), not the top-level
        // `to_string()` (which is only the "reloading --config <path>" context line).
        let chain = format!("{err:#}");
        assert!(
            chain.to_lowercase().contains("unsupported") || chain.contains("beta9"),
            "the error names the version problem: {chain}"
        );
        // Prefs untouched — the rejected reload mutated nothing in memory.
        assert_eq!(
            be.prefs.hostname.as_deref(),
            Some("original-host"),
            "a rejected reload must leave the running prefs untouched"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
