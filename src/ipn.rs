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

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};

use crate::localapi::{PeerReport, StatusReport};
use crate::prefs::Prefs;

/// The IPN lifecycle state, mirroring `ipn.State` (subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Process started, nothing configured yet.
    NoState,
    /// No valid login / not authenticated to control.
    ///
    /// Transient nuance from the concurrent bring-up split: between
    /// [`begin_up`](Backend::begin_up) (which sets `want_running = true` but installs no device yet)
    /// and [`finish_up`](Backend::finish_up), a concurrent `status` observes `(device = None,
    /// want_running = true)` and reports `NeedsLogin` for the duration of the handshake — i.e. a
    /// `status` polled *during* an `up` may briefly read `NeedsLogin` before `Running`. This is the
    /// deliberate latency-vs-staleness tradeoff of not holding the lock across `Device::new` (a
    /// poller is no longer *blocked* for the handshake; it sees this transient state instead). A
    /// future refinement could surface a dedicated "bringing up" signal as `Starting`.
    NeedsLogin,
    /// Registered to control, but the machine is not yet authorized by a tailnet admin (Go's
    /// `ipn.NeedsMachineAuth`). See the `// LIMITATION:` note on [`Backend::derive_state`]: the
    /// engine does not surface this from a status snapshot, and no current code path produces it; it
    /// would require [`Backend::up`] to branch on a typed registration error. Kept for `ipn.State`
    /// parity.
    NeedsMachineAuth,
    /// The node key is already in use by a different user/profile (Go's `ipn.InUseOtherUser`).
    /// Unreachable in this single-user, auth-key-only daemon; kept only for `ipn.State` parity.
    InUseOtherUser,
    /// `WantRunning = true`; engine is up, awaiting the first netmap.
    Starting,
    /// Fully up: netmap received, addresses assigned.
    Running,
    /// Configured + authed, but `WantRunning = false` (explicitly down).
    Stopped,
}

impl State {
    /// The stable string name (matches Tailscale's `ipn.State.String()` values).
    pub fn as_str(self) -> &'static str {
        match self {
            State::NoState => "NoState",
            State::NeedsLogin => "NeedsLogin",
            State::NeedsMachineAuth => "NeedsMachineAuth",
            State::InUseOtherUser => "InUseOtherUser",
            State::Starting => "Starting",
            State::Running => "Running",
            State::Stopped => "Stopped",
        }
    }
}

/// How long to wait for a graceful engine shutdown before it is dropped (more violently). Bounds
/// teardown latency so a wedged engine can't hang the daemon (or an orphaned, superseded `up`).
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Perform the slow engine handshake (`Device::new`) for a [`PendingUp`], **without** holding the
/// backend lock. This is the multi-second, network-bound step (control-plane registration); keeping
/// it off-lock is the whole point of the `begin_up`/`finish_up` split — a concurrent `status` (or
/// any other LocalAPI call) is not blocked behind an in-flight `up`.
///
/// The auth-key secret is exposed exactly once, here, for the single engine call that needs the
/// plaintext; the exposed `String` lives no longer than this call.
pub async fn build_device(
    pending: &PendingUp,
    authkey: Option<secrecy::SecretString>,
) -> Result<tailscale::Device> {
    use secrecy::ExposeSecret;
    let authkey_string = authkey.as_ref().map(|s| s.expose_secret().to_string());
    tailscale::Device::new(&pending.config, authkey_string)
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
    opts: UpOptions,
) -> Result<()> {
    // Phase 1: brief lock — prep + persist prefs, build Config, bump generation.
    let pending = {
        let mut be = backend.lock().await;
        be.begin_up(opts).await
    }?;

    // Phase 2: NO lock held — the slow, network-bound control-plane handshake. Concurrent
    // `status`/`down` proceed freely here; this is the whole point of the split.
    let built = build_device(&pending, authkey).await;

    // Phase 3: brief lock — install iff still current, returning any orphan to shut down off-lock.
    let orphan = {
        let mut be = backend.lock().await;
        be.finish_up(pending, built)
    }?;

    // Lock released — settle the (rare) superseded device off-lock so a supersede never blocks the
    // lock for up to SHUTDOWN_TIMEOUT.
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
/// 2. **Exit-node-only, node up** ([`SetAction::LiveExitNode`]) — the one change the engine applies
///    *live* (no reconnect) via [`tailscale::Device::set_exit_node`]. We re-acquire the lock just
///    long enough to issue that single actor message and await it. `set_exit_node` takes `&self`
///    (not `&mut`); the device is held behind an `Arc` (shared with the SSH task), so it *could* be
///    cloned and hoisted off-lock — but we deliberately do NOT, because it is a quick mailbox
///    round-trip (re-resolve the selector against the live peer set + recompute routes), not the
///    multi-second registration handshake the begin/finish split exists to keep off-lock. Holding
///    the brief lock for it keeps the code simple and the prefs-apply + live-set atomic under one
///    lock. Only NEW flows use the new exit; in-flight connections are untouched (no teardown, no
///    reconnect).
/// 3. **Other prefs changed, node up** ([`SetAction::Rebuild`]) — `hostname` / `accept_routes` /
///    `advertise_*` are baked into the engine's *immutable* construction [`tailscale::Config`], so
///    the only way to apply them to a running node is to **rebuild the device** from the
///    now-updated prefs. This reuses the exact [`begin_up`](Backend::begin_up) →
///    [`build_device`] → [`finish_up`](Backend::finish_up) machinery as `drive_up` (same off-lock
///    handshake, same generation-supersede guard, same off-lock orphan settle), so it inherits the
///    same lock discipline verbatim. **CAVEAT — this is a brief reconnect:** rebuilding tears down
///    the live engine and stands a fresh one up, so the overlay drops and re-registers (a short
///    interruption + a new netmap convergence). `set` is honest about this: only the exit-node path
///    is truly seamless. **No `authkey` is involved** (resume uses the persisted node key), and
///    `want_running` is **never** changed — a `set` that rebuilds keeps a running node running and a
///    (paradoxical) `set` on a down node still just persists; `set` is not `up`/`down`.
///
/// This mirrors `drive_up`'s phasing for the rebuild case. The lock is taken briefly for
/// `begin_set` (apply + persist + decide); then, if rebuilding, briefly for `begin_up`; the lock is
/// **dropped** for the slow `build_device`; taken briefly again for `finish_up`; then dropped to
/// settle any superseded orphan off-lock. A concurrent `status`/`down`/`up` is never blocked behind
/// the handshake, and a `down`/`up` that lands mid-rebuild correctly supersedes it (the rebuilt
/// device is discarded).
pub async fn drive_set(
    backend: &std::sync::Arc<tokio::sync::Mutex<Backend>>,
    opts: SetOptions,
) -> Result<()> {
    // Phase 1: brief lock — apply + persist the pref overrides and decide the reconcile path. For
    // the live exit-node path we ALSO issue the live `set_exit_node` here, under the same brief lock:
    // it is a quick actor message (not the off-lock-worthy registration handshake), so we keep it
    // atomic with the prefs-apply rather than hoisting it off-lock via the device's `Arc`.
    let action = {
        let mut be = backend.lock().await;
        be.begin_set(opts).await
    }?;

    match action {
        // Node down: persisting was the whole job; nothing live to reconcile.
        SetAction::PersistedOnly => Ok(()),
        // Exit-node applied live, under the brief lock, inside `begin_set`. Done.
        SetAction::LiveExitNode => Ok(()),
        // Other prefs changed on a running node → rebuild from the updated prefs, reusing the
        // begin_up/build_device/finish_up off-lock handshake exactly like `drive_up`. The brief
        // reconnect is documented on this function and `SetAction::Rebuild`.
        SetAction::Rebuild => {
            // Phase 2-pre: PREFLIGHT the rebuilt config before tearing the live device down.
            // `begin_up` → `stop_device` drops the running engine, but the SSH root/feature checks
            // (and control-URL/route parse) live in `build_config`, which `begin_up` only reaches
            // AFTER teardown. If that check fails (e.g. `set --ssh` without the `ssh` feature or
            // without root), a naive rebuild would leave a healthy node OFFLINE — a `set` that fails
            // must never drop the tunnel. So validate FIRST under a brief lock; on error, return it
            // with the live device untouched. (The pref is already persisted by `begin_set`; it
            // applies on the next successful `up`/`set` — but the running node stays up now.)
            {
                let be = backend.lock().await;
                be.build_config().await?;
            }
            // Phase 2a: brief lock — begin a bring-up from the (already-updated) prefs. No authkey:
            // a rebuild resumes from the persisted node key; `set` never (re)authenticates. NB:
            // `begin_up` sets `want_running = true`, which for a Rebuild action is a no-op (we only
            // rebuild when a device is already up, i.e. the node was already running) — so `set`
            // does not silently flip `want_running` on a down node (that path is PersistedOnly).
            let pending = {
                let mut be = backend.lock().await;
                be.begin_up(UpOptions::default()).await
            }?;
            // Phase 2b: NO lock held — the slow, network-bound re-registration handshake.
            let built = build_device(&pending, None).await;
            // Phase 2c: brief lock — install iff still current, returning any orphan to settle off-lock.
            let orphan = {
                let mut be = backend.lock().await;
                be.finish_up(pending, built)
            }?;
            // Lock released — settle the (rare) superseded device off-lock.
            shutdown_orphan(orphan).await;
            Ok(())
        }
    }
}

/// What [`Backend::begin_set`] decided a `set` must do to reconcile the live engine with the
/// freshly-persisted prefs. The prefs are *already* applied + persisted by the time this is
/// returned; this only describes the remaining engine-side work (and whether the live exit-node set
/// was already issued under the lock).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetAction {
    /// No device is up: persisting the prefs was the entire job; they take effect on the next `up`.
    PersistedOnly,
    /// The only change was the exit node and a device is up — it was applied LIVE (via
    /// [`tailscale::Device::set_exit_node`]) under the brief `begin_set` lock. No rebuild, no
    /// reconnect; nothing further for the caller to do.
    LiveExitNode,
    /// Other prefs (hostname / accept_routes / advertise_*) changed on a running node: the immutable
    /// engine `Config` must be rebuilt from the updated prefs. The caller ([`drive_set`]) runs the
    /// off-lock `begin_up`/`build_device`/`finish_up` handshake. This is a brief reconnect.
    Rebuild,
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
    /// Run-SSH-server override (`None` leaves the pref unchanged; `Some(b)` sets it).
    pub ssh: Option<bool>,
}

/// Prefs to patch via [`Backend::set`] (the `tnet set` path) — the live-mutation analogue of
/// [`UpOptions`]. Same "leave unchanged unless named" sentinel semantics, but a deliberately
/// narrower field set: `set` never (re)authenticates (no `authkey`), never changes the control
/// server or TUN transport (those are connection-defining and belong to `up`), and never flips
/// `want_running`. It only adjusts policy prefs on an already-configured node. `exit_node` is the
/// one field the engine can apply **live** (via [`tailscale::Device::set_exit_node`]); the rest take
/// effect by reconfiguring a running device, or simply persist when the node is down.
#[derive(Debug, Default, Clone)]
pub struct SetOptions {
    /// Requested hostname (applied on the next device (re)build; the engine has no live hostname set).
    pub hostname: Option<String>,
    /// Accept subnet routes advertised by peers (`None` unchanged).
    pub accept_routes: Option<bool>,
    /// Exit-node selector. Double `Option`: `None` unchanged, `Some(None)` clear, `Some(Some(s))`
    /// set. Applied LIVE when a device is up (no reconnect).
    pub exit_node: Option<Option<String>>,
    /// Advertise this node as an exit node (`None` unchanged).
    pub advertise_exit_node: Option<bool>,
    /// Subnet routes this node advertises (`None` unchanged; `Some(vec)` replaces).
    pub advertise_routes: Option<Vec<String>>,
    /// Run the Tailscale SSH server (`None` unchanged; `Some(b)` sets it). Toggling SSH is a
    /// device-rebuild change (the SSH server task is tied to the device lifecycle), so it takes the
    /// [`SetAction::Rebuild`] path on a running node — not the live exit-node fast path.
    pub ssh: Option<bool>,
}

impl SetOptions {
    /// Whether any field is set (a `set` with nothing named is a no-op the server can reject early).
    pub fn is_empty(&self) -> bool {
        self.hostname.is_none()
            && self.accept_routes.is_none()
            && self.exit_node.is_none()
            && self.advertise_exit_node.is_none()
            && self.advertise_routes.is_none()
            && self.ssh.is_none()
    }

    /// Whether the ONLY change requested is the exit node — the case the engine can satisfy purely
    /// live (via [`tailscale::Device::set_exit_node`]) with no device rebuild. Note `ssh` is
    /// deliberately part of this guard: toggling the SSH server is a device-lifecycle change (the
    /// server task is bound to the device), so a `set` that touches `ssh` is NOT exit-node-only and
    /// must take the rebuild path even if it also names an exit node.
    pub fn is_exit_node_only(&self) -> bool {
        self.exit_node.is_some()
            && self.hostname.is_none()
            && self.accept_routes.is_none()
            && self.advertise_exit_node.is_none()
            && self.advertise_routes.is_none()
            && self.ssh.is_none()
    }
}

/// The daemon backend: owns prefs, the key file, and the live engine handle.
pub struct Backend {
    prefs: Prefs,
    prefs_path: PathBuf,
    key_path: PathBuf,
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
    /// Whether **this process** has attempted a boot-time auto-start (set by
    /// [`mark_boot_attempted_up`](Backend::mark_boot_attempted_up)). Process-local and deliberately
    /// NOT persisted: it lets the SIGHUP reload path distinguish "retry a bring-up we already
    /// attempted this run (a transient failure)" from "originate a connection from an out-of-band
    /// `prefs.json` intent flip" — the latter must not silently resurrect a node, so reload only
    /// retries when this is `true`.
    boot_attempted_up: bool,
}

impl Backend {
    /// Construct a backend from a state directory, loading any persisted prefs.
    pub async fn load(state_dir: &std::path::Path) -> Result<Self> {
        let prefs_path = state_dir.join("prefs.json");
        let key_path = state_dir.join("node.key.json");
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
        Ok(Self {
            prefs,
            prefs_path,
            key_path,
            device: None,
            ssh_task: None,
            ever_configured,
            generation: 0,
            boot_attempted_up: false,
            lifecycle_tx,
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
        // Pure read: do NOT call `tailscale::config::load_key_file`, which create-on-missing-writes a
        // fresh key file as a side effect — checking must never manufacture a key.
        let Ok(bytes) = tokio::fs::read(&self.key_path).await else {
            // Missing (fresh node) or unreadable → treat as "no persisted key".
            return false;
        };
        // The on-disk shape is `{ "key_state": <PersistState> }`. Reuse the engine's own
        // `PersistState` Deserialize (rather than hand-rolling the field set) so this can't drift if
        // the engine's key-state layout changes. A parse failure (truncated/corrupt file) reads as
        // "no persisted key" — the daemon then falls back to fresh auth rather than trusting garbage.
        #[derive(serde::Deserialize)]
        struct KeyFile {
            key_state: tailscale::keys::PersistState,
        }
        // A parseable `PersistState` always carries a (32-byte, non-empty) node key, so a successful
        // parse is exactly the "node key present" condition. We derive the public node key from it
        // both to *use* the parsed state (not just discard it) and as a final structural sanity check
        // that the private key material is well-formed.
        match serde_json::from_slice::<KeyFile>(&bytes) {
            Ok(kf) => {
                let _node_public = kf.key_state.node_key.public_key();
                true
            }
            Err(_) => false,
        }
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
        let pending = self.begin_up(opts).await?;
        let built = build_device(&pending, authkey).await;
        // Single-owner path: settle the (rare) orphan inline. No external lock is held here, so the
        // off-lock requirement is trivially satisfied — but in practice nothing supersedes a
        // synchronous `up`, so this is virtually always a no-op.
        let orphan = self.finish_up(pending, built)?;
        shutdown_orphan(orphan).await;
        Ok(())
    }

    /// Apply a live pref mutation (`tnet set`) in a single call — the simple/owned path for a caller
    /// that holds a `&mut Backend` and has no concurrency to protect (e.g. tests, or a future
    /// single-owner caller). It is the `set` analogue of [`up`](Backend::up).
    ///
    /// Runs the decision ([`begin_set`](Backend::begin_set)) and, for the rebuild sub-case, the full
    /// [`begin_up`](Backend::begin_up) → [`build_device`] → [`finish_up`](Backend::finish_up) inline.
    /// The exit-node live set and the prefs persist are already done by `begin_set`.
    ///
    /// For the **concurrent LocalAPI server**, use [`drive_set`] instead, which keeps the rebuild's
    /// slow `Device::new` handshake **off** the backend lock so a concurrent `status` is not
    /// head-of-line blocked. See [`drive_set`] for the full live-vs-rebuild rationale and the
    /// reconnect caveat.
    ///
    /// `set` never (re)authenticates (no `authkey`), never touches the control URL / TUN transport
    /// (those are connection-defining and belong to `up`), and never flips `want_running`.
    pub async fn set(&mut self, opts: SetOptions) -> Result<()> {
        match self.begin_set(opts).await? {
            // Node down, or exit-node applied live under begin_set — nothing further to do.
            SetAction::PersistedOnly | SetAction::LiveExitNode => Ok(()),
            // A non-exit-node pref changed on a running node: rebuild from the updated prefs to apply
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
                let pending = self.begin_up(UpOptions::default()).await?;
                let built = build_device(&pending, None).await;
                let orphan = self.finish_up(pending, built)?;
                shutdown_orphan(orphan).await;
                Ok(())
            }
        }
    }

    /// Phase 1 of a `set` (shared by [`Backend::set`] and [`drive_set`]): apply the [`SetOptions`]
    /// overrides to `self.prefs`, **persist** them, and decide how to reconcile the live engine —
    /// returning a [`SetAction`] for the caller to carry out (or, for the live exit-node case,
    /// already carried out here).
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
    /// The reconcile decision (and the live exit-node set, when chosen) is the one place that needs
    /// the live device, so it is done here under the (brief) backend lock the caller already holds:
    /// - **No device up** → [`SetAction::PersistedOnly`]: the persist above is the whole job; the new
    ///   prefs apply on the next `up`.
    /// - **Device up AND `opts.is_exit_node_only()`** → apply the exit node **live** here via
    ///   [`tailscale::Device::set_exit_node`] (parse `self.prefs.exit_node` into the engine's
    ///   `ExitNodeSelector`, or `None` if cleared — the `FromStr` is infallible, see
    ///   [`build_config`](Backend::build_config)), then return [`SetAction::LiveExitNode`]. No
    ///   rebuild, no reconnect — the fast path that is the whole point of `set`. The actor message is
    ///   awaited under the lock; the device's `Arc` could in principle be cloned to hoist it off-lock,
    ///   but it is a quick mailbox round-trip, so we keep it atomic with the prefs-apply under the one
    ///   brief lock instead.
    /// - **Device up AND other prefs changed** → [`SetAction::Rebuild`]: the caller must rebuild the
    ///   device from the updated prefs (the engine `Config` is immutable). A brief reconnect.
    ///
    /// Does **no** network I/O for the `Rebuild` case (the slow `Device::new` is the caller's
    /// off-lock job); the only blocking step here is the quick live `set_exit_node` mailbox
    /// round-trip on the exit-node path.
    pub async fn begin_set(&mut self, opts: SetOptions) -> Result<SetAction> {
        // Decide the path BEFORE mutating prefs — `is_exit_node_only()` inspects which fields the
        // request named, which the apply below would not change, but reading it first keeps the
        // decision crisply about the *request* rather than post-apply state.
        let exit_node_only = opts.is_exit_node_only();

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
        if let Some(en) = opts.exit_node {
            self.prefs.exit_node = en;
        }
        if let Some(ae) = opts.advertise_exit_node {
            self.prefs.advertise_exit_node = ae;
        }
        if let Some(routes) = opts.advertise_routes {
            self.prefs.advertise_routes = routes;
        }
        // Run-SSH-server override. Toggling SSH is a device-lifecycle change (the server task is
        // bound to the device), so on a running node it must take the Rebuild path, NOT the live
        // exit-node fast path — `SetOptions::is_exit_node_only` already returns false whenever `ssh`
        // is named (see its doc), so the reconcile match below routes a device-up `ssh` change to
        // `Rebuild`, which on rebuild re-runs `finish_up` and (re)spawns the SSH task from the
        // now-updated `ssh_enabled`. The brief reconnect is documented on `drive_set`.
        if let Some(ssh) = opts.ssh {
            self.prefs.ssh_enabled = ssh;
        }
        // `set` is a policy-pref mutation, not a lifecycle change: deliberately do NOT touch
        // `want_running` / `logged_out` (that is `up`/`down`'s job). It still marks the node as
        // configured-at-least-once (a `set` on a never-touched node has now written prefs), matching
        // `up`/`down`, so a `set`-then-restart reads `Stopped`, not `NoState`.
        self.ever_configured = true;
        self.persist_prefs().await?;

        // Reconcile against the live engine. This is the only step that needs the device.
        match self.device.as_ref() {
            // No engine to reconcile — persisting above is the whole job; prefs apply on next `up`.
            None => Ok(SetAction::PersistedOnly),
            // Fast path: only the exit node changed, and a device is up → apply it LIVE. Parse the
            // (now-updated) pref into the engine selector; `None` (cleared) clears the exit node. The
            // `ExitNodeSelector` `FromStr` is infallible (bare IP → `Ip`, else `Name`), so `.parse()`
            // cannot fail — the `Err` is `core::convert::Infallible` (same total parse `build_config`
            // relies on). The call is awaited under the (brief) lock the caller holds: the device's
            // `Arc` could be cloned to hoist this off-lock, but it is a quick mailbox round-trip
            // (re-resolve selector + recompute routes), not the multi-second registration handshake
            // the off-lock split exists for, so we keep it atomic under the one lock. Only NEW flows
            // use the new exit.
            Some(dev) if exit_node_only => {
                let sel: Option<tailscale::ExitNodeSelector> =
                    self.prefs.exit_node.as_ref().map(|s| s.parse().unwrap());
                dev.set_exit_node(sel)
                    .await
                    .map_err(|e| anyhow!("set exit node failed: {e:?}"))?;
                Ok(SetAction::LiveExitNode)
            }
            // A non-exit-node pref changed on a running node: the engine Config is immutable, so the
            // caller must rebuild the device from the updated prefs (a brief reconnect).
            Some(_) => Ok(SetAction::Rebuild),
        }
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
    pub async fn begin_up(&mut self, opts: UpOptions) -> Result<PendingUp> {
        // Tear down any existing device first so `up` is idempotent / reconfiguring.
        self.stop_device().await;

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
        // Run-SSH-server override (same "unchanged unless named" sentinel). The actual SSH server
        // task is spawned on install in `finish_up` when this is set; `build_config` (below) also
        // preflights the feature/root requirements so an impossible `--ssh` fails the bring-up loudly.
        if let Some(ssh) = opts.ssh {
            self.prefs.ssh_enabled = ssh;
        }
        self.prefs.want_running = true;
        self.prefs.logged_out = false;
        self.ever_configured = true;
        self.persist_prefs().await?;

        let config = self.build_config().await?;
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
        // Spawn the SSH server task iff SSH is enabled (and the daemon was built with the `ssh`
        // feature). It outlives this call, running the engine's fail-closed `listen_ssh` accept loop.
        self.spawn_ssh_task(device);
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
                        tracing::error!(error = ?e, "ssh: could not resolve tailnet IPv4; SSH server not started");
                        return;
                    }
                };
                let listen_addr = std::net::SocketAddr::from((ipv4, 22));
                tracing::info!(%listen_addr, "starting Tailscale SSH server");
                // Runs the accept loop forever; only returns on a bind/setup error (or when this task
                // is aborted by `stop_device`, which drops the future). Either way, log the outcome.
                if let Err(e) = device.listen_ssh(config, listen_addr).await {
                    tracing::error!(error = ?e, "ssh: server exited with error");
                }
            });
            self.ssh_task = Some(handle);
        }
    }

    /// Translate current [`Prefs`] + the on-disk key file into a [`tailscale::Config`] for the
    /// engine. This is the single seam where the daemon's reconfigurable intent becomes the engine's
    /// immutable construction config (Phase-3 platform config will grow here), so `up` stays a thin
    /// orchestrator over it.
    ///
    /// Control-server precedence (highest wins): `prefs.control_url` > `TS_CONTROL_URL` > engine
    /// default (real Tailscale). The base is built from [`tailscale::Config::default_from_env`] so
    /// the env var is honored, then the node key is loaded in (mirroring
    /// `Config::default_with_key_file`, which is just `{ key_state: load_key_file(..), ..default() }`
    /// over the *non*-env default), then prefs override hostname/ephemeral/accept_routes, and finally
    /// `prefs.control_url` overrides the control server last so an explicit pref always wins over the
    /// environment.
    async fn build_config(&self) -> Result<tailscale::Config> {
        // Start from the env-aware default so `TS_CONTROL_URL` (and the other `TS_*` vars) are
        // honored, then fold in the persisted node key — `default_with_key_file` does the same
        // `load_key_file` but over the plain (non-env) default, which would silently ignore the env.
        let mut config = tailscale::Config::default_from_env();
        config.key_state = tailscale::config::load_key_file(&self.key_path, Default::default())
            .await
            .map_err(|e| anyhow!("load key file {}: {e:?}", self.key_path.display()))?;
        config.requested_hostname = self.prefs.hostname.clone();
        // Ephemeral defaults to `true` (see `Prefs::default` / `tailscale::Config.ephemeral`). We
        // deliberately do NOT override it to `false` here just to make persisted-key resume more
        // reliable: ephemeral vs. persistent is a node-identity *intent* decision that belongs to
        // prefs/config, not a silent default the daemon flips behind the operator's back. The
        // consequence — surfaced honestly by `tailnetd`'s auto-start logging — is that an ephemeral
        // node is garbage-collected by control shortly after it disconnects, so after a reboot its
        // persisted node key may already be gone from control and a resume-without-authkey will fail.
        // A node that must survive reboots and resume from its key alone needs `ephemeral = false`.
        config.ephemeral = self.prefs.ephemeral;
        config.accept_routes = self.prefs.accept_routes;
        // Exit node: prefs store the raw selector string; parse it into the engine's
        // `ExitNodeSelector`. `FromStr` is infallible (a bare IP → `Ip`, anything else → `Name`),
        // so the parse cannot fail — `Err` is `core::convert::Infallible` and `unwrap` here is
        // unreachable, not a fallible-result-swallow. `None` leaves `config.exit_node` at its
        // default (no exit node = direct egress).
        if let Some(s) = &self.prefs.exit_node {
            let sel: tailscale::ExitNodeSelector = s.parse().unwrap();
            config.exit_node = Some(sel);
        }
        config.advertise_exit_node = self.prefs.advertise_exit_node;
        // Advertised subnet routes: prefs store raw CIDR strings; parse each into `ipnet::IpNet`.
        // A malformed CIDR FAILS LOUDLY (mirroring the `control_url` parse above) rather than being
        // silently dropped — naming the bad value — because an operator who asked to advertise a
        // route and instead got it silently discarded would have a confusing, hard-to-notice gap.
        // (The engine itself is v4-only: it drops any IPv6 prefix internally after this point, so a
        // v6 CIDR is *accepted and parsed* here, then dropped by the engine with no error — we do
        // NOT pre-filter v6, matching the engine's "accept-then-drop" contract.)
        let advertise_routes = self
            .prefs
            .advertise_routes
            .iter()
            .map(|s| {
                s.parse::<ipnet::IpNet>()
                    .with_context(|| format!("invalid advertise route {s:?}"))
            })
            .collect::<Result<Vec<ipnet::IpNet>>>()?;
        config.advertise_routes = advertise_routes;
        // Apply a custom control server when prefs carry one; this wins over `TS_CONTROL_URL` and
        // the engine default. A malformed URL fails loudly rather than silently falling back —
        // pointing at the wrong control plane must never be silent. Only `http`/`https` are accepted
        // (defense-in-depth: the value is operator-trusted, but rejecting a stray scheme is cheap).
        if let Some(s) = &self.prefs.control_url {
            let url = url::Url::parse(s).with_context(|| format!("invalid control_url {s:?}"))?;
            match url.scheme() {
                "http" | "https" => {}
                other => {
                    return Err(anyhow!(
                        "invalid control_url {s:?}: scheme {other:?} is not http or https"
                    ));
                }
            }
            config.control_server_url = url;
        }
        // TUN-mode data path. Default is the engine's userspace netstack (unprivileged); TUN hands
        // packets to a real kernel interface, which needs (a) a daemon built with the `tun` cargo
        // feature [`tailscale/tun`] and (b) root / CAP_NET_ADMIN. We preflight both and FAIL LOUDLY
        // — never silently downgrade to netstack, because the operator asked for OS-wide
        // connectivity and a silent fallback would be a confusing, hard-to-notice half-working state.
        if self.prefs.tun_enabled {
            #[cfg(not(feature = "tun"))]
            {
                return Err(anyhow!(
                    "TUN mode requested (tun_enabled) but this daemon was built without the `tun` \
                     feature; rebuild with `cargo build --features tun` (and run as root) to use it"
                ));
            }
            #[cfg(feature = "tun")]
            {
                // Privilege preflight: the engine's TUN transport errors `RootUserRequired` without
                // root; surface that here with actionable context before the handshake starts.
                #[cfg(unix)]
                // SAFETY: geteuid() is infallible (no args, no preconditions).
                if unsafe { libc::geteuid() } != 0 {
                    return Err(anyhow!(
                        "TUN mode requires root / CAP_NET_ADMIN to create the kernel TUN interface, \
                         but the daemon is not running as root. Run tailnetd as root (the packaged \
                         systemd/launchd units do) or use the default userspace-networking mode"
                    ));
                }
                // Select the kernel-TUN transport. The engine (v0.6.7+) re-exports `TransportMode`
                // and `TunConfig` from the facade, so the daemon can construct the value directly.
                //
                // Interface name: when the operator did not pass `--tun-name`, we must pick a
                // platform-appropriate default rather than let the engine apply its own. The engine
                // defaults a `None` name to `"tailscale0"` (Linux-style), but on macOS the kernel
                // requires utun interfaces to be named `utun*` — `tailscale0` is rejected by `tun-rs`
                // with "device name must start with utun", and the device (hence the whole overlay
                // data path) fails to come up. So on macOS we default to bare `"utun"`, which the
                // kernel treats as "assign the next free utunN". On Linux we leave `None` so the
                // engine's `tailscale0` default stands. (The real fix belongs in the engine's
                // platform-aware default; tracked as an engine ask — until then this keeps TUN
                // working cross-platform.)
                let tun_name = self.prefs.tun_name.clone().or_else(default_tun_name);
                config.transport_mode = tailscale::TransportMode::Tun(tailscale::TunConfig {
                    name: tun_name,
                    mtu: self.prefs.tun_mtu,
                });
            }
        }
        // Tailscale SSH server preflight. Unlike TUN, SSH is NOT an engine `Config` knob — the server
        // is a daemon-spawned task (see `spawn_ssh_task`), so `ssh_enabled` sets NO field on
        // `config`. It only gates the spawn, plus these two fail-loud preflights mirroring TUN's, so
        // an impossible `--ssh` fails the bring-up here rather than silently doing nothing:
        // (a) built without the `ssh` cargo feature → there is no server to spawn; and
        // (b) running as non-root → the engine's `listen_ssh` must drop privileges to the
        //     policy-mapped local user, which requires root, so the session would fail closed.
        // Both fail loudly here (never a silent no-SSH node when SSH was explicitly requested).
        if self.prefs.ssh_enabled {
            #[cfg(not(feature = "ssh"))]
            {
                return Err(anyhow!(
                    "SSH requested (ssh_enabled) but this daemon was built without the `ssh` \
                     feature; rebuild with `cargo build --features ssh` (and run as root) to use it"
                ));
            }
            #[cfg(feature = "ssh")]
            {
                // Privilege preflight: the engine's `listen_ssh` drops privileges to the
                // policy-mapped local user and so requires root; surface that here with actionable
                // context before the handshake starts.
                #[cfg(unix)]
                // SAFETY: geteuid() is infallible (no args, no preconditions).
                if unsafe { libc::geteuid() } != 0 {
                    return Err(anyhow!(
                        "Tailscale SSH server requires root to drop privileges to the policy-mapped \
                         local user, but the daemon is not running as root. Run tailnetd as root \
                         (the packaged systemd/launchd units do) to use --ssh"
                    ));
                }
            }
        }
        Ok(config)
    }

    /// Bring the node down (`WantRunning = false`) without logging out; tears down the engine.
    pub async fn down(&mut self) -> Result<()> {
        self.stop_device().await;
        // Bump the generation so an `up` whose `Device::new` is still in flight (lock released) is
        // recognized as stale by `finish_up` and its device discarded — `down` wins. The bump also
        // notifies status watchers that the device was torn down.
        self.bump_generation();
        self.prefs.want_running = false;
        self.ever_configured = true;
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

        // Query the (blocking) netmap only when Running — the only state with a self-node/peers.
        // Bounded by a timeout so the backend lock is never held indefinitely (see method doc).
        let (self_ipv4, self_name, peers) = match (state, self.device.as_ref()) {
            (State::Running, Some(dev)) => {
                match tokio::time::timeout(STATUS_QUERY_TIMEOUT, dev.status()).await {
                    Ok(Ok(s)) => {
                        let (ip, name) = match s.self_node {
                            Some(n) => (Some(n.ipv4.to_string()), Some(n.display_name)),
                            None => (None, None),
                        };
                        let peers = s
                            .peers
                            .into_iter()
                            .map(|p| PeerReport {
                                name: p.display_name,
                                ipv4: p.ipv4.to_string(),
                                is_exit_node: p.is_exit_node,
                            })
                            .collect();
                        (ip, name, peers)
                    }
                    // Transient engine error: log and report no addresses/peers (state stays Running).
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "engine status query failed");
                        (None, None, Vec::new())
                    }
                    // Pre-netmap window (or a wedged Running engine): don't hold the lock waiting.
                    // Report Running with no addresses yet; the next status poll fills them in.
                    Err(_elapsed) => {
                        tracing::debug!(
                            "engine status query exceeded {STATUS_QUERY_TIMEOUT:?}; \
                             reporting Running without addresses (netmap not yet converged)"
                        );
                        (None, None, Vec::new())
                    }
                }
            }
            _ => (None, None, Vec::new()),
        };

        StatusReport {
            state: state.as_str().to_string(),
            want_running: self.prefs.want_running,
            self_ipv4,
            self_name,
            auth_url,
            error,
            peers,
        }
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
            self.ever_configured,
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
        // Step 1: stop the SSH server task first so its `Arc` clone of the device is released before
        // we try to reclaim sole ownership. Aborting an already-finished task is harmless.
        if let Some(task) = self.ssh_task.take() {
            task.abort();
            // Await the aborted handle so the task (and its `Arc` clone) is truly gone before we
            // reclaim the device. The result is the expected cancellation `JoinError` — ignore it.
            let _ = task.await;
        }
        // Step 2: reclaim and gracefully shut down the engine. After the abort+await above, the
        // backend holds the only `Arc`, so `into_inner` yields the owned `Device` for `shutdown`.
        if let Some(dev) = self.device.take() {
            match std::sync::Arc::into_inner(dev) {
                Some(owned) => {
                    // `shutdown` consumes the device; bounded so a wedged engine can't hang the daemon.
                    let _ = owned.shutdown(Some(SHUTDOWN_TIMEOUT)).await;
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
            .with_context(|| format!("saving prefs to {}", self.prefs_path.display()))
    }
}

/// The default TUN interface name to request when the operator gave none, by platform.
///
/// `None` means "let the engine choose its default" (`tailscale0` on Linux, which the kernel
/// accepts). macOS is special: the engine coerces a `None` name to `tailscale0`, which the kernel
/// rejects (utun interfaces *must* be named `utun*`), and `tun-rs` also rejects a *bare* `"utun"`
/// (it parses the trailing digits as the unit, and `""` fails: "cannot parse integer from empty
/// string"). The only value that works through the engine on macOS is an explicit, currently-free
/// `utunN`. So on macOS we scan existing interfaces and return the lowest free index. Linux/BSD
/// return `None` (the engine's `tailscale0` default stands).
///
/// (The real fix is a platform-aware default in the engine — see `docs/ENGINE_ASKS.md` #5 — at
/// which point this becomes a redundant no-op. Until then it keeps macOS TUN working.)
///
/// Note the inherent, bounded TOCTOU: another process could claim the chosen `utunN` between this
/// scan and the engine's device create. That is fine — device creation fails closed (no silent
/// downgrade), so the operator simply retries and the next scan picks a different free index.
#[cfg(feature = "tun")]
fn default_tun_name() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        Some(lowest_free_utun())
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// The lowest `utunN` name not currently present on the host (macOS). Enumerates interfaces via
/// `if-addrs`; if enumeration fails, falls back to `utun0` (the kernel will still reject it if taken,
/// which fails closed and prompts a retry — never a silent wrong-interface).
#[cfg(all(feature = "tun", target_os = "macos"))]
fn lowest_free_utun() -> String {
    use std::collections::BTreeSet;
    let used: BTreeSet<u32> = if_addrs::get_if_addrs()
        .map(|ifaces| {
            ifaces
                .into_iter()
                .filter_map(|i| {
                    i.name
                        .strip_prefix("utun")
                        .and_then(|n| n.parse::<u32>().ok())
                })
                .collect()
        })
        .unwrap_or_default();
    let n = (0..)
        .find(|n| !used.contains(n))
        .expect("a free utun index exists");
    format!("utun{n}")
}

/// Pure state-derivation decision, extracted from [`Backend::derive_state`] so it is unit-testable
/// without a live `Backend` or engine.
///
/// Inputs are the four observable facts the reported [`State`] is a function of:
/// - `has_device`: an engine [`tailscale::Device`] is currently constructed (the node is "up").
/// - `have_self_node`: the engine has received a netmap and assigned this node its addresses.
/// - `want_running` / `logged_out`: the persisted [`Prefs`] intent.
/// - `ever_configured`: the node has been configured at least once (distinguishes a never-touched
///   `NoState` from an explicit `Stopped`); persisted across restarts via the prefs file (see
///   [`Backend::load`]).
///
/// See the `// LIMITATION:` note on [`Backend::derive_state`] for why [`State::NeedsMachineAuth`]
/// and [`State::InUseOtherUser`] are never produced here.
fn derive_state_from(
    has_device: bool,
    have_self_node: bool,
    want_running: bool,
    logged_out: bool,
    ever_configured: bool,
) -> State {
    match has_device {
        true if have_self_node => State::Running,
        true => State::Starting,
        false if logged_out => State::NeedsLogin,
        false if want_running => State::NeedsLogin, // wants up but no engine → needs (re)auth
        false if ever_configured => State::Stopped,
        false => State::NoState,
    }
}

/// Map the engine's authoritative [`tailscale::DeviceState`] to the daemon's reported [`State`]
/// plus two optional, mutually-exclusive detail strings: the interactive-login auth URL and the
/// terminal-failure reason. Pure, so the mapping is unit-testable without a live engine.
///
/// Returns `(State, auth_url, error)`:
/// - **`State`** — the lifecycle state surfaced on the wire (`StatusReport.state`). There are only
///   ever the seven `ipn.State` names (pinned by [`state_as_str_is_stable`](tests)); we deliberately
///   do **not** mint an eighth variant for a terminal failure. Go surfaces that case the same way:
///   the state stays `NeedsLogin`, and a separate `ipnstate.Status.ErrMessage` field carries the
///   reason. The `error` return below is that field's analogue.
/// - **`auth_url`** (2nd) — `Some(url)` **only** for `NeedsLogin(url)`: an interactive-login flow is
///   pending and the operator must authorize the node at that URL. Always `None` otherwise.
/// - **`error`** (3rd) — `Some(reason)` **only** for `Failed(e)`: registration hard-failed and the
///   engine will not retry. It carries [`tailscale::RegistrationError`]'s `Display` string so a
///   caller can report *why* (and, via [`RegistrationError::is_permanent`](tailscale::RegistrationError::is_permanent),
///   that it is terminal). Always `None` otherwise.
///
/// This is the source of truth when a device exists: the engine knows about interactive-login,
/// key-expiry, and hard registration failure — distinctions netmap-presence alone cannot make.
/// - `Connecting` → `Starting` (registering; the netmap stream is not yet live), no url, no error.
/// - `Running` → `Running`, no url, no error. The engine publishes `Running` only once "registered
///   and the netmap stream is live" (per its `DeviceState` doc), so it already implies the node is
///   up — we do not second-guess it with a separate self-node check.
/// - `NeedsLogin(url)` → [`State::NeedsLogin`] **carrying the auth URL** — an `up` without a usable
///   auth key needs a human to authorize the node at that URL (the interactive-login flow).
/// - `Expired` → [`State::NeedsLogin`] with **no url and no error**: an expired node key is a
///   re-auth *prompt*, not a hard failure (the operator simply re-runs `tnet up`); the engine
///   carries no URL here, and we deliberately do not populate `error` so an expiry never looks like
///   a terminal registration failure.
/// - `Failed(e)` splits on [`RegistrationError::is_permanent`](tailscale::RegistrationError::is_permanent),
///   because the engine reuses this one variant for two very different cases:
///   - **permanent** (`AuthRejected` / `KeyExpired`) → [`State::NeedsLogin`] with **no url** but
///     **`error = Some(e.to_string())`**: a failure the engine will NOT retry. The state stays
///     `NeedsLogin` (no eighth `ipn.State`; see above), but `error` carries the reason so the
///     daemon/CLI can distinguish "interactive login pending" (`auth_url` set, transient) from
///     "registration hard-failed" (`error` set, terminal). The absent `auth_url` is intentional: a
///     hard failure must NOT masquerade as an interactive-login prompt.
///   - **transient** (`NetworkUnreachable` / `Timeout`) → [`State::Starting`] with **no url and no
///     error**: the engine keeps retrying (it publishes `Failed(NetworkUnreachable)` precisely when
///     "a retry may succeed"), so this is neither terminal nor a login problem. Reporting it via
///     `error` would tell the operator to rotate a key that is actually fine — the exact misleading
///     guidance this mapping exists to avoid — so a transient failure looks like ongoing
///     convergence, and the next poll reflects the retry's outcome.
fn state_from_device(ds: tailscale::DeviceState) -> (State, Option<String>, Option<String>) {
    use tailscale::DeviceState;
    match ds {
        DeviceState::Running => (State::Running, None, None),
        DeviceState::Connecting => (State::Starting, None, None),
        DeviceState::NeedsLogin(url) => (State::NeedsLogin, Some(url.to_string()), None),
        // Key expiry is a re-auth prompt, not a hard failure: NeedsLogin with no url and no error
        // (an expiry must not be reported as a terminal registration failure).
        DeviceState::Expired => (State::NeedsLogin, None, None),
        // A `Failed` outcome splits on permanence — the engine reuses this one variant for BOTH a
        // terminal failure AND a transient one (it publishes `Failed(NetworkUnreachable)` when the
        // control session can't connect, with the explicit intent that "a retry / fresh Device::new
        // may succeed" — see ts_runtime control_runner). Treating every `Failed` as terminal would
        // tell the operator "permanent failure, use a fresh key" on a mere network blip — exactly
        // the misleading guidance this whole change exists to remove. So we gate on
        // `RegistrationError::is_permanent()` (true only for `AuthRejected` / `KeyExpired`):
        DeviceState::Failed(e) if e.is_permanent() => {
            // PERMANENT (bad/expired/unknown key): the engine will NOT retry. Keep the state mapped
            // to NeedsLogin (no eighth ipn.State — Go surfaces this via a separate ErrMessage
            // field), but carry the reason in `error` so the daemon/CLI can tell a hard failure
            // (error set, no auth_url) apart from interactive login (auth_url set, no error). No
            // auth_url: a hard failure is not an interactive-login prompt.
            (State::NeedsLogin, None, Some(e.to_string()))
        }
        // TRANSIENT (`NetworkUnreachable` / `Timeout`): the engine keeps retrying, so this is NOT
        // terminal and NOT a login problem — surface it as `Starting` (still converging), with no
        // `error` (so the CLI never tells the operator to rotate a key that is actually fine) and no
        // auth_url. The next poll reflects the retry's outcome (Running, or a permanent Failed).
        DeviceState::Failed(_) => (State::Starting, None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `derive_state_from` is the whole state machine's decision in one pure function; exercise the
    // full input matrix here so the reported `ipn.State` can never silently drift. (The two
    // parity-only variants — `NeedsMachineAuth` / `InUseOtherUser` — are intentionally not produced
    // by this function; see the `// LIMITATION:` note on `Backend::derive_state`.)

    #[test]
    fn no_device_not_configured_is_no_state() {
        // Fresh process, never brought up, no intent → NoState.
        assert_eq!(
            derive_state_from(false, false, false, false, false),
            State::NoState
        );
    }

    #[test]
    fn no_device_want_running_but_logged_out_is_needs_login() {
        // Logged out always wins (suppresses auto-start); the node needs a (re)login.
        assert_eq!(
            derive_state_from(false, false, true, true, true),
            State::NeedsLogin
        );
        // …and even with want_running false, an explicit logout still reads as NeedsLogin.
        assert_eq!(
            derive_state_from(false, false, false, true, true),
            State::NeedsLogin
        );
    }

    #[test]
    fn no_device_want_running_is_needs_login() {
        // Wants to be up but the engine isn't constructed → needs (re)auth to bring it up.
        assert_eq!(
            derive_state_from(false, false, true, false, true),
            State::NeedsLogin
        );
    }

    #[test]
    fn device_present_no_self_node_is_starting() {
        // Engine is up but no netmap yet → Starting. (This is also where a machine awaiting admin
        // approval honestly lands; see the LIMITATION note.) The prefs are irrelevant once a device
        // exists, so assert both intents collapse to Starting.
        assert_eq!(
            derive_state_from(true, false, true, false, true),
            State::Starting
        );
        assert_eq!(
            derive_state_from(true, false, false, false, false),
            State::Starting
        );
    }

    #[test]
    fn device_present_with_self_node_is_running() {
        // Engine up + netmap received → Running, regardless of the persisted intent.
        assert_eq!(
            derive_state_from(true, true, true, false, true),
            State::Running
        );
        assert_eq!(
            derive_state_from(true, true, false, true, true),
            State::Running
        );
    }

    #[test]
    fn down_after_ever_configured_is_stopped() {
        // No device, not logged out, not wanting to run, but configured before → explicitly Stopped
        // (distinct from the never-configured NoState).
        assert_eq!(
            derive_state_from(false, false, false, false, true),
            State::Stopped
        );
    }

    #[test]
    fn ever_configured_is_the_only_no_state_vs_stopped_discriminator() {
        // With identical (no-device, not-logged-out, not-want-running) inputs, `ever_configured` is
        // the sole bit that flips NoState ↔ Stopped — the distinction finding-4 makes survive a
        // restart. Pin both sides of that single flip in one place.
        assert_eq!(
            derive_state_from(false, false, false, false, false),
            State::NoState
        );
        assert_eq!(
            derive_state_from(false, false, false, false, true),
            State::Stopped
        );
    }

    #[test]
    fn state_as_str_is_stable() {
        // The state string is a wire contract (LocalAPI StatusReport.state); pin every name.
        assert_eq!(State::NoState.as_str(), "NoState");
        assert_eq!(State::NeedsLogin.as_str(), "NeedsLogin");
        assert_eq!(State::NeedsMachineAuth.as_str(), "NeedsMachineAuth");
        assert_eq!(State::InUseOtherUser.as_str(), "InUseOtherUser");
        assert_eq!(State::Starting.as_str(), "Starting");
        assert_eq!(State::Running.as_str(), "Running");
        assert_eq!(State::Stopped.as_str(), "Stopped");
    }

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
            prefs_path: dir.join("prefs.json"),
            key_path: dir.join("node.key.json"),
            device: None,
            ssh_task: None,
            ever_configured: false,
            generation: 0,
            boot_attempted_up: false,
            lifecycle_tx: tokio::sync::watch::channel(0u64).0,
        }
    }

    // `state_from_device` maps the engine's authoritative `DeviceState` → `(State, auth_url, error)`.
    // It is the source of truth when a device exists, so the interactive-login URL surfacing, the
    // expiry→NeedsLogin collapse, and the terminal-failure→`error` surfacing must not drift. The
    // `auth_url` and `error` outputs are mutually exclusive (interactive-login vs. hard failure) and
    // every non-NeedsLogin(url)/non-Failed state carries neither. Pure, so testable without a live
    // engine.

    // macOS picks an explicit free `utunN` (the engine default `tailscale0` is rejected, and a bare
    // `utun` fails tun-rs's unit parse). `if_addrs` is a macOS-only dependency, so this test — which
    // references it — must be `target_os = "macos"`-gated at COMPILE time (a runtime `cfg!()` would
    // still try to compile the `if_addrs` path on Linux, where the crate isn't present).
    #[cfg(all(feature = "tun", target_os = "macos"))]
    #[test]
    fn default_tun_name_is_free_utun_on_macos() {
        let name = default_tun_name().expect("macOS must pick a concrete utun name");
        let n = name
            .strip_prefix("utun")
            .and_then(|s| s.parse::<u32>().ok())
            .expect("name must be utun<N> with a numeric unit");
        // The chosen index must be free: not a utun currently on the host.
        let used: std::collections::BTreeSet<u32> = if_addrs::get_if_addrs()
            .map(|ifs| {
                ifs.into_iter()
                    .filter_map(|i| {
                        i.name
                            .strip_prefix("utun")
                            .and_then(|s| s.parse::<u32>().ok())
                    })
                    .collect()
            })
            .unwrap_or_default();
        assert!(!used.contains(&n), "chosen utun{n} must be free");
    }

    // On non-macOS the daemon defers to the engine's default name (None).
    #[cfg(all(feature = "tun", not(target_os = "macos")))]
    #[test]
    fn default_tun_name_is_none_off_macos() {
        assert_eq!(default_tun_name(), None);
    }

    #[test]
    fn device_running_is_running_no_url() {
        // The engine publishes `Running` only once "registered and the netmap stream is live", so it
        // maps straight to `Running` (no separate self-node check). A healthy state carries neither
        // an auth URL nor a failure reason.
        let (st, url, err) = state_from_device(tailscale::DeviceState::Running);
        assert_eq!(st, State::Running);
        assert!(url.is_none());
        assert!(err.is_none(), "Running is not a failure → no error reason");
    }

    #[test]
    fn device_connecting_is_starting() {
        // Registering, netmap stream not yet live → still converging. Neither an auth URL nor a
        // failure reason while merely converging.
        let (st, url, err) = state_from_device(tailscale::DeviceState::Connecting);
        assert_eq!(st, State::Starting);
        assert!(url.is_none());
        assert!(
            err.is_none(),
            "Connecting is not a failure → no error reason"
        );
    }

    #[test]
    fn device_needs_login_carries_auth_url() {
        // The headline of interactive login: NeedsLogin(url) → State::NeedsLogin + the URL surfaced
        // verbatim so the CLI can print a clickable login link. Interactive login is NOT a hard
        // failure, so the `error` field stays empty (auth_url and error are mutually exclusive).
        let url: url::Url = "https://login.example.com/a/abc123".parse().unwrap();
        let (st, out, err) = state_from_device(tailscale::DeviceState::NeedsLogin(url.clone()));
        assert_eq!(st, State::NeedsLogin);
        assert_eq!(out.as_deref(), Some(url.as_str()));
        assert!(
            err.is_none(),
            "interactive login carries an auth_url, not an error reason"
        );
    }

    #[test]
    fn device_expired_is_needs_login_no_url() {
        // Key expiry needs re-auth but the engine carries no URL here → NeedsLogin, no URL. An
        // expiry is a re-auth *prompt*, not a terminal failure, so `error` is also empty (it must
        // NOT be reported like a hard registration failure).
        let (st, url, err) = state_from_device(tailscale::DeviceState::Expired);
        assert_eq!(st, State::NeedsLogin);
        assert!(url.is_none());
        assert!(
            err.is_none(),
            "key expiry is a re-auth prompt, not a terminal failure → no error reason"
        );
    }

    #[test]
    fn device_failed_carries_error_reason() {
        // A terminal registration failure (bad/unknown auth key) the engine will NOT retry. The
        // state still collapses to `NeedsLogin` (no eighth `ipn.State`; see `state_from_device`'s
        // doc), but the failure must surface through the `error` field — and crucially NOT through
        // `auth_url`, so a hard failure can never be mistaken for an interactive-login prompt.
        let (st, url, err) = state_from_device(tailscale::DeviceState::Failed(
            tailscale::RegistrationError::AuthRejected("bad auth key".into()),
        ));
        assert_eq!(st, State::NeedsLogin, "a hard failure maps to NeedsLogin");
        assert!(
            url.is_none(),
            "a hard failure has NO login URL — it must not look like interactive login"
        );
        let reason = err.expect("a terminal failure must carry its reason in `error`");
        // `RegistrationError::AuthRejected`'s Display is
        // "authentication rejected by control: {0}", so it contains the inner reason verbatim.
        assert!(
            reason.contains("bad auth key"),
            "the error must carry the rejection reason, got {reason:?}"
        );
    }

    #[test]
    fn device_failed_key_expired_carries_error() {
        // The other terminal `RegistrationError` variant: an *expired* node key that surfaces as a
        // hard `Failed` (distinct from the transient `DeviceState::Expired` re-auth prompt above).
        // It likewise stays `NeedsLogin` with no auth_url, but populates `error` with the variant's
        // Display string ("node key expired; re-authentication required").
        let (st, url, err) = state_from_device(tailscale::DeviceState::Failed(
            tailscale::RegistrationError::KeyExpired,
        ));
        assert_eq!(st, State::NeedsLogin);
        assert!(
            url.is_none(),
            "a hard failure carries no interactive-login URL"
        );
        let reason = err.expect("a terminal failure must carry its reason in `error`");
        assert!(
            reason.contains("expired"),
            "the error must describe the key-expiry failure, got {reason:?}"
        );
    }

    #[test]
    fn failed_splits_on_permanence_permanent_carries_error_transient_is_starting() {
        // The core of the review fix: `Failed(e)` is NOT uniformly terminal. The engine reuses the
        // variant for both a permanent failure (the user must re-pair) AND a transient one it keeps
        // retrying (`Failed(NetworkUnreachable)` on a control-session connect blip). The daemon must
        // split on `RegistrationError::is_permanent()` so a network hiccup never tells the operator
        // their key is bad. This test drives BOTH classes and is also the transposition guard for the
        // two same-typed `Option<String>` outputs (auth_url ⊕ error are mutually exclusive).
        let url: url::Url = "https://login.example.com/a/xyz".parse().unwrap();
        let cases = [
            tailscale::RegistrationError::AuthRejected("bad key".into()),
            tailscale::RegistrationError::KeyExpired,
            tailscale::RegistrationError::NeedsLogin(url),
            tailscale::RegistrationError::NetworkUnreachable,
            tailscale::RegistrationError::Timeout,
        ];
        for re in cases {
            let permanent = re.is_permanent();
            let expected_reason = re.to_string();
            let (st, auth_url, error) =
                state_from_device(tailscale::DeviceState::Failed(re.clone()));

            // NEVER populate auth_url for a Failed of any flavor — a hard failure (or a retrying
            // one) must not masquerade as an interactive-login prompt. This is the transposition
            // guard: a swap of the auth_url/error fields would trip here.
            assert!(
                auth_url.is_none(),
                "a Failed variant must NEVER populate auth_url; variant {re:?}"
            );

            if permanent {
                // AuthRejected / KeyExpired: terminal → NeedsLogin + the reason in `error`.
                assert_eq!(
                    st,
                    State::NeedsLogin,
                    "a permanent Failed maps to NeedsLogin; variant {re:?}"
                );
                assert_eq!(
                    error.as_deref(),
                    Some(expected_reason.as_str()),
                    "a permanent Failed must carry its Display reason verbatim in `error`; variant {re:?}"
                );
            } else {
                // NetworkUnreachable / Timeout / the NeedsLogin-URL form: the engine keeps retrying,
                // so this is ongoing convergence, NOT a terminal error. Surface `Starting` with no
                // error — so the CLI never tells the operator to rotate a key that is actually fine.
                assert_eq!(
                    st,
                    State::Starting,
                    "a transient/retrying Failed maps to Starting (still converging); variant {re:?}"
                );
                assert!(
                    error.is_none(),
                    "a transient Failed must NOT populate `error` (no misleading permanent-failure \
                     guidance); variant {re:?}"
                );
            }
        }
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
        let pending = be.begin_up(UpOptions::default()).await.expect("begin_up");
        assert_eq!(
            pending.generation,
            gen0 + 1,
            "begin_up must bump the generation"
        );
        assert!(be.prefs.want_running, "begin_up sets want_running");

        // A `down` lands while the (hypothetical) handshake is still in flight → supersedes.
        be.down().await.expect("down");
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

        let pending = be.begin_up(UpOptions::default()).await.expect("begin_up");
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
    async fn begin_up_applies_exit_node_and_advertise_overrides() {
        // The `UpOptions` sentinel semantics, end-to-end through `begin_up`: a `Some(Some(sel))`
        // sets exit_node, a `Some(None)` clears it, and the advertise overrides set/clear. Driven
        // without an engine (begin_up only mutates + persists prefs and builds Config).
        let dir =
            std::env::temp_dir().join(format!("tailnetd-bu-overrides-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);

        // SET via overrides.
        let _ = be
            .begin_up(UpOptions {
                exit_node: Some(Some("exit-1".to_string())),
                advertise_exit_node: Some(true),
                advertise_routes: Some(vec!["10.0.0.0/8".to_string()]),
                ..UpOptions::default()
            })
            .await
            .expect("begin_up set");
        assert_eq!(be.prefs.exit_node.as_deref(), Some("exit-1"));
        assert!(be.prefs.advertise_exit_node);
        assert_eq!(be.prefs.advertise_routes, vec!["10.0.0.0/8".to_string()]);

        // A plain follow-up `up` (all None) must leave the prefs UNCHANGED.
        let _ = be
            .begin_up(UpOptions::default())
            .await
            .expect("begin_up unchanged");
        assert_eq!(
            be.prefs.exit_node.as_deref(),
            Some("exit-1"),
            "an unchanged (None) override must preserve the stored exit_node"
        );
        assert!(
            be.prefs.advertise_exit_node,
            "unchanged override preserves it"
        );
        assert_eq!(be.prefs.advertise_routes, vec!["10.0.0.0/8".to_string()]);

        // CLEAR exit_node via `Some(None)`, clear the advertised set via `Some(vec![])`.
        let _ = be
            .begin_up(UpOptions {
                exit_node: Some(None),
                advertise_exit_node: Some(false),
                advertise_routes: Some(vec![]),
                ..UpOptions::default()
            })
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
    fn set_options_is_exit_node_only_truth_table() {
        // The fast-path discriminator: `is_exit_node_only` is true IFF exit_node is named AND no
        // other field is — that is the ONLY shape the engine satisfies live (no rebuild). Both the
        // SET and CLEAR exit_node forms qualify; pairing exit_node with anything else does not; and
        // a request that names no exit_node is never "exit-node only".
        assert!(
            SetOptions {
                exit_node: Some(Some("100.64.0.9".into())),
                ..SetOptions::default()
            }
            .is_exit_node_only(),
            "exit_node SET alone is exit-node-only (live path)"
        );
        assert!(
            SetOptions {
                exit_node: Some(None),
                ..SetOptions::default()
            }
            .is_exit_node_only(),
            "exit_node CLEAR alone is exit-node-only (live path)"
        );
        assert!(
            !SetOptions::default().is_exit_node_only(),
            "an empty set names no exit_node → not exit-node-only"
        );
        assert!(
            !SetOptions {
                exit_node: Some(Some("x".into())),
                hostname: Some("h".into()),
                ..SetOptions::default()
            }
            .is_exit_node_only(),
            "exit_node + hostname needs a rebuild → NOT exit-node-only"
        );
        assert!(
            !SetOptions {
                exit_node: Some(Some("x".into())),
                accept_routes: Some(true),
                ..SetOptions::default()
            }
            .is_exit_node_only(),
            "exit_node + accept_routes needs a rebuild → NOT exit-node-only"
        );
        assert!(
            !SetOptions {
                hostname: Some("h".into()),
                ..SetOptions::default()
            }
            .is_exit_node_only(),
            "a non-exit-node change is not exit-node-only"
        );
        // SSH is a device-lifecycle change, so it must take the REBUILD path, never the live
        // exit-node fast path: an ssh-only set is not exit-node-only, and pairing ssh WITH an
        // exit_node still is not (the ssh toggle forces a rebuild even alongside an exit-node change).
        assert!(
            !SetOptions {
                ssh: Some(true),
                ..SetOptions::default()
            }
            .is_exit_node_only(),
            "an ssh-only toggle is a device-lifecycle change → NOT exit-node-only"
        );
        assert!(
            !SetOptions {
                exit_node: Some(Some("100.64.0.9".into())),
                ssh: Some(true),
                ..SetOptions::default()
            }
            .is_exit_node_only(),
            "exit_node + ssh must rebuild (ssh is bound to the device) → NOT exit-node-only"
        );
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
        let action = be
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
            action,
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
        let action = be
            .begin_set(SetOptions::default())
            .await
            .expect("begin_set");
        assert_eq!(action, SetAction::PersistedOnly);
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
            .begin_up(UpOptions::default())
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
            .begin_up(UpOptions {
                ssh: Some(false),
                ..UpOptions::default()
            })
            .await
            .expect("begin_up disable ssh");
        assert!(
            !be.prefs.ssh_enabled,
            "Some(false) must disable ssh_enabled"
        );

        // And a follow-up `None` override must preserve the now-disabled state.
        let _ = be
            .begin_up(UpOptions::default())
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
        let action = be
            .begin_set(SetOptions {
                ssh: Some(true),
                ..SetOptions::default()
            })
            .await
            .expect("begin_set enable ssh");
        assert_eq!(
            action,
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
}
