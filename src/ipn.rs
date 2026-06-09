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
pub async fn shutdown_orphan(orphan: Option<tailscale::Device>) {
    if let Some(dev) = orphan {
        // Best-effort, bounded; the engine's `Runtime::drop` also kills its actors if this times out.
        let _ = dev.shutdown(Some(SHUTDOWN_TIMEOUT)).await;
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
}

/// The daemon backend: owns prefs, the key file, and the live engine handle.
pub struct Backend {
    prefs: Prefs,
    prefs_path: PathBuf,
    key_path: PathBuf,
    /// The running engine, if up. `None` when stopped/needs-login.
    device: Option<tailscale::Device>,
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
    #[must_use = "the returned orphan device must be shut down off-lock"]
    pub fn finish_up(
        &mut self,
        pending: PendingUp,
        device: Result<tailscale::Device>,
    ) -> Result<Option<tailscale::Device>> {
        if pending.generation != self.generation {
            // Superseded by a later up/down while we were handshaking. The newer intent is
            // authoritative; hand any built device back to be torn down off-lock. A build error on a
            // stale attempt is irrelevant (nothing to return).
            tracing::debug!(
                stale_generation = pending.generation,
                current_generation = self.generation,
                "discarding superseded up() result"
            );
            return Ok(device.ok());
        }
        // `device` is already an `anyhow::Result` with engine context from `build_device`.
        let device = device?;
        self.device = Some(device);
        Ok(None)
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

    async fn stop_device(&mut self) {
        if let Some(dev) = self.device.take() {
            // `shutdown` consumes the device; bounded so a wedged engine can't hang the daemon.
            let _ = dev.shutdown(Some(SHUTDOWN_TIMEOUT)).await;
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
}
