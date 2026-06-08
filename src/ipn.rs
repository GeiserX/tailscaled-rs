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
//! actually *reach* `NeedsMachineAuth` from a live status snapshot — the engine does not surface a
//! "machine authorized / awaiting admin approval" signal (see the `// LIMITATION:` note on
//! [`Backend::derive_state`]); it is only reachable via the explicit registration-error path, and
//! `InUseOtherUser` is unreachable in this single-user daemon (auth-key registration only, no
//! interactive multi-profile login). Honest gaps over fabricated states.

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
    NeedsLogin,
    /// Registered to control, but the machine is not yet authorized by a tailnet admin (Go's
    /// `ipn.NeedsMachineAuth`). See the `// LIMITATION:` note on [`Backend::derive_state`]: the
    /// engine does not surface this from a status snapshot, so it is reached only via an explicit
    /// registration-error path, never inferred from a netmap.
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

/// The daemon backend: owns prefs, the key file, and the live engine handle.
pub struct Backend {
    prefs: Prefs,
    prefs_path: PathBuf,
    key_path: PathBuf,
    /// The running engine, if up. `None` when stopped/needs-login.
    device: Option<tailscale::Device>,
    /// Whether the node has ever been brought up in this process (distinguishes `NoState` from
    /// `Stopped`).
    ever_configured: bool,
}

impl Backend {
    /// Construct a backend from a state directory, loading any persisted prefs.
    pub async fn load(state_dir: &std::path::Path) -> Result<Self> {
        let prefs_path = state_dir.join("prefs.json");
        let key_path = state_dir.join("node.key.json");
        let prefs = Prefs::load(&prefs_path)
            .await
            .with_context(|| format!("loading prefs from {}", prefs_path.display()))?;
        let ever_configured = prefs.want_running || prefs.logged_out;
        Ok(Self {
            prefs,
            prefs_path,
            key_path,
            device: None,
            ever_configured,
        })
    }

    /// Whether the persisted intent is to be running (used by the daemon to auto-start on launch).
    pub fn wants_running(&self) -> bool {
        self.prefs.want_running && !self.prefs.logged_out
    }

    /// Bring the node up: set `WantRunning`, (re)build the engine from current prefs, and register.
    ///
    /// `authkey` is the pre-auth key for non-interactive registration (the MVP's only login path).
    /// It is a [`secrecy::SecretString`] so it is zeroized on drop and never lands in a `Debug`
    /// rendering or log line; it is never stored on the [`Backend`] — it flows through this method
    /// and is exposed exactly once, at the [`tailscale::Device::new`] engine call below.
    pub async fn up(
        &mut self,
        authkey: Option<secrecy::SecretString>,
        hostname: Option<String>,
        control_url: Option<String>,
    ) -> Result<()> {
        // Tear down any existing device first so `up` is idempotent / reconfiguring.
        self.stop_device().await;

        if let Some(h) = hostname {
            self.prefs.hostname = Some(h);
        }
        // Capture an overridden control URL into prefs; it is parsed + applied to the engine config
        // below.
        if control_url.is_some() {
            self.prefs.control_url = control_url;
        }
        self.prefs.want_running = true;
        self.prefs.logged_out = false;
        self.ever_configured = true;
        self.persist_prefs().await?;

        let mut config = tailscale::Config::default_with_key_file(&self.key_path)
            .await
            .map_err(|e| anyhow!("load key file {}: {e:?}", self.key_path.display()))?;
        config.requested_hostname = self.prefs.hostname.clone();
        config.ephemeral = self.prefs.ephemeral;
        config.accept_routes = self.prefs.accept_routes;
        // Apply a custom control server when prefs carry one; otherwise keep the engine default
        // (real Tailscale / `TS_CONTROL_URL`). A malformed URL fails loudly rather than silently
        // falling back to the default — pointing at the wrong control plane must never be silent.
        if let Some(s) = &self.prefs.control_url {
            config.control_server_url =
                url::Url::parse(s).with_context(|| format!("invalid control_url {s:?}"))?;
        }

        // Expose the auth-key secret only here, for the single engine call that needs the plaintext
        // (registration). The exposed `String` lives no longer than this `up` call.
        use secrecy::ExposeSecret;
        let authkey_string = authkey.as_ref().map(|s| s.expose_secret().to_string());
        let device = tailscale::Device::new(&config, authkey_string)
            .await
            .map_err(|e| anyhow!("engine start failed: {e:?}"))?;
        self.device = Some(device);
        Ok(())
    }

    /// Bring the node down (`WantRunning = false`) without logging out; tears down the engine.
    pub async fn down(&mut self) -> Result<()> {
        self.stop_device().await;
        self.prefs.want_running = false;
        self.ever_configured = true;
        self.persist_prefs().await?;
        Ok(())
    }

    /// Produce a [`StatusReport`] reflecting the live engine + netmap.
    pub async fn status(&self) -> StatusReport {
        let (self_ipv4, self_name, peers, have_self) = match &self.device {
            Some(dev) => match dev.status().await {
                Ok(s) => {
                    let (ip, name, have) = match s.self_node {
                        Some(n) => (Some(n.ipv4.to_string()), Some(n.display_name), true),
                        None => (None, None, false),
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
                    (ip, name, peers, have)
                }
                Err(_) => (None, None, Vec::new(), false),
            },
            None => (None, None, Vec::new(), false),
        };

        StatusReport {
            state: self.derive_state(have_self).as_str().to_string(),
            want_running: self.prefs.want_running,
            self_ipv4,
            self_name,
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
    // distinction, we surface `Starting` honestly. `NeedsMachineAuth` is reachable only via the
    // explicit registration-error path in [`Backend::up`] (if/when the engine grows a typed
    // registration error, per its `tsr-kqj` TODO); [`State::InUseOtherUser`] is unreachable in this
    // single-user, auth-key-only daemon and is kept purely for `ipn.State` parity.
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
            let _ = dev.shutdown(Some(Duration::from_secs(5))).await;
        }
    }

    async fn persist_prefs(&self) -> Result<()> {
        self.prefs
            .save(&self.prefs_path)
            .await
            .with_context(|| format!("saving prefs to {}", self.prefs_path.display()))
    }
}

/// Pure state-derivation decision, extracted from [`Backend::derive_state`] so it is unit-testable
/// without a live `Backend` or engine.
///
/// Inputs are the four observable facts the reported [`State`] is a function of:
/// - `has_device`: an engine [`tailscale::Device`] is currently constructed (the node is "up").
/// - `have_self_node`: the engine has received a netmap and assigned this node its addresses.
/// - `want_running` / `logged_out`: the persisted [`Prefs`] intent.
/// - `ever_configured`: the node has been brought up at least once this process (distinguishes a
///   never-touched `NoState` from an explicit `Stopped`).
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
}
