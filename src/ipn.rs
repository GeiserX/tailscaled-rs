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
//! than stored, so it can never drift from reality. Compared to the full Go state machine this MVP
//! omits `NeedsMachineAuth` and `InUseOtherUser` (auth-key registration only) and interactive
//! login; those surface as errors for now.

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
    pub async fn up(
        &mut self,
        authkey: Option<String>,
        hostname: Option<String>,
        control_url: Option<String>,
    ) -> Result<()> {
        // Tear down any existing device first so `up` is idempotent / reconfiguring.
        self.stop_device().await;

        if let Some(h) = hostname {
            self.prefs.hostname = Some(h);
        }
        // control_url is captured into prefs for forward-compat but NOT yet applied: the MVP uses
        // the engine's default control server (real Tailscale). Honest gap — wiring a custom
        // control URL needs a `url::Url` on `Config` and is a Phase-2 item.
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

        let device = tailscale::Device::new(&config, authkey)
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
    fn derive_state(&self, have_self_node: bool) -> State {
        match &self.device {
            Some(_) if have_self_node => State::Running,
            Some(_) => State::Starting,
            None if self.prefs.logged_out => State::NeedsLogin,
            None if self.prefs.want_running => State::NeedsLogin, // wants up but no engine → needs (re)auth
            None if self.ever_configured => State::Stopped,
            None => State::NoState,
        }
    }

    /// Gracefully shut down the engine on daemon exit.
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
