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

mod config;
mod control_url;
mod diag;
pub mod install;
mod linkmon;
mod profile;
mod revert_guard;
pub mod serve;
mod state;
mod syspolicy;

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

/// Validate `--advertise-tags` values byte-for-byte against Go's `tailcfg.CheckTag` (which `up`/`set`
/// apply via `Hostinfo.CheckRequestTags`): each must be `tag:<name>` where `<name>` is non-empty,
/// **starts with an ASCII letter**, and contains only `[A-Za-z0-9-]`. Matching Go's gate exactly
/// matters because the engine does NOT re-validate — it ships `requested_tags` straight to control —
/// so this is the *only* client-side check; a too-lax gate lets a malformed tag reach control and be
/// rejected there with a confusing error instead of failing locally with a precise one. Returns the
/// first offender. Pure so it can guard both `begin_up` and `begin_set` before any pref is mutated.
fn validate_advertise_tags(tags: &[String]) -> Result<()> {
    for t in tags {
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
    }
    Ok(())
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
///    `Config.block_incoming`), `ssh` (a device-lifecycle task), or `advertise_tags` (registration-time
///    `Config.requested_tags`) have no live setter, so the only way to apply them to a running node
///    is to **rebuild the device** from the now-updated prefs. This reuses the exact
///    [`begin_up`](Backend::begin_up) → [`build_device`] → [`finish_up`](Backend::finish_up) machinery
///    as `drive_up` (same off-lock handshake, same generation-supersede guard, same off-lock orphan
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
pub async fn drive_set(
    backend: &std::sync::Arc<tokio::sync::Mutex<Backend>>,
    opts: SetOptions,
) -> Result<()> {
    // Phase 1: brief lock — apply + persist the pref overrides and decide the reconcile path. For
    // the live path we ALSO issue the live engine setters here, under the same brief lock: each is a
    // quick actor message (not the off-lock-worthy registration handshake), so we keep them atomic
    // with the prefs-apply rather than hoisting them off-lock via the device's `Arc`.
    let action = {
        let mut be = backend.lock().await;
        be.begin_set(opts).await
    }?;

    match action {
        // Node down: persisting was the whole job; nothing live to reconcile.
        SetAction::PersistedOnly => Ok(()),
        // Every changed pref was live-applicable and applied in place, under the brief lock, inside
        // `begin_set` (`ops` records what was issued). No reconnect. Done.
        SetAction::Live(_) => Ok(()),
        // A rebuild-only pref changed on a running node → rebuild from the updated prefs, reusing the
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
                // A `set`-driven rebuild never (re)authenticates, so it carries no WIF creds (`None`).
                be.begin_up(UpOptions::default(), None).await
            }?;
            // Phase 2b: NO lock held — the slow, network-bound re-registration handshake.
            let built = build_device(&pending, None).await;
            // Phase 2c: brief lock — install iff still current, returning any orphan to settle off-lock.
            let orphan = {
                let mut be = backend.lock().await;
                let orphan = be.finish_up(pending, built)?;
                // A `set`-driven rebuild re-registers the engine just like `up`, so on a successful
                // install `finish_up` flips `has_logged_in` in memory — persist it here too (same
                // contract as `drive_up`/`Backend::up`), or a rebuild-`set` after a prior transient
                // persist failure would leave the flag true-in-memory but false-on-disk and lose the
                // guard's fresh-node exemption across a restart. Non-fatal on failure (node is up).
                if orphan.is_none()
                    && let Err(e) = be.persist_prefs().await
                {
                    tracing::warn!(error = %e, "failed to persist has_logged_in after set-rebuild");
                }
                orphan
            };
            // Lock released — settle the (rare) superseded device off-lock.
            shutdown_orphan(orphan).await;
            Ok(())
        }
    }
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
/// Mirrors `drive_set`'s rebuild phasing precisely: brief lock for `reload_config` (apply + persist +
/// decide); on a rebuild, a brief lock to PREFLIGHT the rebuilt config (so a bad value never drops a
/// healthy tunnel); a brief lock for `begin_up`; the lock is **dropped** for the slow `build_device`;
/// taken briefly again for `finish_up`; then dropped to settle any superseded orphan off-lock. A
/// concurrent `status`/`down`/`up` is never blocked behind the handshake, and a `down`/`up` that lands
/// mid-rebuild correctly supersedes it (the rebuilt device is discarded).
pub async fn drive_reload_config(
    backend: &std::sync::Arc<tokio::sync::Mutex<Backend>>,
) -> Result<()> {
    // Phase 1: brief lock — re-read the config, merge + persist, and decide the reconcile action.
    let action = {
        let mut be = backend.lock().await;
        be.reload_config().await
    }?;

    match action {
        // Node down: persisting the merged prefs was the whole job; they apply on the next `up`.
        ReloadAction::PersistedOnly => return Ok(()),
        // Node up, reloaded `Enabled:false` → tear the engine down to match the already-persisted
        // `want_running=false` (Go applies a reloaded `Enabled:false`). `down` does `stop_device` +
        // bump_generation (so an in-flight bring-up is superseded) + re-persists `want_running=false`
        // (idempotent — `apply_config` already set it). No off-lock build needed for a teardown.
        ReloadAction::BringDown => {
            let mut be = backend.lock().await;
            return be.down().await;
        }
        // Node up, reloaded config keeps it up → fall through to the rebuild handshake below.
        ReloadAction::Rebuild => {}
    }

    // Node up → rebuild from the now-updated prefs, reusing the begin_up/build_device/finish_up
    // off-lock handshake exactly like `drive_set`'s `SetAction::Rebuild`. The brief reconnect is
    // documented on this function.
    //
    // Phase 2-pre: PREFLIGHT the rebuilt config before tearing the live device down. `begin_up` →
    // `stop_device` drops the running engine, but the SSH root/feature checks (and control-URL/route
    // parse) live in `build_config`, which `begin_up` only reaches AFTER teardown. If that check fails
    // (e.g. a reloaded config enables SSH on a daemon without the `ssh` feature or without root), a
    // naive rebuild would leave a healthy node OFFLINE — a reload that fails must never drop the
    // tunnel. So validate FIRST under a brief lock; on error, return it with the live device untouched.
    // (The prefs are already persisted by `reload_config`; they apply on the next successful `up`/`set`
    // — but the running node stays up now.)
    {
        let be = backend.lock().await;
        be.build_config().await?;
    }
    // Phase 2a: brief lock — begin a bring-up from the (already-updated) prefs. No authkey: a reload
    // resumes from the persisted node key; it never (re)authenticates. NB: `begin_up` sets
    // `want_running = true`, which on this arm is a no-op — we only reach `Rebuild` when the node was
    // already up AND the reloaded config kept it up (`want_running` already true). The down node
    // (`PersistedOnly`) and the stop-me-now (`BringDown`) cases were handled above, so `begin_up` here
    // cannot resurrect a node the reloaded config asked to stop.
    let pending = {
        let mut be = backend.lock().await;
        // A reload-driven rebuild never (re)authenticates, so it carries no WIF creds (`None`).
        be.begin_up(UpOptions::default(), None).await
    }?;
    // Phase 2b: NO lock held — the slow, network-bound re-registration handshake.
    let built = build_device(&pending, None).await;
    // Phase 2c: brief lock — install iff still current, returning any orphan to settle off-lock.
    let orphan = {
        let mut be = backend.lock().await;
        let orphan = be.finish_up(pending, built)?;
        // A reload-driven rebuild re-registers the engine just like `up`, so on a successful install
        // `finish_up` flips `has_logged_in` in memory — persist it here too (same contract as
        // `drive_up`/`drive_set`'s rebuild), or a reload after a prior transient persist failure would
        // leave the flag true-in-memory but false-on-disk and lose the guard's fresh-node exemption
        // across a restart. Non-fatal on failure (node is up).
        if orphan.is_none()
            && let Err(e) = be.persist_prefs().await
        {
            tracing::warn!(error = %e, "failed to persist has_logged_in after reload-config rebuild");
        }
        orphan
    };
    // Lock released — settle the (rare) superseded device off-lock.
    shutdown_orphan(orphan).await;
    Ok(())
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
    Live(Vec<LiveSetOp>),
    /// At least one changed pref has NO live setter — `shields_up` (maps to the immutable
    /// `Config.block_incoming`), `ssh` (a device-lifecycle task, not a `Config` knob), or
    /// `advertise_tags` (registration-time `requested_tags`) — so the engine `Config` must be rebuilt
    /// from the updated prefs. The caller ([`drive_set`]) runs the off-lock
    /// `begin_up`/`build_device`/`finish_up` handshake. This is a brief reconnect. (When a `set` mixes
    /// live-applicable and rebuild-only prefs, the whole `set` rebuilds — a rebuild re-applies every
    /// pref from the persisted state anyway, so applying the live ones first would be wasted work.)
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
    /// Advertise-tags override (Go `--advertise-tags`). `None` leaves the pref unchanged; `Some(vec)`
    /// replaces the set (`Some(vec![])` clears it). Each entry must be `tag:<name>` (validated at the
    /// CLI/server boundary).
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
/// `advertise_routes`, `advertise_exit_node`. Only `shields_up` (the immutable
/// `Config.block_incoming`), `ssh` (a device-lifecycle task), and `advertise_tags` (registration-time
/// `requested_tags`) have no live setter and take the device-rebuild path (a brief reconnect). See
/// [`SetOptions::needs_rebuild`] and [`SetAction`].
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
    /// ACL tags this node advertises (`None` unchanged; `Some(vec)` replaces; `tag:<name>` each). Has
    /// NO live engine setter (tags are requested at registration via `Config.requested_tags`), so on
    /// a running node it takes the [`SetAction::Rebuild`] path — a brief reconnect.
    pub advertise_tags: Option<Vec<String>>,
    /// Run the Tailscale SSH server (`None` unchanged; `Some(b)` sets it). Toggling SSH is a
    /// device-rebuild change (the SSH server task is tied to the device lifecycle), so it takes the
    /// [`SetAction::Rebuild`] path on a running node — not the live fast path.
    pub ssh: Option<bool>,
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
    }

    /// Whether applying this `set` on a **running** node requires a device REBUILD (a brief
    /// reconnect) — true IFF it names any pref with no live engine setter: `shields_up` (the
    /// immutable `Config.block_incoming`), `ssh` (a device-lifecycle task, not a `Config` knob), or
    /// `advertise_tags` (registration-time `Config.requested_tags`). The other five fields — `exit_node`,
    /// `hostname`, `accept_routes`, `advertise_routes`, `advertise_exit_node` — each have an in-place
    /// engine setter (v0.28.2), so a `set` naming ONLY those applies live with no reconnect.
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
        self.shields_up.is_some() || self.ssh.is_some() || self.advertise_tags.is_some()
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
    /// The `--config` file path the daemon was started with, or `None` when it was launched without
    /// `--config`. Held so the `reload-config` LocalAPI verb (Go `tailscaled`'s `reload-config` route
    /// → `LocalBackend.ReloadConfig`) can **re-read** the same declarative config file and re-adopt its
    /// fields into the running backend. Set once from `tailnetd`'s `main()` via
    /// [`set_config_path`](Backend::set_config_path) right after [`load`](Backend::load) when `--config`
    /// is given; `reload_config` errors clearly when it is `None` (there is nothing to re-read). This is
    /// process-local boot configuration — like Go, it is NOT persisted (a `--config`-less restart has no
    /// config to reload), and it is deliberately profile-independent: a `switch` does not change which
    /// `--config` file the daemon was launched with.
    config_path: Option<PathBuf>,
    /// The WireGuard/disco UDP listen port (Go `tailscaled --port` / `PORT`), or `None` for an
    /// OS-chosen ephemeral port (the default). Set once from `tailnetd`'s `main()` via
    /// [`set_listen_port`](Backend::set_listen_port) right after [`load`](Backend::load) when `--port`
    /// (or `PORT`) is given, and threaded into the engine [`tailscale::Config`] by
    /// [`build_config`](Backend::build_config). Like `config_path`, this is process-local boot
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
            // No `--config` by default; `tailnetd`'s `main()` calls `set_config_path` right after this
            // when `--config <file>` was given, so `reload_config` can later re-read that exact file.
            config_path: None,
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
        };
        backend.has_node_key = backend.has_persisted_node_key().await;
        Ok(backend)
    }

    /// Record the `--config` file path the daemon was started with, so the `reload-config` LocalAPI
    /// verb can later re-read it (see [`config_path`](Backend::config_path) and
    /// [`reload_config`](Backend::reload_config)). Called once from `tailnetd`'s `main()` right after
    /// [`load`](Backend::load) when `--config <file>` was given — separate from `load` so the common
    /// (config-less) startup path stays untouched and the rare config path is one explicit call. Idempotent
    /// (last write wins), though the daemon only ever calls it once at boot.
    pub fn set_config_path(&mut self, path: PathBuf) {
        self.config_path = Some(path);
    }

    /// Record the WireGuard/disco UDP listen port the daemon was started with (Go `tailscaled --port`
    /// / `PORT`), threaded into the engine config by [`build_config`](Backend::build_config). Called
    /// once from `tailnetd`'s `main()` right after [`load`](Backend::load) when `--port`/`PORT` was
    /// given — separate from `load` (like [`set_config_path`](Backend::set_config_path)) so the common
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

    /// Switch the active profile to `target` (the analogue of Go `tailscale switch <id>`). Tears the
    /// current device down, repoints `prefs`/`prefs_path`/`key_path` at the target profile, reloads
    /// that profile's persisted prefs, persists the `current-profile` pointer, registers the target in
    /// `profiles.json` if new, and bumps the generation (so any in-flight `up` is superseded). It does
    /// **not** auto-`up` the target — the caller decides whether to bring it up (matching Go, where
    /// switch changes the profile and the engine reconciles to the new prefs' `WantRunning`).
    ///
    /// `target` is validated as a profile id ([`profile::is_valid_profile_id`]) so it is always a safe
    /// single path component. Switching to the already-current profile is a no-op success.
    pub async fn switch_profile(&mut self, target: &str) -> Result<()> {
        // Resolve `target` (a profile id OR a display name — Go's `switch` accepts either) to a
        // canonical id BEFORE any teardown, so a no-match is rejected with the device untouched. An
        // existing profile is matched by id or unique name; a syntactically-valid id that is NOT yet
        // known falls through to the id path below (switching to a fresh id creates that profile).
        let meta = profile::load_profiles_file(&self.state_dir).await;
        let resolved = profile::resolve_target_to_id(target, &meta);
        let target: &str = match &resolved {
            Some(id) => id,
            // No id/name match. If it is a syntactically valid id, treat it as a NEW profile id
            // (create-on-switch); otherwise it is neither a known name nor a usable id — reject.
            None if profile::is_valid_profile_id(target) => target,
            None => {
                return Err(anyhow!(
                    "no profile matches {target:?} by id or name (ids: letters, digits, '-' or '_')"
                ));
            }
        };
        if target == self.current_profile {
            return Ok(()); // already on it
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
        Ok(())
    }

    /// Delete profile `target` (the analogue of Go `tailscale switch remove`). Refuses to delete the
    /// **current** profile (Go switches away first; we require the operator to switch away, which is
    /// the safer, more explicit contract) and refuses to delete the reserved `default` profile.
    /// Removes the profile's prefs+key files and its `profiles.json` entry. Idempotent for an
    /// already-absent named profile.
    pub async fn delete_profile(&mut self, target: &str) -> Result<()> {
        if !profile::is_valid_profile_id(target) {
            return Err(anyhow!("invalid profile id {target:?}"));
        }
        if target == profile::DEFAULT_PROFILE_ID {
            return Err(anyhow!("the default profile cannot be removed"));
        }
        if target == self.current_profile {
            return Err(anyhow!(
                "cannot remove the current profile {target:?}; switch to another profile first"
            ));
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
        // Drop it from profiles.json.
        let mut meta = profile::load_profiles_file(&self.state_dir).await;
        if meta.profiles.remove(target).is_some() {
            profile::save_profiles_file(&self.state_dir, &meta)
                .await
                .with_context(|| "persisting profiles.json after delete")?;
        }
        Ok(())
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
        match self.begin_set(opts).await? {
            // Node down, or every changed pref applied live under begin_set — nothing further to do.
            SetAction::PersistedOnly | SetAction::Live(_) => Ok(()),
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
    /// - **Device up AND a rebuild-only pref changed** (`shields_up` / `ssh` / `advertise_tags`, which
    ///   have no live setter) → [`SetAction::Rebuild`]: the caller must rebuild the device from the
    ///   updated prefs (the engine `Config` is immutable). A brief reconnect. A `set` mixing live and
    ///   rebuild-only prefs rebuilds wholesale (the rebuild re-applies the live ones too).
    ///
    /// Does **no** network I/O for the `Rebuild` case (the slow `Device::new` is the caller's
    /// off-lock job); the only blocking steps here are the quick live setter mailbox round-trips on
    /// the `Live` path.
    pub async fn begin_set(&mut self, opts: SetOptions) -> Result<SetAction> {
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

        // PRE-VALIDATE the advertised CIDRs BEFORE mutating/persisting prefs. `build_config` is the
        // final authority (it re-parses the same way; see its `advertise_routes` block), but it only
        // runs on the rebuild path AFTER `persist_prefs` here — so a malformed CIDR would otherwise
        // be written to `prefs.json` and only rejected later, leaving the persisted prefs
        // inconsistent with the running device (a failed `set` having corrupted state). Parse each
        // candidate up-front as `ipnet::IpNet` (byte-identical to `build_config`'s parse) and bail on
        // the first bad one with NOTHING yet mutated or persisted. Defense in depth, not a
        // replacement for the build_config parse.
        if let Some(routes) = opts.advertise_routes.as_ref() {
            for s in routes {
                s.parse::<ipnet::IpNet>()
                    .map_err(|_| anyhow!("invalid advertise route {s:?}"))?;
            }
        }
        // Same pre-validate-before-persist discipline for advertise-tags (tag:<name> form).
        if let Some(tags) = opts.advertise_tags.as_ref() {
            validate_advertise_tags(tags)?;
        }
        // And reject an `auto:` exit-node selector before persisting (this build has no auto-selection;
        // a silent fall-through to `Name("auto:any")` would break exit routing with no error).
        if let Some(Some(sel)) = opts.exit_node.as_ref() {
            validate_exit_node_selector(Some(sel))?;
        }

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
        // `set` is a policy-pref mutation, not a lifecycle change: deliberately do NOT touch
        // `want_running` / `logged_out` (that is `up`/`down`'s job). It still marks the node as
        // configured-at-least-once (a `set` on a never-touched node has now written prefs), matching
        // `up`/`down`, so a `set`-then-restart reads `Stopped`, not `NoState`.
        self.ever_configured = true;
        self.persist_prefs().await?;

        // Reconcile against the live engine. This is the only step that needs the device.
        match self.device.as_ref() {
            // No engine to reconcile — persisting above is the whole job; prefs apply on next `up`.
            None => {
                tracing::info!(
                    action = "persisted-only",
                    "set: reconcile decided (node down; prefs apply on next up)"
                );
                Ok(SetAction::PersistedOnly)
            }
            // A rebuild-only pref (shields_up / ssh / advertise_tags — no live setter) changed on a
            // running node: the engine Config is immutable, so the caller must rebuild the device
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
        }
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
        revert_guard::check_accidental_reverts(&self.prefs, opts, self.prefs.has_logged_in)
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
    pub async fn begin_up(&mut self, opts: UpOptions, wif: Option<&WifCreds>) -> Result<PendingUp> {
        // PRE-VALIDATE the advertised CIDRs FIRST — before tearing down the device, mutating, or
        // persisting prefs. Same persist-before-validate gap as `begin_set`: `build_config` (below,
        // the final authority) only rejects a malformed CIDR AFTER `stop_device` + `persist_prefs`
        // have run, so a bad value would tear down a live engine AND be written to `prefs.json`
        // before being caught. Parse each up-front as `ipnet::IpNet` (byte-identical to
        // `build_config`'s parse) and bail on the first bad one with the device untouched and
        // nothing persisted. Defense in depth, not a replacement for the build_config parse.
        if let Some(routes) = opts.advertise_routes.as_ref() {
            for s in routes {
                s.parse::<ipnet::IpNet>()
                    .map_err(|_| anyhow!("invalid advertise route {s:?}"))?;
            }
        }
        // Same pre-validate-before-teardown discipline for advertise-tags (tag:<name> form).
        if let Some(tags) = opts.advertise_tags.as_ref() {
            validate_advertise_tags(tags)?;
        }
        // And reject an `auto:` exit-node selector before teardown/persist (no auto-selection in this
        // build; a silent fall-through to `Name("auto:any")` would break exit routing with no error).
        if let Some(Some(sel)) = opts.exit_node.as_ref() {
            validate_exit_node_selector(Some(sel))?;
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
        self.prefs.want_running = true;
        self.prefs.logged_out = false;
        self.ever_configured = true;
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
    pub async fn logout(&mut self) -> Result<()> {
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

    /// Build a LOCAL diagnostic marker (the `tnet bugreport` path). Unlike Go's `bugreport`, which
    /// uploads logs to logtail and returns the server-side log id, this fork has no log-upload
    /// backend — the marker is a purely local identifier the operator can quote when reporting an
    /// issue. It carries a `BUG-` prefix, a coarse Unix-seconds stamp (rough ordering/uniqueness),
    /// the daemon version, the active profile, and the `want_running` intent. Reads only `self` (no
    /// engine round-trip), so it works whether or not the node is up.
    ///
    /// `note` is the operator's optional free-text note (Go `bugreport [note]`); when present it is
    /// appended as `-note:<note>`. It is sanitized of control characters first — it is operator-/
    /// caller-supplied text and the marker is meant to be copy-pasted into an issue, so a stray
    /// newline/escape must not corrupt it.
    pub fn bugreport(&self, note: Option<&str>) -> crate::localapi::Response {
        // SystemTime is the real std clock; a coarse seconds stamp makes the marker roughly unique +
        // orderable without adding a uuid dependency.
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut marker = format!(
            "BUG-{secs}-v{}-profile:{}-want_running:{}",
            env!("CARGO_PKG_VERSION"),
            self.current_profile,
            self.prefs.want_running,
        );
        if let Some(n) = note {
            // Strip control chars (newlines/escapes) so the appended note keeps the marker a single
            // clean, copy-pasteable token. `sanitize_marker_note` maps any control char to '_'.
            marker.push_str(&format!("-note:{}", sanitize_marker_note(n)));
        }
        crate::localapi::Response::BugReport { marker }
    }

    /// Report Tailnet Lock status (the `tnet lock status` path). Thin `pub` shim over
    /// [`diag::lock_status`]. See it for the `tka_status` → [`LockReport`](crate::localapi::LockReport)
    /// mapping.
    pub async fn lock_status(dev: &tailscale::Device) -> crate::localapi::Response {
        diag::lock_status(dev).await
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

    /// Report the effective system policy (the `tnet syspolicy list` path; Go
    /// `GetEffectivePolicy(DefaultScope())`). A **static** associated fn (not `&self`): policy
    /// resolution reads no backend/engine/netmap state — like Go's `rsop.PolicyFor`, it merges the
    /// registered policy stores, which is independent of node lifecycle — so it needs neither the
    /// backend lock nor the node to be up. Thin shim over [`syspolicy::effective_policy`]; kept on
    /// `Backend` so the `server.rs` dispatch reads uniformly with the other diagnostics. On this
    /// platform (no registered policy store) the snapshot is always empty — faithful to Go on Linux.
    pub fn syspolicy_list() -> crate::localapi::Response {
        crate::localapi::Response::Policy(syspolicy::effective_policy())
    }

    /// Force a re-read of the effective system policy (the `tnet syspolicy reload` path; Go
    /// `ReloadEffectivePolicy(DefaultScope())`). Static like [`syspolicy_list`](Self::syspolicy_list)
    /// (no backend state, no lock, node-up-independent). Thin shim over
    /// [`syspolicy::reload_effective_policy`]; observationally identical to `syspolicy_list` while no
    /// policy store is registered (the forced re-read re-merges zero sources). Never errors.
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
    /// (`Ok(None)` = no eligible candidate, an honest empty result, not an error).
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
    /// (1) the exit-node selector is concrete (no unsupported `auto:`); (2) **exit-node-vs-advertise
    /// conflict** — cannot use an exit node and advertise as one simultaneously (Go
    /// `checkExitNodePrefsLocked`); (3) every advertised route is a masked CIDR (Go
    /// `checkAdvertiseRoutes`); (4) SSH-server enable requires the `ssh` build feature (the local
    /// analogue of Go's `checkSSHPrefsLocked` capability gate — a faithful, build-time check). Go's
    /// operator/auto-update/profile-name/config-lock/Funnel-shields rules reference prefs this fork
    /// does not model, so they are correctly N/A.
    pub fn check_prefs(
        &self,
        exit_node: Option<Option<String>>,
        advertise_exit_node: Option<bool>,
        advertise_routes: Option<Vec<String>>,
        ssh: Option<bool>,
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

        let mut errors: Vec<String> = Vec::new();

        // (1) exit-node selector must be concrete (reuse the bring-up validator's rule).
        if let Err(e) = validate_exit_node_selector(prospective_exit_node.as_deref()) {
            errors.push(e.to_string());
        }
        // (2) exit-node-vs-advertise conflict (Go: "Cannot advertise an exit node and use an exit
        // node at the same time."). A `Some(sel)` exit node means "use one".
        if prospective_exit_node.is_some() && prospective_advertise_exit {
            errors.push(
                "Cannot advertise an exit node and use an exit node at the same time.".into(),
            );
        }
        // (3) advertise-route CIDR masking (Go: "route %s has non-address bits set; expected %s").
        for route in &prospective_routes {
            match route.parse::<ipnet::IpNet>() {
                Ok(net) => {
                    let masked = net.trunc();
                    if masked != net {
                        errors.push(format!(
                            "route {route} has non-address bits set; expected {masked}"
                        ));
                    }
                }
                Err(e) => errors.push(format!("route {route:?} is not a valid CIDR: {e}")),
            }
        }
        // (4) SSH-server enable requires the `ssh` build feature (local analogue of Go's
        // capability gate — a faithful build-time check; the netmap-capability check is engine-gated).
        if prospective_ssh && cfg!(not(feature = "ssh")) {
            errors.push(
                "Unable to enable Tailscale SSH server: this build was compiled without the `ssh` \
                 feature."
                    .into(),
            );
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
    /// failure, returns a clear [`Response::Error`] — never a self-signed cert. See [`diag::cert_pair`].
    pub async fn cert_pair(dev: &tailscale::Device, domain: &str) -> crate::localapi::Response {
        diag::cert_pair(dev, domain).await
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
    pub async fn set_serve_config(&mut self, cfg: &serve::ServeConfig) -> Result<()> {
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
    pub async fn whois(dev: &tailscale::Device, ip: &str) -> crate::localapi::Response {
        diag::whois(dev, ip).await
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
        self.persist_prefs().await?;
        Ok(authkey)
    }

    /// Re-read the `--config` file the daemon was started with and re-adopt its fields into the running
    /// backend — the Rust analogue of Go `tailscaled`'s `reload-config` LocalAPI route
    /// (`ipn/localapi.go` `serveReloadConfig` → `LocalBackend.ReloadConfig` → `setConfigLocked`,
    /// v1.100.0). Used when an operator edits the declarative config and wants the changes adopted
    /// without restarting the daemon.
    ///
    /// Returns `Ok(true)` when a device is currently up (so the caller — [`drive_reload_config`] — must
    /// rebuild the running engine from the now-updated prefs to actually adopt the change) and
    /// `Ok(false)` when the node is down (persisting the merged prefs was the whole job; they apply on
    /// the next `up`). This mirrors the `begin_set` → [`SetAction`] split: a brief lock applies +
    /// persists + decides, and the off-lock rebuild (if any) is the caller's job so the multi-second
    /// `Device::new` never runs under the backend lock.
    ///
    /// ## Faithful behavior
    ///
    /// - **No `--config` in use** → a clear error. Go's `ReloadConfig` likewise errors when there is no
    ///   config file to reload; reloading is meaningless without one.
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
    pub async fn reload_config(&mut self) -> Result<ReloadAction> {
        let path = match &self.config_path {
            Some(p) => p.clone(),
            None => {
                return Err(anyhow!(
                    "no --config file in use; reload-config requires the daemon to have been started \
                     with --config"
                ));
            }
        };
        // Re-read + re-parse + version-gate the file, with context on failure (a malformed or
        // unsupported-version file is rejected here, before any mutation — the same fail-hard contract
        // as boot). `apply_config` then validates every field BEFORE mutating prefs (all-or-nothing),
        // so a bad reload leaves the running node's prefs untouched.
        let config = crate::conffile::load(&path)
            .with_context(|| format!("reloading --config {}", path.display()))?;
        tracing::info!(path = %path.display(), version = %config.version, "reloading --config");
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
        Ok(match (self.device.is_some(), self.prefs.want_running) {
            (true, true) => ReloadAction::Rebuild,
            (true, false) => ReloadAction::BringDown,
            (false, _) => ReloadAction::PersistedOnly,
        })
    }
}

/// What [`Backend::reload_config`] decided a `reload-config` must do to reconcile the live engine with
/// the freshly-merged-and-persisted config prefs. The prefs are ALREADY applied + persisted by the
/// time this is returned (including `want_running`, which Go's config reload always re-applies); this
/// only tells [`drive_reload_config`] how to bring the live engine into line.
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
            // the re-read path (`set_config_path`).
            config_path: None,
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
        }
    }

    #[test]
    fn check_prefs_validates_without_mutating() {
        // check-prefs (Go CheckPrefs): validate a prospective posture, mutate NOTHING.
        let dir = std::env::temp_dir().join(format!("tailnetd-checkprefs-{}", std::process::id()));
        let be = backend_for(&dir);

        // Clean prospective change → Ok.
        assert!(
            be.check_prefs(Some(Some("100.64.0.9".into())), Some(false), None, None)
                .is_ok(),
            "a concrete exit node with advertise-exit off is valid"
        );

        // Exit-node-vs-advertise conflict → error naming the Go message.
        let err = be
            .check_prefs(Some(Some("100.64.0.9".into())), Some(true), None, None)
            .expect_err("using + advertising an exit node must conflict");
        assert!(
            err.to_string()
                .contains("Cannot advertise an exit node and use an exit node at the same time"),
            "got {err:#}"
        );

        // An unmasked advertised route → error naming the masked form.
        let err = be
            .check_prefs(None, None, Some(vec!["10.0.0.5/24".into()]), None)
            .expect_err("an unmasked CIDR must be rejected");
        assert!(
            err.to_string().contains("has non-address bits set")
                && err.to_string().contains("10.0.0.0/24"),
            "got {err:#}"
        );

        // `auto:` exit node → rejected (reuses the bring-up validator).
        assert!(
            be.check_prefs(Some(Some("auto:any".into())), None, None, None)
                .is_err(),
            "auto: exit-node selection is not supported"
        );

        // The check must not have persisted or mutated prefs — the backend's exit_node is still unset.
        assert!(
            be.prefs.exit_node.is_none() && be.prefs.advertise_routes.is_empty(),
            "check_prefs must mutate nothing"
        );
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
        let crate::localapi::Response::BugReport { marker } = be.bugreport(None) else {
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

        // A note → appended as `-note:<note>`.
        let crate::localapi::Response::BugReport { marker } = be.bugreport(Some("dns broke"))
        else {
            panic!("expected BugReport");
        };
        assert!(
            marker.contains("-note:dns broke"),
            "note appended: {marker}"
        );

        // A hostile note (newline + ESC + BEL) → control chars replaced with '_', marker stays one
        // line/token.
        let crate::localapi::Response::BugReport { marker } =
            be.bugreport(Some("evil\n\x1b[2J\x07x"))
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
        be.down().await.expect("down");
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
        be.logout().await.expect("logout");
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
    async fn logout_is_idempotent_with_no_key_file() {
        // Logging out a never-registered node (no key file) is not an error — the remove is a
        // tolerated NotFound. Mirrors Go's idempotent logout.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-logout-nokey-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        assert!(!tokio::fs::try_exists(&be.key_path).await.unwrap());
        be.logout()
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

        // Switch to a new profile "work": its prefs start at default (NOT the default profile's).
        be.switch_profile("work").await.unwrap();
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
        let result = be.switch_profile("work").await;
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
    async fn profile_delete_refuses_current_and_default_but_removes_others() {
        let dir = std::env::temp_dir().join(format!("tailnetd-prof-del-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = Backend::load(&dir).await.unwrap();

        // Create + populate "work", then switch back to default so "work" is deletable.
        be.switch_profile("work").await.unwrap();
        be.prefs.hostname = Some("work-host".into());
        be.persist_prefs().await.unwrap();
        be.switch_profile(profile::DEFAULT_PROFILE_ID)
            .await
            .unwrap();

        // Refuses the default profile and the current profile.
        assert!(
            be.delete_profile(profile::DEFAULT_PROFILE_ID)
                .await
                .is_err()
        );
        // (current is now default) — deleting current also refused:
        assert!(
            be.delete_profile(&be.current_profile.clone())
                .await
                .is_err()
        );

        // Removes a non-current named profile + its files.
        let (work_prefs, _) = profile::profile_paths(&dir, "work");
        assert!(tokio::fs::try_exists(&work_prefs).await.unwrap());
        be.delete_profile("work").await.unwrap();
        assert!(!tokio::fs::try_exists(&work_prefs).await.unwrap());
        // It's gone from the list (only default remains).
        let list = be.list_profiles().await;
        assert!(!list.iter().any(|e| e.id == "work"));
        // Idempotent: deleting an absent profile is fine.
        be.delete_profile("work").await.unwrap();

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

        let result = be.logout().await;
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
            .begin_up(
                UpOptions {
                    exit_node: Some(Some("exit-1".to_string())),
                    advertise_exit_node: Some(true),
                    advertise_routes: Some(vec!["10.0.0.0/8".to_string()]),
                    ..UpOptions::default()
                },
                None,
            )
            .await
            .expect("begin_up set");
        assert_eq!(be.prefs.exit_node.as_deref(), Some("exit-1"));
        assert!(be.prefs.advertise_exit_node);
        assert_eq!(be.prefs.advertise_routes, vec!["10.0.0.0/8".to_string()]);

        // A plain follow-up `up` (all None) must leave the prefs UNCHANGED.
        let _ = be
            .begin_up(UpOptions::default(), None)
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
                    exit_node: Some(Some("exit-1".to_string())),
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
        // is called in `begin_set`, so a `set` naming only it applies with no reconnect) or REBUILD
        // (no live setter → `needs_rebuild()` must return true so the device is rebuilt). Without this,
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
            // --- REBUILD (no live setter → MUST be in needs_rebuild()) ---
            shields_up: _,
            advertise_tags: _,
            ssh: _,
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
        let action = be.begin_set(opts).await.expect("begin_set");
        assert_eq!(
            action,
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
        let config = crate::conffile::load(&cfg_path).expect("load config");

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
    async fn reload_config_without_config_path_errors_clearly() {
        // `reload_config` re-reads the `--config` file the daemon was started with. A daemon launched
        // WITHOUT `--config` has nothing to reload (`config_path` is None) — it must fail with a clear,
        // actionable error (matching Go's ReloadConfig, which errors when there is no config file),
        // never silently no-op or panic.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-reloadcfg-none-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut be = backend_for(&dir);
        assert!(
            be.config_path.is_none(),
            "a backend with no --config has config_path None"
        );

        let err = be
            .reload_config()
            .await
            .expect_err("reload_config must error when no --config is in use");
        let msg = err.to_string();
        assert!(
            msg.contains("no --config") && msg.contains("reload-config"),
            "the error must explain that reload-config needs --config: {msg}"
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
        be.set_config_path(cfg_path.clone());
        tokio::fs::write(
            &cfg_path,
            br#"{"version":"alpha0","Hostname":"reloaded-host","ShieldsUp":true}"#,
        )
        .await
        .unwrap();

        let action = be.reload_config().await.expect("reload_config succeeds");
        assert_eq!(
            action,
            ReloadAction::PersistedOnly,
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
        be.set_config_path(cfg_path.clone());

        // A config that keeps the node enabled → want_running stays true; down node → PersistedOnly.
        tokio::fs::write(
            &cfg_path,
            br#"{"version":"alpha0","Hostname":"up-host","Enabled":true}"#,
        )
        .await
        .unwrap();
        assert_eq!(
            be.reload_config().await.unwrap(),
            ReloadAction::PersistedOnly,
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
            ReloadAction::PersistedOnly,
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
        be.set_config_path(cfg_path.clone());
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
