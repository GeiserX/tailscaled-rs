//! LocalAPI wire types — the request/response DTOs spoken over the control socket.
//!
//! These are this crate's *own* serde types, deliberately decoupled from the engine's internal
//! types so the IPC surface is stable independent of engine churn. The transport today is
//! newline-delimited JSON over a Unix domain socket (see [`crate::server`]). Peer-credential
//! authorization is implemented (`SO_PEERCRED`, see [`crate::auth`]), matching Tailscale's
//! `LocalAPI` policy: reads are allowed for anyone, writes only for root or the same UID as the
//! daemon.

use serde::{Deserialize, Serialize};

/// A command sent by the CLI to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Report current state and netmap.
    Status,
    /// Stream status: the daemon replies with an initial [`StatusReport`] line and then one more
    /// every time the connection state transitions, until the client disconnects. This is a
    /// long-lived connection (the analogue of `tailscale status --watch`), not a one-shot. Read-only
    /// — gated identically to [`Status`](Request::Status).
    Watch,
    /// Bring the node up (`WantRunning = true`), optionally (re)setting login/config fields.
    Up {
        /// Pre-auth key for non-interactive registration.
        authkey: Option<String>,
        /// Override the control server URL.
        control_url: Option<String>,
        /// Override the requested hostname.
        hostname: Option<String>,
        /// Use a real kernel TUN interface (`TransportMode::Tun`) instead of the userspace netstack.
        /// `None` leaves the persisted pref unchanged; `Some(true/false)` sets it. Requires a daemon
        /// built with the `tun` feature + root; the daemon fails loudly otherwise. `#[serde(default)]`
        /// keeps the wire backward-compatible with clients that omit it.
        #[serde(default)]
        tun: Option<bool>,
        /// Desired TUN interface name (only meaningful with `tun: Some(true)`).
        #[serde(default)]
        tun_name: Option<String>,
        /// TUN interface MTU (only meaningful with `tun: Some(true)`).
        #[serde(default)]
        tun_mtu: Option<u16>,
        /// Exit-node selector override (route this node's egress through a peer exit node), by IP or
        /// MagicDNS name. Double `Option`: outer = "leave pref unchanged" (`None`), inner = the value
        /// (`Some(None)` clears = stop using an exit node; `Some(Some(sel))` sets it).
        ///
        /// `double_option` is load-bearing here: it maps an ABSENT key → `None` (unchanged) but a
        /// present JSON `null` → `Some(None)` (clear). Plain `#[serde(default)]` collapses both to
        /// `None`, which would make the "clear my exit node" command silently deserialize as a no-op
        /// (caught by `request_up_exit_and_advertise_round_trip_and_back_compat`). `skip_serializing_if`
        /// keeps an unchanged field off the wire so it stays backward-compatible with older daemons.
        #[serde(
            default,
            with = "::serde_with::rust::double_option",
            skip_serializing_if = "Option::is_none"
        )]
        exit_node: Option<Option<String>>,
        /// Advertise this node as an exit node (`None` leaves the pref unchanged; `Some(b)` sets it).
        #[serde(default)]
        advertise_exit_node: Option<bool>,
        /// Subnet routes (CIDRs) this node advertises. `None` leaves the pref unchanged; `Some(vec)`
        /// replaces the set (`Some([])` clears).
        #[serde(default)]
        advertise_routes: Option<Vec<String>>,
        /// ACL tags this node requests (Go `--advertise-tags`, each `tag:<name>`). `None` unchanged;
        /// `Some(vec)` replaces (`Some([])` clears). `#[serde(default)]` keeps the wire back-compatible.
        #[serde(default)]
        advertise_tags: Option<Vec<String>>,
        /// Accept (and route to) subnet routes advertised by peers (Go `tailscale up
        /// --accept-routes`). `None` leaves the pref unchanged; `Some(b)` sets it. `#[serde(default)]`
        /// keeps the wire backward-compatible with clients that omit it.
        #[serde(default)]
        accept_routes: Option<bool>,
        /// Run the Tailscale SSH server (`None` leaves the pref unchanged; `Some(b)` sets it).
        /// Requires a daemon built with the `ssh` feature + root; the daemon fails loudly otherwise.
        #[serde(default)]
        ssh: Option<bool>,
        /// Reset every up-managed pref this command does **not** mention back to its default before
        /// applying the named overrides (Go `tailscale up --reset`). This is the one path where `up`
        /// is a true wholesale REPLACE rather than a PATCH. It also SKIPS the accidental-revert guard
        /// (the operator is explicitly opting into "unmentioned settings revert to defaults"), so the
        /// daemon never returns [`Response::RevertGuard`] for a `--reset` up. `#[serde(default)]` keeps
        /// the wire backward-compatible with clients that omit it.
        #[serde(default)]
        reset: bool,
    },
    /// Change individual prefs on the node **without** a full up/down cycle (the analogue of Go's
    /// `tailscale set`). Every field is the same "leave unchanged unless named" sentinel as
    /// [`Up`](Request::Up)'s overrides. Unlike `Up`, `Set` never (re)authenticates and never flips
    /// `want_running` — it only patches the named prefs and reconciles the live engine: `exit_node`
    /// is applied **live** (the engine has a runtime setter, no reconnect), while prefs with no live
    /// setter (`hostname` / `accept_routes` / `advertise_*`) take effect by reconfiguring a running
    /// device (or simply persist if the node is down, applying on the next `up`).
    Set {
        /// Requested hostname.
        #[serde(default)]
        hostname: Option<String>,
        /// Accept (and route to) subnet routes advertised by peers.
        #[serde(default)]
        accept_routes: Option<bool>,
        /// Exit-node selector override — applied LIVE when a device is up (no reconnect). Double
        /// `Option` with `double_option`: absent = unchanged (`None`), present `null` = clear
        /// (`Some(None)`), present value = set (`Some(Some(sel))`). See [`Up`](Request::Up)'s field.
        #[serde(
            default,
            with = "::serde_with::rust::double_option",
            skip_serializing_if = "Option::is_none"
        )]
        exit_node: Option<Option<String>>,
        /// Advertise this node as an exit node (`None` unchanged; `Some(b)` sets it).
        #[serde(default)]
        advertise_exit_node: Option<bool>,
        /// Subnet routes (CIDRs) this node advertises (`None` unchanged; `Some(vec)` replaces,
        /// `Some([])` clears).
        #[serde(default)]
        advertise_routes: Option<Vec<String>>,
        /// ACL tags this node requests (`None` unchanged; `Some(vec)` replaces, `Some([])` clears;
        /// each `tag:<name>`).
        #[serde(default)]
        advertise_tags: Option<Vec<String>>,
        /// Run the Tailscale SSH server (`None` unchanged; `Some(b)` sets it). Toggling SSH via
        /// `set` rebuilds the running device (the SSH server task is tied to the device lifecycle).
        #[serde(default)]
        ssh: Option<bool>,
    },
    /// Report the daemon's own version (Go `tailscale version --daemon` reads `Status.Version`).
    /// Read-only — gated like [`Status`](Request::Status).
    Version,
    /// Report the node's current preferences (Go `tailscale get` / the `GetPrefs` LocalAPI). Replies
    /// with a [`PrefsView`] projection of the persisted prefs. Read-only — gated like
    /// [`Status`](Request::Status). Distinct from the prefs embedded in a full [`Status`] report: this
    /// is the focused "just the prefs" query `tnet get` uses, with no netmap/peer round-trip.
    GetPrefs,
    /// List the known profiles (Go `tailscale switch --list`). Replies with [`Response::Profiles`].
    /// Read-only — gated like [`Status`](Request::Status).
    ProfileList,
    /// Snapshot the node's client metrics in Prometheus text format (Go `tailscale metrics`). Replies
    /// with [`Response::Metrics`]. Read-only — gated like [`Status`](Request::Status). Requires the
    /// node to be up (metrics come from the live engine).
    Metrics,
    /// Report Tailnet Lock (TKA) status (Go `tailscale lock status`, read-only subset). Replies with
    /// [`Response::Lock`]. Read-only — gated like [`Status`](Request::Status).
    LockStatus,
    /// Produce a shareable diagnostic marker (Go `tailscale bugreport`). Replies with
    /// [`Response::BugReport`]. Read-only. NOTE: Go uploads logs to logtail and returns the log id;
    /// this fork has no log-upload backend, so the marker is a LOCAL diagnostic identifier only (it is
    /// not a server-retrievable log id — see the daemon's `bugreport` builder + the CLI note).
    BugReport,
    /// Switch the active profile (Go `tailscale switch <id>`). The daemon tears down the current
    /// device, swaps to the target profile's prefs/key, and persists the pointer. A WRITE (it changes
    /// node lifecycle + persisted state) — gated like `up`/`down`.
    SwitchProfile {
        /// The target profile id (or name; the daemon resolves either).
        target: String,
    },
    /// Delete a profile (Go `tailscale switch remove`). Refuses the current/default profile. A WRITE
    /// — gated like `up`/`down`.
    DeleteProfile {
        /// The profile id to remove.
        target: String,
    },
    /// Connect to `port` on a tailnet host and splice the connection to the client (Go `tailscale
    /// nc`). After the daemon's one-line acknowledgement, this connection is **hijacked**: the daemon
    /// bidirectionally copies bytes between the LocalAPI socket and the overlay TCP stream until
    /// either side closes (like [`Watch`](Request::Watch), it is terminal for the connection). A WRITE
    /// (it opens an outbound connection) — gated like `up`/`down`.
    Nc {
        /// Destination host: a tailnet IP or MagicDNS name.
        host: String,
        /// Destination TCP port.
        port: u16,
    },
    /// Bring the node down (`WantRunning = false`) without logging out.
    Down,
    /// Log the node out (the analogue of Go's `tailscale logout`): deregister the node key with the
    /// control plane, tear the datapath down, and **discard the persisted node key** so the next
    /// `up` re-registers fresh (a new login) rather than resuming the old registration. This is
    /// distinct from [`Down`](Request::Down), which keeps the node key for a seamless resume. A WRITE
    /// — gated like `up`/`down`.
    Logout,
    /// Report this node's own tailnet addresses (Go `tailscale ip`). Read-only — gated like
    /// [`Status`](Request::Status).
    Ip,
    /// Resolve a tailnet IP to the peer that owns it (Go `tailscale whois`). Read-only.
    Whois {
        /// The tailnet IP to resolve.
        ip: String,
    },
    /// Ping a peer over the tailnet overlay and report the round-trip time (Go `tailscale ping`).
    /// Read-only (it sends overlay traffic but changes no state) — gated like [`Status`](Request::Status).
    Ping {
        /// The tailnet IP to ping.
        ip: String,
        /// Per-attempt timeout in milliseconds (`None` → a sensible default).
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    /// Send a local file to a peer via Taildrop (Go `tailscale file cp`). The daemon opens `path`
    /// itself (tnet + tailnetd are same-host/same-user), resolves `peer` against the netmap, and
    /// streams it over the encrypted overlay to the peer's peerAPI. A WRITE (it initiates a transfer)
    /// — gated like `up`/`down`.
    FileCp {
        /// Local filesystem path of the file to send (read by the daemon).
        path: String,
        /// Destination peer: a tailnet IP or MagicDNS name.
        peer: String,
    },
    /// List Taildrop files waiting in this node's receive directory (Go `tailscale file get` with no
    /// args). Read-only.
    FileList,
    /// Fetch a waiting Taildrop file by name, writing it to `dest` (Go `tailscale file get <name>`).
    /// A WRITE (it consumes/deletes the inbound file after copying) — gated like `up`/`down`.
    FileGet {
        /// The waiting file's base name (from [`FileList`](Request::FileList)).
        name: String,
        /// Local destination path the daemon writes the file to.
        dest: String,
        /// Delete the file from the receive directory after a successful fetch (Go default).
        #[serde(default)]
        delete_after: bool,
    },
}

/// The daemon's reply to a [`Request`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    /// A status snapshot.
    Status(StatusReport),
    /// This node's own tailnet addresses (reply to [`Request::Ip`]).
    Ip {
        /// Tailnet IPv4, if assigned.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ipv4: Option<String>,
        /// Tailnet IPv6, if assigned.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ipv6: Option<String>,
    },
    /// The result of a [`Request::Whois`]: the owning peer's identity, or `found: false` if the IP
    /// matched no known tailnet node.
    Whois(WhoisReport),
    /// The result of a [`Request::Ping`]: the measured round-trip time.
    Ping {
        /// Round-trip time in milliseconds.
        rtt_ms: f64,
        /// The pinged tailnet IP (echoed for the CLI).
        ip: String,
    },
    /// The waiting Taildrop files (reply to [`Request::FileList`]).
    Files {
        /// Files in the receive directory, each `(name, size_bytes)`.
        files: Vec<WaitingFileReport>,
    },
    /// The daemon's own version (reply to [`Request::Version`]) — the analogue of Go's
    /// `ipnstate.Status.Version`, used by `tnet version --daemon`.
    Version {
        /// The daemon binary's version (its crate version, `CARGO_PKG_VERSION`).
        version: String,
    },
    /// The node's current preferences (reply to [`Request::GetPrefs`]) — a [`PrefsView`] projection
    /// of the persisted prefs, rendered by `tnet get`.
    Prefs(PrefsView),
    /// The known profiles (reply to [`Request::ProfileList`]), rendered by `tnet switch --list`.
    Profiles {
        /// One entry per known profile (the implicit default plus any named profiles).
        profiles: Vec<ProfileEntry>,
    },
    /// The node's client metrics in Prometheus text exposition format (reply to
    /// [`Request::Metrics`]), printed/written by `tnet metrics`.
    Metrics {
        /// The Prometheus text (`# TYPE <name> <kind>\n<name> <value>\n` per metric).
        text: String,
    },
    /// Tailnet Lock (TKA) status (reply to [`Request::LockStatus`]), rendered by `tnet lock status`.
    Lock(LockReport),
    /// A local diagnostic marker (reply to [`Request::BugReport`]), printed by `tnet bugreport`.
    BugReport {
        /// The marker string (a local identifier + daemon version + node state). NOT a server-side
        /// log id — this fork uploads nothing.
        marker: String,
    },
    /// A command succeeded.
    Ok {
        /// Human-readable detail.
        message: String,
    },
    /// An `up` was rejected because it would silently revert one or more non-default prefs the
    /// command did not mention (the Rust analogue of Go's `checkForAccidentalSettingReverts`). The
    /// daemon does NOT mutate any state — this is a pre-flight rejection. Each entry names the pref
    /// the operator would have unintentionally reset and its CURRENT (about-to-be-lost) value, so the
    /// CLI can render Go's "re-run mentioning the current value of all non-default settings" message
    /// with a copy-pasteable command. Carrying structured `(pref, value)` pairs rather than a
    /// pre-rendered string keeps the daemon free of CLI flag spellings (the daemon has no notion of
    /// `--advertise-routes`); the CLI owns the pref→flag mapping. Bypass with `up --reset` (or by
    /// mentioning the listed flags).
    RevertGuard {
        /// The prefs that would be accidentally reverted, each as `(pref_key, current_value)`. The
        /// `pref_key` is a stable, CLI-agnostic identifier (e.g. `"advertise_routes"`,
        /// `"accept_routes"`, `"exit_node"`, `"ssh"`, `"advertise_exit_node"`, `"hostname"`,
        /// `"control_url"`, `"tun"`) the CLI maps to its flag; `current_value` is the value the
        /// operator must re-mention to keep (already rendered to a flag-value string by the daemon's
        /// pref projection — e.g. `"10.0.0.0/8,192.168.1.0/24"`, `"true"`, an exit-node selector).
        reverts: Vec<RevertedPref>,
    },
    /// A command failed.
    Error {
        /// Human-readable detail.
        message: String,
    },
}

/// One pref that an unguarded `up` would have silently reverted to its default, returned inside
/// [`Response::RevertGuard`]. See that variant for the full rationale.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevertedPref {
    /// Stable, CLI-agnostic pref identifier (e.g. `"advertise_routes"`). The CLI maps this to its
    /// user-facing flag name; the daemon deliberately does not know flag spellings.
    pub key: String,
    /// The current value that would be lost, rendered as the string the operator must re-supply to
    /// keep it (e.g. `"10.0.0.0/8"`, `"true"`, an exit-node selector). For a boolean pref this is
    /// `"true"`/`"false"`; for a list it is the comma-joined set; for an optional string it is the
    /// value itself.
    pub value: String,
}

/// The identity behind a tailnet IP, returned by [`Request::Whois`]. The Rust analogue of tsnet's
/// `WhoIsResponse` (subset). `user` is always `None` in this fork (the domain node model does not
/// retain the owner login — see the engine `WhoIs` docs).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WhoisReport {
    /// Whether the IP resolved to a known tailnet node.
    pub found: bool,
    /// The owning node's display name (FQDN if known, else hostname).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// The owning node's tailnet IPv4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_ipv4: Option<String>,
    /// The owning user's login/email, if control retained it (always `None` in this fork).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// The node's control-granted capabilities (capability name → args).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

/// A single waiting Taildrop file, returned by [`Request::FileList`]. Mirrors the engine's
/// `WaitingFile` (Go `apitype.WaitingFile`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WaitingFileReport {
    /// The file's base name.
    pub name: String,
    /// The file's size in bytes.
    pub size: u64,
}

/// A snapshot of daemon + netmap state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    /// The IPN state name. One of the seven [`crate::ipn::State`] variants (the authoritative
    /// list is [`crate::ipn::State::as_str`]): `NoState`, `NeedsLogin`, `NeedsMachineAuth`,
    /// `InUseOtherUser`, `Starting`, `Running`, `Stopped`. (`NeedsMachineAuth`/`InUseOtherUser`
    /// exist for Go-`ipn.State` parity and are not currently reachable; see `ipn::State`.)
    pub state: String,
    /// The persisted `WantRunning` intent.
    pub want_running: bool,
    /// This node's tailnet IPv4, once a netmap has been received.
    pub self_ipv4: Option<String>,
    /// This node's display name, once known.
    pub self_name: Option<String>,
    /// The interactive-login authorization URL, set only when `state == "NeedsLogin"` because the
    /// engine reported `DeviceState::NeedsLogin(url)` — i.e. an `up` with no usable auth key needs a
    /// human to authorize the node in a browser. `None` in every other state. The CLI prints this so
    /// `tnet up` (no `--authkey`) yields a clickable login link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    /// A terminal registration-failure reason, set only when the engine reported
    /// `DeviceState::Failed(RegistrationError)` — a **permanent** failure (e.g. a bad/expired/unknown
    /// auth key) that the engine will *not* retry. `None` in every other state.
    ///
    /// This is the Rust analogue of Go's `ipnstate.Status.ErrMessage`: rather than fabricate an
    /// eighth `ipn.State`, terminal failure is carried as a separate field so the reported `state`
    /// stays one of the seven canonical `ipn.State` names. It is deliberately distinct from
    /// [`auth_url`](StatusReport::auth_url): an `auth_url` means interactive login is *pending and
    /// will succeed once the user authorizes* (transient), whereas `error` means registration
    /// *hard-failed and re-running with the same key will loop forever* (terminal — the operator must
    /// re-authenticate). The CLI prints this and, on an interactive `up`, bails early instead of
    /// dwelling the full auth-URL poll window implying that login will help.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// A snapshot of the node's persisted configuration intent (its [`Prefs`](crate::prefs::Prefs)),
    /// so `tnet status` can show the full posture — exit node, advertised routes/exit, accept-routes,
    /// SSH, TUN — the way Go `tailscale status` reflects the active prefs. Read straight from the
    /// daemon's prefs (no engine round-trip), so it is always present. `#[serde(default)]` keeps the
    /// wire backward-compatible with clients that predate this field.
    #[serde(default)]
    pub prefs: PrefsView,
    /// Known peers in the netmap.
    pub peers: Vec<PeerReport>,
}

/// A read-only projection of the node's persisted [`Prefs`](crate::prefs::Prefs) for `status`
/// output. Mirrors the policy-relevant fields an operator wants to see at a glance (the analogue of
/// the prefs Go's `tailscale status` surfaces), without exposing the full prefs struct or any secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrefsView {
    /// The configured exit-node selector (IP or MagicDNS name), or `None` if no exit node is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<String>,
    /// Whether this node advertises itself as an exit node.
    pub advertise_exit_node: bool,
    /// Subnet routes (CIDRs) this node advertises to the tailnet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advertise_routes: Vec<String>,
    /// ACL tags (`tag:<name>`) this node requests at registration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advertise_tags: Vec<String>,
    /// Whether this node accepts subnet routes advertised by peers.
    pub accept_routes: bool,
    /// Whether the Tailscale SSH server is *enabled* by the persisted pref (`ssh_enabled`). This is
    /// the configured *intent*, NOT proof the server is actually accepting connections — see
    /// [`ssh_running`](PrefsView::ssh_running) for liveness.
    pub ssh: bool,
    /// Whether the Tailscale SSH server task is actually *live* (spawned and not yet finished), as
    /// opposed to merely enabled by the [`ssh`](PrefsView::ssh) pref. The server task can die at
    /// bind time (e.g. it never resolved a tailnet IPv4, or `listen_ssh` returned an error), in which
    /// case `ssh` stays `true` but `ssh_running` reads `false` — so an operator is not misled into
    /// thinking SSH is serving when the task has exited. Always `false` when SSH is not enabled, when
    /// the node is down, or in a daemon built without the `ssh` feature (no task is ever spawned).
    /// `#[serde(default)]` keeps the wire backward-compatible with clients that predate this field.
    #[serde(default)]
    pub ssh_running: bool,
    /// Whether the node uses the kernel-TUN data path (vs the userspace netstack).
    pub tun: bool,
}

/// Tailnet Lock (TKA) status in a [`Response::Lock`] reply (Go `tailscale lock status`, read-only
/// subset). Mirrors the engine's `ts_control::TkaStatus`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LockReport {
    /// Whether Tailnet Lock is in use (control sent TKA info for this node).
    pub enabled: bool,
    /// The base32 `AUMHash` of control's latest authority head (empty when none / not enabled).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub head: String,
    /// Whether control believes Tailnet Lock should be disabled (a disablement is pending).
    #[serde(default)]
    pub disabled: bool,
}

/// One profile in a [`Response::Profiles`] reply (Go `tailscale switch --list`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileEntry {
    /// The profile id (`"default"` for the legacy/top-level profile).
    pub id: String,
    /// Display name (falls back to the id when unset).
    pub name: String,
    /// Whether this is the currently-active profile.
    pub current: bool,
}

/// A single peer entry in a [`StatusReport`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerReport {
    /// Display name (FQDN if known, else bare hostname).
    pub name: String,
    /// Tailnet IPv4 address.
    pub ipv4: String,
    /// Whether the peer advertises a default route (is an exit-node candidate).
    pub is_exit_node: bool,
    /// The peer's stable node ID (the engine's `StableNodeId`). Used as the Go `status --json`
    /// `Peer`-map key. NOTE: Go keys that map by the node *public key* (`nodekey:…`); this fork keys
    /// by the stable node ID instead, since that is the durable peer identifier the engine surfaces —
    /// a documented, honest deviation (see the `status --json` renderer). `#[serde(default)]` keeps
    /// the wire backward-compatible with clients/daemons that predate this field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stable_id: String,
    /// Whether the peer is currently online (connected to the control plane), if known. `None` when
    /// the engine has not reported liveness for this peer. Feeds the Go `PeerStatus.Online` field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // The CLI and daemon are separate processes that agree only on this JSON wire format, so the
    // tagged representations are a contract: assert the exact `cmd`/`kind` discriminants.

    #[test]
    fn request_status_wire_format() {
        let json = serde_json::to_string(&Request::Status).unwrap();
        assert_eq!(json, r#"{"cmd":"status"}"#);
    }

    #[test]
    fn request_up_round_trips_with_fields() {
        let req = Request::Up {
            authkey: Some("tskey-auth-xxx".to_string()),
            control_url: None,
            hostname: Some("node-a".to_string()),
            tun: Some(true),
            tun_name: Some("tailscale0".to_string()),
            tun_mtu: Some(1280),
            exit_node: Some(Some("100.64.0.9".to_string())),
            advertise_exit_node: Some(true),
            advertise_routes: Some(vec!["192.168.1.0/24".to_string()]),
            advertise_tags: Some(vec!["tag:server".to_string()]),
            accept_routes: Some(true),
            ssh: Some(true),
            reset: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: Request = serde_json::from_str(&json).unwrap();
        match back {
            Request::Up {
                authkey,
                hostname,
                control_url,
                tun,
                tun_name,
                tun_mtu,
                exit_node,
                advertise_exit_node,
                advertise_routes,
                advertise_tags: _,
                accept_routes,
                ssh,
                reset,
            } => {
                assert!(reset, "reset must survive the wire round-trip when set");
                assert_eq!(authkey.as_deref(), Some("tskey-auth-xxx"));
                assert_eq!(hostname.as_deref(), Some("node-a"));
                assert!(control_url.is_none());
                assert_eq!(tun, Some(true));
                assert_eq!(ssh, Some(true));
                assert_eq!(tun_name.as_deref(), Some("tailscale0"));
                assert_eq!(tun_mtu, Some(1280));
                assert_eq!(exit_node, Some(Some("100.64.0.9".to_string())));
                assert_eq!(advertise_exit_node, Some(true));
                assert_eq!(advertise_routes, Some(vec!["192.168.1.0/24".to_string()]));
                assert_eq!(accept_routes, Some(true));
            }
            other => panic!("expected Up, got {other:?}"),
        }
    }

    #[test]
    fn request_down_wire_format() {
        assert_eq!(
            serde_json::to_string(&Request::Down).unwrap(),
            r#"{"cmd":"down"}"#
        );
    }

    #[test]
    fn request_watch_wire_format() {
        // `watch` is the streaming-status command; assert its discriminant so daemon + CLI agree.
        assert_eq!(
            serde_json::to_string(&Request::Watch).unwrap(),
            r#"{"cmd":"watch"}"#
        );
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"watch"}"#).unwrap(),
            Request::Watch
        ));
    }

    #[test]
    fn version_request_response_round_trip() {
        // The `version` discriminant + the daemon's reply shape must be stable across the CLI/daemon
        // process boundary (they agree only on this JSON wire format).
        assert_eq!(
            serde_json::to_string(&Request::Version).unwrap(),
            r#"{"cmd":"version"}"#
        );
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"version"}"#).unwrap(),
            Request::Version
        ));
        let resp = Response::Version {
            version: "0.9.0".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        match serde_json::from_str::<Response>(&json).unwrap() {
            Response::Version { version } => assert_eq!(version, "0.9.0"),
            other => panic!("expected Version, got {other:?}"),
        }
    }

    #[test]
    fn get_prefs_request_response_round_trip() {
        // `get_prefs` discriminant + the Prefs(PrefsView) reply must survive the wire.
        assert_eq!(
            serde_json::to_string(&Request::GetPrefs).unwrap(),
            r#"{"cmd":"get_prefs"}"#
        );
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"get_prefs"}"#).unwrap(),
            Request::GetPrefs
        ));
        let resp = Response::Prefs(PrefsView {
            advertise_routes: vec!["10.0.0.0/8".into()],
            accept_routes: true,
            ..PrefsView::default()
        });
        let json = serde_json::to_string(&resp).unwrap();
        match serde_json::from_str::<Response>(&json).unwrap() {
            Response::Prefs(v) => {
                assert_eq!(v.advertise_routes, vec!["10.0.0.0/8".to_string()]);
                assert!(v.accept_routes);
            }
            other => panic!("expected Prefs, got {other:?}"),
        }
    }

    #[test]
    fn response_error_is_tagged() {
        let resp = Response::Error {
            message: "boom".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, r#"{"kind":"error","message":"boom"}"#);
    }

    #[test]
    fn status_report_round_trips() {
        let report = Response::Status(StatusReport {
            state: "Running".to_string(),
            want_running: true,
            self_ipv4: Some("100.70.22.12".to_string()),
            self_name: Some("node-a".to_string()),
            auth_url: None,
            error: None,
            prefs: Default::default(),
            peers: vec![PeerReport {
                name: "peer-b".to_string(),
                ipv4: "100.64.0.2".to_string(),
                is_exit_node: true,
                ..Default::default()
            }],
        });
        let json = serde_json::to_string(&report).unwrap();
        let back: Response = serde_json::from_str(&json).unwrap();
        match back {
            Response::Status(s) => {
                assert_eq!(s.state, "Running");
                assert_eq!(s.peers.len(), 1);
                assert!(s.peers[0].is_exit_node);
                assert!(s.auth_url.is_none());
            }
            other => panic!("expected Status, got {other:?}"),
        }
        // `auth_url` is `skip_serializing_if = None`, so a no-login status carries no `auth_url` key.
        assert!(
            !json.contains("auth_url"),
            "auth_url must be omitted when None"
        );
        // `error` is likewise `skip_serializing_if = None`: a non-failing status carries no `error` key.
        assert!(
            !json.contains("\"error\""),
            "error must be omitted when None"
        );
    }

    #[test]
    fn status_report_auth_url_round_trips() {
        // Interactive login: when the daemon surfaces a NeedsLogin auth URL it must serialize and
        // survive the round-trip so the CLI can print it.
        let report = StatusReport {
            state: "NeedsLogin".to_string(),
            want_running: true,
            self_ipv4: None,
            self_name: None,
            auth_url: Some("https://login.example.com/a/abc123".to_string()),
            error: None,
            prefs: Default::default(),
            peers: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("auth_url"));
        // Interactive login is transient, not a terminal failure: the URL is present, `error` absent.
        assert!(
            !json.contains("\"error\""),
            "error must be absent when only auth_url is set"
        );
        let back: StatusReport = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.auth_url.as_deref(),
            Some("https://login.example.com/a/abc123")
        );
        assert_eq!(back.state, "NeedsLogin");
        assert!(back.error.is_none());
    }

    #[test]
    fn status_report_error_round_trips() {
        // Terminal failure: a bad/expired/unknown auth key makes the engine report
        // `DeviceState::Failed`, which surfaces as `state == "NeedsLogin"` with a populated `error`
        // and no `auth_url`. The reason string must serialize and survive the round-trip so the CLI
        // can print it and bail instead of dwelling the auth-URL poll window.
        let report = StatusReport {
            state: "NeedsLogin".to_string(),
            want_running: true,
            self_ipv4: None,
            self_name: None,
            auth_url: None,
            error: Some("authentication rejected by control: invalid key".to_string()),
            prefs: Default::default(),
            peers: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"error\""));
        assert!(json.contains("authentication rejected by control: invalid key"));
        let back: StatusReport = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.error.as_deref(),
            Some("authentication rejected by control: invalid key")
        );
        assert_eq!(back.state, "NeedsLogin");
        assert!(back.auth_url.is_none());
    }

    #[test]
    fn status_report_error_omitted_when_none() {
        // `error` is `skip_serializing_if = None`: a status that is not a terminal failure must not
        // carry an `error` key on the wire.
        let report = StatusReport {
            state: "Running".to_string(),
            want_running: true,
            self_ipv4: Some("100.70.22.12".to_string()),
            self_name: Some("node-a".to_string()),
            auth_url: None,
            error: None,
            prefs: Default::default(),
            peers: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            !json.contains("\"error\""),
            "error must be omitted when None"
        );
    }

    #[test]
    fn status_report_error_and_auth_url_are_independent() {
        // The wire format keeps the transient (interactive login pending) and terminal (registration
        // hard-failed) cases distinct: each report carries exactly one of the two fields, never both.

        // Interactive login pending: `auth_url` present, `error` absent.
        let pending = StatusReport {
            state: "NeedsLogin".to_string(),
            want_running: true,
            self_ipv4: None,
            self_name: None,
            auth_url: Some("https://login.example.com/a/abc123".to_string()),
            error: None,
            prefs: Default::default(),
            peers: vec![],
        };
        let pending_json = serde_json::to_string(&pending).unwrap();
        assert!(pending_json.contains("auth_url"));
        assert!(!pending_json.contains("\"error\""));
        let pending_back: StatusReport = serde_json::from_str(&pending_json).unwrap();
        assert_eq!(
            pending_back.auth_url.as_deref(),
            Some("https://login.example.com/a/abc123")
        );
        assert!(pending_back.error.is_none());

        // Terminal failure: `error` present, `auth_url` absent.
        let failed = StatusReport {
            state: "NeedsLogin".to_string(),
            want_running: true,
            self_ipv4: None,
            self_name: None,
            auth_url: None,
            error: Some("authentication rejected by control: invalid key".to_string()),
            prefs: Default::default(),
            peers: vec![],
        };
        let failed_json = serde_json::to_string(&failed).unwrap();
        assert!(failed_json.contains("\"error\""));
        assert!(!failed_json.contains("auth_url"));
        let failed_back: StatusReport = serde_json::from_str(&failed_json).unwrap();
        assert_eq!(
            failed_back.error.as_deref(),
            Some("authentication rejected by control: invalid key")
        );
        assert!(failed_back.auth_url.is_none());
    }

    #[test]
    fn request_up_all_none_round_trips() {
        // The CLI sends `up` with every override absent (use the daemon's persisted prefs /
        // engine defaults). The all-`None` shape must survive the JSON wire intact.
        let req = Request::Up {
            authkey: None,
            control_url: None,
            hostname: None,
            tun: None,
            tun_name: None,
            tun_mtu: None,
            exit_node: None,
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            accept_routes: None,
            ssh: None,
            reset: false,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: Request = serde_json::from_str(&json).unwrap();
        match back {
            Request::Up {
                authkey,
                control_url,
                hostname,
                tun,
                tun_name,
                tun_mtu,
                exit_node,
                advertise_exit_node,
                advertise_routes,
                advertise_tags: _,
                accept_routes,
                ssh,
                reset,
            } => {
                assert!(!reset);
                assert!(authkey.is_none());
                assert!(control_url.is_none());
                assert!(hostname.is_none());
                assert!(tun.is_none());
                assert!(tun_name.is_none());
                assert!(tun_mtu.is_none());
                assert!(exit_node.is_none());
                assert!(advertise_exit_node.is_none());
                assert!(advertise_routes.is_none());
                assert!(accept_routes.is_none());
                assert!(ssh.is_none());
            }
            other => panic!("expected Up, got {other:?}"),
        }
    }

    #[test]
    fn request_up_exit_and_advertise_round_trip_and_back_compat() {
        // A client that omits the new fields (old wire) must still deserialize — `#[serde(default)]`
        // fills them as `None` (= "leave pref unchanged"). Pin that back-compat plus the populated
        // round-trip for the three routing fields.
        let old_wire = r#"{"cmd":"up","authkey":null,"hostname":"h"}"#;
        match serde_json::from_str::<Request>(old_wire).expect("old wire still parses") {
            Request::Up {
                exit_node,
                advertise_exit_node,
                advertise_routes,
                advertise_tags: _,
                accept_routes,
                hostname,
                ..
            } => {
                assert_eq!(hostname.as_deref(), Some("h"));
                assert!(exit_node.is_none(), "omitted exit_node defaults to None");
                assert!(advertise_exit_node.is_none());
                assert!(advertise_routes.is_none());
                assert!(
                    accept_routes.is_none(),
                    "omitted accept_routes defaults to None (leave pref unchanged)"
                );
            }
            other => panic!("expected Up, got {other:?}"),
        }

        // Clearing an exit node (`Some(None)`) must be distinct on the wire from "unchanged" (`None`).
        let clear = Request::Up {
            authkey: None,
            control_url: None,
            hostname: None,
            tun: None,
            tun_name: None,
            tun_mtu: None,
            exit_node: Some(None),
            advertise_exit_node: Some(false),
            advertise_routes: Some(vec![]),
            advertise_tags: None,
            accept_routes: None,
            ssh: None,
            reset: false,
        };
        let json = serde_json::to_string(&clear).unwrap();
        match serde_json::from_str::<Request>(&json).unwrap() {
            Request::Up {
                exit_node,
                advertise_exit_node,
                advertise_routes,
                advertise_tags: _,
                ..
            } => {
                assert_eq!(
                    exit_node,
                    Some(None),
                    "Some(None) = clear, distinct from unchanged"
                );
                assert_eq!(advertise_exit_node, Some(false));
                assert_eq!(advertise_routes, Some(vec![]));
            }
            other => panic!("expected Up, got {other:?}"),
        }
    }

    #[test]
    fn exit_node_double_option_wire_distinguishes_clear_from_unchanged() {
        // The load-bearing `double_option` contract, pinned at the RAW WIRE layer (the existing
        // round-trip test only ever constructs `Some(None)` in Rust, which a plain
        // `#[serde(default)] Option<Option<String>>` would also round-trip — so it does NOT actually
        // exercise the absent-vs-`null` deserialize split that `double_option` exists for). The bug
        // that was found+fixed is precisely that a present JSON `null` (the "clear my exit node"
        // command) silently collapses to `None` ("leave unchanged") without `double_option`, making
        // the clear a no-op. This test fails if `double_option` is removed.

        // (1) DESERIALIZE: a present `null` must decode to `Some(None)` = CLEAR — distinct from an
        //     absent key, which decodes to `None` = UNCHANGED. This is the half a plain
        //     `#[serde(default)]` gets wrong (it would yield `None` for both).
        let cleared = match serde_json::from_str::<Request>(r#"{"cmd":"up","exit_node":null}"#)
            .expect("a present exit_node:null must parse")
        {
            Request::Up { exit_node, .. } => exit_node,
            other => panic!("expected Up, got {other:?}"),
        };
        assert_eq!(
            cleared,
            Some(None),
            "a present JSON null must decode to Some(None) = CLEAR (double_option), not None"
        );
        let unchanged = match serde_json::from_str::<Request>(r#"{"cmd":"up"}"#)
            .expect("an absent exit_node must parse")
        {
            Request::Up { exit_node, .. } => exit_node,
            other => panic!("expected Up, got {other:?}"),
        };
        assert_eq!(
            unchanged, None,
            "an absent exit_node key must decode to None = UNCHANGED"
        );
        assert_ne!(
            cleared, unchanged,
            "clear (Some(None)) and unchanged (None) must be distinct after decoding the wire"
        );

        // (2) SERIALIZE: the two intents must also be byte-distinct on the wire — CLEAR emits a
        //     present `exit_node:null`, while UNCHANGED omits the key entirely (skip_serializing_if).
        //     A consumer that re-parses either form must recover the original intent (round-trip).
        let clear_json = serde_json::to_string(&Request::Up {
            authkey: None,
            control_url: None,
            hostname: None,
            tun: None,
            tun_name: None,
            tun_mtu: None,
            exit_node: Some(None),
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            accept_routes: None,
            ssh: None,
            reset: false,
        })
        .unwrap();
        let unchanged_json = serde_json::to_string(&Request::Up {
            authkey: None,
            control_url: None,
            hostname: None,
            tun: None,
            tun_name: None,
            tun_mtu: None,
            exit_node: None,
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            accept_routes: None,
            ssh: None,
            reset: false,
        })
        .unwrap();
        assert!(
            clear_json.contains("\"exit_node\":null"),
            "CLEAR must serialize a present exit_node:null, got {clear_json}"
        );
        // Match the `exit_node` KEY specifically — `advertise_exit_node` also contains the substring
        // `exit_node`, so a naive `contains("exit_node")` would false-positive on it. Re-parse to a
        // generic Value and check the map keys instead of substring-matching the raw JSON.
        let unchanged_val: serde_json::Value = serde_json::from_str(&unchanged_json).unwrap();
        assert!(
            unchanged_val.get("exit_node").is_none(),
            "UNCHANGED must omit the exit_node key entirely (skip_serializing_if), got {unchanged_json}"
        );
        // CLEAR, by contrast, carries an explicit `exit_node: null` key.
        let clear_val: serde_json::Value = serde_json::from_str(&clear_json).unwrap();
        assert_eq!(
            clear_val.get("exit_node"),
            Some(&serde_json::Value::Null),
            "CLEAR must carry an explicit exit_node:null key, got {clear_json}"
        );
        assert_ne!(
            clear_json, unchanged_json,
            "clear and unchanged must be byte-distinct on the wire"
        );
    }

    #[test]
    fn request_set_exit_node_double_option_distinguishes_clear_from_unchanged() {
        // `Request::Set` carries the SAME load-bearing `double_option` on `exit_node` as `Up`, but
        // (unlike `Up`) had no wire test — so a refactor dropping the serde attr would make
        // `tnet set --clear-exit-node` a silent no-op with nothing to catch it. This mirrors `Up`'s
        // `exit_node_double_option_wire_distinguishes_clear_from_unchanged` for the `set` path.

        // (1) DESERIALIZE: a present `null` must decode to `Some(None)` = CLEAR — distinct from an
        //     absent key, which decodes to `None` = UNCHANGED. A plain `#[serde(default)]` would
        //     collapse both to `None`, silently dropping the clear.
        let cleared = match serde_json::from_str::<Request>(r#"{"cmd":"set","exit_node":null}"#)
            .expect("a present exit_node:null must parse")
        {
            Request::Set { exit_node, .. } => exit_node,
            other => panic!("expected Set, got {other:?}"),
        };
        assert_eq!(
            cleared,
            Some(None),
            "a present JSON null must decode to Some(None) = CLEAR (double_option), not None"
        );
        let unchanged = match serde_json::from_str::<Request>(r#"{"cmd":"set"}"#)
            .expect("an absent exit_node must parse")
        {
            Request::Set { exit_node, .. } => exit_node,
            other => panic!("expected Set, got {other:?}"),
        };
        assert_eq!(
            unchanged, None,
            "an absent exit_node key must decode to None = UNCHANGED"
        );
        assert_ne!(
            cleared, unchanged,
            "clear (Some(None)) and unchanged (None) must be distinct after decoding the wire"
        );

        // A present value must decode to `Some(Some(sel))` = SET.
        let set = match serde_json::from_str::<Request>(r#"{"cmd":"set","exit_node":"100.64.0.9"}"#)
            .expect("a present exit_node value must parse")
        {
            Request::Set { exit_node, .. } => exit_node,
            other => panic!("expected Set, got {other:?}"),
        };
        assert_eq!(
            set,
            Some(Some("100.64.0.9".to_string())),
            "a present exit_node value must decode to Some(Some(sel)) = SET"
        );

        // (2) SERIALIZE: the two intents must be byte-distinct on the wire — CLEAR emits a present
        //     `exit_node:null`, while UNCHANGED omits the key entirely (skip_serializing_if). A
        //     consumer that re-parses either form must recover the original intent.
        let clear_json = serde_json::to_string(&Request::Set {
            hostname: None,
            accept_routes: None,
            exit_node: Some(None),
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            ssh: None,
        })
        .unwrap();
        let unchanged_json = serde_json::to_string(&Request::Set {
            hostname: None,
            accept_routes: None,
            exit_node: None,
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            ssh: None,
        })
        .unwrap();
        // Match the `exit_node` KEY specifically — `advertise_exit_node` also contains the substring
        // `exit_node`, so re-parse to a generic Value and check the map keys instead of substring-
        // matching the raw JSON.
        let clear_val: serde_json::Value = serde_json::from_str(&clear_json).unwrap();
        assert_eq!(
            clear_val.get("exit_node"),
            Some(&serde_json::Value::Null),
            "CLEAR must carry an explicit exit_node:null key, got {clear_json}"
        );
        let unchanged_val: serde_json::Value = serde_json::from_str(&unchanged_json).unwrap();
        assert!(
            unchanged_val.get("exit_node").is_none(),
            "UNCHANGED must omit the exit_node key entirely (skip_serializing_if), got {unchanged_json}"
        );
        assert_ne!(
            clear_json, unchanged_json,
            "clear and unchanged must be byte-distinct on the wire"
        );
    }

    #[test]
    fn secret_string_debug_is_redacted() {
        // Auth keys flow through the daemon as `secrecy::SecretString` precisely so they never
        // land in a `Debug` rendering or log line. Pin that redaction property here.
        // NB: the sentinel deliberately avoids a real provider prefix (e.g. `tskey-auth-`) so
        // secret scanners don't flag this redaction test as a leaked credential (it isn't one).
        let sentinel = "SENSITIVE-VALUE-SHOULD-NOT-APPEAR";
        let s = secrecy::SecretString::from(sentinel.to_string());
        assert!(!format!("{s:?}").contains(sentinel));
    }
}
