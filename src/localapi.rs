//! LocalAPI wire types — the request/response DTOs spoken over the control socket.
//!
//! These are this crate's *own* serde types, deliberately decoupled from the engine's internal
//! types so the IPC surface is stable independent of engine churn. The transport today is
//! newline-delimited JSON over a Unix domain socket (see [`crate::server`]). Peer-credential
//! authorization is implemented (`SO_PEERCRED`, see [`crate::auth`]), matching Tailscale's
//! `LocalAPI` policy: reads are allowed for anyone, writes only for root or the same UID as the
//! daemon.

use serde::{Deserialize, Serialize};

/// What [`Request::FileGetDir`] does when a same-named file already exists in the target directory —
/// the faithful analogue of Go's `--conflict=(skip|overwrite|rename)` (`onConflict` in
/// `cmd/tailscale/cli/file.go`). The default is [`Skip`](ConflictPolicy::Skip), matching Go: never
/// silently clobber an existing file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    /// Refuse to overwrite: leave the conflicting file in the inbox and report an error for it, while
    /// still receiving any non-conflicting files (Go `skip`, the default). The safe choice.
    #[default]
    Skip,
    /// Replace the existing file. The daemon `remove`s the target FIRST and then exclusively creates
    /// it anew, so it never writes *through* a symlink an attacker planted at a known name (Go
    /// `overwrite`, which removes-then-`O_CREATE|O_EXCL` for exactly this reason).
    Overwrite,
    /// Keep both: write to an alternately-numbered name in the style of Chrome Downloads —
    /// `name (1).ext`, `name (2).ext`, … — up to a bounded number of attempts (Go `rename`).
    Rename,
}

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
        /// Accept the tailnet's MagicDNS config (Go `tailscale up --accept-dns`, default-on). `None`
        /// leaves the pref unchanged; `Some(b)` sets it. `#[serde(default)]` keeps the wire back-compat.
        #[serde(default)]
        accept_dns: Option<bool>,
        /// Shields-up: block inbound peer connections terminating on this node (Go `--shields-up`).
        /// `None` leaves the pref unchanged; `Some(b)` sets it. `#[serde(default)]` keeps the wire
        /// backward-compatible with clients that omit it.
        #[serde(default)]
        shields_up: Option<bool>,
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
        /// Force a fresh re-registration (Go `tailscale up --force-reauth`). When set, the daemon
        /// discards the persisted node key before the bring-up handshake, so the engine cannot
        /// resume the old registration and instead registers FRESH — surfacing a new login/auth URL
        /// for an interactive (authkey-less) up. This is a **lifecycle action, not a pref**: it
        /// changes no persisted setting, so it is NOT part of the accidental-revert guard / `--reset`
        /// lockstep, and a bare `up --force-reauth` (no other flags) stays a bare up (never trips the
        /// guard). `#[serde(default)]` keeps the wire backward-compatible with clients that omit it.
        #[serde(default)]
        force_reauth: bool,
        /// Register as an ephemeral node (Go `tailscale up --ephemeral`). `None` leaves the pref
        /// unchanged; `Some(b)` sets it. A registration-time intent (default-false/persistent for a
        /// fresh node). `#[serde(default)]` keeps the wire backward-compatible with clients that omit it.
        #[serde(default)]
        ephemeral: Option<bool>,
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
        /// Accept the tailnet's MagicDNS config (Go `tailscale set --accept-dns`). `None` unchanged;
        /// `Some(b)` sets it. Applied LIVE on a running device (`Device::set_accept_dns`).
        #[serde(default)]
        accept_dns: Option<bool>,
        /// Shields-up: block inbound peer connections terminating on this node (Go `--shields-up`).
        /// `None` unchanged; `Some(b)` sets it. Takes effect by reconfiguring a running device.
        #[serde(default)]
        shields_up: Option<bool>,
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
    /// with [`Response::Metrics`]. A WRITE for authorization purposes — Go gates `serveMetrics` on
    /// `PermitWrite` ("out of paranoia that the metrics might contain something sensitive"), so it is
    /// gated like `up`/`down` (root/same-uid), not like a status read. Requires the node to be up
    /// (metrics come from the live engine).
    Metrics,
    /// Report Tailnet Lock (TKA) status (Go `tailscale lock status`, read-only subset). Replies with
    /// [`Response::Lock`]. Read-only — gated like [`Status`](Request::Status).
    LockStatus,
    /// Report the control-pushed MagicDNS configuration (Go `tailscale dns status`). Replies with
    /// [`Response::DnsStatus`]. Read-only — gated like [`Status`](Request::Status). Requires the node
    /// to be up (the config comes from the live engine's netmap).
    DnsStatus,
    /// Report this node's network-conditions report (Go `tailscale netcheck`). Replies with
    /// [`Response::Netcheck`]. Read-only — gated like [`Status`](Request::Status). Requires the node
    /// to be up (the measurements come from the live engine's net-report). NOTE: this fork's
    /// net-report measures ONLY DERP-region latency (see [`NetcheckReport`]).
    Netcheck,
    /// Provision (or fetch) a TLS certificate + key for `domain` via the tailnet's ACME flow (Go
    /// `tailscale cert <domain>`). Replies with [`Response::Cert`] carrying the leaf+chain and the
    /// private key as PEM. Requires the node to be up (issuance goes through the live engine's
    /// control connection) AND a daemon built with the `acme` cargo feature; without it the daemon
    /// fails closed with a clear error (never a self-signed cert). Gated like [`Status`](Request::Status)
    /// for read; issuance itself is a control round-trip, not a local mutation of node prefs.
    Cert {
        /// The DNS name to certify — must be one of the tailnet's `CertDomains` (Go validates the
        /// same; an arbitrary domain is refused by control/ACME).
        domain: String,
    },
    /// Produce a shareable diagnostic marker (Go `tailscale bugreport`). Replies with
    /// [`Response::BugReport`]. Read-only. NOTE: Go uploads logs to logtail and returns the log id;
    /// this fork has no log-upload backend, so the marker is a LOCAL diagnostic identifier only (it is
    /// not a server-retrievable log id — see the daemon's `bugreport` builder + the CLI note).
    BugReport {
        /// An optional operator note (Go `bugreport [note]`) appended to the marker. `None` when the
        /// positional was omitted. `#[serde(default)]` + `skip_serializing_if` keep the wire
        /// backward-compatible (an older client sends the bare variant, which deserializes to `None`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// Read the node's serve configuration (Go `GetServeConfig`; `tnet serve status`). Replies with
    /// [`Response::ServeConfig`]. Read-only — gated like [`Status`](Request::Status).
    GetServeConfig,
    /// Replace the node's serve configuration (Go `SetServeConfig`; `tnet serve --tcp` / `reset`).
    /// The daemon persists it and re-arms its serve accept loops to match. A WRITE — gated like
    /// `up`/`down`.
    SetServeConfig {
        /// The new serve config (replaces the current one wholesale).
        config: ServeConfig,
    },
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
    /// Fetch an OIDC id-token for this node, scoped to `audience` (Go `tailscale id-token <aud>`).
    /// The daemon asks control to mint a signed JWT; replies with [`Response::IdToken`]. A WRITE: it
    /// MINTS a bearer credential identifying this node (Go gates `serveIDToken` on `PermitWrite`, not
    /// the `PermitRead` it uses for `whois`), so it is gated like `up`/`down` — a non-root/non-owner
    /// local user must not be able to mint a node credential. Requires the node to be up (the issuance
    /// goes over the live control connection).
    IdToken {
        /// The OIDC audience (`aud` claim) the token is minted for.
        audience: String,
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
        /// Optional override for the name the file is sent AS (Go `--name`); `None` → the daemon uses
        /// the path's basename. Validated to a single safe component on the daemon side.
        #[serde(default)]
        name: Option<String>,
    },
    /// List Taildrop files waiting in this node's receive directory. Read-only.
    ///
    /// Fork-specific verb: Go v1.100.0 has no `file list` — its `tailscale file get <dir>` drains the
    /// whole inbox into a directory, and bare `file get` errors. This build instead splits discovery
    /// (`list`) from a per-file `get <name> <dest>` (see [`FileGet`](Request::FileGet)); the
    /// directory-draining Go model is tracked as a follow-up.
    FileList,
    /// Fetch a waiting Taildrop file by name, writing it to `dest`. A WRITE (it consumes/deletes the
    /// inbound file after copying) — gated like `up`/`down`.
    ///
    /// Fork-specific: Go's `tailscale file get <target-directory>` takes a DIRECTORY and drains the
    /// entire inbox (with a `--conflict` policy defaulting to skip/refuse-overwrite). This build's
    /// per-name fetch is not Go's command shape; the Go directory model + conflict policy is tracked
    /// as a follow-up (see `bd` `tsd-file-model`).
    FileGet {
        /// The waiting file's base name (from [`FileList`](Request::FileList)).
        name: String,
        /// Local destination path the daemon writes the file to.
        dest: String,
        /// Delete the file from the receive directory after a successful fetch (Go default).
        #[serde(default)]
        delete_after: bool,
    },
    /// Drain the **entire** Taildrop inbox into a directory — the faithful analogue of Go's
    /// `tailscale file get <target-directory>` (`runFileGetOneBatch`). For each waiting file the
    /// daemon writes `<dir>/<name>` under the [`conflict`](Request::FileGetDir::conflict) policy, then
    /// (on success) removes it from the inbox, so a second drain does not re-fetch it. A WRITE (it
    /// writes files as the daemon's uid and consumes the inbox) — gated like `up`/`down`. The reply is
    /// a per-file [`Response::FilesGot`] so the CLI can render Go-style result lines and set its exit
    /// code from the outcomes. This is distinct from the per-file [`FileGet`](Request::FileGet) (kept
    /// as a fork convenience for fetching one named file to an exact path).
    FileGetDir {
        /// Target directory the inbox is drained into (must already exist and be a directory — the
        /// daemon validates, matching Go's `os.Stat`+`IsDir` check). The special value `/dev/null`
        /// **wipes** the inbox without writing anything (Go's `wipeInbox`).
        dir: String,
        /// What to do when `<dir>/<name>` already exists. Defaults to [`ConflictPolicy::Skip`] (Go's
        /// default — never clobber: refuse the conflicting file and leave it in the inbox).
        #[serde(default)]
        conflict: ConflictPolicy,
    },
    /// List the tailnet peers this node can Taildrop a file *to* (Go `file cp --targets` /
    /// `file-targets` LocalAPI). Read-only — it only enumerates eligible peers, gated like `status`.
    /// The daemon projects the engine's `Device::file_targets()` (which already applies Go's
    /// eligibility filter: a reachable peerAPI **and** same-owner-or-shared, gated on this node holding
    /// the file-sharing capability) into [`Response::FileTargets`].
    FileTargets,
    /// Capture the dataplane's plaintext packets to a pcap file for `seconds`, then stop (Go
    /// `tailscale debug capture`). A WRITE: it installs a dataplane capture hook and writes a file as
    /// the daemon's uid, so it's gated like `up`/`down`. The daemon owns a `BufWriter<File>` at `path`,
    /// runs the engine's `capture_pcap` for the bounded window, then `stop_capture` (flush + close).
    DebugCapture {
        /// Local path the daemon writes the pcap to (a fresh path, or an existing regular file to
        /// truncate; a non-regular existing target is refused).
        path: String,
        /// How long to capture before stopping (bounds the call so the CLI returns). `None` = the
        /// daemon's dispatch applies a sane default (the `tnet` CLI always sends an explicit value).
        #[serde(default)]
        seconds: Option<u64>,
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
    /// The result of a [`Request::Ping`]: the measured round-trip time and the path it took.
    Ping {
        /// Round-trip time in milliseconds.
        rtt_ms: f64,
        /// The pinged tailnet IP (echoed for the CLI).
        ip: String,
        /// The direct underlay endpoint the peer answered on — the analogue of Go's
        /// `ipnstate.PingResult.Endpoint`. `Some(addr)` ⇒ a **direct** path is established (the
        /// `ip:port` the data plane reaches the peer at); `None` ⇒ no direct path, so the overlay is
        /// relayed through DERP (Go prints `via DERP`). This is what `tnet ping --until-direct` waits
        /// on: it keeps pinging until this becomes `Some`. Backfilled from the engine's
        /// `Device::direct_path` (a cached snapshot of the last disco probe — no extra network
        /// round-trip). NOTE the endpoint and the RTT come from **different** measurements: the RTT
        /// is the netstack-ICMP echo just sent, while the endpoint is the cached disco-path snapshot
        /// (up to one probe interval stale). So on a peer mid-upgrade DERP→direct the endpoint can
        /// briefly lag the RTT — `--until-direct` may take a ping or two longer than Go to notice the
        /// upgrade (it still converges). Sourcing both from one fresh `ping_disco` is a fidelity
        /// follow-up (see the ping backlog bead).
        #[serde(default)]
        endpoint: Option<String>,
    },
    /// The waiting Taildrop files (reply to [`Request::FileList`]).
    Files {
        /// Files in the receive directory, each `(name, size_bytes)`.
        files: Vec<WaitingFileReport>,
    },
    /// Per-file outcomes of draining the inbox (reply to [`Request::FileGetDir`]). One entry per file
    /// the daemon attempted, in inbox order, so the CLI can print Go-style result/error lines and
    /// decide its exit code (non-zero if any file failed, or if nothing moved while files waited).
    FilesGot {
        /// One outcome per attempted file.
        results: Vec<FileGotReport>,
    },
    /// The peers this node can Taildrop to (reply to [`Request::FileTargets`]), sorted by the engine
    /// (MagicDNS name). Empty when the node holds no file-sharing capability (fail-closed) or has no
    /// eligible peers.
    FileTargets {
        /// One entry per eligible target peer.
        targets: Vec<FileTargetReport>,
    },
    /// The daemon's own version (reply to [`Request::Version`]) — the analogue of Go's
    /// `ipnstate.Status.Version`, used by `tnet version --daemon`.
    Version {
        /// The daemon binary's version (its crate version, `CARGO_PKG_VERSION`).
        version: String,
    },
    /// The OIDC id-token minted by control (reply to [`Request::IdToken`]), printed by
    /// `tnet id-token`.
    IdToken {
        /// The signed JWT (an OIDC id-token scoped to the requested audience).
        token: String,
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
    /// The control-pushed MagicDNS configuration (reply to [`Request::DnsStatus`]), rendered by
    /// `tnet dns status`.
    DnsStatus(DnsStatusReport),
    /// The node's network-conditions report (reply to [`Request::Netcheck`]), rendered by
    /// `tnet netcheck`.
    Netcheck(NetcheckReport),
    /// An issued TLS certificate (reply to [`Request::Cert`]), written out by `tnet cert`. Both fields
    /// are PEM text: `cert_pem` is the leaf + intermediate chain, `key_pem` is the private key. The
    /// key is sensitive — the CLI writes it `0600` and the daemon never logs it.
    Cert {
        /// The leaf certificate + intermediate chain, PEM-encoded.
        cert_pem: String,
        /// The private key, PEM-encoded. Sensitive: written `0600`, never logged.
        key_pem: String,
    },
    /// A local diagnostic marker (reply to [`Request::BugReport`]), printed by `tnet bugreport`.
    BugReport {
        /// The marker string (a local identifier + daemon version + node state). NOT a server-side
        /// log id — this fork uploads nothing.
        marker: String,
    },
    /// The node's serve configuration (reply to [`Request::GetServeConfig`]), rendered by
    /// `tnet serve status`.
    ServeConfig(ServeConfig),
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
    /// The node's control-granted capabilities (capability name → args). This is the **node-level**
    /// cap map (Go `Node.CapMap` — node attributes like `can-funnel`); just the names are kept (the
    /// args are dropped for the summary). Distinct from [`cap_map`](WhoisReport::cap_map).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// The **flow-scoped** peer-capability grants for the `this-node → queried-IP` flow — Go
    /// `apitype.WhoIsResponse.CapMap` (`tailcfg.PeerCapMap`): the capabilities control's packet-filter
    /// rules authorize for traffic from this node to the queried address, keyed by capability name
    /// with raw (JSON-encoded) value strings the daemon never parses (kept here, unlike
    /// [`capabilities`](WhoisReport::capabilities), since the grant *values* are the point). Empty
    /// when no grant matches the flow. `#[serde(default)]` +
    /// `skip_serializing_if` keep the wire backward-compatible (an older daemon/client omits the
    /// field, which deserializes to an empty map).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub cap_map: std::collections::BTreeMap<String, Vec<String>>,
    /// The node's control-granted ACL tags (e.g. `tag:server`), if any. `#[serde(default)]` +
    /// `skip_serializing_if` keep the wire backward-compatible (an older daemon/client simply omits
    /// the field, which deserializes to an empty set).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// When the node's key expires, in the engine's chrono `DateTime<Utc>` Display form
    /// (`YYYY-MM-DD HH:MM:SS UTC` — note this is NOT RFC3339's `T…Z`), or `None` if the key has no
    /// expiry. Surfaced so `whois`/`whoami` can show an upcoming/elapsed key expiry (Go carries it in
    /// its `whois --json`). Back-compatible (omitted when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_key_expiry: Option<String>,
    /// The node's liveness: `Some(true)` = control-connected (online), `Some(false)` = offline,
    /// `None` = unknown (the same control-plane signal `status` uses for peers). Back-compatible
    /// (omitted when unknown).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    /// When the node was last seen by control, in chrono `DateTime<Utc>` Display form
    /// (`YYYY-MM-DD HH:MM:SS UTC`, NOT RFC3339), or `None` if never/unknown. Like `status`, this is
    /// only *meaningful* (and only rendered) when the node is offline — an online node's last-seen is
    /// "now". Back-compatible (omitted when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
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

/// The outcome of receiving one inbox file during a [`Request::FileGetDir`] drain. On success
/// `written` names the actual path the file landed at (which differs from `<dir>/<name>` under the
/// `rename` policy) and `error` is `None`; on failure `error` carries the reason and `written` is
/// `None` (the file is left in the inbox). `name` is always the inbox base name so the CLI can
/// attribute the line either way.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileGotReport {
    /// The inbox file's base name.
    pub name: String,
    /// Bytes written (meaningful only on success).
    #[serde(default)]
    pub size: u64,
    /// The path the file was written to on success (may be a numbered variant under `rename`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written: Option<String>,
    /// The failure reason when this file could not be received (then it stays in the inbox).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One Taildrop-able peer (reply element of [`Request::FileTargets`]), projected from the engine's
/// `FileTarget`. Mirrors the columns Go's `file cp --targets` prints: the peer's tailnet IP, its
/// MagicDNS/computed name, and its online status.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileTargetReport {
    /// The peer's primary tailnet IP (Go prints `Node.Addresses[0]`).
    pub ip: String,
    /// The peer's display/MagicDNS name (Go `Node.ComputedName`).
    pub name: String,
    /// Online status: `Some(true)` online, `Some(false)` offline, `None` unknown (Go distinguishes
    /// the three; offline/unknown peers are still listed — an offline send simply times out).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
}

/// A snapshot of daemon + netmap state.
///
/// Container-level `#[serde(default)]`: every field is omittable on the wire and falls back to
/// [`StatusReport::default`], so a JSON document missing any field (e.g. an older client's status
/// line) deserializes instead of hard-erroring. Fields keep their `skip_serializing_if` so the
/// emitted wire still drops empty optionals.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// A snapshot of the node's persisted configuration intent (its [`Prefs`](crate::prefs::Prefs)),
    /// so `tnet status` can show the full posture — exit node, advertised routes/exit, accept-routes,
    /// SSH, TUN — the way Go `tailscale status` reflects the active prefs. Read straight from the
    /// daemon's prefs (no engine round-trip), so it is always present. The container-level
    /// `#[serde(default)]` keeps the wire backward-compatible with clients that predate this field.
    pub prefs: PrefsView,
    /// This node's tailnet IPv6, once a netmap has been received (Go `Status.TailscaleIPs[1]`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_ipv6: Option<String>,
    /// The stable id (resolved to the peer's display name where possible) of the exit node traffic is
    /// **currently** egressing through, if any (Go `Status.ExitNodeStatus.ID`). `None` when no exit
    /// node is engaged. Distinct from the *configured* `prefs.exit_node` selector: this is what is
    /// actually live (the route updater's fail-closed answer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_exit_node: Option<String>,
    /// The tailnet's MagicDNS suffix (e.g. `tail0123.ts.net`), Go `Status.MagicDNSSuffix`. `None`
    /// before the first netmap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub magic_dns_suffix: Option<String>,
    /// Known peers in the netmap.
    pub peers: Vec<PeerReport>,
    /// The daemon's own version (its crate version), Go `Status.Version`. Carried so `status --json`
    /// can surface it the way Go does (and the way `tnet version --daemon` already reports it
    /// separately). The container-level `#[serde(default)]` + `skip_serializing_if` keep the wire
    /// backward-compatible with clients that predate this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Whether this node holds a persisted node key (Go `Status.HaveNodeKey`). The daemon computes
    /// this directly from the on-disk key (`has_persisted_node_key`), the analogue of Go's
    /// `hasNodeKeyLocked` — NOT a proxy for the IPN state. (An *expired* node still holds its key on
    /// disk, so it must report `true` even while the state is `NeedsLogin`; only `logout`/`force-reauth`
    /// discard the key.) The container-level `#[serde(default)]` keeps the wire backward-compatible.
    pub have_node_key: bool,
}

/// A read-only projection of the node's persisted [`Prefs`](crate::prefs::Prefs) for `status`
/// output. Mirrors the policy-relevant fields an operator wants to see at a glance (the analogue of
/// the prefs Go's `tailscale status` surfaces), without exposing the full prefs struct or any secret.
///
/// Container-level `#[serde(default)]` (matching [`crate::prefs::Prefs`]): every field is omittable
/// on the wire and falls back to [`PrefsView::default`], so a JSON projection missing any field
/// deserializes instead of hard-erroring. Fields keep their `skip_serializing_if` so empty
/// optionals/collections are still dropped from the emitted wire.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PrefsView {
    /// The configured exit-node selector (IP or MagicDNS name), or `None` if no exit node is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<String>,
    /// Whether this node advertises itself as an exit node.
    pub advertise_exit_node: bool,
    /// Subnet routes (CIDRs) this node advertises to the tailnet.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub advertise_routes: Vec<String>,
    /// ACL tags (`tag:<name>`) this node requests at registration.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub advertise_tags: Vec<String>,
    /// Whether this node accepts subnet routes advertised by peers.
    pub accept_routes: bool,
    /// Whether this node accepts the tailnet's MagicDNS configuration (Go `--accept-dns` / `CorpDNS`).
    /// Default-on in the persisted [`Prefs`]; here it is always populated by `prefs_view()` from the
    /// live pref (PrefsView is a fresh, fully-populated reply from a lockstep-versioned daemon — never
    /// a partial/upgraded payload), so the container `#[serde(default)]` (→ `false`) only applies to an
    /// impossible missing-field case. No field-level `true` default, to avoid disagreeing with the
    /// derived `Default`.
    pub accept_dns: bool,
    /// Whether shields-up is on (block inbound peer connections terminating on this node).
    pub shields_up: bool,
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
    /// The container-level `#[serde(default)]` keeps the wire backward-compatible with clients that
    /// predate this field.
    pub ssh_running: bool,
    /// Whether the node uses the kernel-TUN data path (vs the userspace netstack).
    pub tun: bool,
}

/// The node's serve configuration (the TCP-forward subset of Go `ipn.ServeConfig`), carried by
/// [`Request::SetServeConfig`] / [`Response::ServeConfig`]. Persistence + the served/not-served logic
/// live in `crate::ipn::serve`.
///
/// **Wire shape.** Plain TCP forward + `AllowFunnel` round-trip byte-for-byte with Go (PascalCase,
/// `omitempty`), e.g. `{"TCP":{"8443":{"TCPForward":"127.0.0.1:5000"}}}`. As of the `Web`-map work
/// (`tsd-6p4`, Stage A), the Go top-level [`web`](ServeConfig::web) map
/// (`Web map[HostPort]*WebServerConfig`) is ALSO modelled, so a *web* serve config written by an
/// upstream `tailscaled` (`{"TCP":{"443":{"HTTPS":true}},"Web":{"host:443":{"Handlers":{"/":
/// {"Proxy":"…"}}}}}`) now deserializes its handler bodies here instead of silently dropping them.
/// The legacy per-handler [`text`](TcpPortHandler::text)/[`redirect`](TcpPortHandler::redirect)/
/// [`mounts`](TcpPortHandler::mounts) fields are RETAINED for read-compat with serve-config files this
/// fork already wrote (Stage A is additive — the translation reads both; Stage B moves the CLI to
/// write only the `Web` map). Go's `Services`/`Foreground` remain unmodeled (out of scope).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServeConfig {
    /// Per-tailnet-port handler, keyed by the tailnet listen port AS A STRING. The key is a string
    /// (not `u16`) deliberately: this DTO is carried inside the internally-tagged [`Request`] enum,
    /// whose deserialization buffers through `serde_json::Value` — and a `Value` map only has string
    /// keys, so an integer-keyed map fails to round-trip there ("invalid type: string, expected u16").
    /// A string key also matches Go's wire JSON (`{"TCP":{"8443":{...}}}`) byte-for-byte. The daemon
    /// parses the key to a port number where it needs one.
    #[serde(
        default,
        rename = "TCP",
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    pub tcp: std::collections::BTreeMap<String, TcpPortHandler>,
    /// Ports for which Funnel (public-internet ingress) is enabled (Go `ipn.ServeConfig.AllowFunnel`,
    /// `map[HostPort]bool`). Keyed by the Go `HostPort` form `host:port` (the node's MagicDNS name +
    /// `:` + port, e.g. `host.tailnet.ts.net:443`) so the wire matches Go byte-for-byte. A value of
    /// `true` means funnel is on for that host:port; the key is removed when funnel is turned off
    /// (so an off port never appears). Empty = no funnel (and the field is omitted from the wire).
    #[serde(
        default,
        rename = "AllowFunnel",
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    pub allow_funnel: std::collections::BTreeMap<String, bool>,
    /// Web handlers keyed by the Go `HostPort` form `host:port` (the node's MagicDNS name + `:` + port,
    /// e.g. `host.tailnet.ts.net:443`) — Go `ipn.ServeConfig.Web` (`map[HostPort]*WebServerConfig`). A
    /// `TCP[port]` handler with `HTTPS`/`HTTP` set points at the `Web[host:port]` entry, which holds the
    /// per-mount-path [`HttpHandler`]s (proxy / text / redirect / path). Empty = no web serve (omitted
    /// from the wire). This is the Go-faithful location for web-handler bodies; the legacy
    /// `TcpPortHandler.{text,redirect,mounts}` fields are kept only for read-compat (see the struct doc).
    #[serde(
        default,
        rename = "Web",
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    pub web: std::collections::BTreeMap<String, WebServerConfig>,
}

/// One served tailnet port (Go `ipn.TCPPortHandler`); only `tcp_forward` is served by this build.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcpPortHandler {
    /// Serve HTTPS on this port: the engine terminates TLS for the node's MagicDNS name and
    /// reverse-proxies each request to [`tcp_forward`](TcpPortHandler::tcp_forward) (the proxy
    /// backend). Served via engine delegation (`crate::ipn::serve::build_web_serve_state` →
    /// `Device::set_serve_config`); needs an issuable cert (the `acme` feature + a SaaS tailnet).
    #[serde(default, rename = "HTTPS", skip_serializing_if = "core::ops::Not::not")]
    pub https: bool,
    /// Serve HTTP on this port, reverse-proxying to [`tcp_forward`](TcpPortHandler::tcp_forward).
    /// Like [`https`](TcpPortHandler::https) but records HTTP intent; the engine serves both via the
    /// same native reverse-proxy path.
    #[serde(default, rename = "HTTP", skip_serializing_if = "core::ops::Not::not")]
    pub http: bool,
    /// `IP:port` to forward/proxy inbound TCP to. For a plain TCP forward (no `https`/`http`) this is
    /// the raw splice target; for an `https`/`http` web entry it is the reverse-proxy backend. Empty
    /// = not a forward.
    #[serde(
        default,
        rename = "TCPForward",
        skip_serializing_if = "String::is_empty"
    )]
    pub tcp_forward: String,
    /// If non-empty, terminate TLS for this SNI before forwarding (NOT served — needs a TLS server).
    #[serde(
        default,
        rename = "TerminateTLS",
        skip_serializing_if = "String::is_empty"
    )]
    pub terminate_tls: String,
    /// PROXY-protocol version to prepend before forwarding (Go `omitzero`; 0 = none).
    #[serde(default, rename = "ProxyProtocol", skip_serializing_if = "is_zero_i32")]
    pub proxy_protocol: i32,
    /// Serve a fixed plaintext body on this port instead of proxying (Go `HTTPHandler.Text`; engine
    /// [`ServeTarget::Text`](tailscale::ServeTarget::Text)). Web entry; TLS-terminated. `None` = not a
    /// text handler. Mutually exclusive with [`tcp_forward`](TcpPortHandler::tcp_forward) as the
    /// served target (a port serves one of: proxy / text / redirect / mounts).
    #[serde(default, rename = "Text", skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Serve an HTTP redirect on this port (engine [`ServeTarget::Redirect`](tailscale::ServeTarget::Redirect)).
    /// Web entry; TLS-terminated. `None` = not a redirect. (Go's CLI has no redirect path at v1.100.0,
    /// but the engine serves it, so this is a faithful engine-backed extension.)
    #[serde(default, rename = "Redirect", skip_serializing_if = "Option::is_none")]
    pub redirect: Option<RedirectSpec>,
    /// HTTP path-prefix mounts on this port (Go `WebServerConfig.Handlers`, keyed by mount path →
    /// engine [`ServeTarget::Path`](tailscale::ServeTarget::Path)). When non-empty, the port serves a
    /// path-prefix mux (longest-match wins; unmatched = fail-closed 404). A single `/` mount is
    /// equivalent to a bare proxy/text/redirect on the port. Empty = no mounts.
    #[serde(
        default,
        rename = "Mounts",
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    pub mounts: std::collections::BTreeMap<String, WebMount>,
}

/// An HTTP redirect handler (Go `HTTPHandler.Redirect`; engine
/// [`ServeTarget::Redirect`](tailscale::ServeTarget::Redirect)). `status` must be in `300..=399` and
/// `to` must not contain CR/LF (response-splitting guard) — both enforced by the engine's
/// `validate()` and checked daemon-side before the engine call.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedirectSpec {
    /// The `Location:` target. Supports the engine's `${HOST}` / `${REQUEST_URI}` expansion.
    #[serde(rename = "To")]
    pub to: String,
    /// The redirect HTTP status (e.g. 301, 302). Must be in `300..=399`.
    #[serde(rename = "Status")]
    pub status: u16,
}

/// The set of HTTP handlers for one web `host:port` (Go `ipn.WebServerConfig`), keyed by mount path
/// (`/`, `/foo`, …) → [`HttpHandler`]. The value type of [`ServeConfig::web`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebServerConfig {
    /// Mount-point → handler (Go `WebServerConfig.Handlers`, `map[string]*HTTPHandler`). A single `/`
    /// entry is a bare handler on the port; multiple are a longest-match path mux.
    #[serde(
        default,
        rename = "Handlers",
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    pub handlers: std::collections::BTreeMap<String, HttpHandler>,
}

/// One HTTP handler at a mount point (Go `ipn.HTTPHandler`). Exactly one of `proxy`/`text`/`path`/
/// `redirect` is set. Field names + `omitempty` match Go's wire JSON so a handler authored by an
/// upstream `tailscaled` round-trips. `redirect` is Go's **string** form (`"https://…"`, or
/// `"<code>:https://…"` to pick the status) — NOT this fork's older `RedirectSpec{To,Status}` object
/// (which stays only on the legacy [`TcpPortHandler::redirect`] read-compat field); the translation
/// parses this string into the engine's `ServeTarget::Redirect{to,status}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpHandler {
    /// Absolute path to a directory/file to serve (Go `HTTPHandler.Path`). Engine
    /// [`ServeTarget::Path`] is a path-MUX, not a filesystem server — a filesystem `Path` handler has
    /// no engine analogue at this pin and is recognized-but-not-served; carried for wire fidelity.
    #[serde(default, rename = "Path", skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// Reverse-proxy backend (`http://localhost:3000/`, `localhost:3030`, `3030`) — Go
    /// `HTTPHandler.Proxy`; engine [`ServeTarget::Proxy`](tailscale::ServeTarget::Proxy).
    #[serde(default, rename = "Proxy", skip_serializing_if = "String::is_empty")]
    pub proxy: String,
    /// Fixed plaintext body to serve (Go `HTTPHandler.Text`; engine
    /// [`ServeTarget::Text`](tailscale::ServeTarget::Text)).
    #[serde(default, rename = "Text", skip_serializing_if = "String::is_empty")]
    pub text: String,
    /// HTTP redirect target (Go `HTTPHandler.Redirect`). The Go string form: a bare URL redirects 302,
    /// or `"<httpcode>:<url>"` picks the status. Empty = not a redirect. Parsed into
    /// [`ServeTarget::Redirect`](tailscale::ServeTarget::Redirect) by the translation.
    #[serde(default, rename = "Redirect", skip_serializing_if = "String::is_empty")]
    pub redirect: String,
}

/// One handler mounted at a path prefix on a web port (the value of [`TcpPortHandler::mounts`]).
/// Mirrors the engine's non-`Path` [`ServeTarget`](tailscale::ServeTarget) arms (a mount cannot itself
/// be a nested path mux — the engine bounds `Path` nesting to one level).
///
/// **Legacy/read-compat only.** This fork-native (`{kind,…}`) shape predates the Go `Web` map; it is
/// retained so a serve-config.json this fork already wrote still deserializes. New configs use
/// [`HttpHandler`] under [`ServeConfig::web`]. See the [`ServeConfig`] doc.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum WebMount {
    /// Reverse-proxy the decrypted stream to a local `host:port` backend.
    Proxy {
        /// `host:port` to dial for the proxied backend.
        to: String,
    },
    /// Serve a fixed plaintext body, then close.
    Text {
        /// The exact bytes to write.
        body: String,
    },
    /// HTTP redirect response.
    Redirect {
        /// The `Location:` target.
        to: String,
        /// The redirect status (`300..=399`).
        status: u16,
    },
}

fn is_zero_i32(n: &i32) -> bool {
    *n == 0
}

/// Tailnet Lock (TKA) status in a [`Response::Lock`] reply (Go `tailscale lock status`, read-only
/// subset). Mirrors the engine's `ts_control::TkaStatus`.
///
/// Container-level `#[serde(default)]`: every field is omittable on the wire and falls back to
/// [`LockReport::default`], so a JSON document missing any field deserializes instead of
/// hard-erroring. `head` keeps its `skip_serializing_if` so an empty hash is dropped on the wire.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LockReport {
    /// Whether Tailnet Lock is in use (control sent TKA info for this node).
    pub enabled: bool,
    /// The base32 `AUMHash` of control's latest authority head (empty when none / not enabled).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub head: String,
    /// Whether control believes Tailnet Lock should be disabled (a disablement is pending).
    pub disabled: bool,
}

/// The control-pushed MagicDNS configuration in a [`Response::DnsStatus`] reply (Go `tailscale dns
/// status`, the MagicDNS-configuration sections). Mirrors the engine's `tailscale::DnsConfig`, but
/// stored as this crate's own wire types (resolver addresses pre-rendered to strings via
/// [`DnsResolver::udp_addr`](tailscale::DnsResolver::udp_addr)) so the CLI renders our DTO and never
/// the engine's type. The Go "Use Tailscale DNS" accept-dns line + the "System DNS configuration"
/// section are deliberately NOT carried (no CorpDNS pref / no engine OS-DNS accessor in this fork);
/// the CLI renderer notes both as not-surfaced-by-this-build.
///
/// Container-level `#[serde(default)]`: every field is omittable on the wire and falls back to
/// [`DnsStatusReport::default`], so a JSON document missing any field deserializes instead of
/// hard-erroring. The collection fields keep their `skip_serializing_if` so empty collections are
/// still dropped from the emitted wire.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DnsStatusReport {
    /// Whether MagicDNS is enabled tailnet-wide (engine `DnsConfig::magic_dns`, Go `Proxied`).
    pub magic_dns: bool,
    /// The tailnet DNS search suffix(es) (engine `search_domains`), lowercased, no trailing dot.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub search_domains: Vec<String>,
    /// Global upstream resolvers in preference order (engine `resolvers`), each as an `addr:port`
    /// string via [`DnsResolver::udp_addr`](tailscale::DnsResolver::udp_addr).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<String>,
    /// Split-DNS routes (engine `routes`): DNS suffix → the upstream resolver `addr:port` strings
    /// that answer that suffix. An empty value list is a negative route (names under the suffix are
    /// not resolved).
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub routes: std::collections::BTreeMap<String, Vec<String>>,
    /// Fallback resolvers (engine `fallback_resolvers`), preferred over [`resolvers`](DnsStatusReport::resolvers)
    /// for names matching no route, each as an `addr:port` string.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fallback_resolvers: Vec<String>,
    /// DNS names control will assist provisioning TLS certs for (engine `cert_domains`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cert_domains: Vec<String>,
    /// Control-pushed static host records (engine `extra_records`), each as `(name, addr)` with the
    /// address rendered to a string.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_records: Vec<(String, String)>,
    /// DNS suffixes this node (when acting as an exit-node DNS proxy) must not answer (engine
    /// `exit_node_filtered_set`), lowercased, no trailing dot.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exit_node_filtered_set: Vec<String>,
}

/// The node's network-conditions report in a [`Response::Netcheck`] reply (Go `tailscale netcheck`).
/// Mirrors the engine's `tailscale::NetcheckReport`, but as this crate's own wire type with the
/// per-region latency pre-rendered to milliseconds (so the CLI renders our DTO, never the engine's
/// `Duration`). HONEST REDUCED SCOPE: this fork's net-report measures ONLY DERP-region latency, so
/// Go's UDP/IPv4/IPv6/`MappingVariesByDestIP`/PortMapping(UPnP/PMP/PCP) fields are NOT carried, and
/// DERP regions are identified by id (the engine exposes no region name/code) — the CLI renderer
/// notes both omissions, mirroring the dns-status/serve honest-omission pattern.
///
/// Derives `PartialEq` but **not** `Eq`: [`RegionLatencyView::latency_ms`] is an `f64`, which is not
/// `Eq` (NaN), so the report cannot be `Eq` either.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NetcheckReport {
    /// The id of the preferred (lowest-latency) DERP region this node homes to (engine
    /// `NetcheckReport::preferred_derp`, Go `Report.PreferredDERP`). `None` before the first
    /// measurement / when no region was reachable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_derp: Option<u32>,
    /// Per-region measured latencies, in the engine's latency-ascending order (engine
    /// `NetcheckReport::region_latencies`, Go `Report.RegionLatency`). The first entry, when present,
    /// is the [`preferred_derp`](NetcheckReport::preferred_derp) region. Empty before the first
    /// measurement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub region_latencies: Vec<RegionLatencyView>,
}

/// One DERP region's measured latency in a [`NetcheckReport`] (engine `tailscale::RegionLatency`),
/// with the latency pre-rendered to milliseconds. Derives `PartialEq` but **not** `Eq` (the `f64`
/// [`latency_ms`](RegionLatencyView::latency_ms) is not `Eq`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RegionLatencyView {
    /// The DERP region id (engine `RegionLatency::region_id`, Go `tailcfg.DERPRegionID`). The engine
    /// carries no region name/code, so the CLI renders this id.
    pub region_id: u32,
    /// The measured round-trip latency to the region's closest DERP node, in milliseconds (engine
    /// `RegionLatency::latency`, a `Duration`, rendered via `as_secs_f64() * 1000.0`).
    pub latency_ms: f64,
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
    /// The peer's tailnet IPv6 address, if known (Go `PeerStatus.TailscaleIPs[1]`). `#[serde(default)]`
    /// keeps the wire backward-compatible with clients that predate this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    /// The routes this peer accepts traffic for — its own `/32`+`/128` plus any advertised subnet
    /// routes and the exit-node default route (Go `PeerStatus.AllowedIPs`). Empty when none/unknown.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_routes: Vec<String>,
    /// When control last saw this peer online, per Go `PeerStatus.LastSeen` — meaningful mainly while
    /// the peer is offline. `None` when unknown / never seen. Format is the engine `chrono`
    /// `DateTime<Utc>` Display form (RFC3339-*shaped* but space-separated with a ` UTC` suffix, e.g.
    /// `2026-06-11 05:19:14 UTC`, not strict RFC3339 `…T…Z`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// The peer's current direct UDP endpoint (`host:port`) when a direct path is confirmed (Go
    /// `PeerStatus.CurAddr`). `Some` ⇒ traffic flows directly; `None` ⇒ it relays via DERP (see
    /// [`relay`](PeerReport::relay)). Mutually exclusive with `relay` for a routed peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cur_addr: Option<String>,
    /// The DERP region code the peer relays through when there is no direct path (Go
    /// `PeerStatus.Relay`, e.g. `"nyc"`). `Some` ⇔ [`cur_addr`](PeerReport::cur_addr) is `None` and
    /// the home DERP region is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
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
            accept_dns: Some(false),
            shields_up: Some(true),
            ssh: Some(true),
            reset: true,
            force_reauth: false,
            ephemeral: None,
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
                accept_dns,
                shields_up,
                ssh,
                reset,
                force_reauth: _,
                ephemeral: _,
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
                assert_eq!(
                    accept_dns,
                    Some(false),
                    "accept_dns survives the wire round-trip"
                );
                assert_eq!(shields_up, Some(true));
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
    fn request_debug_capture_wire_format() {
        // Pin the `debug_capture` discriminant + field names so daemon + CLI agree.
        assert_eq!(
            serde_json::to_string(&Request::DebugCapture {
                path: "/tmp/x.pcap".into(),
                seconds: Some(5),
            })
            .unwrap(),
            r#"{"cmd":"debug_capture","path":"/tmp/x.pcap","seconds":5}"#
        );
        // An omitted `seconds` (the raw-client case) parses to None (the daemon then defaults it).
        match serde_json::from_str::<Request>(r#"{"cmd":"debug_capture","path":"/tmp/x.pcap"}"#)
            .unwrap()
        {
            Request::DebugCapture { path, seconds } => {
                assert_eq!(path, "/tmp/x.pcap");
                assert_eq!(seconds, None);
            }
            other => panic!("expected DebugCapture, got {other:?}"),
        }
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
    fn id_token_request_response_round_trip() {
        // `id_token` discriminant + the IdToken(token) reply must survive the wire (CLI and daemon
        // are separate processes agreeing only on this JSON). The audience round-trips on the request.
        let req = Request::IdToken {
            audience: "https://example.com".into(),
        };
        let rj = serde_json::to_string(&req).unwrap();
        assert!(
            rj.contains(r#""cmd":"id_token""#),
            "snake_case discriminant: {rj}"
        );
        match serde_json::from_str::<Request>(&rj).unwrap() {
            Request::IdToken { audience } => assert_eq!(audience, "https://example.com"),
            other => panic!("expected IdToken, got {other:?}"),
        }
        let resp = Response::IdToken {
            token: "header.payload.sig".into(),
        };
        let pj = serde_json::to_string(&resp).unwrap();
        assert!(
            pj.contains(r#""kind":"id_token""#),
            "response discriminant locked: {pj}"
        );
        match serde_json::from_str::<Response>(&pj).unwrap() {
            Response::IdToken { token } => assert_eq!(token, "header.payload.sig"),
            other => panic!("expected IdToken, got {other:?}"),
        }
    }

    #[test]
    fn bug_report_request_wire_is_back_compatible() {
        // `BugReport` changed from a unit variant to `{ note: Option<String> }`. This LOCKS the wire
        // back-compat both ways (the riskiest part of that change): a no-note request must serialize
        // BYTE-IDENTICAL to the old bare unit variant (`skip_serializing_if` is what makes this hold —
        // no `"note":null`), and the old bare JSON must still deserialize (→ note: None). Mirrors the
        // per-variant wire-lock convention every sibling request already follows.
        assert_eq!(
            serde_json::to_string(&Request::BugReport { note: None }).unwrap(),
            r#"{"cmd":"bug_report"}"#,
            "no-note must be byte-identical to the old unit variant's wire form"
        );
        // Old client's bare JSON → new struct variant with note: None (forward-compat).
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"bug_report"}"#).unwrap(),
            Request::BugReport { note: None }
        ));
        // With a note, the field is present on the wire and round-trips.
        assert_eq!(
            serde_json::to_string(&Request::BugReport {
                note: Some("dns broke".into())
            })
            .unwrap(),
            r#"{"cmd":"bug_report","note":"dns broke"}"#
        );
        match serde_json::from_str::<Request>(r#"{"cmd":"bug_report","note":"x"}"#).unwrap() {
            Request::BugReport { note } => assert_eq!(note.as_deref(), Some("x")),
            other => panic!("expected BugReport, got {other:?}"),
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
    fn dns_status_request_response_round_trip() {
        // `dns_status` discriminant + the DnsStatus(DnsStatusReport) reply must survive the wire
        // (the CLI and daemon are separate processes agreeing only on this JSON format).
        assert_eq!(
            serde_json::to_string(&Request::DnsStatus).unwrap(),
            r#"{"cmd":"dns_status"}"#
        );
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"dns_status"}"#).unwrap(),
            Request::DnsStatus
        ));
        let report = DnsStatusReport {
            magic_dns: true,
            search_domains: vec!["user.ts.net".into()],
            resolvers: vec!["100.100.100.100:53".into()],
            routes: std::collections::BTreeMap::from([(
                "corp.example.com".to_string(),
                vec!["10.0.0.53:53".to_string()],
            )]),
            fallback_resolvers: vec!["1.1.1.1:53".into()],
            cert_domains: vec!["host.user.ts.net".into()],
            extra_records: vec![("printer.user.ts.net".into(), "100.64.0.7".into())],
            exit_node_filtered_set: vec![".internal".into()],
        };
        let resp = Response::DnsStatus(report.clone());
        let json = serde_json::to_string(&resp).unwrap();
        match serde_json::from_str::<Response>(&json).unwrap() {
            Response::DnsStatus(r) => assert_eq!(r, report),
            other => panic!("expected DnsStatus, got {other:?}"),
        }
        // The empty/no-netmap report (every field default) round-trips too, and its empty
        // collections are omitted from the wire (skip_serializing_if), with `magic_dns` present.
        let empty = Response::DnsStatus(DnsStatusReport::default());
        let empty_json = serde_json::to_string(&empty).unwrap();
        assert!(
            !empty_json.contains("search_domains"),
            "empty collections must be omitted: {empty_json}"
        );
        assert!(
            !empty_json.contains("resolvers"),
            "empty collections must be omitted: {empty_json}"
        );
        match serde_json::from_str::<Response>(&empty_json).unwrap() {
            Response::DnsStatus(r) => assert_eq!(r, DnsStatusReport::default()),
            other => panic!("expected DnsStatus, got {other:?}"),
        }
    }

    #[test]
    fn cert_request_response_round_trip() {
        // The `cert` request (carrying the domain) and the `Cert { cert_pem, key_pem }` reply must
        // survive the wire intact — the CLI writes the PEMs the daemon issued, so neither may be
        // mangled or truncated. Pin the request discriminant + field and the reply's two PEM bodies.
        let req = Request::Cert {
            domain: "host.user.ts.net".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains(r#""cmd":"cert""#) && json.contains(r#""domain":"host.user.ts.net""#),
            "{json}"
        );
        match serde_json::from_str::<Request>(&json).unwrap() {
            Request::Cert { domain } => assert_eq!(domain, "host.user.ts.net"),
            other => panic!("expected Cert, got {other:?}"),
        }
        let resp = Response::Cert {
            cert_pem: "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----\n".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----\n".into(),
        };
        let rjson = serde_json::to_string(&resp).unwrap();
        match serde_json::from_str::<Response>(&rjson).unwrap() {
            Response::Cert { cert_pem, key_pem } => {
                assert!(cert_pem.contains("BEGIN CERTIFICATE"), "{cert_pem}");
                assert!(key_pem.contains("BEGIN PRIVATE KEY"), "{key_pem}");
            }
            other => panic!("expected Cert, got {other:?}"),
        }
    }

    #[test]
    fn whois_report_round_trips_with_tags_and_expiry() {
        // The enriched whois reply (ACL tags + node-key expiry) must survive the wire (CLI and daemon
        // are separate processes agreeing only on this JSON), and the new fields must be
        // backward-compatible: an old wire omitting them deserializes to empty/None, and empty fields
        // are omitted from the serialized JSON (skip_serializing_if).
        let report = WhoisReport {
            found: true,
            node_name: Some("peer-b.example.ts.net".into()),
            node_ipv4: Some("100.64.0.2".into()),
            user: None,
            capabilities: vec!["funnel".into()],
            cap_map: std::collections::BTreeMap::from([(
                "https://tailscale.com/cap/file-sharing".to_string(),
                vec![r#"{"foo":1}"#.to_string()],
            )]),
            tags: vec!["tag:server".into(), "tag:ci".into()],
            node_key_expiry: Some("2026-09-01 12:00:00 UTC".into()),
            online: Some(false),
            last_seen: Some("2026-06-11 05:19:14 UTC".into()),
        };
        let json = serde_json::to_string(&Response::Whois(report.clone())).unwrap();
        match serde_json::from_str::<Response>(&json).unwrap() {
            Response::Whois(r) => {
                assert_eq!(r.tags, report.tags, "tags must round-trip");
                assert_eq!(
                    r.node_key_expiry, report.node_key_expiry,
                    "node_key_expiry must round-trip"
                );
                assert_eq!(r.online, report.online, "online must round-trip");
                assert_eq!(r.last_seen, report.last_seen, "last_seen must round-trip");
                assert_eq!(r.capabilities, report.capabilities);
                assert_eq!(r.cap_map, report.cap_map, "cap_map must round-trip");
                assert_eq!(r.node_name, report.node_name);
            }
            other => panic!("expected Whois, got {other:?}"),
        }

        // Back-compat: an old wire with NO tags / node_key_expiry / online / last_seen keys still
        // parses, defaulting to empty Vec / None (a whois never invents data control did not send).
        let old_wire =
            r#"{"kind":"whois","found":true,"node_name":"peer-b","node_ipv4":"100.64.0.2"}"#;
        match serde_json::from_str::<Response>(old_wire).expect("old wire parses") {
            Response::Whois(r) => {
                assert!(r.tags.is_empty(), "omitted tags default to empty");
                assert!(
                    r.node_key_expiry.is_none(),
                    "omitted node_key_expiry defaults to None"
                );
                assert!(r.online.is_none(), "omitted online defaults to None");
                assert!(r.last_seen.is_none(), "omitted last_seen defaults to None");
                assert!(r.cap_map.is_empty(), "omitted cap_map defaults to empty");
            }
            other => panic!("expected Whois, got {other:?}"),
        }

        // Empty fields are omitted from the wire (skip_serializing_if) — no `"tags":[]` noise.
        let empty_json = serde_json::to_string(&Response::Whois(WhoisReport {
            found: false,
            ..Default::default()
        }))
        .unwrap();
        // Quoted-key checks (not bare substrings) so this stays correct even if a future field name
        // happens to contain one of these as a substring.
        assert!(
            !empty_json.contains("\"tags\"")
                && !empty_json.contains("\"node_key_expiry\"")
                && !empty_json.contains("\"online\"")
                && !empty_json.contains("\"last_seen\"")
                && !empty_json.contains("\"cap_map\""),
            "empty optional fields must be omitted from the wire: {empty_json}"
        );
    }

    #[test]
    fn prefs_view_tolerates_omitted_fields_on_the_wire() {
        // Wire-compat: the container-level `#[serde(default)]` makes every PrefsView field omittable,
        // so an older/partial JSON projection that omits the previously-non-defaulted fields
        // (`advertise_exit_node`, `accept_routes`, `ssh`, `tun`, and the bools that only had a
        // field-level default) deserializes to PrefsView::default() instead of hard-erroring. This
        // fails if the container default is removed (a missing non-defaulted field would error).

        // (1) The empty document parses entirely to defaults.
        let empty = serde_json::from_str::<PrefsView>(r#"{}"#)
            .expect("an empty PrefsView document must parse with the container default");
        assert_eq!(empty.exit_node, None, "omitted exit_node defaults to None");
        assert!(
            !empty.advertise_exit_node,
            "omitted advertise_exit_node defaults to false"
        );
        assert!(
            empty.advertise_routes.is_empty(),
            "omitted advertise_routes defaults to empty"
        );
        assert!(
            empty.advertise_tags.is_empty(),
            "omitted advertise_tags defaults to empty"
        );
        assert!(
            !empty.accept_routes,
            "omitted accept_routes defaults to false"
        );
        assert!(!empty.shields_up, "omitted shields_up defaults to false");
        assert!(!empty.ssh, "omitted ssh defaults to false");
        assert!(!empty.ssh_running, "omitted ssh_running defaults to false");
        assert!(!empty.tun, "omitted tun defaults to false");

        // (2) A partial document sets the present fields and defaults the omitted ones — in
        //     particular the previously-non-defaulted `tun`/`ssh`/`advertise_exit_node` are absent
        //     yet still parse.
        let partial =
            serde_json::from_str::<PrefsView>(r#"{"accept_routes":true,"shields_up":true}"#)
                .expect("a partial PrefsView document must parse");
        assert!(partial.accept_routes, "present accept_routes is honored");
        assert!(partial.shields_up, "present shields_up is honored");
        assert!(
            !partial.advertise_exit_node,
            "omitted advertise_exit_node still defaults to false"
        );
        assert!(!partial.ssh, "omitted ssh still defaults to false");
        assert!(!partial.tun, "omitted tun still defaults to false");
    }

    #[test]
    fn status_report_tolerates_omitted_fields_on_the_wire() {
        // Wire-compat: the container-level `#[serde(default)]` makes every StatusReport field
        // omittable, so a JSON status line that omits the previously-non-defaulted fields
        // (`want_running`, `peers`, and the nested `prefs`) deserializes to StatusReport::default()
        // instead of hard-erroring. This fails if the container default is removed.

        // (1) The empty document parses entirely to defaults (including the nested PrefsView).
        let empty = serde_json::from_str::<StatusReport>(r#"{}"#)
            .expect("an empty StatusReport document must parse with the container default");
        assert_eq!(empty.state, "", "omitted state defaults to empty");
        assert!(
            !empty.want_running,
            "omitted want_running defaults to false"
        );
        assert_eq!(empty.self_ipv4, None, "omitted self_ipv4 defaults to None");
        assert_eq!(empty.auth_url, None, "omitted auth_url defaults to None");
        assert_eq!(empty.error, None, "omitted error defaults to None");
        assert!(empty.peers.is_empty(), "omitted peers defaults to empty");
        assert_eq!(empty.version, None, "omitted version defaults to None");
        assert!(
            !empty.have_node_key,
            "omitted have_node_key defaults to false"
        );
        // The nested `prefs` also defaults (PrefsView does not derive PartialEq, so check a field).
        assert_eq!(
            empty.prefs.exit_node, None,
            "omitted prefs defaults to PrefsView::default()"
        );
        assert!(
            !empty.prefs.accept_routes,
            "omitted prefs defaults to PrefsView::default()"
        );

        // (2) A partial document with only the IPN state still parses, defaulting the rest — the
        //     previously-non-defaulted `want_running`/`peers` are absent yet do not error.
        let partial = serde_json::from_str::<StatusReport>(r#"{"state":"Running"}"#)
            .expect("a partial StatusReport document must parse");
        assert_eq!(partial.state, "Running", "present state is honored");
        assert!(
            !partial.want_running,
            "omitted want_running still defaults to false"
        );
        assert!(
            partial.peers.is_empty(),
            "omitted peers still defaults to empty"
        );
    }

    #[test]
    fn netcheck_request_response_round_trip() {
        // `netcheck` discriminant + the Netcheck(NetcheckReport) reply must survive the wire (the CLI
        // and daemon are separate processes agreeing only on this JSON format).
        assert_eq!(
            serde_json::to_string(&Request::Netcheck).unwrap(),
            r#"{"cmd":"netcheck"}"#
        );
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"netcheck"}"#).unwrap(),
            Request::Netcheck
        ));
        let report = NetcheckReport {
            preferred_derp: Some(1),
            region_latencies: vec![
                RegionLatencyView {
                    region_id: 1,
                    latency_ms: 23.4,
                },
                RegionLatencyView {
                    region_id: 2,
                    latency_ms: 41.7,
                },
            ],
        };
        let resp = Response::Netcheck(report.clone());
        let json = serde_json::to_string(&resp).unwrap();
        match serde_json::from_str::<Response>(&json).unwrap() {
            Response::Netcheck(r) => assert_eq!(r, report),
            other => panic!("expected Netcheck, got {other:?}"),
        }
        // The empty/pre-measurement report (every field default) round-trips too, and its empty
        // collection + None preferred are omitted from the wire (skip_serializing_if).
        let empty = Response::Netcheck(NetcheckReport::default());
        let empty_json = serde_json::to_string(&empty).unwrap();
        assert!(
            !empty_json.contains("preferred_derp"),
            "None preferred_derp must be omitted: {empty_json}"
        );
        assert!(
            !empty_json.contains("region_latencies"),
            "empty region_latencies must be omitted: {empty_json}"
        );
        match serde_json::from_str::<Response>(&empty_json).unwrap() {
            Response::Netcheck(r) => assert_eq!(r, NetcheckReport::default()),
            other => panic!("expected Netcheck, got {other:?}"),
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
            self_ipv6: None,
            active_exit_node: None,
            magic_dns_suffix: None,
            peers: vec![PeerReport {
                name: "peer-b".to_string(),
                ipv4: "100.64.0.2".to_string(),
                is_exit_node: true,
                ..Default::default()
            }],
            version: None,
            have_node_key: false,
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
            self_ipv6: None,
            active_exit_node: None,
            magic_dns_suffix: None,
            peers: vec![],
            version: None,
            have_node_key: false,
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
            self_ipv6: None,
            active_exit_node: None,
            magic_dns_suffix: None,
            peers: vec![],
            version: None,
            have_node_key: false,
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
            self_ipv6: None,
            active_exit_node: None,
            magic_dns_suffix: None,
            peers: vec![],
            version: None,
            have_node_key: false,
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
            self_ipv6: None,
            active_exit_node: None,
            magic_dns_suffix: None,
            peers: vec![],
            version: None,
            have_node_key: false,
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
            self_ipv6: None,
            active_exit_node: None,
            magic_dns_suffix: None,
            peers: vec![],
            version: None,
            have_node_key: false,
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
            accept_dns: None,
            shields_up: None,
            ssh: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
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
                accept_dns,
                shields_up,
                ssh,
                reset,
                force_reauth: _,
                ephemeral: _,
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
                assert!(accept_dns.is_none());
                assert!(shields_up.is_none());
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
            accept_dns: None,
            shields_up: None,
            ssh: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
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
    fn request_up_force_reauth_round_trips_and_back_compat() {
        // (1) BACK-COMPAT: an old client that omits `force_reauth` must still parse, defaulting it to
        // false (`#[serde(default)]`). A force-reauth must NEVER be silently inferred from an old wire.
        let old_wire = r#"{"cmd":"up","authkey":null,"hostname":"h"}"#;
        let parsed = serde_json::from_str::<Request>(old_wire).expect("old wire parses");
        match parsed {
            Request::Up { force_reauth, .. } => assert!(
                !force_reauth,
                "omitted force_reauth must default to false (never infer a reauth)"
            ),
            other => panic!("expected Up, got {other:?}"),
        }

        // (2) ROUND-TRIP: force_reauth:true survives serialize→deserialize.
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
            accept_dns: None,
            shields_up: None,
            ssh: None,
            reset: false,
            force_reauth: true,
            ephemeral: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        match serde_json::from_str::<Request>(&json).unwrap() {
            Request::Up { force_reauth, .. } => {
                assert!(force_reauth, "force_reauth:true must round-trip")
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
            accept_dns: None,
            shields_up: None,
            ssh: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
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
            accept_dns: None,
            shields_up: None,
            ssh: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
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
            accept_dns: None,
            shields_up: None,
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
            accept_dns: None,
            shields_up: None,
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
