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
    /// Stream node updates over a long-lived connection (the analogue of `tailscale status --watch`
    /// and `tailscale debug watch-ipn-bus`), not a one-shot. Read-only — gated identically to
    /// [`Status`](Request::Status).
    ///
    /// ## Two wire-compatible shapes on one verb (the back-compat contract)
    ///
    /// `watch` is **dual-path**, switched purely by whether any mask field below is set:
    ///
    /// - **Bare** (`{"cmd":"watch"}`, every mask field `false`/omitted) → the daemon streams
    ///   [`Response::Status`] frames: an initial [`StatusReport`] then one more on every
    ///   connection-state transition. This is the *unchanged* legacy path `tnet status --watch`
    ///   speaks. The [`skip_serializing_if`](serde) attributes on the mask fields drop them when
    ///   `false`, so a freshly-constructed bare watch still serializes to *exactly* `{"cmd":"watch"}`
    ///   — byte-for-byte what older clients/daemons send and expect (pinned by the
    ///   `request_watch_wire_format` test).
    /// - **Masked** (any field `true`) → the daemon instead streams [`Response::Notify`] frames built
    ///   on the engine's IPN bus ([`Device::watch_ipn_bus`](tailscale::Device::watch_ipn_bus)) — the
    ///   faithful analogue of Go's `WatchNotifications` with a `NotifyWatchOpt` mask. Each [`NotifyView`]
    ///   carries only the fields that changed (Go's nil-means-unchanged semantics).
    ///
    /// Keeping both on one `cmd` (rather than minting a second verb) mirrors Go, where the single
    /// `WatchIPNBus` LocalAPI route takes the mask as a parameter; the mask *is* the path selector.
    Watch {
        /// Front-load the current connection state (and, in `NeedsLogin`, the auth URL as
        /// [`NotifyView::browse_to_url`]) as the first [`Response::Notify`] frame. The faithful
        /// analogue of Go's `ipn.NotifyInitialState` (`1 << 1`), threaded through to the engine's
        /// [`NotifyWatchOpt::INITIAL_STATE`](tailscale::NotifyWatchOpt::INITIAL_STATE). `#[serde(default)]`
        /// makes it `false` when omitted (so a bare watch still parses); `skip_serializing_if` drops it
        /// from the wire when `false`, preserving the exact `{"cmd":"watch"}` legacy encoding.
        #[serde(default, skip_serializing_if = "core::ops::Not::not")]
        initial_state: bool,
        /// Front-load the current peer set as the first [`Response::Notify`] frame's
        /// [`NotifyView::net_map`]. The faithful analogue of Go's `ipn.NotifyInitialNetMap` (`1 << 3`),
        /// threaded through to the engine's [`NotifyWatchOpt::INITIAL_NETMAP`](tailscale::NotifyWatchOpt::INITIAL_NETMAP).
        /// Same `#[serde(default)]` + `skip_serializing_if` back-compat discipline as
        /// [`initial_state`](Request::Watch::initial_state).
        #[serde(default, skip_serializing_if = "core::ops::Not::not")]
        initial_netmap: bool,
        /// Stream the node's prefs as [`NotifyView::prefs`]: a front-loaded snapshot on subscribe,
        /// then a fresh frame on every prefs change (`up`/`set`/`logout`/`switch`/`reload-config`).
        /// The faithful analogue of Go's `ipn.NotifyInitialPrefs` + ongoing `Notify.Prefs`. Unlike
        /// `initial_state`/`initial_netmap` this is **daemon-built**, not an engine `NotifyWatchOpt`
        /// bit — this fork's prefs are daemon-owned (the engine has no prefs cell), so the daemon
        /// broadcasts them from its own `persist_prefs` chokepoint. Same `#[serde(default)]` +
        /// `skip_serializing_if` back-compat discipline (a bare watch stays `{"cmd":"watch"}`).
        #[serde(default, skip_serializing_if = "core::ops::Not::not")]
        prefs: bool,
    },
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
        /// Operator: the OS username allowed to drive the daemon without root (Go `tailscale up
        /// --operator`). Double `Option` with `double_option` for the same reason as
        /// [`exit_node`](Request::Up::exit_node): an ABSENT key is "unchanged" (`None`) while a
        /// present `null` is "clear the operator" (`Some(None)`), which a plain `#[serde(default)]`
        /// would collapse into a silent no-op.
        #[serde(
            default,
            with = "::serde_with::rust::double_option",
            skip_serializing_if = "Option::is_none"
        )]
        operator: Option<Option<String>>,
        /// Allow a peer using this node as an exit node to reach this node's local LAN (Go
        /// `tailscale up --exit-node-allow-lan-access`). `None` unchanged; `Some(b)` sets it.
        #[serde(default)]
        exit_node_allow_lan_access: Option<bool>,
        /// Advertise this node as an app connector (Go `tailscale up --advertise-connector`). `None`
        /// unchanged; `Some(b)` sets it.
        #[serde(default)]
        advertise_connector: Option<bool>,
        /// Allow the management plane to gather device-posture information (Go `tailscale up
        /// --report-posture`). `None` unchanged; `Some(b)` sets it.
        #[serde(default)]
        report_posture: Option<bool>,
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
        /// Workload-identity-federation (WIF) / OAuth registration credentials (Go `tailscale up
        /// --client-id/--client-secret/--id-token/--audience`). Like [`authkey`](Request::Up::authkey)
        /// these are **registration-time-only and NOT prefs** (Go marks them "prefless"): the engine
        /// exchanges an OAuth client secret or an IdP-issued OIDC token for a real auth key during
        /// registration (engine `identity-federation` feature), and nothing is persisted. They are
        /// carried on the wire only when the operator passes them, exposed once from the CLI's
        /// `SecretString`s. Precedence mirrors Go: an explicit `authkey` wins, else `client_secret`
        /// (used as the OAuth secret), else the WIF `id_token`/`audience` exchange. All four default to
        /// absent and `#[serde(default)]` keeps the wire backward-compatible. The daemon refuses them
        /// with a clear error unless built with the `identity-federation` feature (never silently
        /// ignored — honest-omission). `client_secret`/`id_token` are secrets; the CLI holds them in
        /// `SecretString` and the daemon hands them straight to the engine without logging.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_secret: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id_token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
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
        /// Advertise this node as an app connector (Go `tailscale set --advertise-connector`). `None`
        /// unchanged; `Some(b)` sets it. Reaches control via `Hostinfo.AppConnector`, so changing it
        /// on a running node rebuilds the device (a brief reconnect).
        #[serde(default)]
        advertise_connector: Option<bool>,
        /// Accept admin-console-triggered auto-updates (Go `tailscale set --auto-update`). `None`
        /// unchanged; `Some(b)` sets it. Reaches control via `Hostinfo.AllowsUpdate`, so changing it
        /// on a running node rebuilds the device (a brief reconnect).
        #[serde(default)]
        auto_update: Option<bool>,
        /// Check for available updates in the background (Go `tailscale set --update-check`). `None`
        /// unchanged; `Some(b)` sets it.
        #[serde(default)]
        update_check: Option<bool>,
        /// Operator username (Go `tailscale set --operator`). Double `Option`, same encoding as
        /// [`Up`](Request::Up)'s: absent = unchanged, `null` = clear, value = set.
        #[serde(
            default,
            with = "::serde_with::rust::double_option",
            skip_serializing_if = "Option::is_none"
        )]
        operator: Option<Option<String>>,
        /// Login-profile nickname (Go `tailscale set --nickname`). Double `Option`: absent =
        /// unchanged, `null` = clear, value = set.
        #[serde(
            default,
            with = "::serde_with::rust::double_option",
            skip_serializing_if = "Option::is_none"
        )]
        nickname: Option<Option<String>>,
        /// Allow the management plane to gather device-posture information (Go `tailscale set
        /// --report-posture`). `None` unchanged; `Some(b)` sets it.
        #[serde(default)]
        report_posture: Option<bool>,
        /// Run the local web client (Go `tailscale set --webclient`). `None` unchanged; `Some(b)`
        /// sets it.
        #[serde(default)]
        webclient: Option<bool>,
        /// Allow a peer using this node as an exit node to reach this node's local LAN (Go
        /// `tailscale set --exit-node-allow-lan-access`). `None` unchanged; `Some(b)` sets it.
        #[serde(default)]
        exit_node_allow_lan_access: Option<bool>,
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
    /// Read the Tailnet Lock update-chain history (Go `tailscale lock log`, i.e. Go
    /// `LocalClient.NetworkLockLog`). Replies with [`Response::LockLog`]. Read-only — gated like
    /// [`Status`](Request::Status): the engine reads the node's already-synced + verified AUM chain
    /// locally, with no control round-trip and no mutation. `limit` caps how many entries come back,
    /// counted from the chain head (newest) backwards; the CLI defaults it to Go's `--limit` default
    /// of 50.
    LockLog { limit: usize },
    /// Initialize Tailnet Lock with this node as the sole initial trusted key (Go `tailscale lock
    /// init`, single-node case). Submits the signed genesis to control; replies with
    /// [`Response::Ok`]/[`Response::Error`]. A **write** — gated like `up`/`down` (root/same-uid): it
    /// establishes tailnet-wide trust. Requires the node to be up. `secret_hex` is the hex-encoded
    /// disablement secret the lock is gated with (the daemon decodes it to the bytes `tka_init` takes);
    /// operator-supplied, never logged.
    LockInit { secret_hex: String },
    /// Co-sign a node key into Tailnet Lock (Go `tailscale lock sign`). Submits the signature to
    /// control over the engine's TKA mutation RPC; replies with [`Response::Ok`]/[`Response::Error`].
    /// A **write** — gated like `up`/`down` (root/same-uid): it mutates tailnet-wide trust. Requires
    /// the node to be up. `node_key` is the `nodekey:<hex>` form (the daemon parses it to the engine's
    /// `NodePublicKey`).
    LockSign { node_key: String },
    /// Disable Tailnet Lock for the tailnet by presenting the disablement secret (Go `tailscale lock
    /// disable`). Submits to control; replies with [`Response::Ok`]/[`Response::Error`]. A **write**,
    /// and a tailnet-wide irreversible one — gated like `up`/`down`. Requires the node to be up.
    /// `secret_hex` is the hex-encoded disablement secret (the daemon decodes it to the raw bytes the
    /// engine's `tka_disable` expects). The secret is operator-supplied; it is never logged.
    LockDisable { secret_hex: String },
    /// Report the control-pushed MagicDNS configuration (Go `tailscale dns status`). Replies with
    /// [`Response::DnsStatus`]. Read-only — gated like [`Status`](Request::Status). Requires the node
    /// to be up (the config comes from the live engine's netmap).
    DnsStatus,
    /// Resolve a name through the node's own MagicDNS path (Go `tailscale dns query`). Replies with
    /// [`Response::DnsQuery`]. Read-only — gated like [`Status`](Request::Status). Requires the node
    /// to be up (the query runs through the live engine's MagicDNS forwarder). `qtype` is the numeric
    /// RFC 1035 TYPE (the CLI maps the name → number); the daemon passes it straight to the engine.
    DnsQuery {
        /// The DNS name to resolve.
        name: String,
        /// The numeric DNS query type (1=A, 28=AAAA, 12=PTR, …).
        qtype: u16,
    },
    /// Report this node's network-conditions report (Go `tailscale netcheck`). Replies with
    /// [`Response::Netcheck`]. Read-only — gated like [`Status`](Request::Status). Requires the node
    /// to be up (the measurements come from the live engine's net-report). NOTE: this fork's
    /// net-report measures ONLY DERP-region latency (see [`NetcheckReport`]).
    Netcheck,
    /// Ask the daemon to suggest the best available exit node (Go `tailscale exit-node suggest` →
    /// `LocalClient.SuggestExitNode`). Replies with [`Response::ExitNodeSuggestion`] carrying the
    /// suggested node (or `None` when there is no eligible candidate — NOT an error, mirroring Go's
    /// empty response). Read-only — it computes a suggestion from the netmap + latency, mutating
    /// nothing (gated like [`Status`](Request::Status)). Requires the node to be up.
    SuggestExitNode,
    /// Report the Tailscale **Services** (VIPs) this node can reach (Go `tailscale service list` →
    /// the LocalAPI `services` verb). Replies with [`Response::Services`]. Read-only — Go's
    /// `serveServices` is a GET that only reads the netmap, so this is classified like
    /// [`Status`](Request::Status). Requires the node to be up: the Service set is decoded from the
    /// **self node's** capability map, which only exists once control has sent a netmap (Go's handler
    /// answers `503 no netmap` in the same situation).
    Services,
    /// Report the effective system policy / MDM configuration (Go `tailscale syspolicy list`).
    /// Replies with [`Response::Policy`]. Read-only — Go gates BOTH `list` and `reload` on
    /// `PermitRead` (the LocalAPI `policy/` handler checks only `PermitRead`), so this is classified
    /// like [`Status`](Request::Status). Node-up-independent: policy resolution reads OS/registered
    /// policy stores, not the netmap, so it works whether or not the node is up. On a Linux/Unix host
    /// no policy store is registered, so the reply is an empty-but-valid snapshot (the CLI prints "No
    /// policy settings") — matching Go's runtime behavior on those platforms.
    SyspolicyList,
    /// Force a re-read + re-merge of the effective system policy (Go `tailscale syspolicy reload`).
    /// Replies with [`Response::Policy`]. Despite being a "reload", it mutates **no node state** — it
    /// re-reads the external policy sources — so Go gates it on `PermitRead` (same handler as
    /// `list`), and this is classified read-only like [`SyspolicyList`](Request::SyspolicyList). With
    /// no registered policy store (Linux/Unix) the forced re-read re-merges zero sources and yields
    /// the same empty snapshot as `list`.
    SyspolicyReload,
    /// Check whether the OS is configured to forward IP traffic — a subnet-router / exit-node
    /// readiness diagnostic (Go `tailscale`'s `check-ip-forwarding` LocalAPI, called by `up`/`set` on
    /// the advertise-routes path). Replies with [`Response::IpForwardingCheck`] carrying a `warning`
    /// string (empty = all good). Read-only — gated like [`Status`](Request::Status); node-up
    /// independent (it reads OS sysctls, not the netmap). FAITHFUL OS-SPECIFICITY (matches Go): in
    /// netstack mode there is nothing to check (the kernel does not forward — userspace does), so the
    /// warning is always empty; on Linux with a kernel TUN it reads `/proc/sys/net/ipv4/ip_forward`
    /// and `/proc/sys/net/ipv6/conf/all/forwarding`; on macOS/other it is a no-op (empty), exactly as
    /// Go's `netutil.CheckIPForwarding` returns `nil` off Linux/BSD.
    CheckIpForwarding,
    /// Validate a prospective set of prefs WITHOUT applying them (Go `tailscale`'s `check-prefs`
    /// LocalAPI → `LocalBackend.CheckPrefs`, called by `up`/`set` to fail fast). Replies with
    /// [`Response::Ok`] on success or [`Response::Error`] naming the violation(s). A **write** (Go
    /// gates `serveCheckPrefs` on `PermitWrite`), but it MUTATES NOTHING — it only runs the same
    /// validation the bring-up path would. This fork mirrors the subset of Go's rule chain that maps
    /// to its prefs: the exit-node-vs-advertise-exit-node conflict, SSH-server capability, and
    /// advertise-route CIDR masking (Go's operator/auto-update/profile/config-lock rules reference
    /// prefs this fork does not model). The fields are the same "leave unchanged unless named"
    /// sentinels as [`Set`](Request::Set) — a check validates the prospective combined posture.
    CheckPrefs {
        /// Prospective exit-node selector (same double-option semantics as [`Set::exit_node`]).
        #[serde(
            default,
            with = "::serde_with::rust::double_option",
            skip_serializing_if = "Option::is_none"
        )]
        exit_node: Option<Option<String>>,
        /// Prospective advertise-exit-node intent.
        #[serde(default)]
        advertise_exit_node: Option<bool>,
        /// Prospective advertised subnet routes (CIDRs).
        #[serde(default)]
        advertise_routes: Option<Vec<String>>,
        /// Prospective SSH-server enable intent.
        #[serde(default)]
        ssh: Option<bool>,
    },
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
        /// The caller's minimum acceptable remaining validity, in whole seconds (Go `tailscale cert
        /// --min-validity`, which reaches Go's daemon as the `min_validity` query parameter of
        /// `LocalClient.CertPairWithValidity`). `None` = no minimum (Go's zero duration), which is
        /// what an older client that omits the field sends.
        ///
        /// HONEST SCOPE: Go renews a *cached* cert when less than this much of its lifetime remains.
        /// This fork's engine keeps no cert cache — every call issues fresh — so the engine accepts
        /// the value for signature compatibility and a freshly issued (full-lifetime) cert satisfies
        /// any minimum. The field is wired end to end rather than dropped at the CLI so the day the
        /// engine grows a cache, the operator's request is already arriving here.
        ///
        /// Whole seconds: an ACME certificate's lifetime is measured in days, so sub-second
        /// precision would be noise on the wire (the CLI parses Go's duration grammar and floors).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min_validity_secs: Option<u64>,
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
        /// Run the extra diagnostic pass (Go `bugreport --diagnose` →
        /// `ipn.BugReportOpts.Diagnose` → `LocalBackend.Doctor`). The daemon then fills
        /// [`Response::BugReport::checks`]; the marker itself is unaffected. `false` (the default)
        /// keeps the wire byte-identical to a request from a client that predates the flag.
        #[serde(default, skip_serializing_if = "core::ops::Not::not")]
        diagnose: bool,
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
    ///
    /// The `Ok` message distinguishes the three outcomes Go's CLI reports in words: already on this
    /// profile (nothing changed), switched to a profile that still needs a login, and switched to a
    /// registered profile that is merely down.
    SwitchProfile {
        /// The target profile id (or name; the daemon resolves either).
        target: String,
    },
    /// Delete a profile (Go `tailscale switch remove`). The target may be an id or a display name,
    /// like [`SwitchProfile`](Request::SwitchProfile). Refuses a target that matches no known profile
    /// (Go: `No profile named %q`) and the reserved `default` profile. Naming the profile that is
    /// currently active is a **success** that removes nothing, as in Go (`Already on account %q`,
    /// exit 0); the `Ok` message says so. A WRITE — gated like `up`/`down`.
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
    /// Bring the node down (`WantRunning = false`) without logging out. A WRITE — gated like
    /// `up`/`logout`.
    Down {
        /// The operator's justification for the disconnect (Go `tailscale down --reason`, which
        /// travels as the base64 `X-Tailscale-Reason` LocalAPI header on the prefs edit). `None`
        /// when the flag was omitted — which is also what an older client sending the bare
        /// `{"cmd":"down"}` deserializes to.
        ///
        /// Same HONEST SCOPE as [`Logout::reason`](Request::Logout): this fork registers no policy
        /// store that could *require* a justification and the engine has no audit-log transport to
        /// control, so the daemon records the reason in its own log alongside the disconnect and
        /// nothing else consumes it. It is not forwarded to the control plane.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Log the node out (the analogue of Go's `tailscale logout`): deregister the node key with the
    /// control plane, tear the datapath down, and **discard the persisted node key** so the next
    /// `up` re-registers fresh (a new login) rather than resuming the old registration. This is
    /// distinct from [`Down`](Request::Down), which keeps the node key for a seamless resume. A WRITE
    /// — gated like `up`/`down`.
    Logout {
        /// The operator's justification for the logout (Go `tailscale logout --reason`, which travels
        /// as the base64 `X-Tailscale-Reason` LocalAPI header). `None` when the flag was omitted —
        /// which is also what an older client sending the bare `{"cmd":"logout"}` deserializes to.
        ///
        /// HONEST SCOPE: in Go the reason is what lets a user disconnect a node whose MDM policy
        /// requires a justification, and it is recorded in the node's audit log. This fork registers
        /// no policy store on Unix (see [`SyspolicyList`](Request::SyspolicyList)) and the engine has
        /// no audit-log transport to control, so the daemon *records the reason in its own log*
        /// alongside the logout and nothing else consumes it. It is not forwarded to the control
        /// plane.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Report this node's own tailnet addresses (Go `tailscale ip`). Read-only — gated like
    /// [`Status`](Request::Status).
    Ip,
    /// Resolve a tailnet IP to the peer that owns it (Go `tailscale whois`). Read-only.
    ///
    /// Go's argument is `ip[:port]` and its LocalAPI query is `?proto=&addr=`, so the flow triple is
    /// carried here as three fields: the address in [`ip`](Request::Whois::ip), the optional flow
    /// [`port`](Request::Whois::port), and the optional [`proto`](Request::Whois::proto). Both new
    /// fields are `#[serde(default)]`, so a request written by an older CLI (address only) still
    /// deserializes.
    Whois {
        /// The tailnet IP to resolve. Address only — the port travels in [`port`](Request::Whois::port),
        /// the way Go's `serveWhoIs` splits `addr` into a `netip.AddrPort` before the lookup.
        ip: String,
        /// The flow's port, from Go's `ip[:port]` argument form. `None` when the caller named a bare
        /// IP (Go's `netip.AddrPortFrom(ip, 0)`).
        ///
        /// HONEST SCOPE: a whois is a *flow* lookup in Go only for flows tailscaled itself proxies —
        /// `LocalBackend.WhoIs` consults the port (and [`proto`](Request::Whois::proto)) solely in its
        /// `ProxyMapper` fallback, reached when the address matches no node in the netmap. When the
        /// address IS a tailnet address — every address this fork can answer for — Go resolves it by
        /// IP and never looks at the port. The engine's `Device::whois` likewise resolves by IP and
        /// discards the port, so this field records what was asked without changing the answer. The
        /// engine surface a proxied-flow lookup would need is engine ask #35.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        /// The flow's protocol (Go `whois --proto`, `?proto=` on the LocalAPI query). `None` is Go's
        /// empty value: "both". See [`port`](Request::Whois::port) for why this fork records it but
        /// cannot select on it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proto: Option<WhoisProto>,
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
    /// Force the engine to rebind its UDP sockets (Go `tailscale debug rebind`), rendered by
    /// `tnet debug rebind`. A connectivity-recovery knob — tears down and re-creates magicsock's
    /// underlying sockets to clear a wedged NAT binding or recover after a link change, without a
    /// node restart. A **write** (mutates live datapath state): gated like `down`/`logout`. Needs the
    /// node up. Replies with [`Response::Ok`]/[`Response::Error`].
    DebugRebind,
    /// Force an immediate STUN re-probe / endpoint re-derivation WITHOUT rebinding the socket (Go
    /// `tailscale debug restun` → magicsock `Conn.ReSTUN`), rendered by `tnet debug restun`. Strictly
    /// lighter than [`DebugRebind`](Self::DebugRebind): it keeps the existing UDP socket + its NAT
    /// mapping and only re-runs the STUN sweep now (re-learning this node's reflexive/public address)
    /// instead of waiting out the periodic prober — the knob to reach for when the public endpoint may
    /// have changed but the socket is still fine. A **write** (mutates live datapath state): gated like
    /// `down`/`logout`. Needs the node up. Replies with [`Response::Ok`]/[`Response::Error`].
    DebugReStun,
    /// Run a port-mapping diagnostic and stream its log back, one [`Response::PortmapLog`] frame
    /// per line (Go `tailscale debug portmap` → the `debug-portmap` LocalAPI route, served by
    /// `feature/debugportmapper`), rendered by `tnet debug portmap`.
    ///
    /// The daemon probes the LAN gateway for NAT-PMP / PCP / UPnP-IGD support and, if any answers,
    /// asks for a UDP mapping — reporting each step as it happens. This is the one verb on this fork
    /// that STREAMS a reply per line rather than answering once, because the run takes up to
    /// [`duration_ms`](Request::DebugPortmap::duration_ms) and its value is in watching it unfold;
    /// Go streams the same text over a flushed `text/plain` body. The daemon closes the connection
    /// when the run ends.
    ///
    /// A **write** for authorization: Go gates `serveDebugPortmap` on `PermitWrite` ("debug access
    /// denied" otherwise), and the run sends packets to the LAN gateway asking it to open a hole, so
    /// it is gated like `up`/`down` (root/same-uid). Node-up independent — the probe talks to the
    /// local router, not through the tailnet, so it answers with the node down.
    DebugPortmap {
        /// How long the whole run may take, in milliseconds. The CLI parses Go's `--duration`
        /// duration string (`5s`) and sends the resolved milliseconds, so the wire carries a plain
        /// number rather than a Go-specific grammar the daemon would have to re-parse.
        duration_ms: u64,
        /// Which protocol to exercise: `""` (all — the default), `"pmp"`, `"pcp"` or `"upnp"`.
        /// Anything else is refused with [`Response::Error`] carrying Go's `unknown portmap debug
        /// type` (Go answers 400 with that same text).
        #[serde(default)]
        ty: String,
        /// `"<gateway>/<self>"` — override gateway auto-detection with an explicit pair (Go's
        /// `gateway_and_self` query parameter, which its CLI builds from `--gateway-addr` +
        /// `--self-addr`). `None` auto-detects from the host routing table.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gateway_and_self: Option<String>,
        /// Log raw HTTP for the UPnP leg (Go's `--log-http`). Carried for parity; this fork's UPnP
        /// leg is discovery-only, so it currently adds no output.
        #[serde(default)]
        log_http: bool,
    },
    /// Re-read the daemon's `--config` file and adopt the changed fields into the running node (Go
    /// `tailscaled`'s `reload-config` LocalAPI route → `LocalBackend.ReloadConfig` → `setConfigLocked`,
    /// v1.100.0). Rendered by `tnet reload-config`. The daemon re-loads the same declarative config it
    /// was started with, merges it over the prefs (layered — an unset config field leaves its pref
    /// untouched), persists the result, and — if the node is up — rebuilds the running engine from the
    /// updated prefs to actually adopt the change (a brief reconnect, like a rebuild-only `set`); if the
    /// node is down, the merged prefs apply on the next `up`. A **write** — gated like `up`/`down`: Go
    /// gates `serveReloadConfig` on `PermitWrite`, and it reconfigures the running node. Fails with a
    /// clear error when the daemon was started WITHOUT `--config` (there is nothing to reload) or when
    /// the config file is now malformed (rejected with the running node untouched — the fail-fast
    /// contract). Replies with [`Response::Ok`]/[`Response::Error`]. NOTE: a reloaded config's `AuthKey`
    /// is deliberately ignored (a reload is not a re-registration — see the daemon's `reload_config`).
    ReloadConfig,
}

/// The daemon's reply to a [`Request`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    /// A status snapshot.
    Status(StatusReport),
    /// A single IPN-bus notification frame — the streamed reply to a **masked** [`Request::Watch`]
    /// (one with `initial_state`/`initial_netmap` set), the faithful analogue of Go's
    /// `WatchNotifications` feed. Only ever sent on the masked watch path; the bare watch path streams
    /// [`Status`](Response::Status) instead.
    Notify(NotifyView),
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
    /// Tailnet Lock (TKA) update-chain history (reply to [`Request::LockLog`]), rendered by
    /// `tnet lock log`.
    LockLog(LockLogReport),
    /// The control-pushed MagicDNS configuration (reply to [`Request::DnsStatus`]), rendered by
    /// `tnet dns status`.
    DnsStatus(DnsStatusReport),
    /// The outcome of a MagicDNS-path resolution (reply to [`Request::DnsQuery`]), rendered by
    /// `tnet dns query`.
    DnsQuery(DnsQueryReport),
    /// The node's network-conditions report (reply to [`Request::Netcheck`]), rendered by
    /// `tnet netcheck`.
    Netcheck(NetcheckReport),
    /// The suggested exit node (reply to [`Request::SuggestExitNode`]), rendered by `tnet exit-node
    /// suggest`. `suggestion` is `None` when the engine found no eligible candidate — an honest empty
    /// result, not an error (mirroring Go's empty `SuggestExitNode` response). A **struct** variant
    /// (not a newtype over `Option`): the `Response` enum is internally tagged (`tag = "kind"`), which
    /// cannot merge its tag into a bare `Option`/`null` content, so the optional payload is carried as
    /// a named field instead.
    ExitNodeSuggestion {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        suggestion: Option<ExitNodeSuggestionView>,
    },
    /// The Tailscale Services (VIPs) this node can reach (reply to [`Request::Services`]), rendered
    /// by `tnet service list`. Sorted by [`ServiceReport::name`], one entry per Service (Go returns a
    /// `map[tailcfg.ServiceName]tailcfg.ServiceDetails`, which the CLI sorts by name before printing;
    /// sorting daemon-side makes the wire itself deterministic). Empty when control has granted this
    /// node no Services — an honest empty result, not an error. A **struct** variant (not a newtype
    /// over the `Vec`): the `Response` enum is internally tagged (`tag = "kind"`), which cannot merge
    /// its tag into a bare sequence, so the payload is carried as a named field — the same shape
    /// `Files`/`FileTargets` use.
    Services {
        /// One entry per Service this node can reach.
        services: Vec<ServiceReport>,
    },
    /// The effective system policy snapshot (reply to [`Request::SyspolicyList`] /
    /// [`Request::SyspolicyReload`]), rendered by `tnet syspolicy list` / `reload`.
    Policy(PolicyReport),
    /// The OS IP-forwarding readiness result (reply to [`Request::CheckIpForwarding`]). `warning` is
    /// empty when forwarding is fine (or N/A — netstack/macOS); a non-empty string is the
    /// human-readable warning the CLI prints (Go's `{"Warning": "..."}` shape, lower-cased on our
    /// snake_case wire). Mirrors Go's `serveCheckIPForwarding` anonymous `{Warning string}`.
    IpForwardingCheck {
        /// Empty = forwarding OK / not applicable; non-empty = the warning to surface.
        warning: String,
    },
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
        /// The `--diagnose` pass, one `name: detail` line per check, ready to print (see
        /// [`crate::ipn::doctor`]). EMPTY unless the request set
        /// [`diagnose`](Request::BugReport::diagnose) — Go's `Doctor` likewise runs only then.
        /// Returned rather than logged because this fork uploads no logs: the lines are for the
        /// operator to read and paste, not for support to fetch. `#[serde(default)]` + skip keeps
        /// the wire backward-compatible with a client that predates the flag.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        checks: Vec<String>,
    },
    /// The node's serve configuration (reply to [`Request::GetServeConfig`]), rendered by
    /// `tnet serve status`.
    ServeConfig(ServeConfig),
    /// One line of a `debug portmap` run's log (a streamed reply to [`Request::DebugPortmap`]).
    /// The daemon emits these as the run narrates itself and then closes the connection; the CLI
    /// prints each `line` verbatim, so the output is byte-identical to what `tailscale debug
    /// portmap` writes to stdout.
    PortmapLog {
        /// One log line, without its trailing newline.
        line: String,
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

/// The transport protocol of the flow a [`Request::Whois`] asks about — Go `tailscale whois
/// --proto`, documented upstream as `protocol; one of "tcp" or "udp"; empty means both`.
///
/// Go passes the flag's string straight through to `?proto=` unvalidated (an unrecognized value
/// simply matches nothing in its proxied-flow table). This fork parses it into a closed enum
/// instead — see [`FromStr`](WhoisProto::from_str) — because the value can never select anything
/// here (engine ask #35), and a silently-ignored `--proto=TCP` typo would be indistinguishable from
/// a working one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WhoisProto {
    /// Go `--proto=tcp`.
    Tcp,
    /// Go `--proto=udp`.
    Udp,
}

impl std::fmt::Display for WhoisProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

impl std::str::FromStr for WhoisProto {
    type Err = String;

    /// Parse Go's two documented values. Case-sensitive and exact, like every other proto string Go
    /// compares against (`ProxyMapper.WhoIsIPPort` keys its table on the literal `"tcp"`/`"udp"`),
    /// so `TCP` is a refusal rather than a silent alias. The empty string is NOT accepted here: it is
    /// Go's "both", which this fork models as `None` at the call site, not as a variant.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => Err(format!(
                "invalid --proto {other:?}: expected \"tcp\" or \"udp\" (empty means both)"
            )),
        }
    }
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
    /// When the node's key expires, in strict RFC3339 (`2026-09-01T12:00:00+00:00`, via
    /// `DateTime::to_rfc3339` — Go-`ipnstate`-compatible), or `None` if the key has no expiry.
    /// Surfaced so `whois`/`whoami` can show an upcoming/elapsed key expiry (Go carries it in its
    /// `whois --json`). Back-compatible (omitted when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_key_expiry: Option<String>,
    /// The node's liveness: `Some(true)` = control-connected (online), `Some(false)` = offline,
    /// `None` = unknown (the same control-plane signal `status` uses for peers). Back-compatible
    /// (omitted when unknown).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    /// When the node was last seen by control, in strict RFC3339 (`2026-06-11T05:19:14+00:00`, via
    /// `DateTime::to_rfc3339` — Go-`ipnstate`-compatible), or `None` if never/unknown. Like `status`,
    /// this is only *meaningful* (and only rendered) when the node is offline — an online node's
    /// last-seen is "now". Back-compatible (omitted when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
}

/// The effective system-policy snapshot, returned by [`Request::SyspolicyList`] /
/// [`Request::SyspolicyReload`] and rendered by `tnet syspolicy list` / `reload`. The Rust analogue
/// of Go's `util/syspolicy/setting.Snapshot`: a scope plus the merged set of policy settings.
///
/// On a Linux/Unix host no policy store is registered, so [`settings`](PolicyReport::settings) is
/// empty and the CLI prints "No policy settings" — matching Go's runtime behavior (Go registers a
/// store only on Windows). The struct still carries the full shape so a future managed-platform
/// source (or the wire from a host that DID resolve settings) round-trips faithfully.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyReport {
    /// The scope the snapshot was resolved for, as Go's `PolicyScope.String()` spells it — `"Device"`
    /// on every non-Windows host (Go's `setting.DefaultScope()` is the device scope, which is what
    /// the CLI always requests). Carried so the renderer/JSON can show which scope was queried.
    pub scope: String,
    /// The merged policy settings, sorted by key for stable rendering (Go sorts with
    /// `slices.Sorted(policy.Keys())` before printing). Empty on a host with no registered policy
    /// store. Each entry is one resolved policy key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub settings: Vec<PolicySetting>,
}

/// One resolved policy setting inside a [`PolicyReport`] — the Rust analogue of Go's
/// `setting.RawItem` keyed by its policy name. Carries the value, the originating store, and any
/// resolution error, mirroring the four CLI columns (Name / Origin / Value / Error).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySetting {
    /// The policy key (Go `pkey.Key` — e.g. `"LoginURL"`, `"ExitNodeID"`). The "Name" column.
    pub key: String,
    /// The originating policy store, as Go's `Origin.String()` renders it (e.g. `"Platform
    /// (Device)"`), or empty when the setting has no recorded origin. The "Origin" column.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub origin: String,
    /// The resolved value rendered as a string (Go prints the `any` value with `%v`). `None` when the
    /// setting resolved to an error instead of a value (then [`error`](PolicySetting::error) is set).
    /// The "Value" column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// The resolution error for this key, if any (Go prints it wrapped in `{...}` in the "Error"
    /// column). Mutually exclusive with [`value`](PolicySetting::value) in Go's renderer. `None` when
    /// the setting resolved cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One Tailscale **Service** (a VIP service) this node can reach, in a [`Response::Services`] reply.
/// The Rust analogue of Go's `tailcfg.ServiceDetails`, which control delivers to each node as the
/// value of a `services/<opaque>` entry in the **self node's** capability map (Go
/// `tailcfg.NodeAttrPrefixServices`; decoded daemon-side by `ipn::diag::services_from_cap_map`,
/// the port of Go's `netmap.NetworkMap.Services()`).
///
/// A Service is not a peer: it is a virtual service with its own addresses, and which Services a
/// node can see is decided by the tailnet's ACLs. Rendered by `tnet service list`, and consulted by
/// `tnet ip <service-VIP>` (Go `ip.go`'s Service fallback).
///
/// Container-level `#[serde(default)]` so a wire document missing any field deserializes to the
/// [`ServiceReport::default`] value rather than hard-erroring. Not `Eq`: an action's
/// [`attributes`](ServiceActionReport::attributes) carry arbitrary JSON.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceReport {
    /// The Service's canonical name, `svc:<dns-label>` (Go `ServiceDetails.Name`). This is the map
    /// key Go's `services` verb returns, taken from the value's own `Name` field — never parsed out
    /// of the capability key, whose suffix is opaque and server-chosen.
    pub name: String,
    /// An optional human-readable label (Go `ServiceDetails.DisplayName`). Empty when control sent
    /// none; clients fall back to [`name`](ServiceReport::name).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    /// The Service's virtual IP addresses (Go `ServiceDetails.Addrs`), re-rendered from the parsed
    /// address so a differently-spelled literal normalizes. IPv4 first when the tailnet has IPv4
    /// enabled — Go's table prints `Addrs[0]`, which is the v6 address on a v6-only tailnet.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<String>,
    /// The protocol/port combinations the Service accepts (Go `ServiceDetails.Ports`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<ServicePortRange>,
    /// How a client may interact with this Service (Go `ServiceDetails.Actions`). Empty when control
    /// sent none, in which case clients infer the interaction from the ports instead.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ServiceActionReport>,
}

/// One action a client may invoke against a [`ServiceReport`] — the Rust analogue of Go's
/// `tailcfg.ServiceAction`. Drives the TYPE column of `tnet service list`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceActionReport {
    /// The action's type slug (Go `ServiceAction.Type`, e.g. `ssh`, `http`, `postgresql`). Carried as
    /// an opaque string, not an enum: Go tells clients to *ignore* types they do not recognize, so a
    /// type this build has never heard of must survive the wire rather than fail it.
    pub action_type: String,
    /// The target TCP port for this action (Go `ServiceAction.Port`).
    pub port: u16,
    /// An optional label for client menus (Go `ServiceAction.DisplayName`). Empty when absent.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    /// Optional per-action metadata (Go `ServiceAction.Attributes`), keyed by attribute name with the
    /// raw JSON value kept verbatim — this daemon neither interprets nor validates it, exactly as Go
    /// carries `RawMessage`. Preserved so `tnet service list --json` emits what control sent.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub attributes: std::collections::BTreeMap<String, serde_json::Value>,
}

/// A protocol + inclusive port range on a [`ServiceReport`] — the Rust analogue of Go's
/// `tailcfg.ProtoPortRange`.
///
/// On the wire between control and the node this is a **string**, not an object: Go's type
/// implements `encoding.TextMarshaler`, so a Service's `Ports` arrive as `"tcp:443"`, `"udp:1-100"`,
/// `"443"` or `"*"`. The daemon parses that text form once ([`FromStr`]) and hands the CLI the
/// decoded triple, so the renderer can both re-emit Go's spelling ([`Display`]) and answer the
/// question Go's TYPE column asks — "is this a single TCP port?" — without re-parsing strings.
///
/// `proto == 0` means "all protocols" (Go's `int(0)`); otherwise it is an IP protocol number
/// (6 = TCP, 17 = UDP). A `first..=last` span of `0..=65535` means "all ports".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServicePortRange {
    /// IP protocol number (Go `ProtoPortRange.Proto`). `0` = all protocols.
    pub proto: u8,
    /// Inclusive first port (Go `Ports.First`).
    pub first: u16,
    /// Inclusive last port (Go `Ports.Last`).
    pub last: u16,
}

/// Go `ipproto.preferredNames` — the protocol-number → name table `ipproto.Proto.MarshalText` emits
/// and `UnmarshalText` accepts (case-insensitively). Mirrored so a rendered [`ServicePortRange`]
/// matches Go's bytes and a parse accepts every name Go accepts. Numbers absent from the table
/// render as their decimal value, as Go's does.
const PROTO_NAMES: &[(u8, &str)] = &[
    (51, "ah"),
    (33, "dccp"),
    (8, "egp"),
    (50, "esp"),
    (47, "gre"),
    (1, "icmp"),
    (2, "igmp"),
    (9, "igp"),
    (4, "ipv4"),
    (58, "ipv6-icmp"),
    (132, "sctp"),
    (6, "tcp"),
    (17, "udp"),
];

/// The IP protocol number of TCP, the only protocol Go infers a Service action type for.
const PROTO_TCP: u8 = 6;

impl ServicePortRange {
    /// The full `0..=65535` "all ports" span (Go `PortRangeAny`).
    fn ports_is_any(&self) -> bool {
        self.first == 0 && self.last == 65535
    }

    /// Whether this range names exactly one TCP port, and which — the shape Go's
    /// `serviceActionTypes` infers a well-known action from (`Proto` unset or TCP, `First == Last`).
    /// `None` for anything else, which Go skips.
    pub fn single_tcp_port(&self) -> Option<u16> {
        if self.proto != 0 && self.proto != PROTO_TCP {
            return None;
        }
        if self.first != self.last {
            return None;
        }
        Some(self.first)
    }
}

impl std::fmt::Display for ServicePortRange {
    /// Mirrors Go `ProtoPortRange.String()`: `"*"` for all-protocols + all-ports; otherwise
    /// `[<proto>:]<ports>`, where the proto token is present only when `proto != 0` and the ports
    /// token is a single port, `*` for the any-span, or `first-last`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.proto == 0 && self.ports_is_any() {
            return f.write_str("*");
        }
        if self.proto != 0 {
            match PROTO_NAMES.iter().find(|(n, _)| *n == self.proto) {
                Some((_, name)) => write!(f, "{name}:")?,
                None => write!(f, "{}:", self.proto)?,
            }
        }
        if self.ports_is_any() {
            f.write_str("*")
        } else if self.first == self.last {
            write!(f, "{}", self.first)
        } else {
            write!(f, "{}-{}", self.first, self.last)
        }
    }
}

impl std::str::FromStr for ServicePortRange {
    type Err = String;

    /// Parse Go's text form `[<proto>:]<ports>` — the inverse of the [`Display`] impl, ported from
    /// `tailcfg.parseProtoPortRange` + `ParseHostPortRange`.
    ///
    /// Go lower-cases the whole token first, splits on the LAST colon, and treats a colon-less token
    /// as `*:<ports>` (all protocols). `<proto>` is `*` (all), a `PROTO_NAMES` name, or a decimal
    /// number; `<ports>` is `*` (the any span), a single port, or `low-high` with `low <= high`.
    /// Fail-closed: anything else is an error, so a Service carrying a port range this build cannot
    /// read is dropped whole rather than rendered as a guess — which is Go's behaviour too (its
    /// `json.Unmarshal` of the enclosing `ServiceDetails` fails and the Service is skipped).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err("empty string".to_string());
        }
        let lower = s.to_ascii_lowercase();
        if lower == "*" {
            return Ok(Self {
                proto: 0,
                first: 0,
                last: 65535,
            });
        }
        // Go: a token with no colon is rewritten to `*:<ports>`, then split on the LAST colon.
        let (proto_str, ports) = match lower.rsplit_once(':') {
            Some((p, ports)) => (p, ports),
            None => ("*", lower.as_str()),
        };
        if proto_str.is_empty() {
            return Err("empty protocol".to_string());
        }
        if proto_str.contains(',') {
            return Err("host cannot contain a comma (\",\")".to_string());
        }
        let proto = if proto_str == "*" {
            0
        } else {
            match PROTO_NAMES.iter().find(|(_, name)| *name == proto_str) {
                Some((n, _)) => *n,
                None => proto_str
                    .parse::<u8>()
                    .map_err(|_| format!("unknown protocol {proto_str:?}"))?,
            }
        };
        let (first, last) = if ports == "*" {
            (0, 65535)
        } else {
            match ports.split_once('-') {
                None => {
                    let p = ports
                        .parse::<u16>()
                        .map_err(|_| format!("invalid port {ports:?}"))?;
                    (p, p)
                }
                Some((lo, hi)) => {
                    let lo = lo
                        .parse::<u16>()
                        .map_err(|_| format!("invalid port range {ports:?}"))?;
                    let hi = hi
                        .parse::<u16>()
                        .map_err(|_| format!("invalid port range {ports:?}"))?;
                    if lo > hi {
                        return Err(format!("invalid port range {ports:?}"));
                    }
                    (lo, hi)
                }
            }
        };
        Ok(Self { proto, first, last })
    }
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
    /// The exit node traffic is **currently** egressing through, resolved to the peer's display name
    /// where possible (friendlier than a raw id) for the human `tnet status` line. `None` when no exit
    /// node is engaged. Distinct from the *configured* `prefs.exit_node` selector: this is what is
    /// actually live (the route updater's fail-closed answer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_exit_node: Option<String>,
    /// The raw **StableNodeID** of the currently-active exit node — the value Go's `status --json`
    /// puts in `ExitNodeStatus.ID` (a `tailcfg.StableNodeID`, e.g. `"nABC123"`, which keys the `Peer`
    /// map), NOT a display name. Carried separately from [`active_exit_node`](StatusReport::active_exit_node)
    /// (the resolved name, for the human line) so the `--json` shape stays Go-tooling-compatible: a
    /// script doing `jq -r .ExitNodeStatus.ID` can match it against `Peer` keys. `None` when no exit
    /// node is engaged. `#[serde(default)]` + skip keeps the wire backward-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_exit_node_id: Option<String>,
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
    /// Health-check problems currently raised on this node (Go `ipnstate.Status.Health`), as the
    /// human-readable texts Go's `health.Tracker.Strings()` emits. Empty means "nothing known to be
    /// wrong" — the same meaning as Go's empty slice.
    ///
    /// This fork registers exactly one warnable, Go's `captive-portal-detected`, so this list is
    /// either empty or holds that one message; it is not the full Go health-tracker surface. The
    /// container-level `#[serde(default)]` plus `skip_serializing_if` keep the wire backward-compatible
    /// with clients that predate this field, and keep a healthy node's status line unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub health: Vec<String>,
}

/// A read-only projection of the node's persisted [`Prefs`](crate::prefs::Prefs) for `status`
/// output. Mirrors the policy-relevant fields an operator wants to see at a glance (the analogue of
/// the prefs Go's `tailscale status` surfaces), without exposing the full prefs struct or any secret.
///
/// Container-level `#[serde(default)]` (matching [`crate::prefs::Prefs`]): every field is omittable
/// on the wire and falls back to [`PrefsView::default`], so a JSON projection missing any field
/// deserializes instead of hard-erroring. Fields keep their `skip_serializing_if` so empty
/// optionals/collections are still dropped from the emitted wire.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PrefsView {
    /// The requested hostname (Go `--hostname` / `Prefs.Hostname`), or `None` to use the OS hostname.
    /// Surfaced so `tnet get` can show it (Go's `get` lists hostname). Back-compat: omitted when None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
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
    /// Whether this node advertises itself as an app connector (Go `Prefs.AppConnector.Advertise`).
    pub advertise_connector: bool,
    /// Whether the node accepts admin-console-triggered auto-updates (Go `Prefs.AutoUpdate.Apply`).
    /// Tri-state like Go's `opt.Bool`: `None` = never stated, `Some(false)`/`Some(true)` = explicit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_update: Option<bool>,
    /// Whether a background update *check* is enabled (Go `Prefs.AutoUpdate.Check`, default-on).
    /// Like [`accept_dns`](PrefsView::accept_dns) this is always populated by `prefs_view()` from the
    /// live pref, so the derived `Default` (`false`) never disagrees with the pref's `true` default in
    /// practice — it only covers an impossible missing-field payload.
    pub update_check: bool,
    /// The OS username allowed to operate the daemon without root (Go `Prefs.OperatorUser`), or
    /// `None` for no operator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// The login profile's nickname (Go `Prefs.ProfileName`), or `None` when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    /// Whether the management plane may gather device-posture information (Go `Prefs.PostureChecking`).
    pub report_posture: bool,
    /// Whether the local web client is enabled (Go `Prefs.RunWebClient`).
    pub webclient: bool,
    /// Whether a peer using this node as an exit node may reach this node's local LAN (Go
    /// `Prefs.ExitNodeAllowLANAccess`).
    pub exit_node_allow_lan_access: bool,
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
    /// The `Location:` target, sent **verbatim**. There is no variable expansion: the engine's
    /// `serve_redirect` writes one fixed response for every request on the port and never parses the
    /// request, so it has no per-request value to substitute. A `${HOST}` / `${REQUEST_URI}`
    /// placeholder reaches the client as those literal characters — write a literal URL. (`tnet serve
    /// redirect` refuses both placeholders up front; a config that already carries one is still
    /// served verbatim rather than silently dropped.)
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

/// Tailnet Lock (TKA) update-chain history in a [`Response::LockLog`] reply (Go `tailscale lock
/// log`). Mirrors the engine's `Vec<TkaLogEntry>`, plus the lock-enabled flag from `tka_status` so
/// the CLI can tell "lock is off" apart from "lock is on but no chain has synced here yet" — an
/// empty entry list alone cannot distinguish the two.
///
/// Container-level `#[serde(default)]`: every field is omittable on the wire and falls back to
/// [`LockLogReport::default`], so a JSON document missing any field deserializes instead of
/// hard-erroring. `entries` keeps its `skip_serializing_if` so an empty history is dropped on the wire.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct LockLogReport {
    /// Whether Tailnet Lock is in use (control sent TKA info for this node) — the same signal
    /// [`LockReport::enabled`] carries.
    pub enabled: bool,
    /// The update-chain entries, **head-first** (newest → oldest), already truncated to the
    /// requested limit by the engine.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<LockLogEntry>,
}

/// One update-chain entry in a [`LockLogReport`] — the daemon's wire form of the engine's
/// `TkaLogEntry` (Go `ipnstate.NetworkLockUpdate`). The engine's byte fields are pre-rendered to
/// their text forms *daemon-side* so the wire DTO stays plain strings (the same pattern
/// [`DnsStatusReport`] uses for resolver addresses) and the CLI never has to name an engine type.
///
/// Container-level `#[serde(default)]` for the same forward-compat reason as [`LockLogReport`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct LockLogEntry {
    /// The AUM's chain-link hash (Go `NetworkLockUpdate.Hash`) in Go's text form: RFC 4648 standard
    /// base32, no padding — the same encoding [`LockReport::head`] carries, so the newest entry's
    /// hash is directly comparable with the head `tnet lock status` prints.
    pub hash: String,
    /// The change kind (Go `NetworkLockUpdate.Change`), e.g. `add-key` / `remove-key` / `checkpoint`.
    pub change: String,
    /// The id of each trusted key that signed this AUM, hex-encoded and `tlpub:`-prefixed — the form
    /// Go prints tailnet-lock key ids in. Empty for an unsigned AUM (the genesis checkpoint).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signer_key_ids: Vec<String>,
    /// The AUM's canonical CBOR serialization (Go `NetworkLockUpdate.Raw`), hex-encoded. Carried so
    /// an operator can decode the full AUM out-of-band; the daemon itself never decodes it (it has no
    /// AUM decoder), which is why `tnet lock log`'s human output cannot print Go's per-kind key
    /// detail. Emitted only by `tnet lock log --json`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub raw: String,
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

/// The outcome of a MagicDNS-path resolution in a [`Response::DnsQuery`] reply (Go `tailscale dns
/// query`). Projected from the engine's `tailscale::DnsQueryResult`. Like Go's `LocalClient.QueryDNS`,
/// the engine returns the **raw DNS response datagram** (header + question + any answer records), NOT
/// parsed records — this fork's wire codec has no answer-record decoder, so the CLI renders the RCODE,
/// the resolvers consulted, and a decode of the fixed DNS header (id/flags/counts) plus the raw bytes
/// as hex, and deliberately does NOT pretty-print individual A/AAAA/CNAME records (the honest-omission
/// boundary; documented in the renderer). The query name + numeric qtype are echoed back for context.
///
/// Container-level `#[serde(default)]` so a wire document missing any field deserializes to the
/// [`DnsQueryReport::default`] value rather than hard-erroring.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DnsQueryReport {
    /// The queried name, echoed back.
    pub name: String,
    /// The numeric DNS query type that was asked (1=A, 28=AAAA, …), echoed back.
    pub qtype: u16,
    /// The RCODE from the response header's low 4 bits (engine `DnsQueryResult::rcode`): 0=NoError,
    /// 2=SERVFAIL, 3=NXDOMAIN, 5=Refused, ….
    pub rcode: u8,
    /// The upstream resolver(s) consulted, each as an `addr:port` string (engine
    /// `resolvers_consulted`). Empty for a locally-answered query (an authoritative tailnet name, a
    /// NODATA, or a fail-closed NXDOMAIN — nothing egressed).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resolvers_consulted: Vec<String>,
    /// The raw DNS response datagram (engine `DnsQueryResult::response`), as lowercase hex. The CLI
    /// decodes the fixed 12-byte header from this; the answer records are NOT decoded (see the struct
    /// doc). Empty only if the engine returned no bytes.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub response_hex: String,
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

/// The suggested exit node in a [`Response::ExitNodeSuggestion`] reply (Go `tailscale exit-node
/// suggest`). Mirrors the engine's `tailscale::ExitNodeSuggestion` as this crate's own wire type:
/// the suggested node's stable id (pass to `tnet set --exit-node=<id>` to engage it) + its display
/// name (for surfacing to the operator).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitNodeSuggestionView {
    /// The suggested exit node's stable node id (engine `ExitNodeSuggestion::id`, Go
    /// `apitype.ExitNodeSuggestionResponse.ID`). This is the `--exit-node=<id>` selector to engage it.
    pub id: String,
    /// The suggested exit node's display name (engine `ExitNodeSuggestion::name`, Go
    /// `apitype.ExitNodeSuggestionResponse.Name`), for the human-facing suggestion line.
    pub name: String,
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

/// One IPN-bus notification, the body of a [`Response::Notify`] frame — the LocalAPI wire shape of
/// the engine's [`tailscale::Notify`] and the faithful analogue of Go's `ipn.Notify` as streamed by
/// `WatchNotifications`.
///
/// ## Nil-means-unchanged
///
/// Every field is `Option` and **set only when that thing changed in this event**; a `None` field
/// means "unchanged since the last frame", exactly like Go's `*ipn.Notify` whose fields are nil
/// pointers unless updated. A consumer keeps its own running view and applies each frame's non-`None`
/// fields over it. The daemon never emits an all-`None` frame (the engine's bus skips empty
/// notifications), so at least one field is always populated.
///
/// ## What Phase 1 carries — and what it deliberately does not
///
/// The engine's [`Notify`](tailscale::Notify) (v0.39.0) has exactly three fields — `state`,
/// `net_map`, `browse_to_url` — so this view fills exactly those (with `state`'s terminal-failure
/// reason split out into [`error`](NotifyView::error), mirroring how [`StatusReport`] already
/// separates `state` from `error`). It has **no `prefs` field**: a prefs-change broadcast is a later
/// phase, not this one.
///
/// The richer Go `Notify` fields (`Health`, `PeerChangedPatch`, `Engine`, `FilesWaiting`,
/// `SuggestedExitNode`, …) are intentionally **absent**: the fork's engine does not surface them on
/// its bus (there is no incremental peer-patch feed, no engine-status or health stream here), so
/// faithfully reflecting "what the engine actually knows" means omitting them rather than fabricating
/// empty values. In particular [`net_map`](NotifyView::net_map) is always the **full** peer set, never
/// a delta — the engine has no `PeerChangedPatch` analogue.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct NotifyView {
    /// The new connection state, if it changed this frame: one of the seven `ipn.State` names
    /// (`NoState` / `NeedsLogin` / `NeedsMachineAuth` / `InUseOtherUser` / `Starting` / `Running` /
    /// `Stopped`) — the SAME string [`StatusReport::state`] uses, derived from the engine's
    /// `DeviceState` via the shared `state_from_device` mapping so the two surfaces can never drift.
    /// `None` when this frame did not carry a state change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// A terminal registration-failure reason accompanying [`state`](NotifyView::state), if any —
    /// the analogue of Go's `ipnstate.Status.ErrMessage`. Populated (alongside a `NeedsLogin` state)
    /// only for a **permanent** failure (bad/expired/unknown key); `None` otherwise. Comes from the
    /// same `state_from_device` mapping `StatusReport` uses, so a hard failure (`error` set, no
    /// `browse_to_url`) reads distinctly from an interactive-login prompt (`browse_to_url` set, no
    /// `error`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// An interactive-login / consent URL the operator should open (Go `Notify.BrowseToURL`), if this
    /// frame carried one. Two sources feed it in the engine: the registration-time auth URL derived
    /// from `NeedsLogin` (set alongside `state`), and a mid-session `MapResponse.PopBrowserURL`
    /// (re-auth on an already-running node, streamed standalone). `None` when this frame carried no
    /// URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browse_to_url: Option<String>,
    /// The **full** current peer set, if the netmap changed this frame (Go `Notify.NetMap`). Each
    /// entry reuses the same [`PeerReport`] projection [`StatusReport::peers`] uses, from the identical
    /// `StatusNode` → `PeerReport` mapping (see [`crate::ipn`]'s status projection), so the watch feed
    /// and a one-shot `status` describe peers identically. NOT a delta — always the entire set (the
    /// engine has no incremental peer-patch feed). `None` when this frame carried no netmap change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_map: Option<Vec<PeerReport>>,
    /// The node's current prefs, if the `prefs` mask bit was set (Go `Notify.Prefs`). A front-loaded
    /// snapshot on subscribe, then a fresh frame on every prefs change. Reuses the same [`PrefsView`]
    /// projection [`StatusReport::prefs`] / `GetPrefs` use, so the watch feed and a one-shot read
    /// describe prefs identically. DAEMON-built (not an engine `Notify` field — this fork's prefs are
    /// daemon-owned). `None` when this frame carried no prefs change (or the `prefs` bit was unset).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefs: Option<PrefsView>,
}

/// A single peer entry in a [`StatusReport`].
///
/// Derives `PartialEq` so it can nest inside [`NotifyView`]'s `Option<Vec<PeerReport>>` (which is
/// `PartialEq` for frame-equality in tests); all fields are `PartialEq` scalars/strings.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
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
    /// the peer is offline. `None` when unknown / never seen. Strict RFC3339
    /// (`2026-06-11T05:19:14+00:00`, via `DateTime::to_rfc3339`), matching Go's `ipnstate` timestamps
    /// so a JSON consumer parses it directly.
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
    /// The peer's advertised SSH host public keys, in `known_hosts` format (Go
    /// `ipnstate.PeerStatus.SSH_HostKeys`). Used by `tnet ssh` to pin the peer's host key
    /// (`StrictHostKeyChecking=yes` against a generated `ssh_known_hosts`), so the connection verifies
    /// the host key from the netmap instead of a TOFU prompt. Empty when control advertised none
    /// (never fabricated). `#[serde(default)]` keeps the wire backward-compatible with clients/daemons
    /// that predate this field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_host_keys: Vec<String>,
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
            operator: None,
            exit_node_allow_lan_access: None,
            advertise_connector: None,
            report_posture: None,
            reset: true,
            force_reauth: false,
            ephemeral: None,
            client_id: Some("oauth-client-1".to_string()),
            client_secret: Some("tskey-client-secret".to_string()),
            id_token: None,
            audience: None,
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
                operator: _,
                exit_node_allow_lan_access: _,
                advertise_connector: _,
                report_posture: _,
                reset,
                force_reauth: _,
                ephemeral: _,
                client_id,
                client_secret,
                id_token,
                audience,
            } => {
                assert!(reset, "reset must survive the wire round-trip when set");
                assert_eq!(authkey.as_deref(), Some("tskey-auth-xxx"));
                assert_eq!(hostname.as_deref(), Some("node-a"));
                assert!(control_url.is_none());
                assert_eq!(tun, Some(true));
                assert_eq!(ssh, Some(true));
                assert_eq!(tun_name.as_deref(), Some("tailscale0"));
                // Workload-identity creds survive the wire round-trip (client_id/secret set here).
                assert_eq!(client_id.as_deref(), Some("oauth-client-1"));
                assert_eq!(client_secret.as_deref(), Some("tskey-client-secret"));
                assert!(id_token.is_none() && audience.is_none());
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
            serde_json::to_string(&Request::Down { reason: None }).unwrap(),
            r#"{"cmd":"down"}"#,
            "no reason must serialize to the historical bare form"
        );
        // `tnet down --reason "<text>"` (Go `tailscale down --reason`): the justification travels to
        // the daemon verbatim, exactly as `logout --reason` does, and the bare `{"cmd":"down"}` an
        // older client sends must still parse.
        let json = serde_json::to_string(&Request::Down {
            reason: Some("scheduled maintenance".into()),
        })
        .unwrap();
        assert!(
            json.contains(r#""cmd":"down""#)
                && json.contains(r#""reason":"scheduled maintenance""#),
            "{json}"
        );
        match serde_json::from_str::<Request>(&json).unwrap() {
            Request::Down { reason } => {
                assert_eq!(reason.as_deref(), Some("scheduled maintenance"))
            }
            other => panic!("expected Down, got {other:?}"),
        }
        match serde_json::from_str::<Request>(r#"{"cmd":"down"}"#).unwrap() {
            Request::Down { reason } => assert_eq!(reason, None),
            other => panic!("expected Down, got {other:?}"),
        }
    }

    #[test]
    fn request_reload_config_wire_format() {
        // `reload_config` (Go `tailscaled`'s `reload-config`): a unit variant. Pin its discriminant so
        // the CLI and daemon — separate processes agreeing only on this JSON — stay in lockstep.
        assert_eq!(
            serde_json::to_string(&Request::ReloadConfig).unwrap(),
            r#"{"cmd":"reload_config"}"#
        );
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"reload_config"}"#).unwrap(),
            Request::ReloadConfig
        ));
    }

    #[test]
    fn lock_log_wire_format_round_trips() {
        // `lock log` (Go `tailscale lock log`): the CLI and daemon are separate processes agreeing
        // only on this JSON, so pin both discriminants and the field names.
        assert_eq!(
            serde_json::to_string(&Request::LockLog { limit: 50 }).unwrap(),
            r#"{"cmd":"lock_log","limit":50}"#
        );
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"lock_log","limit":7}"#).unwrap(),
            Request::LockLog { limit: 7 }
        ));

        let report = LockLogReport {
            enabled: true,
            entries: vec![LockLogEntry {
                hash: "MZXW6YTBOI".to_string(),
                change: "add-key".to_string(),
                signer_key_ids: vec!["tlpub:aabb".to_string()],
                raw: "a1626b76".to_string(),
            }],
        };
        let json = serde_json::to_string(&Response::LockLog(report.clone())).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"lock_log","enabled":true,"entries":[{"hash":"MZXW6YTBOI","change":"add-key","signer_key_ids":["tlpub:aabb"],"raw":"a1626b76"}]}"#
        );
        match serde_json::from_str::<Response>(&json).unwrap() {
            Response::LockLog(back) => assert_eq!(back, report),
            other => panic!("expected a lock_log reply, got {other:?}"),
        }

        // Empty history: the entries list is dropped on the wire, and a document missing it (or
        // missing `enabled`) still deserializes to the default rather than hard-erroring.
        assert_eq!(
            serde_json::to_string(&Response::LockLog(LockLogReport::default())).unwrap(),
            r#"{"kind":"lock_log","enabled":false}"#
        );
        match serde_json::from_str::<Response>(r#"{"kind":"lock_log"}"#).unwrap() {
            Response::LockLog(back) => assert_eq!(back, LockLogReport::default()),
            other => panic!("expected a lock_log reply, got {other:?}"),
        }
    }

    #[test]
    fn request_watch_wire_format() {
        // `watch` is the streaming command; assert its discriminant so daemon + CLI agree. The mask
        // fields gained in Phase 1 (`initial_state`/`initial_netmap`) are `skip_serializing_if`-false,
        // so a BARE watch must still serialize to EXACTLY `{"cmd":"watch"}` (byte-for-byte the legacy
        // encoding `tnet status --watch` speaks) and a legacy `{"cmd":"watch"}` line must still parse —
        // the dual-path back-compat contract.
        assert_eq!(
            serde_json::to_string(&Request::Watch {
                initial_state: false,
                initial_netmap: false,
                prefs: false,
            })
            .unwrap(),
            r#"{"cmd":"watch"}"#
        );
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"watch"}"#).unwrap(),
            Request::Watch {
                initial_state: false,
                initial_netmap: false,
                prefs: false,
            }
        ));
        // A masked watch round-trips its bits (the Notify-path selector): each `true` field appears on
        // the wire, and the masked request decodes back to the same flags. (`prefs` is the Phase-2
        // daemon-built bit; it serializes/parses identically to the engine bits.)
        assert_eq!(
            serde_json::to_string(&Request::Watch {
                initial_state: true,
                initial_netmap: true,
                prefs: true,
            })
            .unwrap(),
            r#"{"cmd":"watch","initial_state":true,"initial_netmap":true,"prefs":true}"#
        );
        match serde_json::from_str::<Request>(
            r#"{"cmd":"watch","initial_state":true,"initial_netmap":true,"prefs":true}"#,
        )
        .unwrap()
        {
            Request::Watch {
                initial_state,
                initial_netmap,
                prefs,
            } => {
                assert!(initial_state && initial_netmap && prefs);
            }
            other => panic!("expected masked Watch, got {other:?}"),
        }
        // A `prefs`-only watch (the Phase-2 daemon-built path) is also masked — only `prefs` on the wire.
        assert_eq!(
            serde_json::to_string(&Request::Watch {
                initial_state: false,
                initial_netmap: false,
                prefs: true,
            })
            .unwrap(),
            r#"{"cmd":"watch","prefs":true}"#
        );
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
    fn request_debug_portmap_wire_format_and_streamed_reply() {
        // Pin the `debug_portmap` discriminant + field names so daemon + CLI agree. An absent
        // gateway override stays off the wire (auto-detect), which is what a bare
        // `tnet debug portmap` sends.
        assert_eq!(
            serde_json::to_string(&Request::DebugPortmap {
                duration_ms: 5_000,
                ty: String::new(),
                gateway_and_self: None,
                log_http: false,
            })
            .unwrap(),
            r#"{"cmd":"debug_portmap","duration_ms":5000,"ty":"","log_http":false}"#
        );
        // With `--gateway-addr`/`--self-addr` the pair travels as one `<gateway>/<self>` string,
        // the same shape Go's client puts in its `gateway_and_self` query parameter.
        assert_eq!(
            serde_json::to_string(&Request::DebugPortmap {
                duration_ms: 1_500,
                ty: "pmp".into(),
                gateway_and_self: Some("192.0.2.1/192.0.2.2".into()),
                log_http: true,
            })
            .unwrap(),
            r#"{"cmd":"debug_portmap","duration_ms":1500,"ty":"pmp","gateway_and_self":"192.0.2.1/192.0.2.2","log_http":true}"#
        );
        // Every optional field defaults, so a minimal raw-client line still parses.
        match serde_json::from_str::<Request>(r#"{"cmd":"debug_portmap","duration_ms":250}"#)
            .unwrap()
        {
            Request::DebugPortmap {
                duration_ms,
                ty,
                gateway_and_self,
                log_http,
            } => {
                assert_eq!(duration_ms, 250);
                assert_eq!(ty, "");
                assert_eq!(gateway_and_self, None);
                assert!(!log_http);
            }
            other => panic!("expected DebugPortmap, got {other:?}"),
        }
        // The reply is a stream of log lines; each frame must survive the process boundary intact,
        // because the CLI prints `line` verbatim.
        let json = serde_json::to_string(&Response::PortmapLog {
            line: "Probe: {PCP:false PMP:true UPnP:true}".into(),
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"kind":"portmap_log","line":"Probe: {PCP:false PMP:true UPnP:true}"}"#
        );
        match serde_json::from_str::<Response>(&json).unwrap() {
            Response::PortmapLog { line } => {
                assert_eq!(line, "Probe: {PCP:false PMP:true UPnP:true}")
            }
            other => panic!("expected PortmapLog, got {other:?}"),
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
        // `BugReport` changed from a unit variant to `{ note: Option<String> }`, and then grew
        // `diagnose: bool`. This LOCKS the wire back-compat both ways (the riskiest part of those
        // changes): a plain request must serialize BYTE-IDENTICAL to the old bare unit variant
        // (`skip_serializing_if` on both fields is what makes this hold — no `"note":null`, no
        // `"diagnose":false`), and the old bare JSON must still deserialize (→ note: None,
        // diagnose: false). Mirrors the per-variant wire-lock convention every sibling request
        // already follows.
        assert_eq!(
            serde_json::to_string(&Request::BugReport {
                note: None,
                diagnose: false
            })
            .unwrap(),
            r#"{"cmd":"bug_report"}"#,
            "a plain bugreport must be byte-identical to the old unit variant's wire form"
        );
        // Old client's bare JSON → new struct variant with both fields defaulted (forward-compat).
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"bug_report"}"#).unwrap(),
            Request::BugReport {
                note: None,
                diagnose: false
            }
        ));
        // With a note, the field is present on the wire and round-trips.
        assert_eq!(
            serde_json::to_string(&Request::BugReport {
                note: Some("dns broke".into()),
                diagnose: false
            })
            .unwrap(),
            r#"{"cmd":"bug_report","note":"dns broke"}"#
        );
        match serde_json::from_str::<Request>(r#"{"cmd":"bug_report","note":"x"}"#).unwrap() {
            Request::BugReport { note, diagnose } => {
                assert_eq!(note.as_deref(), Some("x"));
                assert!(!diagnose, "an absent diagnose key means the pass is off");
            }
            other => panic!("expected BugReport, got {other:?}"),
        }
        // `--diagnose` rides as its own key and round-trips.
        assert_eq!(
            serde_json::to_string(&Request::BugReport {
                note: None,
                diagnose: true
            })
            .unwrap(),
            r#"{"cmd":"bug_report","diagnose":true}"#
        );
        match serde_json::from_str::<Request>(r#"{"cmd":"bug_report","diagnose":true}"#).unwrap() {
            Request::BugReport { note, diagnose } => {
                assert_eq!(note, None);
                assert!(diagnose);
            }
            other => panic!("expected BugReport, got {other:?}"),
        }
    }

    #[test]
    fn bug_report_response_checks_are_wire_optional() {
        // The reply grew `checks` alongside `--diagnose`. A marker-only reply (the no-`--diagnose`
        // case, and every reply an older daemon sends) must stay byte-identical to the pre-change
        // wire form, and old JSON must still deserialize — otherwise a mixed-version pair breaks on
        // the one command an operator reaches for when things are already broken.
        assert_eq!(
            serde_json::to_string(&Response::BugReport {
                marker: "BUG-1-0".into(),
                checks: Vec::new()
            })
            .unwrap(),
            r#"{"kind":"bug_report","marker":"BUG-1-0"}"#,
            "no checks must not appear on the wire at all"
        );
        match serde_json::from_str::<Response>(r#"{"kind":"bug_report","marker":"BUG-1-0"}"#)
            .unwrap()
        {
            Response::BugReport { marker, checks } => {
                assert_eq!(marker, "BUG-1-0");
                assert!(checks.is_empty(), "an absent checks key means no pass ran");
            }
            other => panic!("expected BugReport, got {other:?}"),
        }
        // With a pass, the lines ride along and round-trip in order.
        let json = serde_json::to_string(&Response::BugReport {
            marker: "BUG-1-0".into(),
            checks: vec!["state: Running".into(), "profile: default".into()],
        })
        .unwrap();
        match serde_json::from_str::<Response>(&json).unwrap() {
            Response::BugReport { checks, .. } => {
                assert_eq!(checks, ["state: Running", "profile: default"]);
            }
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
    fn service_port_range_parses_and_renders_gos_text_form() {
        use crate::localapi::ServicePortRange;
        // Go's `ProtoPortRange` is a TextMarshaler, so a Service's `Ports` arrive as strings.
        // Every documented form round-trips through the ported codec.
        let cases = [
            (
                "*",
                ServicePortRange {
                    proto: 0,
                    first: 0,
                    last: 65535,
                },
            ),
            (
                "443",
                ServicePortRange {
                    proto: 0,
                    first: 443,
                    last: 443,
                },
            ),
            (
                "tcp:443",
                ServicePortRange {
                    proto: 6,
                    first: 443,
                    last: 443,
                },
            ),
            (
                "udp:1-100",
                ServicePortRange {
                    proto: 17,
                    first: 1,
                    last: 100,
                },
            ),
            (
                "tcp:*",
                ServicePortRange {
                    proto: 6,
                    first: 0,
                    last: 65535,
                },
            ),
            (
                "80-90",
                ServicePortRange {
                    proto: 0,
                    first: 80,
                    last: 90,
                },
            ),
            (
                "ipv6-icmp:0",
                ServicePortRange {
                    proto: 58,
                    first: 0,
                    last: 0,
                },
            ),
        ];
        for (text, want) in cases {
            let got: ServicePortRange = text.parse().unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(got, want, "parsing {text:?}");
            assert_eq!(got.to_string(), text, "rendering {want:?}");
        }
        // Go lower-cases the token and resolves a numeric protocol through the same name table, so
        // both spellings normalize to the canonical one on the way back out.
        assert_eq!(
            "TCP:443".parse::<ServicePortRange>().unwrap().to_string(),
            "tcp:443"
        );
        assert_eq!(
            "6:443".parse::<ServicePortRange>().unwrap().to_string(),
            "tcp:443"
        );
        // A protocol with no `preferredNames` entry renders as its decimal number, as Go's does.
        assert_eq!(
            "99:443".parse::<ServicePortRange>().unwrap().to_string(),
            "99:443"
        );
        // Fail-closed: malformed text is an error, never a guessed range.
        for bad in [
            "",
            "tcp:",
            "tcp:notaport",
            ":443",
            "tcp:900-100",
            "nosuchproto:443",
        ] {
            assert!(
                bad.parse::<ServicePortRange>().is_err(),
                "{bad:?} must not parse into a port range"
            );
        }
    }

    #[test]
    fn service_port_range_single_tcp_port_matches_gos_inference_filter() {
        use crate::localapi::ServicePortRange;
        // Go infers a well-known action only from a single TCP port: an unset proto counts as TCP,
        // a real non-TCP proto does not, and a range is skipped however it is spelled.
        let single_tcp: ServicePortRange = "tcp:443".parse().unwrap();
        assert_eq!(single_tcp.single_tcp_port(), Some(443));
        let unset_proto: ServicePortRange = "22".parse().unwrap();
        assert_eq!(unset_proto.single_tcp_port(), Some(22));
        let udp: ServicePortRange = "udp:53".parse().unwrap();
        assert_eq!(udp.single_tcp_port(), None);
        let range: ServicePortRange = "tcp:80-90".parse().unwrap();
        assert_eq!(range.single_tcp_port(), None);
        let any: ServicePortRange = "*".parse().unwrap();
        assert_eq!(any.single_tcp_port(), None);
    }

    #[test]
    fn services_request_response_round_trip() {
        // The `services` discriminant + the Services(Vec<ServiceReport>) reply must survive the wire
        // (the CLI and daemon are separate processes agreeing only on this JSON format).
        assert_eq!(
            serde_json::to_string(&Request::Services).unwrap(),
            r#"{"cmd":"services"}"#
        );
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"services"}"#).unwrap(),
            Request::Services
        ));
        let report = ServiceReport {
            name: "svc:db".into(),
            display_name: "Production database".into(),
            addrs: vec!["100.64.0.10".into(), "fd7a:115c:a1e0::a".into()],
            ports: vec![ServicePortRange {
                proto: 6,
                first: 5432,
                last: 5432,
            }],
            actions: vec![ServiceActionReport {
                action_type: "postgresql".into(),
                port: 5432,
                display_name: "Postgres".into(),
                attributes: std::collections::BTreeMap::from([(
                    "tailscale.com/cap/resource-name".to_string(),
                    serde_json::json!("orders"),
                )]),
            }],
        };
        let resp = Response::Services {
            services: vec![report.clone()],
        };
        let json = serde_json::to_string(&resp).unwrap();
        match serde_json::from_str::<Response>(&json).unwrap() {
            Response::Services { services } => assert_eq!(services, vec![report]),
            other => panic!("expected Services, got {other:?}"),
        }
        // An empty Service set is a valid answer (the tailnet grants this node none), and every
        // empty field of a bare report is dropped from the wire.
        let empty = serde_json::to_string(&Response::Services {
            services: vec![ServiceReport::default()],
        })
        .unwrap();
        assert!(
            !empty.contains("display_name")
                && !empty.contains("addrs")
                && !empty.contains("actions"),
            "empty ServiceReport fields must be omitted from the wire: {empty}"
        );
        match serde_json::from_str::<Response>(&empty).unwrap() {
            Response::Services { services } => assert_eq!(services, vec![ServiceReport::default()]),
            other => panic!("expected Services, got {other:?}"),
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
    fn syspolicy_request_response_round_trip() {
        // The `syspolicy_list`/`syspolicy_reload` discriminants + the Policy(PolicyReport) reply must
        // survive the wire (CLI ⇄ daemon agree only on this JSON). Pin both request verbs.
        assert_eq!(
            serde_json::to_string(&Request::SyspolicyList).unwrap(),
            r#"{"cmd":"syspolicy_list"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::SyspolicyReload).unwrap(),
            r#"{"cmd":"syspolicy_reload"}"#
        );
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"syspolicy_list"}"#).unwrap(),
            Request::SyspolicyList
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"syspolicy_reload"}"#).unwrap(),
            Request::SyspolicyReload
        ));

        // A populated snapshot round-trips with all four logical fields of each setting intact.
        let report = PolicyReport {
            scope: "Device".into(),
            settings: vec![
                PolicySetting {
                    key: "ExitNodeID".into(),
                    origin: "Platform (Device)".into(),
                    value: Some("n123".into()),
                    error: None,
                },
                PolicySetting {
                    key: "AuthKey".into(),
                    origin: "Platform (Device)".into(),
                    value: None,
                    error: Some("decrypt failed".into()),
                },
            ],
        };
        let resp = Response::Policy(report.clone());
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""kind":"policy""#), "discriminant: {json}");
        match serde_json::from_str::<Response>(&json).unwrap() {
            Response::Policy(r) => assert_eq!(r, report),
            other => panic!("expected Policy, got {other:?}"),
        }

        // The empty snapshot (the normal Linux/Unix result) round-trips, and its empty `settings`
        // collection is omitted from the wire (skip_serializing_if) while `scope` is present.
        let empty = Response::Policy(PolicyReport {
            scope: "Device".into(),
            settings: vec![],
        });
        let empty_json = serde_json::to_string(&empty).unwrap();
        assert!(
            !empty_json.contains("settings"),
            "empty settings must be omitted from the wire: {empty_json}"
        );
        assert!(
            empty_json.contains(r#""scope":"Device""#),
            "scope kept: {empty_json}"
        );
        match serde_json::from_str::<Response>(&empty_json).unwrap() {
            Response::Policy(r) => {
                assert_eq!(r.scope, "Device");
                assert!(r.settings.is_empty());
            }
            other => panic!("expected Policy, got {other:?}"),
        }
    }

    #[test]
    fn cert_request_response_round_trip() {
        // The `cert` request (carrying the domain) and the `Cert { cert_pem, key_pem }` reply must
        // survive the wire intact — the CLI writes the PEMs the daemon issued, so neither may be
        // mangled or truncated. Pin the request discriminant + field and the reply's two PEM bodies.
        let req = Request::Cert {
            domain: "host.user.ts.net".into(),
            min_validity_secs: Some(2_592_000),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains(r#""cmd":"cert""#) && json.contains(r#""domain":"host.user.ts.net""#),
            "{json}"
        );
        assert!(
            json.contains(r#""min_validity_secs":2592000"#),
            "the requested minimum validity must reach the daemon: {json}"
        );
        match serde_json::from_str::<Request>(&json).unwrap() {
            Request::Cert {
                domain,
                min_validity_secs,
            } => {
                assert_eq!(domain, "host.user.ts.net");
                assert_eq!(min_validity_secs, Some(2_592_000));
            }
            other => panic!("expected Cert, got {other:?}"),
        }
        // No `--min-validity`: the field is omitted from the wire entirely, and an older client's
        // bare `{"cmd":"cert","domain":...}` still deserializes (to "no minimum" — Go's zero
        // duration).
        let bare = serde_json::to_string(&Request::Cert {
            domain: "host.user.ts.net".into(),
            min_validity_secs: None,
        })
        .unwrap();
        assert!(
            !bare.contains("min_validity_secs"),
            "an unset minimum must not appear on the wire: {bare}"
        );
        match serde_json::from_str::<Request>(r#"{"cmd":"cert","domain":"host.user.ts.net"}"#)
            .unwrap()
        {
            Request::Cert {
                domain,
                min_validity_secs,
            } => {
                assert_eq!(domain, "host.user.ts.net");
                assert_eq!(min_validity_secs, None, "an absent field means no minimum");
            }
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
    fn logout_reason_round_trips_and_stays_backward_compatible() {
        // `tnet logout --reason "<text>"` (Go `tailscale logout --reason`, which sends the base64
        // `X-Tailscale-Reason` header): the justification must reach the daemon verbatim, and the
        // bare `{"cmd":"logout"}` an older client sends must still parse — the field is the only
        // thing that changed about the variant.
        let json = serde_json::to_string(&Request::Logout {
            reason: Some("laptop returned to IT".into()),
        })
        .unwrap();
        assert!(
            json.contains(r#""cmd":"logout""#)
                && json.contains(r#""reason":"laptop returned to IT""#),
            "{json}"
        );
        match serde_json::from_str::<Request>(&json).unwrap() {
            Request::Logout { reason } => {
                assert_eq!(reason.as_deref(), Some("laptop returned to IT"))
            }
            other => panic!("expected Logout, got {other:?}"),
        }
        let bare = serde_json::to_string(&Request::Logout { reason: None }).unwrap();
        assert_eq!(
            bare, r#"{"cmd":"logout"}"#,
            "no reason must serialize to the historical bare form"
        );
        match serde_json::from_str::<Request>(r#"{"cmd":"logout"}"#).unwrap() {
            Request::Logout { reason } => assert_eq!(reason, None),
            other => panic!("expected Logout, got {other:?}"),
        }
    }

    #[test]
    fn whois_request_carries_gos_flow_triple_and_stays_backward_compatible() {
        // Go's `whois [--proto tcp|udp] ip[:port]` is a flow triple, so the request carries the port
        // and the protocol alongside the address. Both are additive: the bare `{"cmd":"whois",
        // "ip":...}` an older CLI sends must still parse, and a bare-IP request must still serialize
        // to exactly that historical form (skip_serializing_if).
        let json = serde_json::to_string(&Request::Whois {
            ip: "100.64.0.9".into(),
            port: Some(22),
            proto: Some(WhoisProto::Tcp),
        })
        .unwrap();
        assert_eq!(
            json, r#"{"cmd":"whois","ip":"100.64.0.9","port":22,"proto":"tcp"}"#,
            "the proto must ride the wire as Go's lowercase spelling"
        );
        match serde_json::from_str::<Request>(&json).unwrap() {
            Request::Whois { ip, port, proto } => {
                assert_eq!(ip, "100.64.0.9");
                assert_eq!(port, Some(22));
                assert_eq!(proto, Some(WhoisProto::Tcp));
            }
            other => panic!("expected Whois, got {other:?}"),
        }
        let bare = serde_json::to_string(&Request::Whois {
            ip: "100.64.0.9".into(),
            port: None,
            proto: None,
        })
        .unwrap();
        assert_eq!(
            bare, r#"{"cmd":"whois","ip":"100.64.0.9"}"#,
            "a bare-IP whois must serialize to the historical form"
        );
        match serde_json::from_str::<Request>(r#"{"cmd":"whois","ip":"100.64.0.9"}"#).unwrap() {
            Request::Whois { ip, port, proto } => {
                assert_eq!(ip, "100.64.0.9");
                assert_eq!(port, None, "an older CLI's request means Go's port 0");
                assert_eq!(proto, None, "and Go's empty proto: both");
            }
            other => panic!("expected Whois, got {other:?}"),
        }
        // A proto the daemon does not know must not deserialize into some default — the closed enum
        // is what keeps a bogus value off the lookup path.
        assert!(
            serde_json::from_str::<Request>(r#"{"cmd":"whois","ip":"100.64.0.9","proto":"sctp"}"#)
                .is_err(),
            "an unknown proto must be a parse failure, not a silent fallback"
        );
    }

    #[test]
    fn whois_proto_parses_and_renders_gos_two_values() {
        // Go documents the flag as `one of "tcp" or "udp"; empty means both`. The empty case is
        // modelled as `None` at the call site, so `FromStr` accepts exactly the two named values,
        // exactly as spelled.
        assert_eq!("tcp".parse::<WhoisProto>(), Ok(WhoisProto::Tcp));
        assert_eq!("udp".parse::<WhoisProto>(), Ok(WhoisProto::Udp));
        assert_eq!(WhoisProto::Tcp.to_string(), "tcp");
        assert_eq!(WhoisProto::Udp.to_string(), "udp");
        for bad in ["TCP", "Udp", "sctp", "icmp", ""] {
            let err = bad
                .parse::<WhoisProto>()
                .expect_err("only Go's two documented values parse");
            assert!(
                err.contains("expected \"tcp\" or \"udp\" (empty means both)"),
                "the refusal should quote Go's own flag documentation: {err}"
            );
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
            // RFC3339 (what the daemon now emits via DateTime::to_rfc3339) — Go-ipnstate-compatible.
            node_key_expiry: Some("2026-09-01T12:00:00+00:00".into()),
            online: Some(false),
            last_seen: Some("2026-06-11T05:19:14+00:00".into()),
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
    fn suggest_exit_node_request_response_round_trip() {
        // `suggest-exit-node` discriminant + the ExitNodeSuggestion(Option<..>) reply must survive the
        // wire. The Some(..) case carries the id+name; the None case (no eligible candidate) is an
        // honest empty result, NOT an error, and must round-trip as `null`.
        assert_eq!(
            serde_json::to_string(&Request::SuggestExitNode).unwrap(),
            r#"{"cmd":"suggest_exit_node"}"#
        );
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"suggest_exit_node"}"#).unwrap(),
            Request::SuggestExitNode
        ));
        // Some(suggestion) round-trips with both fields.
        let sugg = ExitNodeSuggestionView {
            id: "nABC123".to_string(),
            name: "exit-fra-1".to_string(),
        };
        let resp = Response::ExitNodeSuggestion {
            suggestion: Some(sugg.clone()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        match serde_json::from_str::<Response>(&json).unwrap() {
            Response::ExitNodeSuggestion {
                suggestion: Some(s),
            } => assert_eq!(s, sugg),
            other => panic!("expected ExitNodeSuggestion(Some), got {other:?}"),
        }
        // None (no candidate) round-trips as a distinct, non-error empty result.
        let none = Response::ExitNodeSuggestion { suggestion: None };
        let none_json = serde_json::to_string(&none).unwrap();
        match serde_json::from_str::<Response>(&none_json).unwrap() {
            Response::ExitNodeSuggestion { suggestion: None } => {}
            other => panic!("expected ExitNodeSuggestion(None), got {other:?}"),
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
            active_exit_node_id: None,
            magic_dns_suffix: None,
            peers: vec![PeerReport {
                name: "peer-b".to_string(),
                ipv4: "100.64.0.2".to_string(),
                is_exit_node: true,
                ..Default::default()
            }],
            version: None,
            have_node_key: false,
            health: Vec::new(),
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
            active_exit_node_id: None,
            magic_dns_suffix: None,
            peers: vec![],
            version: None,
            have_node_key: false,
            health: Vec::new(),
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
            active_exit_node_id: None,
            magic_dns_suffix: None,
            peers: vec![],
            version: None,
            have_node_key: false,
            health: Vec::new(),
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
            active_exit_node_id: None,
            magic_dns_suffix: None,
            peers: vec![],
            version: None,
            have_node_key: false,
            health: Vec::new(),
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
            active_exit_node_id: None,
            magic_dns_suffix: None,
            peers: vec![],
            version: None,
            have_node_key: false,
            health: Vec::new(),
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
            active_exit_node_id: None,
            magic_dns_suffix: None,
            peers: vec![],
            version: None,
            have_node_key: false,
            health: Vec::new(),
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
            operator: None,
            exit_node_allow_lan_access: None,
            advertise_connector: None,
            report_posture: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
            client_id: None,
            client_secret: None,
            id_token: None,
            audience: None,
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
                operator: _,
                exit_node_allow_lan_access: _,
                advertise_connector: _,
                report_posture: _,
                reset,
                force_reauth: _,
                ephemeral: _,
                client_id,
                client_secret,
                id_token,
                audience,
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
                assert!(client_id.is_none() && client_secret.is_none());
                assert!(id_token.is_none() && audience.is_none());
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
            operator: None,
            exit_node_allow_lan_access: None,
            advertise_connector: None,
            report_posture: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
            client_id: None,
            client_secret: None,
            id_token: None,
            audience: None,
        };
        let json = serde_json::to_string(&clear).unwrap();
        match serde_json::from_str::<Request>(&json).unwrap() {
            Request::Up {
                exit_node,
                advertise_exit_node,
                advertise_routes,
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
            operator: None,
            exit_node_allow_lan_access: None,
            advertise_connector: None,
            report_posture: None,
            reset: false,
            force_reauth: true,
            ephemeral: None,
            client_id: None,
            client_secret: None,
            id_token: None,
            audience: None,
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
    fn go_parity_pref_flags_round_trip_on_the_wire() {
        // The Go `up`/`set` pref flags added alongside their engine `Config` fields. Two contracts:
        // (a) each decodes to its OWN field (a mis-keyed rename would land on the wrong pref), and
        // (b) an ABSENT key stays "unchanged" (`None`) — never a silent default-off.

        // `up` carries the four Go registers on BOTH commands.
        match serde_json::from_str::<Request>(
            r#"{"cmd":"up","operator":"alice","exit_node_allow_lan_access":true,
                "advertise_connector":true,"report_posture":false}"#,
        )
        .expect("up with the shared pref flags must parse")
        {
            Request::Up {
                operator,
                exit_node_allow_lan_access,
                advertise_connector,
                report_posture,
                ..
            } => {
                assert_eq!(operator, Some(Some("alice".to_string())));
                assert_eq!(exit_node_allow_lan_access, Some(true));
                assert_eq!(advertise_connector, Some(true));
                assert_eq!(report_posture, Some(false));
            }
            other => panic!("expected Up, got {other:?}"),
        }
        match serde_json::from_str::<Request>(r#"{"cmd":"up"}"#).expect("bare up parses") {
            Request::Up {
                operator,
                exit_node_allow_lan_access,
                advertise_connector,
                report_posture,
                ..
            } => {
                assert_eq!(operator, None, "absent → unchanged");
                assert_eq!(exit_node_allow_lan_access, None, "absent → unchanged");
                assert_eq!(advertise_connector, None, "absent → unchanged");
                assert_eq!(report_posture, None, "absent → unchanged");
            }
            other => panic!("expected Up, got {other:?}"),
        }

        // `set` carries all eight (Go registers `nickname`/`webclient`/`auto_update`/`update_check`
        // on `set` only).
        match serde_json::from_str::<Request>(
            r#"{"cmd":"set","advertise_connector":true,"auto_update":false,"update_check":false,
                "operator":"alice","nickname":"laptop","report_posture":true,"webclient":true,
                "exit_node_allow_lan_access":true}"#,
        )
        .expect("set with every pref flag must parse")
        {
            Request::Set {
                advertise_connector,
                auto_update,
                update_check,
                operator,
                nickname,
                report_posture,
                webclient,
                exit_node_allow_lan_access,
                ..
            } => {
                assert_eq!(advertise_connector, Some(true));
                assert_eq!(
                    auto_update,
                    Some(false),
                    "an explicit decline must stay distinct from never-stated"
                );
                assert_eq!(update_check, Some(false));
                assert_eq!(operator, Some(Some("alice".to_string())));
                assert_eq!(nickname, Some(Some("laptop".to_string())));
                assert_eq!(report_posture, Some(true));
                assert_eq!(webclient, Some(true));
                assert_eq!(exit_node_allow_lan_access, Some(true));
            }
            other => panic!("expected Set, got {other:?}"),
        }

        // `operator`/`nickname` are `double_option` for the same reason `exit_node` is (see the test
        // below): a present `null` is CLEAR, an absent key is UNCHANGED. Without it the clear form
        // (`--operator=`) would silently deserialize as a no-op.
        match serde_json::from_str::<Request>(r#"{"cmd":"set","operator":null,"nickname":null}"#)
            .expect("present nulls must parse")
        {
            Request::Set {
                operator, nickname, ..
            } => {
                assert_eq!(operator, Some(None), "present null → CLEAR");
                assert_eq!(nickname, Some(None), "present null → CLEAR");
            }
            other => panic!("expected Set, got {other:?}"),
        }
        match serde_json::from_str::<Request>(r#"{"cmd":"set"}"#).expect("bare set parses") {
            Request::Set {
                operator, nickname, ..
            } => {
                assert_eq!(operator, None, "absent → UNCHANGED, not clear");
                assert_eq!(nickname, None, "absent → UNCHANGED, not clear");
            }
            other => panic!("expected Set, got {other:?}"),
        }

        // BACK-COMPAT: an "unchanged" value stays OFF the wire, so a request from a newer CLI that
        // names none of these is byte-identical to what an older one sent.
        let bare = serde_json::to_value(Request::Set {
            hostname: None,
            accept_routes: None,
            accept_dns: None,
            shields_up: None,
            exit_node: None,
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            ssh: None,
            advertise_connector: None,
            auto_update: None,
            update_check: None,
            operator: None,
            nickname: None,
            report_posture: None,
            webclient: None,
            exit_node_allow_lan_access: None,
        })
        .unwrap();
        for key in ["operator", "nickname"] {
            assert!(
                bare.get(key).is_none(),
                "an unchanged {key} must be omitted from the wire entirely"
            );
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
            operator: None,
            exit_node_allow_lan_access: None,
            advertise_connector: None,
            report_posture: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
            client_id: None,
            client_secret: None,
            id_token: None,
            audience: None,
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
            operator: None,
            exit_node_allow_lan_access: None,
            advertise_connector: None,
            report_posture: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
            client_id: None,
            client_secret: None,
            id_token: None,
            audience: None,
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
            advertise_connector: None,
            auto_update: None,
            update_check: None,
            operator: None,
            nickname: None,
            report_posture: None,
            webclient: None,
            exit_node_allow_lan_access: None,
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
            advertise_connector: None,
            auto_update: None,
            update_check: None,
            operator: None,
            nickname: None,
            report_posture: None,
            webclient: None,
            exit_node_allow_lan_access: None,
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
