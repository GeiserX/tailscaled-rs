//! `tnet` — the thin CLI client.
//!
//! Carries no node logic: every command marshals a [`Request`] to the daemon's LocalAPI socket and
//! renders the [`Response`]. This mirrors how Tailscale's `tailscale` CLI is a thin front-end over
//! `tailscaled`'s LocalAPI.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use tailscaled_rs::localapi::{Request, Response, RevertedPref};

/// Env var consulted for the auth key when neither `--authkey` nor `--authkey-file` is given.
const AUTHKEY_ENV: &str = "TS_AUTH_KEY";

#[derive(Parser)]
#[command(name = "tnet", about = "Control client for the tailnetd daemon")]
struct Cli {
    /// Path to the daemon's LocalAPI socket (defaults to the daemon's resolved path).
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

// NB: neither `Cli` nor `Command` derives `Debug`. That is deliberate — it keeps the parsed
// `authkey` off any accidental `{:?}` / debug-log path. Keep it that way (the secret is held in a
// `SecretString` once resolved; see `resolve_authkey`).
#[derive(Subcommand)]
enum Command {
    /// Bring the node up and connect to the tailnet.
    Up {
        /// Pre-auth key for non-interactive registration. Exposes the key in argv/shell history;
        /// prefer `--authkey-file` or the `TS_AUTH_KEY` env var. Precedence:
        /// `--authkey-file` > `--authkey` > `$TS_AUTH_KEY`.
        /// (INSECURE: visible in `ps`/shell history — prefer --authkey-file or $TS_AUTH_KEY.)
        #[arg(long, conflicts_with = "authkey_file")]
        authkey: Option<String>,
        /// Read the pre-auth key from a file (avoids argv/shell-history exposure). Takes precedence
        /// over `--authkey`; if neither is given, falls back to `$TS_AUTH_KEY`.
        #[arg(long, value_name = "PATH")]
        authkey_file: Option<PathBuf>,
        /// Requested hostname.
        #[arg(long)]
        hostname: Option<String>,
        /// Control server URL override (e.g. a self-hosted Headscale). Applied to the engine on
        /// `up`; a malformed URL fails loudly rather than silently using the default. Changing it on
        /// a node that is already running requires `--force-reauth` (switching control servers is a
        /// fresh registration, not an in-place tweak) — the daemon refuses the change otherwise.
        #[arg(long)]
        control_url: Option<String>,
        /// Enable kernel-TUN mode (`TransportMode::Tun`) instead of the userspace netstack. Requires
        /// a daemon built with the `tun` feature and run as root; the daemon fails loudly otherwise.
        /// Mutually exclusive with `--no-tun`; omitting both leaves the persisted setting unchanged.
        #[arg(long, conflicts_with = "no_tun")]
        tun: bool,
        /// Disable kernel-TUN mode, forcing the userspace netstack. Mutually exclusive with `--tun`;
        /// omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_tun: bool,
        /// Desired TUN interface name (e.g. `tailscale0`); only meaningful with `--tun`.
        #[arg(long, value_name = "NAME")]
        tun_name: Option<String>,
        /// TUN interface MTU (Tailscale's overlay MTU is 1280); only meaningful with `--tun`.
        #[arg(long, value_name = "MTU")]
        tun_mtu: Option<u16>,
        /// Route this node's outbound traffic through a peer exit node, named by its tailnet IP or
        /// MagicDNS name (e.g. `100.64.0.9` or `exit-1`). Mutually exclusive with
        /// `--clear-exit-node`; omitting both leaves the persisted exit-node setting unchanged.
        /// (Automatic selection — Go's `--exit-node auto:any` — is not supported by this build; pass
        /// a concrete exit node.)
        #[arg(long, value_name = "IP|NAME", conflicts_with = "clear_exit_node")]
        exit_node: Option<String>,
        /// Stop routing through any exit node (clears the exit-node setting). Use this instead of an
        /// empty `--exit-node`, which clap can't tell apart from the flag being unset. Mutually
        /// exclusive with `--exit-node`.
        #[arg(long)]
        clear_exit_node: bool,
        /// Offer this node to the tailnet as an exit node (other nodes may route their traffic
        /// through it). Mutually exclusive with `--no-advertise-exit-node`; omitting both leaves the
        /// persisted setting unchanged.
        #[arg(long, conflicts_with = "no_advertise_exit_node")]
        advertise_exit_node: bool,
        /// Stop offering this node as an exit node. Mutually exclusive with
        /// `--advertise-exit-node`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_advertise_exit_node: bool,
        /// Advertise these subnet routes (comma-separated CIDRs, e.g.
        /// `192.168.1.0/24,10.0.0.0/8`) so other tailnet nodes can reach those subnets through this
        /// node. Replaces the whole advertised set. Use `--clear-advertise-routes` to advertise
        /// none; passing neither leaves the persisted set unchanged.
        #[arg(long, value_name = "CIDR,...", value_delimiter = ',')]
        advertise_routes: Vec<String>,
        /// Stop advertising any subnet routes (clears the advertised set). Use this instead of an
        /// empty `--advertise-routes`, since clap can't distinguish "advertise none" from the flag
        /// being unset.
        // `--clear-advertise-routes` is the canonical spelling (consistent with `--clear-exit-node`);
        // `--advertise-routes-clear` is kept as an alias for backward-compatibility.
        #[arg(long = "clear-advertise-routes", alias = "advertise-routes-clear")]
        advertise_routes_clear: bool,
        /// Advertise these ACL tags (comma-separated `tag:<name>`, e.g. `tag:server,tag:ci`) at
        /// registration (Go `--advertise-tags`). Replaces the whole set. Use `--clear-advertise-tags`
        /// to request none; passing neither leaves the persisted set unchanged.
        #[arg(long, value_name = "tag:NAME,...", value_delimiter = ',')]
        advertise_tags: Vec<String>,
        /// Stop advertising any ACL tags (clears the set). Use this instead of an empty
        /// `--advertise-tags`, since clap can't distinguish "request none" from the flag being unset.
        #[arg(long = "clear-advertise-tags")]
        advertise_tags_clear: bool,
        /// Accept (and route to) subnet routes advertised by peers (Go `tailscale up
        /// --accept-routes`). Mutually exclusive with `--no-accept-routes`; omitting both leaves the
        /// persisted setting unchanged.
        #[arg(long, conflicts_with = "no_accept_routes")]
        accept_routes: bool,
        /// Stop accepting subnet routes advertised by peers. Mutually exclusive with
        /// `--accept-routes`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_accept_routes: bool,
        /// Accept the tailnet's MagicDNS configuration (Go `tailscale up --accept-dns`; on by
        /// default). Mutually exclusive with `--no-accept-dns`; omitting both leaves the persisted
        /// setting unchanged.
        #[arg(long, conflicts_with = "no_accept_dns")]
        accept_dns: bool,
        /// Ignore the tailnet's MagicDNS configuration (keep the system resolver). Mutually exclusive
        /// with `--accept-dns`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_accept_dns: bool,
        /// Block incoming connections from other nodes (Go `tailscale up --shields-up`). Mutually
        /// exclusive with `--no-shields-up`; omitting both leaves the persisted setting unchanged.
        #[arg(long, conflicts_with = "no_shields_up")]
        shields_up: bool,
        /// Allow incoming connections from other nodes (default). Mutually exclusive with
        /// `--shields-up`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_shields_up: bool,
        /// Run the Tailscale SSH server on this node (accept tailnet SSH on port 22, authorized by
        /// the control SSH policy). Requires a daemon built with the `ssh` feature and run as root.
        /// Mutually exclusive with `--no-ssh`; omitting both leaves the setting unchanged.
        #[arg(long, conflicts_with = "no_ssh")]
        ssh: bool,
        /// Stop running the Tailscale SSH server on this node. Mutually exclusive with `--ssh`;
        /// omitting both leaves the setting unchanged.
        #[arg(long)]
        no_ssh: bool,
        /// Reset every setting this command does not mention back to its default (Go `tailscale up
        /// --reset`). By default `tnet up` refuses to silently revert a non-default setting you did
        /// not re-mention (it tells you to re-state it or pass `--reset`); `--reset` is how you opt
        /// into "anything I didn't mention goes back to default". This is the only form of `up` that
        /// is a true wholesale replace rather than a patch of just the flags you passed.
        #[arg(long)]
        reset: bool,
        /// Force re-authentication: discard this node's key and register fresh, surfacing a new login
        /// URL (Go `tailscale up --force-reauth`). WARNING: this may bring the Tailscale connection
        /// down while it re-registers, so do NOT run it remotely over SSH/RDP — you may lock yourself
        /// out. It changes no settings (your prefs are kept); it only forces a new login.
        #[arg(long)]
        force_reauth: bool,
        /// Register as an ephemeral node: control garbage-collects it shortly after it disconnects
        /// (Go `tailscale up --ephemeral`). Useful for short-lived CI jobs / containers. WARNING: an
        /// ephemeral node will NOT rejoin after a reboot without a fresh auth key (control will have
        /// GC'd it). Mutually exclusive with `--no-ephemeral`; omitting both leaves the setting
        /// unchanged. The default for a fresh node is PERSISTENT (survives reboots).
        #[arg(long, conflicts_with = "no_ephemeral")]
        ephemeral: bool,
        /// Register as a persistent node (the default): keeps its registration across reboots and
        /// resumes from its key alone. Mutually exclusive with `--ephemeral`; omitting both leaves the
        /// setting unchanged.
        #[arg(long)]
        no_ephemeral: bool,
        /// Wait up to this many seconds for the node to reach the Running state after bringing it up,
        /// then exit (Go `tailscale up --timeout`). On timeout, exits non-zero. Omitted = don't wait
        /// (return as soon as the daemon accepts the up); `0` = wait forever. Handy in scripts as
        /// `tnet up --authkey <KEY> --timeout 30 && start-my-service`. For an interactive (no-authkey)
        /// up the login URL is printed first, then the wait runs — so a short timeout may elapse
        /// before a human authorizes. NOTE: this takes integer SECONDS (`--timeout 30`); Go's flag is
        /// a duration string (`30s`), so a duration suffix is not accepted here.
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
        /// Pre-accept a named risk and skip its safety refusal (Go `--accept-risk`). Currently the one
        /// enforced risk is `lose-ssh`: `--force-reauth` over a Tailscale SSH session can drop that
        /// very session (it re-registers the node), so it is refused unless you pass
        /// `--accept-risk=lose-ssh` (or `--accept-risk=all`). Unlike Go's interactive y/N prompt, this
        /// daemon CLI refuses non-interactively — pass the flag to override.
        #[arg(long, value_name = "RISK")]
        accept_risk: Option<String>,
    },
    /// Tweak individual prefs on an already-configured node, without an up/down cycle (the analogue
    /// of Go's `tailscale set`). This never (re)authenticates and never changes whether the node is
    /// up — it only patches the prefs you name and reconciles the running engine. The exit-node
    /// change applies live (no reconnect); the others take effect on a running device or persist for
    /// the next `up` if the node is down. Omitting a flag leaves that pref unchanged; pass no flags
    /// and the daemon reports "no preferences specified".
    Set {
        /// Requested hostname. Omit to leave the persisted hostname unchanged.
        #[arg(long)]
        hostname: Option<String>,
        /// Accept (and route to) subnet routes advertised by peers. Mutually exclusive with
        /// `--no-accept-routes`; omitting both leaves the persisted setting unchanged.
        #[arg(long, conflicts_with = "no_accept_routes")]
        accept_routes: bool,
        /// Stop accepting subnet routes advertised by peers. Mutually exclusive with
        /// `--accept-routes`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_accept_routes: bool,
        /// Accept the tailnet's MagicDNS configuration (Go `tailscale set --accept-dns`). Mutually
        /// exclusive with `--no-accept-dns`; omitting both leaves the persisted setting unchanged.
        #[arg(long, conflicts_with = "no_accept_dns")]
        accept_dns: bool,
        /// Ignore the tailnet's MagicDNS configuration (keep the system resolver). Mutually exclusive
        /// with `--accept-dns`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_accept_dns: bool,
        /// Block incoming connections from other nodes. Mutually exclusive with `--no-shields-up`;
        /// omitting both leaves the persisted setting unchanged.
        #[arg(long, conflicts_with = "no_shields_up")]
        shields_up: bool,
        /// Allow incoming connections from other nodes (default). Mutually exclusive with
        /// `--shields-up`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_shields_up: bool,
        /// Route this node's outbound traffic through a peer exit node, named by its tailnet IP or
        /// MagicDNS name (e.g. `100.64.0.9` or `exit-1`). Applied live on a running node — no
        /// reconnect. Mutually exclusive with `--clear-exit-node`; omitting both leaves the persisted
        /// exit-node setting unchanged.
        #[arg(long, value_name = "IP|NAME", conflicts_with = "clear_exit_node")]
        exit_node: Option<String>,
        /// Stop routing through any exit node (clears the exit-node setting). Use this instead of an
        /// empty `--exit-node`, which clap can't tell apart from the flag being unset. Mutually
        /// exclusive with `--exit-node`.
        #[arg(long)]
        clear_exit_node: bool,
        /// Offer this node to the tailnet as an exit node (other nodes may route their traffic
        /// through it). Mutually exclusive with `--no-advertise-exit-node`; omitting both leaves the
        /// persisted setting unchanged.
        #[arg(long, conflicts_with = "no_advertise_exit_node")]
        advertise_exit_node: bool,
        /// Stop offering this node as an exit node. Mutually exclusive with
        /// `--advertise-exit-node`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_advertise_exit_node: bool,
        /// Advertise these subnet routes (comma-separated CIDRs, e.g.
        /// `192.168.1.0/24,10.0.0.0/8`) so other tailnet nodes can reach those subnets through this
        /// node. Replaces the whole advertised set. Use `--clear-advertise-routes` to advertise
        /// none; passing neither leaves the persisted set unchanged.
        #[arg(long, value_name = "CIDR,...", value_delimiter = ',')]
        advertise_routes: Vec<String>,
        /// Stop advertising any subnet routes (clears the advertised set). Use this instead of an
        /// empty `--advertise-routes`, since clap can't distinguish "advertise none" from the flag
        /// being unset.
        // `--clear-advertise-routes` is the canonical spelling (consistent with `--clear-exit-node`);
        // `--advertise-routes-clear` is kept as an alias for backward-compatibility.
        #[arg(long = "clear-advertise-routes", alias = "advertise-routes-clear")]
        advertise_routes_clear: bool,
        /// Advertise these ACL tags (comma-separated `tag:<name>`, e.g. `tag:server,tag:ci`) at
        /// registration (Go `--advertise-tags`). Replaces the whole set. Use `--clear-advertise-tags`
        /// to request none; passing neither leaves the persisted set unchanged.
        #[arg(long, value_name = "tag:NAME,...", value_delimiter = ',')]
        advertise_tags: Vec<String>,
        /// Stop advertising any ACL tags (clears the set). Use this instead of an empty
        /// `--advertise-tags`, since clap can't distinguish "request none" from the flag being unset.
        #[arg(long = "clear-advertise-tags")]
        advertise_tags_clear: bool,
        /// Run the Tailscale SSH server on this node (accept tailnet SSH on port 22, authorized by
        /// the control SSH policy). Requires a daemon built with the `ssh` feature and run as root.
        /// Mutually exclusive with `--no-ssh`; omitting both leaves the setting unchanged.
        #[arg(long, conflicts_with = "no_ssh")]
        ssh: bool,
        /// Stop running the Tailscale SSH server on this node. Mutually exclusive with `--ssh`;
        /// omitting both leaves the setting unchanged.
        #[arg(long)]
        no_ssh: bool,
        /// Pre-accept a named risk and skip its safety refusal (Go `--accept-risk`), e.g. `lose-ssh`
        /// or `all`. On `set` the enforced risk is `lose-ssh`: toggling the Tailscale SSH server
        /// (`--ssh`/`--no-ssh`) over a Tailscale SSH session reroutes/drops that session, so it is
        /// refused unless you pass `--accept-risk=lose-ssh`.
        #[arg(long, value_name = "RISK")]
        accept_risk: Option<String>,
    },
    /// Disconnect the node without logging out.
    Down,
    /// Log out: deregister this node from the control plane and discard its node key, so the next
    /// `up` registers as a fresh login (requires a new auth key / interactive login). Unlike `down`,
    /// which keeps the registration for a seamless reconnect, `logout` ends it. Mirrors Go
    /// `tailscale logout`.
    Logout,
    /// Switch between profiles (separate accounts/tailnets), or list/remove them. Mirrors Go
    /// `tailscale switch`. Each profile keeps its own prefs + node key; switching tears down the
    /// current connection and activates the target (run `tnet up` to connect it).
    Switch {
        /// List known profiles (with a `*` marking the current one) instead of switching.
        #[arg(long)]
        list: bool,
        /// The profile id to switch to (omit with `--list`). Ignored when `--list` is given.
        #[arg(value_name = "PROFILE")]
        target: Option<String>,
        #[command(subcommand)]
        cmd: Option<SwitchCmd>,
    },
    /// Print the version of this client (and, with `--daemon`, the running daemon). Mirrors Go
    /// `tailscale version`.
    Version {
        /// Also query and print the running daemon's version (Go `--daemon`). Without it, `version`
        /// answers purely locally and never contacts the daemon.
        #[arg(long)]
        daemon: bool,
        /// Output as JSON, in the shape of Go's `version.Meta`: `majorMinorPatch`/`short`/`long`/`cap`
        /// always, plus `unstableBranch` (when the minor is odd) and `daemonLong` (with `--daemon`).
        /// Git-stamp fields (`gitCommit`/`gitDirty`/…) are honestly omitted — the fork is not
        /// git-stamped. Mirrors Go `--json`.
        #[arg(long)]
        json: bool,
        /// Check for a newer upstream release (Go `--upstream`). This build does not fetch from any
        /// release server, so it returns "fetching latest version not supported in this build" and
        /// exits non-zero — faithful to Go's behavior when upstream-checking is unavailable.
        #[arg(long)]
        upstream: bool,
    },
    /// Show current preference values (Go `tailscale get`). With no setting name, shows all prefs;
    /// with a name (e.g. `accept-routes`), shows just that one. Setting names match the `tnet set`
    /// flags.
    Get {
        /// A single setting to show (e.g. `accept-routes`, `exit-node`, `ssh`); omit (or `all`) to
        /// show every setting.
        #[arg(value_name = "SETTING")]
        setting: Option<String>,
        /// Output as JSON (a flattened `{ "setting-name": value }` map, matching Go `get --json`).
        #[arg(long, conflicts_with = "set_flags")]
        json: bool,
        /// Output every setting as a single re-appliable `tnet set …` flag-argument line (Go
        /// `get --set-flags`), e.g. `--accept-routes=true --hostname=node-a …`. Mutually exclusive
        /// with `--json`; a single-`SETTING` query is ignored for this mode (it emits all flags).
        #[arg(long)]
        set_flags: bool,
    },
    /// Show daemon and netmap status.
    Status {
        /// Stream status continuously, re-printing on every state transition, until interrupted
        /// (Ctrl-C). Like `tailscale status --watch`.
        #[arg(long)]
        watch: bool,
        /// Output as JSON, in the shape of Go's `ipnstate.Status` (a faithful subset). Mirrors
        /// `tailscale status --json`.
        #[arg(long)]
        json: bool,
        /// Show only active peers (Go `--active`). NOTE: Go's "active" means recent traffic; this
        /// fork has no per-peer traffic signal, so it approximates it with the peer's *online*
        /// (control-plane-connected) state — peers with unknown liveness are hidden.
        #[arg(long)]
        active: bool,
        /// Hide the peer list (Go `--peers=false`). Use `--no-peers`.
        #[arg(long = "no-peers")]
        no_peers: bool,
        /// Hide this node's own line/object (Go `--self=false`). Use `--no-self`.
        #[arg(long = "no-self")]
        no_self: bool,
        /// Serve an HTML status page from an embedded web server instead of printing (Go `tailscale
        /// status --web`). Runs until interrupted (Ctrl-C); each page load reflects the live status.
        /// Mutually exclusive with `--json`/`--watch`.
        #[arg(long, conflicts_with_all = ["json", "watch"])]
        web: bool,
        /// In `--web` mode, the address to listen on (Go `--listen`, default `127.0.0.1:8384`; use a
        /// `:0` port for an automatic free port). Ignored without `--web`.
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
        /// In `--web` mode, do NOT open a browser at the served URL (Go's `--browser=false`; the
        /// browser opens by default). Ignored without `--web`.
        #[arg(long)]
        no_browser: bool,
    },
    /// Block until the node is connected (state `Running` with a tailnet IP), then exit 0. Mirrors
    /// Go `tailscale wait` — handy in scripts as `tnet wait && start-my-service`.
    Wait {
        /// How long to wait, in seconds, before giving up (omitted / `0` = wait forever). On
        /// timeout, exits non-zero.
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
    },
    /// Show the machine + user identity of THIS node (Go `tailscale whoami`): equivalent to
    /// `tnet whois` against the node's own tailnet IP.
    Whoami {
        /// Output as JSON (the whois record for this node).
        #[arg(long)]
        json: bool,
    },
    /// Show tailnet IP addresses — this node's by default, or a peer's if named. Mirrors Go
    /// `tailscale ip`.
    Ip {
        /// Show only the IPv4 address (Go `-4`). Mutually exclusive with `-6`.
        #[arg(short = '4', conflicts_with = "v6")]
        v4: bool,
        /// Show only the IPv6 address (Go `-6`). Mutually exclusive with `-4`.
        #[arg(short = '6')]
        v6: bool,
        /// Show only the first/primary address (Go `-1`).
        #[arg(short = '1')]
        first: bool,
        /// A peer (by MagicDNS name or IP) whose address to show instead of this node's. Resolved
        /// against the current netmap (the peer set `status` reports).
        #[arg(value_name = "PEER")]
        peer: Option<String>,
    },
    /// Show which tailnet node owns an IP address.
    Whois {
        /// The tailnet IP to resolve to its owning node.
        #[arg(value_name = "IP")]
        ip: String,
    },
    /// Fetch an OIDC id-token for this node, scoped to an audience (Go `tailscale id-token <aud>`).
    /// Control mints a signed JWT identifying this machine; prints the raw token. Requires the node
    /// to be up and a control server new enough to issue id-tokens.
    #[command(name = "id-token")]
    IdToken {
        /// The OIDC audience (the token's `aud` claim) — typically the URL/identifier of the service
        /// that will verify the token.
        #[arg(value_name = "AUDIENCE")]
        audience: String,
    },
    /// Ping a tailnet peer over the overlay and report the round-trip time (Go `tailscale ping`).
    ///
    /// By default this stops after 10 pings OR as soon as a **direct** (non-DERP) path is
    /// established, whichever comes first — matching Go. Each result line reports the path the pong
    /// took: `via <ip:port>` for a direct connection, `via DERP` when the overlay is still relayed.
    Ping {
        /// The tailnet IP of the peer to ping.
        #[arg(value_name = "IP")]
        ip: String,
        /// Per-attempt timeout in milliseconds (omit for a sensible default).
        #[arg(long, value_name = "MS")]
        timeout: Option<u64>,
        /// Max number of pings to send (Go `-c`). Default 10; `0` means infinity (ping until a direct
        /// path is established, or forever if `--no-until-direct`). Prints one result line per
        /// attempt, then a summary; a failed attempt is counted but does not abort the rest.
        #[arg(short = 'c', long, value_name = "N", default_value_t = 10)]
        count: u32,
        /// Stop once a direct (non-DERP) path is established (Go `--until-direct`, **on by default**).
        /// A new node usually starts out DERP-relayed and upgrades to a direct path within a few
        /// pings; with this on, `ping` returns as soon as that happens. Mutually exclusive with
        /// `--no-until-direct`.
        #[arg(long, conflicts_with = "no_until_direct")]
        until_direct: bool,
        /// Keep pinging for the full count even after a direct path is established (disables the
        /// default `--until-direct` early stop). Mutually exclusive with `--until-direct`.
        #[arg(long)]
        no_until_direct: bool,
    },
    /// Send and receive files over Taildrop (Go `tailscale file`).
    File {
        #[command(subcommand)]
        cmd: FileCmd,
    },
    /// Print this node's client metrics in Prometheus text format (Go `tailscale metrics`). With
    /// `write <path>`, writes them to a file instead of stdout.
    Metrics {
        #[command(subcommand)]
        cmd: Option<MetricsCmd>,
    },
    /// Print open-source license information (Go `tailscale licenses`). Local-only — contacts no
    /// daemon. This fork's own license + where to find the dependency licenses.
    Licenses,
    /// Tailnet Lock (TKA) commands. Currently `status` (read-only): whether lock is in use, the
    /// authority head, and any pending disablement. Mirrors Go `tailscale lock status`.
    Lock {
        #[command(subcommand)]
        cmd: LockCmd,
    },
    /// DNS commands. Currently `status` (read-only): the control-pushed MagicDNS configuration —
    /// MagicDNS on/off, resolvers in preference order, split-DNS routes, search/cert domains, extra
    /// records, and exit-node-filtered suffixes. Mirrors Go `tailscale dns status`.
    Dns {
        #[command(subcommand)]
        cmd: DnsCmd,
    },
    /// Show this node's network-conditions report (Go `tailscale netcheck`): the nearest (preferred)
    /// DERP region and the per-region DERP latency, lowest first. NOTE: this build's net-report
    /// measures DERP-region latency ONLY — Go's UDP/IPv4/IPv6/MappingVariesByDestIP/PortMapping flags
    /// are not measured, and DERP regions are shown by id (the engine carries no region name).
    Netcheck {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Exit-node commands. `list` shows tailnet peers offering to be exit nodes. Mirrors Go
    /// `tailscale exit-node`.
    #[command(name = "exit-node")]
    ExitNode {
        #[command(subcommand)]
        cmd: ExitNodeCmd,
    },
    /// Print a shareable diagnostic marker for bug reports (Go `tailscale bugreport`). NOTE: this
    /// fork uploads no logs — the marker is a LOCAL identifier (id + daemon version + state) to quote
    /// when reporting an issue, not a server-retrievable log id.
    Bugreport {
        /// An optional note (Go `bugreport [note]`) appended to the marker — e.g. a short description
        /// of what went wrong. Control characters are stripped so the marker stays one clean token.
        #[arg(value_name = "NOTE")]
        note: Option<String>,
    },
    /// Provision a TLS certificate + key for a tailnet domain via ACME (Go `tailscale cert`). The
    /// domain must be one of your tailnet's cert domains (`tnet dns status` lists them). Requires a
    /// daemon built with the `acme` feature; without it the command fails with a clear error rather
    /// than emitting a self-signed cert. By default writes `DOMAIN.crt` + `DOMAIN.key` in the current
    /// directory; override the paths with `--cert-file`/`--key-file`, or pass `-` for either to write
    /// that PEM to stdout instead.
    Cert {
        /// The DNS name to certify (one of the tailnet's cert domains).
        #[arg(value_name = "DOMAIN")]
        domain: String,
        /// Output path for the cert (leaf + chain) PEM, or `-` for stdout. Defaults to `DOMAIN.crt`
        /// when neither `--cert-file` nor `--key-file` is given.
        #[arg(long, value_name = "PATH")]
        cert_file: Option<String>,
        /// Output path for the private-key PEM, or `-` for stdout. Defaults to `DOMAIN.key` when
        /// neither `--cert-file` nor `--key-file` is given. Written with `0600` permissions.
        #[arg(long, value_name = "PATH")]
        key_file: Option<String>,
    },
    /// Connect to a TCP port on a tailnet host and pipe stdin/stdout over the overlay (Go `tailscale
    /// nc`). Like netcat: bytes from stdin go to the peer, the peer's bytes go to stdout, until EOF.
    Nc {
        /// Destination host: a tailnet IP or MagicDNS name.
        #[arg(value_name = "HOST")]
        host: String,
        /// Destination TCP port.
        #[arg(value_name = "PORT")]
        port: u16,
    },
    /// Expose a local service on the tailnet (Go `tailscale serve`): `tcp` (raw TCP forward, the
    /// daemon's own accept loop) and `https`/`http` (web reverse-proxy, terminated + served by the
    /// engine for the node's MagicDNS name). HTTPS issuance needs the `acme` feature + a SaaS tailnet.
    Serve {
        #[command(subcommand)]
        cmd: ServeCmd,
    },
    /// Expose a tailnet port to the PUBLIC internet via Tailscale Funnel (Go `tailscale funnel`).
    /// `funnel <port> on` enables Funnel for a port; `off` disables it. Configure `serve https <port>
    /// <target>` so there is a proxy backend to expose (order doesn't matter — the funnel lane picks up
    /// whatever serve exists). The node must have Funnel enabled for the tailnet (the `https` +
    /// `funnel` node attributes) and the port must be Funnel-allowed; the public ingress path needs a
    /// real Tailscale SaaS tailnet (a self-hosted control plane has no ingress relay).
    Funnel {
        /// The tailnet port to expose (must already have a `serve https`/`http` handler).
        #[arg(value_name = "PORT")]
        port: u16,
        /// `on` to enable Funnel for the port, `off` to disable it.
        #[arg(value_name = "ON_OFF", value_parser = ["on", "off"])]
        on_off: String,
    },
    /// Debugging tools (Go `tailscale debug`).
    Debug {
        #[command(subcommand)]
        cmd: DebugCmd,
    },
    /// Install tailnetd as a system service (systemd/launchd) that starts at boot. Requires root.
    Install,
    /// Remove the tailnetd system service. Requires root; leaves node state.
    Uninstall,
}

/// `tnet debug` subcommands (Go `tailscale debug`).
#[derive(Subcommand)]
enum DebugCmd {
    /// Capture the dataplane's plaintext packets to a pcap file (Go `tailscale debug capture`). The
    /// file is a classic pcap (link-type USER0 + Tailscale's per-packet path preamble) — open it in
    /// Wireshark, with Tailscale's `ts-dissector.lua` for per-packet direction. Captures for
    /// `--seconds`, then stops.
    Capture {
        /// Local path to write the pcap to (a fresh path, or an existing regular file to overwrite).
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// How long to capture before stopping, in seconds.
        #[arg(long, default_value_t = 10)]
        seconds: u64,
    },
    /// Dump the node's current preferences as JSON (Go `tailscale debug prefs`). A read-only view of
    /// the persisted prefs — the same data `tnet get` renders, but as the raw pretty-printed object
    /// for scripting/debugging rather than the human/flag view.
    Prefs,
}

/// `tnet serve` subcommands. Mirrors the TCP-forward subset of Go `tailscale serve`.
#[derive(Subcommand)]
enum ServeCmd {
    /// Forward a tailnet TCP port to a local address (Go `serve --tcp <port> <target>`). Inbound
    /// connections on tailnet `<PORT>` are spliced to `<TARGET>` (`host:port`, or a bare port meaning
    /// `127.0.0.1:<port>`).
    Tcp {
        /// The tailnet port to listen on.
        #[arg(value_name = "PORT")]
        port: u16,
        /// Local forward target: `host:port`, or a bare port for `127.0.0.1:<port>`.
        #[arg(value_name = "TARGET")]
        target: String,
    },
    /// Serve HTTPS on a tailnet port, reverse-proxying to a local backend (Go `serve --https`). The
    /// engine terminates TLS for this node's MagicDNS name and proxies each request to `<TARGET>`.
    /// Requires the daemon's `acme` feature + a Funnel/HTTPS-enabled SaaS tailnet to issue the cert;
    /// otherwise the engine fails closed (no plaintext) and `serve status` shows it as not yet active.
    Https {
        /// The tailnet port to terminate TLS on.
        #[arg(value_name = "PORT")]
        port: u16,
        /// What to serve: a proxy backend (`host:port`, or a bare port for `127.0.0.1:<port>`), or
        /// `text:<body>` to serve a fixed plaintext body (Go `serve` `text:` target).
        #[arg(value_name = "TARGET")]
        target: String,
        /// Mount the handler at this URL path prefix instead of `/` (Go `serve --set-path`). With
        /// multiple mounts on one port the longest-matching prefix wins (unmatched = 404).
        #[arg(long = "set-path", value_name = "MOUNT")]
        set_path: Option<String>,
    },
    /// Serve HTTP on a tailnet port, reverse-proxying to a local backend (Go `serve --http`). Like
    /// [`Https`](ServeCmd::Https) but records HTTP intent; the engine reverse-proxies via the same
    /// native serve path.
    Http {
        /// The tailnet port to serve on.
        #[arg(value_name = "PORT")]
        port: u16,
        /// What to serve: a proxy backend (`host:port`, or a bare port for `127.0.0.1:<port>`), or
        /// `text:<body>` to serve a fixed plaintext body.
        #[arg(value_name = "TARGET")]
        target: String,
        /// Mount the handler at this URL path prefix instead of `/` (Go `serve --set-path`).
        #[arg(long = "set-path", value_name = "MOUNT")]
        set_path: Option<String>,
    },
    /// Serve an HTTP redirect on a tailnet port (engine-backed extension — Go's CLI has no redirect
    /// path at v1.100.0, but the engine serves it). TLS-terminated like `https`.
    Redirect {
        /// The tailnet port to terminate TLS on and redirect from.
        #[arg(value_name = "PORT")]
        port: u16,
        /// The `Location:` target to redirect to (supports the engine's `${HOST}` / `${REQUEST_URI}`).
        #[arg(value_name = "TO")]
        to: String,
        /// The redirect HTTP status (must be in 300..=399). Defaults to 302.
        #[arg(value_name = "STATUS", default_value_t = 302)]
        status: u16,
    },
    /// Show the current serve configuration.
    Status {
        /// Output as JSON (the raw ServeConfig).
        #[arg(long)]
        json: bool,
    },
    /// Clear the entire serve configuration.
    Reset,
}

/// `tnet metrics` subcommands. Bare `tnet metrics` prints to stdout; `print` is the explicit
/// stdout form (Go `tailscale metrics print`); `write <path>` writes a file.
#[derive(Subcommand)]
enum MetricsCmd {
    /// Print the metrics to stdout (Go `tailscale metrics print`) — the explicit form of bare
    /// `tnet metrics`.
    Print,
    /// Write the metrics to a file instead of stdout.
    Write {
        /// Destination path.
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
}

/// `tnet lock` subcommands.
#[derive(Subcommand)]
enum LockCmd {
    /// Show Tailnet Lock status (read-only).
    Status {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// `tnet dns` subcommands. Currently just `status`; structured as a subcommand group to leave room
/// for future DNS subcommands (e.g. `query`).
#[derive(Subcommand)]
enum DnsCmd {
    /// Show the control-pushed MagicDNS configuration (read-only).
    Status {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// `tnet exit-node` subcommands.
#[derive(Subcommand)]
enum ExitNodeCmd {
    /// List tailnet peers offering to be exit nodes.
    List,
}

/// The `tnet switch` subcommands. Mirrors Go's `tailscale switch remove`.
#[derive(Subcommand)]
enum SwitchCmd {
    /// Remove a profile (delete its prefs + node key). Cannot remove the current or default profile.
    Remove {
        /// The profile id to remove.
        #[arg(value_name = "PROFILE")]
        target: String,
    },
}

/// The `tnet file` subcommands (Taildrop). Mirrors Go's `tailscale file cp` / `file get`. Like
/// `Command`, this deliberately does not derive `Debug` (it travels alongside `Command` through the
/// same parse path; keeping the choice uniform avoids reintroducing a debug-print surface).
#[derive(Subcommand)]
enum FileCmd {
    /// Send local files to a tailnet peer via Taildrop (Go `tailscale file cp <files...> <target>:`).
    ///
    /// The final argument is the destination peer and MUST end in a colon (`peer-b:`,
    /// `100.64.0.9:`, or `[fd7a::1]:` for an IPv6 literal) — matching Go, which uses the trailing
    /// colon to disambiguate a peer from a file path. One or more files may precede it. With
    /// `--targets` (and no files/target), instead lists the peers you can send to.
    ///
    /// NOTE: unlike Go, this build does NOT support `-` (stdin) as a file — the daemon opens each
    /// path itself (tnet + tailnetd are same-host/same-user), so there is no stdin to hand it; pass a
    /// real file path. Streaming stdin over the LocalAPI is a tracked follow-up.
    Cp {
        /// The files to send, followed by the destination `<peer>:` (trailing colon required). Empty
        /// only when `--targets` is given. `-` (stdin) is not supported by this build.
        #[arg(value_name = "FILES... TARGET:")]
        args: Vec<String>,
        /// Destination filename override (Go `--name`): with a single explicit file, send it under
        /// this name instead of its base name. Cannot be combined with multiple files. (Go also uses
        /// `--name` to name stdin content, but this build does not support stdin.)
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Instead of sending, list the tailnet peers you can Taildrop to (Go `file cp --targets` /
        /// the `file-targets` LocalAPI): one line per peer — its tailnet IP, name, and online status.
        #[arg(long)]
        targets: bool,
    },
    /// List files waiting in the Taildrop inbox.
    List,
    /// Receive waiting Taildrop files. Two shapes:
    ///
    /// * `get <target-directory>` — drain the ENTIRE inbox into a directory (the Go-faithful
    ///   `tailscale file get <dir>`). Use `--conflict` to choose what happens when a same-named file
    ///   already exists. The special target `/dev/null` wipes the inbox without writing anything.
    /// * `get <name> <dest>` — fetch ONE named waiting file (from `tnet file list`) to an exact path
    ///   (a fork convenience; not a Go command shape).
    ///
    /// Which one runs is decided by the argument count: one positional = directory drain, two = the
    /// single-file fetch.
    Get {
        /// The target directory to drain into, OR (when a second positional is given) the waiting
        /// file's base name to fetch.
        #[arg(value_name = "TARGET")]
        target: String,
        /// Optional. When present, switches to single-file mode: the local destination path to write
        /// the file named by `TARGET` to.
        #[arg(value_name = "DEST")]
        dest: Option<String>,
        /// Directory-drain mode only: what to do when a same-named file already exists in the target
        /// directory (Go `--conflict`). `skip` (default) never overwrites — it leaves the file in the
        /// inbox and reports it; `overwrite` replaces the existing file (removing it first, so a
        /// planted symlink is never followed); `rename` keeps both by writing a numbered variant
        /// (`name (1).ext`). Ignored in single-file (`get <name> <dest>`) mode.
        #[arg(long, value_enum, default_value_t = ConflictArg::Skip)]
        conflict: ConflictArg,
        /// Single-file mode only: delete the file from the inbox after a successful fetch. (The
        /// directory-drain mode always removes received files from the inbox, like Go.)
        #[arg(long)]
        delete_after: bool,
    },
}

/// CLI surface for the `--conflict` flag (Go `onConflict`). Maps to the wire
/// [`ConflictPolicy`](tailscaled_rs::localapi::ConflictPolicy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ConflictArg {
    /// Never overwrite: leave a conflicting file in the inbox and report it (the safe default).
    Skip,
    /// Replace an existing file (removed first, so a symlink at the name is not followed).
    Overwrite,
    /// Keep both: write a Chrome-style numbered variant, `name (1).ext`.
    Rename,
}

impl From<ConflictArg> for tailscaled_rs::localapi::ConflictPolicy {
    fn from(a: ConflictArg) -> Self {
        use tailscaled_rs::localapi::ConflictPolicy;
        match a {
            ConflictArg::Skip => ConflictPolicy::Skip,
            ConflictArg::Overwrite => ConflictPolicy::Overwrite,
            ConflictArg::Rename => ConflictPolicy::Rename,
        }
    }
}

/// Map the `--exit-node` / `--clear-exit-node` flag pair to the wire field's double `Option`.
/// `--exit-node <sel>` → `Some(Some(sel))` (set it); `--clear-exit-node` → `Some(None)` (stop using
/// an exit node); neither → `None` (leave the persisted pref unchanged). A set value wins if both
/// somehow arrive, though clap's `conflicts_with` already guarantees they are never both present.
fn resolve_exit_node(set: Option<String>, clear: bool) -> Option<Option<String>> {
    match (set, clear) {
        (Some(s), _) => Some(Some(s)),
        (_, true) => Some(None),
        _ => None,
    }
}

/// Map the `--accept-routes` / `--no-accept-routes` flag pair to a tri-state `Option<bool>`.
/// Enable → `Some(true)`; disable → `Some(false)`; neither → `None` (leave the persisted pref
/// unchanged). Mirrors the `--tun`/`--no-tun` mapping; clap's `conflicts_with` guarantees the two
/// are never both set.
fn resolve_accept_routes(accept: bool, no_accept: bool) -> Option<bool> {
    match (accept, no_accept) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Map the `--accept-dns` / `--no-accept-dns` flag pair to a tri-state `Option<bool>`.
/// Enable → `Some(true)`; disable → `Some(false)`; neither → `None` (leave the persisted pref
/// unchanged). clap's `conflicts_with` guarantees the two are never both set.
fn resolve_accept_dns(accept: bool, no_accept: bool) -> Option<bool> {
    match (accept, no_accept) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Map the `--ephemeral` / `--no-ephemeral` flag pair to a tri-state `Option<bool>`.
/// Enable → `Some(true)`; disable → `Some(false)`; neither → `None` (leave the persisted pref
/// unchanged). clap's `conflicts_with` guarantees the two are never both set.
fn resolve_ephemeral(ephemeral: bool, no_ephemeral: bool) -> Option<bool> {
    match (ephemeral, no_ephemeral) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Resolve the `--until-direct` / `--no-until-direct` flag pair into a plain `bool`, **defaulting to
/// `true`** to match Go's `tailscale ping` (where `--until-direct` is a bool flag that defaults
/// true). Unlike the prefs toggles this is NOT tri-state: there is no "leave unchanged" — every ping
/// invocation needs a concrete stop policy, and the Go default is "stop once direct". `--until-direct`
/// → `true`; `--no-until-direct` → `false`; neither → `true` (the default). clap's `conflicts_with`
/// guarantees the two are never both set. Pure → unit-testable.
fn resolve_until_direct(until_direct: bool, no_until_direct: bool) -> bool {
    match (until_direct, no_until_direct) {
        // `--no-until-direct` explicitly turns the early-stop off (ping the full count).
        (_, true) => false,
        // `--until-direct` explicitly turns it on (redundant with the default, but a user may pass it).
        (true, _) => true,
        // Neither flag → Go's default: stop once a direct path is established.
        (false, false) => true,
    }
}

/// Parse and validate a `file cp` destination argument into the bare peer selector (IP or MagicDNS
/// name), enforcing Go's `runCp` rules:
///
/// - The argument MUST end in a colon (`peer-b:`, `100.64.0.9:`) — Go uses the trailing colon to
///   tell a destination apart from a file path; a missing colon is an error.
/// - An IPv6 literal MUST be bracketed (`[fd7a::1]:`); a bare `fd7a::1:` is rejected with Go's
///   "an IPv6 literal must be written as [..]" guidance. Brackets are only valid around an actual
///   IPv6 literal (Go rejects `[peer-b]:` / `[1.2.3.4]:`).
///
/// Returns the inner selector with the colon (and any brackets) stripped. Pure → unit-testable
/// without a daemon. Mirrors `cmd/tailscale/cli/file.go` `runCp`.
fn parse_cp_target(arg: &str) -> Result<String> {
    let target = arg.strip_suffix(':').ok_or_else(|| {
        anyhow::anyhow!("final argument to 'file cp' must end in a colon (e.g. {arg}:)")
    })?;

    let had_brackets = target.starts_with('[') && target.ends_with(']');
    let inner = if had_brackets {
        &target[1..target.len() - 1]
    } else {
        target
    };

    // An empty peer (`:` or `[]:`) can't resolve — reject at the CLI with a clear message rather than
    // sending `""` to the daemon for a less-precise "no peer matches" round-trip.
    if inner.is_empty() {
        anyhow::bail!("empty peer in 'file cp' target (expected e.g. `peer-b:`)");
    }

    // Bracket/IPv6 consistency, mirroring Go: a bare IPv6 literal must be bracketed, and brackets are
    // only valid around an actual IPv6 literal.
    match inner.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(ip)) if !had_brackets => {
            anyhow::bail!("an IPv6 literal must be written as [{ip}]");
        }
        _ if had_brackets && !matches!(inner.parse(), Ok(std::net::IpAddr::V6(_))) => {
            anyhow::bail!("unexpected brackets around target {target:?}");
        }
        _ => {}
    }
    Ok(inner.to_string())
}

/// Map the `--shields-up` / `--no-shields-up` flag pair to a tri-state `Option<bool>`.
/// Enable → `Some(true)`; disable → `Some(false)`; neither → `None` (leave the persisted pref
/// unchanged). Mirrors the `--tun`/`--no-tun` mapping; clap's `conflicts_with` guarantees the two
/// are never both set.
fn resolve_shields_up(shields_up: bool, no_shields_up: bool) -> Option<bool> {
    match (shields_up, no_shields_up) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Map the `--tun` / `--no-tun` flag pair to a tri-state `Option<bool>` — enable → `Some(true)`,
/// disable → `Some(false)`, neither → `None` (leave the persisted pref unchanged). A named helper
/// for symmetry with the other tri-state resolvers (`resolve_accept_routes` / `resolve_ssh` / …),
/// rather than inlining the same `match` at the call site. clap's `conflicts_with` guarantees the
/// two flags are never both set.
fn resolve_tun(tun: bool, no_tun: bool) -> Option<bool> {
    match (tun, no_tun) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Map the `--advertise-exit-node` / `--no-advertise-exit-node` flag pair to a tri-state
/// `Option<bool>`. Enable → `Some(true)`; disable → `Some(false)`; neither → `None` (leave the
/// persisted pref unchanged). Mirrors the `--tun`/`--no-tun` mapping; clap's `conflicts_with`
/// guarantees the two are never both set.
fn resolve_advertise_exit_node(advertise: bool, no_advertise: bool) -> Option<bool> {
    match (advertise, no_advertise) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Map the `--ssh` / `--no-ssh` flag pair to a tri-state `Option<bool>`. Enable → `Some(true)` (run
/// the Tailscale SSH server); disable → `Some(false)`; neither → `None` (leave the persisted pref
/// unchanged). Mirrors the `--tun`/`--no-tun` mapping; clap's `conflicts_with` guarantees the two
/// are never both set.
fn resolve_ssh(ssh: bool, no_ssh: bool) -> Option<bool> {
    match (ssh, no_ssh) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Whether `ip` is a Tailscale-assigned address — the Rust analogue of Go `tsaddr.IsTailscaleIP`.
/// CGNAT `100.64.0.0/10` **minus** the ChromeOS-VM subrange `100.115.92.0/23` (Go excludes it —
/// `IsTailscaleIPv4 = CGNATRange.Contains && !ChromeOSVMRange.Contains`), plus the Tailscale ULA
/// `fd7a:115c:a1e0::/48`. Used by the risk gate to decide whether an SSH session originates from the
/// tailnet (a `--force-reauth` then risks dropping that very session). Pure → unit-testable.
fn is_tailscale_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            // CGNAT 100.64.0.0/10: octet0 == 100 AND octet1's top two bits == 0b01 (64..=127).
            let in_cgnat = o[0] == 100 && (o[1] & 0xc0) == 0x40;
            // ChromeOS-VM 100.115.92.0/23: 100.115.{92,93}.x — excluded from the Tailscale set.
            let in_chromeos_vm = o[0] == 100 && o[1] == 115 && (o[2] == 92 || o[2] == 93);
            in_cgnat && !in_chromeos_vm
        }
        // Tailscale ULA fd7a:115c:a1e0::/48 — match the full /48 (all three leading segments).
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
        }
    }
}

/// Whether an `SSH_CLIENT` value denotes a session whose client is a Tailscale IP — the Rust analogue
/// of Go's `isSSHOverTailscale()`. `SSH_CLIENT` is `<client-ip> <client-port> <server-port>`; take the
/// first space-separated token, parse it, and test it with [`is_tailscale_ip`]. An empty or
/// unparseable value (or a non-tailnet client) → false. Split out from [`is_ssh_over_tailscale`] so it
/// is testable without mutating the process environment. Pure.
fn ssh_client_is_tailscale(ssh_client: &str) -> bool {
    // `split_once(' ')` mirrors Go's `strings.Cut(sshClient, " ")` + its `!ok` (no-space) → false:
    // a well-formed SSH_CLIENT is always `<ip> <client-port> <server-port>`, so a value with no space
    // is malformed and rejected (rather than parsing a bare IP).
    let Some((ip_str, _rest)) = ssh_client.split_once(' ') else {
        return false;
    };
    ip_str
        .parse::<std::net::IpAddr>()
        .map(is_tailscale_ip)
        .unwrap_or(false)
}

/// Whether this CLI is running over a Tailscale-SSH session (Go `isSSHOverTailscale`): reads
/// `$SSH_CLIENT` and delegates to [`ssh_client_is_tailscale`]. Reads the process environment, so it is
/// not pure — but the decision logic it wraps is. (Go additionally walks `/proc/<sid>/environ` under
/// sudo; this fork reads only `$SSH_CLIENT`. Concretely: `sudo` strips `SSH_CLIENT` from the
/// environment, so `sudo tnet up --force-reauth` over a Tailscale SSH session will NOT be refused
/// here even though Go's would. That is the fail-*open* direction — the gate is advisory, not a
/// security boundary (the operator can always bypass it with `--accept-risk` anyway), so a missed
/// refusal costs only a warning, and the lock-out it guards against is recoverable out-of-band.)
fn is_ssh_over_tailscale() -> bool {
    std::env::var("SSH_CLIENT")
        .map(|c| ssh_client_is_tailscale(&c))
        .unwrap_or(false)
}

/// Whether a named `risk` is in the operator's `--accept-risk` value — the Rust analogue of Go's
/// `isRiskAccepted`: split on `,` and accept if any token equals the risk name or the catch-all `all`.
/// Like Go, tokens are matched **raw** (NOT trimmed): Go compares `strings.SplitSeq(accepted, ",")`
/// members verbatim, so `--accept-risk="foo, lose-ssh"` does NOT accept `lose-ssh` there (the token is
/// `" lose-ssh"`); use `foo,lose-ssh` (no spaces) or `all`. Matching Go is the safer default for a
/// safety gate (fewer accidental accepts). Pure.
fn risk_accepted(accepted: &str, risk: &str) -> bool {
    accepted.split(',').any(|r| r == risk || r == "all")
}

/// The pure decision behind the SSH-server-toggle `lose-ssh` risk — the Rust analogue of Go's
/// `presentSSHToggleRisk` (`up.go`). Returns the *direction* of a refusal, or `None` to allow:
/// - `None` (allow) when the toggle isn't mentioned (`want` is `None`), or we're not over a Tailscale
///   SSH session (`!over_ssh`), or the operator pre-accepted the risk (`lose-ssh`/`all`), or the
///   toggle is a no-op (`want == Some(have)`) — Go's `!isSSHOverTailscale() || wantSSH == haveSSH`.
/// - `Some(true)` when ENABLING the SSH server (`want = Some(true)`, `have = false`) — Go reroutes SSH
///   traffic to Tailscale SSH and the current session disconnects.
/// - `Some(false)` when DISABLING it (`want = Some(false)`, `have = true`) — the session over Tailscale
///   SSH disconnects.
///
/// Pure (no I/O), so the branch logic is unit-testable; the async [`refuse_ssh_toggle_risk_if_needed`]
/// supplies `over_ssh` (the env probe) + `have` (a `GetPrefs` round-trip) and renders the message.
fn ssh_toggle_refusal(
    want: Option<bool>,
    have: bool,
    over_ssh: bool,
    accepted: &str,
) -> Option<bool> {
    let want = want?;
    if !over_ssh || want == have || risk_accepted(accepted, "lose-ssh") {
        return None;
    }
    Some(want) // want == true → enabling refusal; false → disabling refusal
}

/// Refuse an SSH-server toggle that would drop the operator's own Tailscale SSH session, unless they
/// pre-accepted `lose-ssh` (Go's `presentSSHToggleRisk`, enforced fail-closed). Shared by the `up` and
/// `set` handlers. **Short-circuits cheaply**: it only performs the `GetPrefs` round-trip (to learn the
/// current `ssh` pref = `haveSSH`) when the toggle is actually mentioned AND we're over a Tailscale SSH
/// session AND the risk wasn't pre-accepted — so the common path (no `--ssh`/`--no-ssh`, or not over
/// SSH) makes no extra daemon call. On a real refusal it prints the direction-appropriate message +
/// the `--accept-risk=lose-ssh` override and exits non-zero, before the caller builds/sends its
/// request. `want_ssh` is `resolve_ssh(ssh, no_ssh)` (the mentioned toggle, or `None`).
async fn refuse_ssh_toggle_risk_if_needed(
    socket: &std::path::Path,
    want_ssh: Option<bool>,
    accept_risk: Option<&str>,
) -> Result<()> {
    let accepted = accept_risk.unwrap_or("");
    // Cheap pre-conditions first — avoid the GetPrefs round-trip unless a refusal is even possible.
    let Some(want) = want_ssh else { return Ok(()) };
    if !is_ssh_over_tailscale() || risk_accepted(accepted, "lose-ssh") {
        return Ok(());
    }
    // Now learn haveSSH (the persisted ssh pref) via the same one-shot read the `get` command uses.
    let have = match round_trip(socket, &Request::GetPrefs).await {
        Ok(Response::Prefs(v)) => v.ssh,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to get-prefs (ssh-risk check): {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "reading prefs for the ssh-toggle risk check at {}",
                    socket.display()
                )
            });
        }
    };
    match ssh_toggle_refusal(Some(want), have, true, accepted) {
        // Go's `presentSSHToggleRisk` strings, verbatim (up.go), so the operator-facing wording
        // matches upstream exactly; the override hint is added (Go prompts interactively; this CLI
        // refuses fail-closed and points at the same `--accept-risk=lose-ssh` escape hatch).
        Some(true) => {
            eprintln!(
                "You are connected over Tailscale; this action will reroute SSH traffic to \
                 Tailscale SSH and will result in your session disconnecting."
            );
            eprintln!("To override, re-run with --accept-risk=lose-ssh");
            std::process::exit(1);
        }
        Some(false) => {
            eprintln!(
                "You are connected using Tailscale SSH; this action will result in your session \
                 disconnecting."
            );
            eprintln!("To override, re-run with --accept-risk=lose-ssh");
            std::process::exit(1);
        }
        None => Ok(()),
    }
}

/// Map the `--advertise-routes` / `--advertise-routes-clear` flags to the wire field's
/// `Option<Vec<String>>`. Any routes passed → `Some(routes)` (replace the set); else
/// `--advertise-routes-clear` → `Some(vec![])` (advertise none); else `None` (leave the persisted
/// set unchanged). A non-empty list takes precedence over the clear flag.
fn resolve_advertise_routes(routes: Vec<String>, clear: bool) -> Option<Vec<String>> {
    if !routes.is_empty() {
        Some(routes)
    } else if clear {
        Some(vec![])
    } else {
        None
    }
}

/// Restore the default `SIGPIPE` disposition (terminate) before doing any output.
///
/// The Rust runtime installs `SIG_IGN` for `SIGPIPE` before `main`, which turns a write to a closed
/// pipe into an `EPIPE` error — and `print!`/`println!` then **panic** ("failed printing to stdout",
/// exit 101). For a Unix CLI that is wrong: piping a large output into `head`, or any reader that
/// exits early, should make the writer terminate *silently* on the broken pipe, exactly as Go's
/// `tailscale` (and every well-behaved CLI) does. Resetting to `SIG_DFL` here restores that: a broken
/// pipe kills the process with `SIGPIPE` (exit 141) instead of an ugly Rust panic. Output-only — no
/// effect on the daemon's socket I/O (the daemon binary does the same for symmetry).
fn reset_sigpipe() {
    // SAFETY: `signal` with `SIG_DFL` for `SIGPIPE` is async-signal-safe and has no preconditions; we
    // call it once at the very start of `main`, before any threads/output. This is the standard CLI
    // fix (ripgrep/fd do the same); the `unsafe` is only because `libc::signal` is an FFI call.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // FIRST: restore default SIGPIPE so a broken output pipe (`tnet status | head`) terminates
    // cleanly instead of panicking the print. Must run before any stdout write.
    reset_sigpipe();
    let cli = Cli::parse();
    let socket = cli.socket.unwrap_or_else(tailscaled_rs::socket_path);

    match cli.command {
        Command::Up {
            authkey,
            authkey_file,
            hostname,
            control_url,
            tun,
            no_tun,
            tun_name,
            tun_mtu,
            exit_node,
            clear_exit_node,
            advertise_exit_node,
            no_advertise_exit_node,
            advertise_routes,
            advertise_routes_clear,
            advertise_tags,
            advertise_tags_clear,
            accept_routes,
            no_accept_routes,
            accept_dns,
            no_accept_dns,
            shields_up,
            no_shields_up,
            ssh,
            no_ssh,
            reset,
            force_reauth,
            ephemeral,
            no_ephemeral,
            timeout,
            accept_risk,
        } => {
            run_up(
                &socket,
                authkey,
                authkey_file,
                hostname,
                control_url,
                tun,
                no_tun,
                tun_name,
                tun_mtu,
                exit_node,
                clear_exit_node,
                advertise_exit_node,
                no_advertise_exit_node,
                advertise_routes,
                advertise_routes_clear,
                advertise_tags,
                advertise_tags_clear,
                accept_routes,
                no_accept_routes,
                accept_dns,
                no_accept_dns,
                shields_up,
                no_shields_up,
                ssh,
                no_ssh,
                reset,
                force_reauth,
                ephemeral,
                no_ephemeral,
                timeout,
                accept_risk,
            )
            .await
        }
        Command::Set {
            hostname,
            accept_routes,
            no_accept_routes,
            accept_dns,
            no_accept_dns,
            shields_up,
            no_shields_up,
            exit_node,
            clear_exit_node,
            advertise_exit_node,
            no_advertise_exit_node,
            advertise_routes,
            advertise_routes_clear,
            advertise_tags,
            advertise_tags_clear,
            ssh,
            no_ssh,
            accept_risk,
        } => {
            run_set(
                &socket,
                hostname,
                accept_routes,
                no_accept_routes,
                accept_dns,
                no_accept_dns,
                shields_up,
                no_shields_up,
                exit_node,
                clear_exit_node,
                advertise_exit_node,
                no_advertise_exit_node,
                advertise_routes,
                advertise_routes_clear,
                advertise_tags,
                advertise_tags_clear,
                ssh,
                no_ssh,
                accept_risk,
            )
            .await
        }
        Command::Bugreport { note } => dispatch_simple(&socket, Request::BugReport { note }).await,
        Command::Cert {
            domain,
            cert_file,
            key_file,
        } => run_cert(&socket, domain, cert_file, key_file).await,
        // `nc` hijacks its connection (the daemon splices to the overlay after a one-line ack), so it
        // is handled by a dedicated piping path, not the generic round-trip.
        Command::Nc { host, port } => run_nc(&socket, &host, port)
            .await
            .with_context(|| format!("nc to {host}:{port} via {}", socket.display())),
        // `serve`: read-modify-write the ServeConfig (tcp/reset) or render it (status). Inline because
        // tcp/reset must GET the current config, mutate, then SET it.
        Command::Serve { cmd } => run_serve(&socket, cmd)
            .await
            .with_context(|| format!("serve via {}", socket.display())),
        // `funnel <port> on|off`: GET status (for the node's MagicDNS name → the HostPort key) + the
        // current ServeConfig, toggle AllowFunnel, SET it back. Inline (read-modify-write, like serve).
        Command::Funnel { port, on_off } => run_funnel(&socket, port, &on_off)
            .await
            .with_context(|| format!("funnel via {}", socket.display())),
        // `debug capture`: send DebugCapture (a long-lived write — the daemon taps the dataplane for
        // `seconds`, then replies with the byte count). Inline early-return like the other subcommand
        // groups.
        Command::Debug { cmd } => match cmd {
            DebugCmd::Capture { path, seconds } => run_debug_capture(&socket, path, seconds).await,
            DebugCmd::Prefs => run_debug_prefs(&socket).await,
        },
        // `install` / `uninstall` (Go `tailscaled install-system-daemon` / `uninstall-system-daemon`):
        // purely LOCAL, privileged file + service-manager work — they never touch the LocalAPI socket.
        // Handled inline (early return), root-gated inside `run_install`/`run_uninstall`.
        Command::Install => tailscaled_rs::ipn::install::run_install()
            .context("installing the tailnetd system service"),
        Command::Uninstall => tailscaled_rs::ipn::install::run_uninstall()
            .context("removing the tailnetd system service"),
        Command::Down => dispatch_simple(&socket, Request::Down).await,
        Command::Logout => dispatch_simple(&socket, Request::Logout).await,
        // `switch` (Go `tailscale switch`): --list renders a table; `remove <id>` deletes; a bare
        // `<target>` switches. Handled inline — `--list` renders the Profiles reply, and the three
        // modes map to different requests.
        Command::Switch { list, target, cmd } => run_switch(&socket, list, target, cmd).await,
        // `version` answers from the CLI's own crate version. WITHOUT `--daemon` it never contacts
        // the daemon (Go also prints the client version with no LocalAPI call) — handle it here and
        // return. WITH `--daemon` it round-trips `Request::Version` to learn the daemon's version,
        // then renders both; we do that inline here (rather than falling through to the generic
        // response printer) so the client/daemon pairing + `--json` shape stay in one place.
        Command::Version {
            daemon,
            json,
            upstream,
        } => run_version(&socket, daemon, json, upstream).await,
        // `get` (Go `tailscale get`): round-trip GetPrefs, then render. Handled inline (early return)
        // because its `setting`/`json` args shape the output and are not part of the wire request —
        // keeping the projection→render in one place, like `version`.
        Command::Get {
            setting,
            json,
            set_flags,
        } => run_get(&socket, setting, json, set_flags).await,
        // `wait` (Go `tailscale wait`): poll until the node is Running with a tailnet IP, honoring an
        // optional timeout. Handled inline (it loops + has its own exit-code contract), not a
        // one-shot request.
        Command::Wait { timeout } => wait_for_running(&socket, timeout)
            .await
            .with_context(|| format!("waiting for the node to come up at {}", socket.display())),
        // `whoami` (Go `tailscale whoami`): resolve this node's own identity — Status to learn the
        // self tailnet IP, then Whois on that IP. Handled inline because it chains two requests and
        // its `--json` shape is the whois record. Reuses the same `format_whois` renderer as `whois`.
        Command::Whoami { json } => run_whoami(&socket, json).await,
        // `status` (Go `tailscale status`): plain status round-trips one `Status`; `--web`/`--watch`
        // are long-lived and return inside `run_status`.
        Command::Status {
            watch,
            json,
            active,
            no_peers,
            no_self,
            web,
            listen,
            no_browser,
        } => {
            run_status(
                &socket, watch, json, active, no_peers, no_self, web, listen, no_browser,
            )
            .await
        }
        // `ip` (Go `tailscale ip`): self addresses by default, or a peer's if named, with -4/-6/-1
        // filters. Handled inline because the filters + the optional peer lookup shape the output
        // (and the peer case fetches Status to resolve by name/IP against the netmap).
        Command::Ip {
            v4,
            v6,
            first,
            peer,
        } => run_ip(&socket, v4, v6, first, peer).await,
        Command::Whois { ip } => run_whois(&socket, ip).await,
        Command::IdToken { audience } => {
            dispatch_simple(&socket, Request::IdToken { audience }).await
        }
        // `ping` (Go `tailscale ping [-c N]`): the engine pings one-at-a-time, so `-c` is a CLI-side
        // loop over `Request::Ping`. Handled inline (the loop + summary + exit-code contract); each
        // attempt prints a result line, a failure is counted but does not abort the rest, and the
        // command exits non-zero only if NOTHING was received.
        Command::Ping {
            ip,
            timeout,
            count,
            until_direct,
            no_until_direct,
        } => {
            run_ping(
                &socket,
                ip,
                timeout,
                count,
                resolve_until_direct(until_direct, no_until_direct),
            )
            .await
        }
        // Taildrop. The nested subcommand picks which wire `Request` to send: `cp` and `get` are
        // writes (the daemon reads/consumes a file) and reply `Ok`; `list` is read-only and replies
        // `Files`.
        // `metrics` (Go `tailscale metrics`): fetch the Prometheus text, then print or write it.
        // Inline because `write <path>` chooses a file sink over stdout.
        Command::Metrics { cmd } => run_metrics(&socket, cmd).await,
        // `licenses` is purely local (Go contacts no daemon either) — print + return.
        Command::Licenses => {
            print!("{}", format_licenses());
            Ok(())
        }
        // `lock status` (Go `tailscale lock status`): fetch + render the TKA status.
        Command::Lock {
            cmd: LockCmd::Status { json },
        } => run_lock_status(&socket, json).await,
        // `dns status` (Go `tailscale dns status`): fetch + render the control-pushed MagicDNS config.
        Command::Dns {
            cmd: DnsCmd::Status { json },
        } => run_dns_status(&socket, json).await,
        // `netcheck` (Go `tailscale netcheck`): fetch + render the net-report (DERP-region latency).
        Command::Netcheck { json } => run_netcheck(&socket, json).await,
        // `exit-node list` (Go `tailscale exit-node list`): reuse Status, filter to exit-node peers.
        Command::ExitNode {
            cmd: ExitNodeCmd::List,
        } => run_exit_node_list(&socket).await,
        Command::File { cmd } => run_file(&socket, cmd).await,
    }
}

/// Print `tnet version` output (thin wrapper over [`format_version`], which is pure + unit-tested).
/// `cap` is the engine's current capability version (the `cap` field of Go's `version.Meta`).
fn print_version(client: &str, daemon: Option<&str>, cap: u16, json: bool) {
    print!("{}", format_version(client, daemon, cap, json));
}

/// Send a write `Request` that replies `Ok`/`Error`, printing `ok: <msg>` on success or the error +
/// exit 1 on failure. Used by the `switch`/`switch remove` inline arms (they're plain writes whose
/// success is just an acknowledgement). Returns `Ok(())` so the caller can `return` it directly.
async fn send_ok_or_die(socket: &std::path::Path, request: Request) -> Result<()> {
    match round_trip(socket, &request).await {
        Ok(Response::Ok { message }) => {
            println!("ok: {message}");
            Ok(())
        }
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response: {other:?}"),
        Err(e) => Err(e).with_context(|| format!("talking to daemon at {}", socket.display())),
    }
}

/// Round-trip a one-shot `Request` whose reply is rendered with no command-specific state, then
/// return. Covers the truly-generic writes — `down`/`logout` (reply `Ok`), `bugreport` (reply
/// `BugReport`), and `id-token` (reply `IdToken`) — distributing the former shared post-match render
/// arms for those response shapes into one place. Models its error/exit handling on
/// [`send_ok_or_die`]: a `Response::Error` prints `error: <msg>` and exits 1; a transport error is
/// returned with the same "talking to daemon" context the old fall-through block used.
async fn dispatch_simple(socket: &std::path::Path, request: Request) -> Result<()> {
    let response = round_trip(socket, &request)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;
    match response {
        Response::Ok { message } => {
            println!("ok: {message}");
        }
        // `bugreport`: print the local marker + a one-line honesty note (no logs were uploaded).
        Response::BugReport { marker } => {
            println!("{marker}");
            eprintln!(
                "(local diagnostic marker — this client uploads no logs; quote it when reporting an issue)"
            );
        }
        // `id-token`: print the raw JWT on its own line (Go's `outln(tr.IDToken)`) for easy capture
        // into a variable / piping to a verifier. The token is opaque base64url — no sanitization
        // needed (it is control-minted, not free-form text).
        Response::IdToken { token } => println!("{token}"),
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
    Ok(())
}

/// `up` (Go `tailscale up`): bring the node up / re-apply prefs. Runs the two SSH-risk pre-flight
/// gates, resolves the auth key, builds the wire `Request::Up`, round-trips it, then renders the
/// reply. On a successful `Ok`, a keyless (interactive) up polls `status` to surface the login URL,
/// and `--timeout` bounds a client-side wait for Running. The accidental-revert guard
/// (`RevertGuard`) and `Error` both exit non-zero without changing the node. The pre-flight ORDER is
/// load-bearing: force-reauth refusal → SSH-toggle gate → `--timeout` capture → authkey resolution →
/// interactive flag → build request.
#[allow(clippy::too_many_arguments)]
async fn run_up(
    socket: &std::path::Path,
    authkey: Option<String>,
    authkey_file: Option<std::path::PathBuf>,
    hostname: Option<String>,
    control_url: Option<String>,
    tun: bool,
    no_tun: bool,
    tun_name: Option<String>,
    tun_mtu: Option<u16>,
    exit_node: Option<String>,
    clear_exit_node: bool,
    advertise_exit_node: bool,
    no_advertise_exit_node: bool,
    advertise_routes: Vec<String>,
    advertise_routes_clear: bool,
    advertise_tags: Vec<String>,
    advertise_tags_clear: bool,
    accept_routes: bool,
    no_accept_routes: bool,
    accept_dns: bool,
    no_accept_dns: bool,
    shields_up: bool,
    no_shields_up: bool,
    ssh: bool,
    no_ssh: bool,
    reset: bool,
    force_reauth: bool,
    ephemeral: bool,
    no_ephemeral: bool,
    timeout: Option<u64>,
    accept_risk: Option<String>,
) -> Result<()> {
    // Risk gate (Go `--accept-risk`/`riskLoseSSH`): `--force-reauth` re-registers the node,
    // which can drop the very Tailscale-SSH session you're typing from. Refuse it over such a
    // session unless the operator pre-accepted `lose-ssh` (or `all`). Detected entirely
    // CLI-side from `$SSH_CLIENT` (like Go's `isSSHOverTailscale`), BEFORE anything reaches the
    // daemon. Unlike Go's interactive y/N, this daemon CLI refuses non-interactively (it has no
    // TTY-prompt path) — faithful to Go's own non-interactive branch + the same flag/values.
    if force_reauth
        && is_ssh_over_tailscale()
        && !risk_accepted(accept_risk.as_deref().unwrap_or(""), "lose-ssh")
    {
        eprintln!(
            "refusing --force-reauth: you appear to be connected over a Tailscale SSH \
             session, and re-registering the node may drop it (you could lock yourself out)."
        );
        eprintln!("To override, re-run with --accept-risk=lose-ssh");
        std::process::exit(1);
    }
    // Risk gate 2 (Go `presentSSHToggleRisk`): toggling the Tailscale SSH server over a
    // Tailscale SSH session reroutes/drops that session. Refuse unless `--accept-risk=lose-ssh`.
    // Short-circuits (no daemon call) unless `--ssh`/`--no-ssh` is mentioned, we're over SSH,
    // and the risk wasn't accepted; only then does it read `haveSSH` to compare. Runs before
    // the request is built, so a refusal changes nothing on the node. (bead tsd-eqx)
    refuse_ssh_toggle_risk_if_needed(socket, resolve_ssh(ssh, no_ssh), accept_risk.as_deref())
        .await?;
    // `--timeout` is a CLIENT-SIDE wait, not a pref and not a wire field: capture it so the
    // post-`up` success path waits for Running (Go `up --timeout`). `None` here means the post-up
    // path will not wait; `Some(secs)` arms the wait (0 = forever, per `wait_for_running`).
    let up_timeout = timeout;
    // Resolve the secret through the precedence chain and hold it as a `SecretString`
    // (zeroized on drop, never `Debug`-printed). Expose it only here, at the moment we
    // serialize the wire `Request` — the field on the wire stays a plain `Option<String>`.
    let authkey = resolve_authkey(authkey, authkey_file).await?;
    // `--force-reauth` re-registers fresh; with no authkey that is an interactive login (the
    // daemon wipes the key, the engine reaches NeedsLogin, and the poll below surfaces the new
    // auth URL) — exactly the keyless-up interactive path, so the same `interactive_up` gate
    // (authkey absent) drives it. No separate polling logic is needed for force-reauth.
    let interactive_up = authkey.is_none();
    let request = Request::Up {
        authkey: authkey.map(|k| k.expose_secret().to_owned()),
        control_url,
        hostname,
        // `--tun` → Some(true) (enable); `--no-tun` → Some(false) (disable); neither →
        // None (leave the pref unchanged), so `tnet up` without either flag never silently
        // flips a TUN node. clap's `conflicts_with` guarantees the two are never both set.
        tun: resolve_tun(tun, no_tun),
        tun_name,
        tun_mtu,
        // `--exit-node <sel>` sets, `--clear-exit-node` stops using one, neither leaves it
        // unchanged; clap's `conflicts_with` guarantees the two are never both set.
        exit_node: resolve_exit_node(exit_node, clear_exit_node),
        // `--advertise-exit-node`/`--no-advertise-exit-node` tri-state (mirrors `--tun`).
        advertise_exit_node: resolve_advertise_exit_node(
            advertise_exit_node,
            no_advertise_exit_node,
        ),
        // Passed routes replace the set; `--advertise-routes-clear` empties it; neither
        // leaves the persisted set unchanged.
        advertise_routes: resolve_advertise_routes(advertise_routes, advertise_routes_clear),
        // Passed tags replace the set; `--clear-advertise-tags` empties it; neither leaves it
        // unchanged. Reuses the same Vec+clear→Option resolver as advertise-routes.
        advertise_tags: resolve_advertise_routes(advertise_tags, advertise_tags_clear),
        // `--accept-routes`/`--no-accept-routes` tri-state (mirrors `--tun`); reuses the same
        // resolver as the `set` arm.
        accept_routes: resolve_accept_routes(accept_routes, no_accept_routes),
        // `--accept-dns`/`--no-accept-dns` tri-state (default-on; mirrors the `set` arm).
        accept_dns: resolve_accept_dns(accept_dns, no_accept_dns),
        // `--shields-up`/`--no-shields-up` tri-state (mirrors `--tun`); reuses the same
        // resolver as the `set` arm.
        shields_up: resolve_shields_up(shields_up, no_shields_up),
        // `--ssh`/`--no-ssh` tri-state (mirrors `--tun`).
        ssh: resolve_ssh(ssh, no_ssh),
        // `--reset`: reset unmentioned settings to default + bypass the accidental-revert
        // guard. A plain bool flag (Go's `--reset`), passed straight through.
        reset,
        // `--force-reauth`: discard the node key so the bring-up re-registers fresh (new
        // login). A plain bool flag (Go's `--force-reauth`), passed straight through.
        force_reauth,
        // `--ephemeral`/`--no-ephemeral` tri-state (registration-time intent; default persistent).
        ephemeral: resolve_ephemeral(ephemeral, no_ephemeral),
    };
    let response = round_trip(socket, &request)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;
    match response {
        Response::Ok { message } => {
            println!("ok: {message}");
            // Interactive login: an authkey-less `up` succeeds at the daemon, but the node now needs
            // a human to authorize it. The auth URL isn't known yet at `up`-time — it arrives once
            // the engine reaches `NeedsLogin` — so poll `status` briefly to surface it (or a
            // terminal registration failure).
            if interactive_up {
                match poll_for_auth_url(socket).await {
                    AuthOutcome::Url(url) => {
                        println!();
                        println!("To authenticate this node, visit:");
                        println!("    {url}");
                        println!();
                        println!(
                            "(the node will finish connecting automatically once authorized; \
                                  run `tnet status` to check)"
                        );
                    }
                    AuthOutcome::Failed(reason) => {
                        // Registration hard-failed. An interactive `up` that terminally fails must
                        // not exit 0 implying success, and must not tell the operator to log in —
                        // re-running with the same key loops forever. Surface the reason and exit
                        // non-zero (mirroring the `Response::Error` path below).
                        eprintln!();
                        eprintln!("registration failed: {}", sanitize_multiline(&reason));
                        eprintln!(
                            "(this is a permanent failure — re-run `tnet up --authkey <NEW_KEY>` \
                             with a fresh key; the same key will keep failing)"
                        );
                        std::process::exit(1);
                    }
                    AuthOutcome::None => {}
                }
            }
            // `up --timeout`: bound the wait for the node to reach Running (Go `tailscale up
            // --timeout`). Only an `up` that passed `--timeout` arms this (`up_timeout` is `None` for
            // an `up` without the flag, preserving the fire-and-return default). The auth URL above is
            // printed FIRST, so an interactive up still surfaces it before waiting (Go waits for
            // Running regardless of interactive vs keyed). A timeout is a non-zero exit — the daemon
            // accepted the up, but the node did not come up in time.
            if let Some(secs) = up_timeout
                && let Err(e) = wait_for_running(socket, Some(secs)).await
            {
                eprintln!("{e:#}");
                std::process::exit(1);
            }
            Ok(())
        }
        // The daemon refused an `up` that would silently revert non-default settings the command did
        // not mention (Go's accidental-revert guard). Render Go's guidance with a copy-pasteable
        // command and exit non-zero — nothing was changed on the node.
        Response::RevertGuard { reverts } => {
            eprint!("{}", format_revert_guard(&reverts));
            std::process::exit(1);
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to up: {other:?}"),
    }
}

/// `set` (Go `tailscale set`): patch individual prefs on an already-configured node — never
/// (re)authenticates, never changes up/down. Runs the SSH-toggle risk gate BEFORE building the
/// request (so a refusal changes nothing), builds the wire `Request::Set`, round-trips it, then
/// renders the reply: `Ok` acknowledges, the accidental-revert guard (`RevertGuard`) and `Error`
/// both exit non-zero without changing the node.
#[allow(clippy::too_many_arguments)]
async fn run_set(
    socket: &std::path::Path,
    hostname: Option<String>,
    accept_routes: bool,
    no_accept_routes: bool,
    accept_dns: bool,
    no_accept_dns: bool,
    shields_up: bool,
    no_shields_up: bool,
    exit_node: Option<String>,
    clear_exit_node: bool,
    advertise_exit_node: bool,
    no_advertise_exit_node: bool,
    advertise_routes: Vec<String>,
    advertise_routes_clear: bool,
    advertise_tags: Vec<String>,
    advertise_tags_clear: bool,
    ssh: bool,
    no_ssh: bool,
    accept_risk: Option<String>,
) -> Result<()> {
    // Risk gate (Go `presentSSHToggleRisk`, the `set` call site): toggling the Tailscale SSH
    // server over a Tailscale SSH session reroutes/drops that session — refuse unless
    // `--accept-risk=lose-ssh`. Short-circuits (no daemon call) unless `--ssh`/`--no-ssh` is
    // mentioned, we're over SSH, and the risk wasn't accepted. Runs before the request is
    // built, so a refusal changes nothing. (bead tsd-eqx — same enforcement as the `up` path.)
    refuse_ssh_toggle_risk_if_needed(socket, resolve_ssh(ssh, no_ssh), accept_risk.as_deref())
        .await?;
    let request = Request::Set {
        hostname,
        // `--accept-routes`/`--no-accept-routes` tri-state (mirrors `--tun`).
        accept_routes: resolve_accept_routes(accept_routes, no_accept_routes),
        // `--accept-dns`/`--no-accept-dns` tri-state (default-on).
        accept_dns: resolve_accept_dns(accept_dns, no_accept_dns),
        // `--shields-up`/`--no-shields-up` tri-state (mirrors `--tun`).
        shields_up: resolve_shields_up(shields_up, no_shields_up),
        // `--exit-node <sel>` sets, `--clear-exit-node` stops using one, neither leaves it
        // unchanged; clap's `conflicts_with` guarantees the two are never both set. Reuses the
        // same resolver as the `up` arm.
        exit_node: resolve_exit_node(exit_node, clear_exit_node),
        // `--advertise-exit-node`/`--no-advertise-exit-node` tri-state (mirrors `--tun`).
        advertise_exit_node: resolve_advertise_exit_node(
            advertise_exit_node,
            no_advertise_exit_node,
        ),
        // Passed routes replace the set; `--advertise-routes-clear` empties it; neither leaves
        // the persisted set unchanged.
        advertise_routes: resolve_advertise_routes(advertise_routes, advertise_routes_clear),
        // Passed tags replace the set; `--clear-advertise-tags` empties it; neither unchanged.
        advertise_tags: resolve_advertise_routes(advertise_tags, advertise_tags_clear),
        // `--ssh`/`--no-ssh` tri-state (mirrors `--tun`).
        ssh: resolve_ssh(ssh, no_ssh),
    };
    let response = round_trip(socket, &request)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;
    match response {
        Response::Ok { message } => {
            println!("ok: {message}");
            Ok(())
        }
        // The daemon refused a `set` that would silently revert non-default settings the command did
        // not mention (Go's accidental-revert guard). Render Go's guidance + exit non-zero — nothing
        // was changed on the node.
        Response::RevertGuard { reverts } => {
            eprint!("{}", format_revert_guard(&reverts));
            std::process::exit(1);
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to set: {other:?}"),
    }
}

/// `status` (Go `tailscale status`): render the node + peer table. `--web` serves a long-lived
/// embedded HTTP page and `--watch` streams updates (both return without the one-shot path); plain
/// `status` round-trips one `Status`, applies the client-side `--active`/`--no-peers`/`--no-self`
/// filters, then renders the human table or (`--json`) the Go `ipnstate.Status`-shaped object.
#[allow(clippy::too_many_arguments)]
async fn run_status(
    socket: &std::path::Path,
    watch: bool,
    json: bool,
    active: bool,
    no_peers: bool,
    no_self: bool,
    web: bool,
    listen: Option<String>,
    no_browser: bool,
) -> Result<()> {
    // `status --web` is a long-lived embedded HTTP server, not a one-shot — handle it here and
    // return (like --watch). Default listen 127.0.0.1:8384; browser opens unless --no-browser.
    if web {
        let listen = listen.unwrap_or_else(|| "127.0.0.1:8384".to_string());
        return run_status_web(socket, &listen, !no_browser)
            .await
            .with_context(|| format!("serving status --web on {listen}"));
    }
    if watch {
        return watch_status(socket)
            .await
            .with_context(|| format!("watching status at {}", socket.display()));
    }
    let status_filter = StatusFilter {
        active_only: active,
        hide_peers: no_peers,
        hide_self: no_self,
    };
    let response = round_trip(socket, &Request::Status)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;
    match response {
        Response::Status(s) => {
            // Apply the client-side --active / --no-peers / --no-self filters before rendering, so
            // both the human and --json paths honor them identically.
            let s = status_filter.apply(s);
            if json {
                // Go `status --json`: the ipnstate.Status-shaped object (faithful subset).
                match format_status_json(&s) {
                    Ok(out) => print!("{out}"),
                    Err(e) => {
                        eprintln!("error: serializing status: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                print_status(&s);
            }
            Ok(())
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to status: {other:?}"),
    }
}

/// `debug capture`: send DebugCapture (a long-lived write — the daemon taps the dataplane for
/// `seconds`, then replies with the byte count).
async fn run_debug_capture(
    socket: &std::path::Path,
    path: std::path::PathBuf,
    seconds: u64,
) -> Result<()> {
    let path = path.to_string_lossy().into_owned();
    let resp = round_trip(
        socket,
        &Request::DebugCapture {
            path,
            seconds: Some(seconds),
        },
    )
    .await
    .with_context(|| format!("debug capture via {}", socket.display()))?;
    match resp {
        Response::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        Response::Error { message } => anyhow::bail!("debug capture failed: {message}"),
        other => anyhow::bail!("unexpected response to debug capture: {other:?}"),
    }
}

/// `debug prefs` (Go `tailscale debug prefs`): round-trip `GetPrefs` and print the prefs view as
/// pretty JSON. The raw-object counterpart to `tnet get`'s human/flag rendering — same data
/// (`Response::Prefs`), different shape, for scripting/debugging. Read-only.
async fn run_debug_prefs(socket: &std::path::Path) -> Result<()> {
    let view = match round_trip(socket, &Request::GetPrefs).await {
        Ok(Response::Prefs(v)) => v,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to debug prefs: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("getting prefs at {}", socket.display()));
        }
    };
    // Pretty JSON of the prefs view (Go's `json.MarshalIndent(prefs, "", "\t")`). `PrefsView` is a
    // plain serde struct, so this cannot fail in practice; fall back to `{}` rather than panic.
    println!(
        "{}",
        serde_json::to_string_pretty(&view).unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

/// `switch` (Go `tailscale switch`): `--list` renders a table; `remove <id>` deletes; a bare
/// `<target>` switches. `--list` renders the Profiles reply, and the three modes map to different
/// requests.
async fn run_switch(
    socket: &std::path::Path,
    list: bool,
    target: Option<String>,
    cmd: Option<SwitchCmd>,
) -> Result<()> {
    // `switch remove <id>` (subcommand) takes precedence.
    if let Some(SwitchCmd::Remove { target }) = cmd {
        return send_ok_or_die(socket, Request::DeleteProfile { target }).await;
    }
    if list {
        match round_trip(socket, &Request::ProfileList).await {
            Ok(Response::Profiles { profiles }) => {
                print!("{}", format_profiles(&profiles));
                return Ok(());
            }
            Ok(Response::Error { message }) => {
                eprintln!("error: {message}");
                std::process::exit(1);
            }
            Ok(other) => anyhow::bail!("unexpected response to profile list: {other:?}"),
            Err(e) => {
                return Err(e).with_context(|| format!("listing profiles at {}", socket.display()));
            }
        }
    }
    match target {
        Some(target) => send_ok_or_die(socket, Request::SwitchProfile { target }).await,
        None => {
            eprintln!("usage: tnet switch <profile> | --list | remove <profile>");
            std::process::exit(1);
        }
    }
}

/// Render the `tnet licenses` notice (Go `tailscale licenses`). Local-only, pure → unit-testable.
///
/// Faithful to Go's command shape (a short notice + a pointer to where the full license texts live)
/// but with content true to THIS fork rather than Tailscale's URL: this is a Rust port under
/// BSD-3-Clause, and its dependency-license texts are reproducible offline via `cargo` tooling
/// (`cargo about`/`cargo license` over `Cargo.lock`), so we point there instead of a hosted page that
/// would not describe this project's actual dependency set.
fn format_licenses() -> String {
    format!(
        "\n\
         {name} is a Rust reimplementation of the Tailscale daemon + CLI, licensed under \
         {license}.\n\
         It wouldn't be possible without thousands of open-source contributors. For this project's \
         license and the licenses of its dependencies:\n\
         \n    \
         {repo}\n    \
         (dependency licenses: `cargo install cargo-about && cargo about generate` over Cargo.lock)\n",
        name = env!("CARGO_PKG_NAME"),
        license = env!("CARGO_PKG_LICENSE"),
        repo = env!("CARGO_PKG_REPOSITORY"),
    )
}

/// `version` answers from the CLI's own crate version. WITHOUT `--daemon` it never contacts the
/// daemon (Go also prints the client version with no LocalAPI call). WITH `--daemon` it round-trips
/// `Request::Version` to learn the daemon's version, then renders both inline (rather than falling
/// through to the generic response printer) so the client/daemon pairing + `--json` shape stay in
/// one place.
async fn run_version(
    socket: &std::path::Path,
    daemon: bool,
    json: bool,
    upstream: bool,
) -> Result<()> {
    // `--upstream` would fetch the latest release from a release server; this build does no
    // such network call, so return Go's verbatim message + a non-zero exit (faithful, offline,
    // names no infrastructure). Checked before the local render so `version --upstream` never
    // prints a version line implying success.
    if upstream {
        eprintln!("fetching latest version not supported in this build");
        std::process::exit(1);
    }
    let client_version = env!("CARGO_PKG_VERSION");
    let daemon_version = if daemon {
        match round_trip(socket, &Request::Version).await {
            Ok(Response::Version { version }) => Some(version),
            Ok(other) => {
                anyhow::bail!("unexpected response to version request: {other:?}")
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("querying daemon version at {}", socket.display()));
            }
        }
    } else {
        None
    };
    // `cap` = the engine's current capability version (Go `version.Meta.cap`), read from the
    // engine's `ts_capabilityversion` crate (pinned to the same rev as the engine facade).
    let cap = u16::from(ts_capabilityversion::CapabilityVersion::CURRENT);
    print_version(client_version, daemon_version.as_deref(), cap, json);
    Ok(())
}

/// `get` (Go `tailscale get`): round-trip GetPrefs, then render. Inline because its
/// `setting`/`json`/`set_flags` args shape the output and are not part of the wire request — keeping
/// the projection→render in one place, like `version`.
async fn run_get(
    socket: &std::path::Path,
    setting: Option<String>,
    json: bool,
    set_flags: bool,
) -> Result<()> {
    let view = match round_trip(socket, &Request::GetPrefs).await {
        Ok(Response::Prefs(v)) => v,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to get request: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("getting prefs at {}", socket.display()));
        }
    };
    // `--set-flags` (Go `get --set-flags`): emit every setting as one re-appliable `set` arg line,
    // regardless of a single-SETTING arg (Go's set-flags mode always emits all). clap's
    // `conflicts_with` guarantees `json` is false here.
    if set_flags {
        println!("{}", format_get_set_flags(&view));
        return Ok(());
    }
    match format_get(&view, setting.as_deref(), json) {
        Ok(out) => print!("{out}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
    Ok(())
}

/// `whoami` (Go `tailscale whoami`): resolve this node's own identity — Status to learn the self
/// tailnet IP, then Whois on that IP. Inline because it chains two requests and its `--json` shape is
/// the whois record. Reuses the same `format_whois` renderer as `whois`.
async fn run_whoami(socket: &std::path::Path, json: bool) -> Result<()> {
    let status = match round_trip(socket, &Request::Status).await {
        Ok(Response::Status(s)) => s,
        Ok(other) => anyhow::bail!("unexpected response to status request: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying status at {}", socket.display()));
        }
    };
    let Some(self_ip) = status.self_ipv4.clone() else {
        // No tailnet IP yet → not up (Go errors here too, citing the backend state).
        eprintln!(
            "no current tailnet IP address (state: {}); is the node up?",
            status.state
        );
        std::process::exit(1);
    };
    match round_trip(
        socket,
        &Request::Whois {
            ip: self_ip.clone(),
        },
    )
    .await
    {
        Ok(Response::Whois(w)) => {
            if json {
                // The whois record as JSON (Go `whoami --json` emits the WhoIsResponse).
                match serde_json::to_string_pretty(&w) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("error: serializing whois: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                print!("{}", format_whois(&w, &self_ip));
            }
            Ok(())
        }
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to whois request: {other:?}"),
        Err(e) => {
            Err(e).with_context(|| format!("resolving self identity at {}", socket.display()))
        }
    }
}

/// `ip` (Go `tailscale ip`): self addresses by default, or a peer's if named, with -4/-6/-1
/// filters. Inline because the filters + the optional peer lookup shape the output (and the peer
/// case fetches Status to resolve by name/IP against the netmap).
async fn run_ip(
    socket: &std::path::Path,
    v4: bool,
    v6: bool,
    first: bool,
    peer: Option<String>,
) -> Result<()> {
    let sel = IpSelect { v4, v6, first };
    let out = if let Some(peer) = peer {
        // Peer address: resolve the named peer against the status peer set (by MagicDNS name
        // or tailnet IP). We fetch Status (not whois, which is IP-only) so a NAME also works.
        let status = match round_trip(socket, &Request::Status).await {
            Ok(Response::Status(s)) => s,
            Ok(other) => anyhow::bail!("unexpected response to status request: {other:?}"),
            Err(e) => {
                return Err(e).with_context(|| format!("querying status at {}", socket.display()));
            }
        };
        match status
            .peers
            .iter()
            .find(|p| p.name == peer || p.ipv4 == peer)
        {
            // Peers currently expose only an IPv4 in our PeerReport, so -6 yields nothing.
            Some(p) => format_ip_filtered(Some(&p.ipv4), None, sel),
            None => {
                eprintln!("no peer matching {peer:?} in the current netmap");
                std::process::exit(1);
            }
        }
    } else {
        // Self addresses.
        match round_trip(socket, &Request::Ip).await {
            Ok(Response::Ip { ipv4, ipv6 }) => {
                format_ip_filtered(ipv4.as_deref(), ipv6.as_deref(), sel)
            }
            Ok(Response::Error { message }) => {
                eprintln!("error: {message}");
                std::process::exit(1);
            }
            Ok(other) => anyhow::bail!("unexpected response to ip request: {other:?}"),
            Err(e) => {
                return Err(e).with_context(|| format!("querying ip at {}", socket.display()));
            }
        }
    };
    print!("{out}");
    Ok(())
}

/// `ping` (Go `tailscale ping [-c N] [--until-direct]`): the engine pings one-at-a-time, so the
/// count + the `--until-direct` early-stop are a CLI-side loop over `Request::Ping`. Inline (the
/// loop + summary + exit-code contract); each attempt prints a result line reporting the path the
/// pong took (`via <endpoint>` direct vs `via DERP` relayed), a failure is counted but does not
/// abort the rest, and the exit verdict follows Go's [`ping_verdict`].
///
/// `count == 0` means infinity (Go `-c 0`): loop until a direct path is established (when
/// `until_direct`) or forever. `until_direct` (Go's default-true) returns as soon as the overlay
/// upgrades to a direct path — the ICMP echo each attempt sends is itself what nudges magicsock to
/// attempt that upgrade.
async fn run_ping(
    socket: &std::path::Path,
    ip: String,
    timeout: Option<u64>,
    count: u32,
    until_direct: bool,
) -> Result<()> {
    let infinite = count == 0;
    let mut received = 0u32;
    let mut went_direct = false;
    let mut seq = 0u32;
    loop {
        seq += 1;
        // The last attempt of a finite run (an infinite run only stops on a direct path or ^C).
        let last = !infinite && seq >= count;
        match round_trip(
            socket,
            &Request::Ping {
                ip: ip.clone(),
                timeout_ms: timeout,
            },
        )
        .await
        {
            Ok(Response::Ping {
                rtt_ms,
                ip,
                endpoint,
            }) => {
                received += 1;
                let direct = endpoint.is_some();
                if direct {
                    went_direct = true;
                }
                println!(
                    "{}",
                    format_ping_line(&ip, rtt_ms, endpoint.as_deref(), seq, count)
                );
                // Early stop: a direct (non-DERP) path is exactly what `--until-direct` waits for
                // (Go returns success here without sending the rest of the count).
                if until_direct && direct {
                    break;
                }
                if last {
                    break;
                }
                // Pace at ~1 ping/second like Go, so `-c N` is a steady stream rather than a burst.
                // Go sleeps ONLY after a pong (a timeout already consumed its own wait), so the
                // sleep lives in this arm, not after a miss.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            Ok(Response::Error { message }) => {
                // A per-attempt failure (timeout, transient unreachability) is counted as a miss
                // but does not abort the run — keep pinging like Go. No sleep after a miss: the
                // per-attempt timeout already elapsed (matches Go's immediate retry on deadline).
                eprintln!("{}", format_ping_miss(&ip, &message, seq, count));
                if last {
                    break;
                }
            }
            Ok(other) => anyhow::bail!("unexpected response to ping: {other:?}"),
            Err(e) => {
                return Err(e).with_context(|| format!("pinging at {}", socket.display()));
            }
        }
    }
    // Summary for any multi-attempt run (a single ping's one line is self-explanatory). `seq` is the
    // number actually sent, which is honest when `--until-direct` stopped the run early.
    if count != 1 {
        println!("{}", format_ping_summary(seq, received));
    }
    // Exit verdict (Go's end-of-loop logic): non-zero if nothing replied, or if `--until-direct` was
    // asked for but no direct path was ever established.
    match ping_verdict(received, went_direct, until_direct) {
        PingVerdict::Ok => Ok(()),
        PingVerdict::NoReply => {
            eprintln!("no reply");
            std::process::exit(1);
        }
        PingVerdict::NoDirect => {
            eprintln!("direct connection not established");
            std::process::exit(1);
        }
    }
}

/// The process-exit verdict for a `ping` run, decided from the run tally. A separate enum (rather
/// than threading exit codes inline) so the Go end-of-loop logic is a pure, unit-testable function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PingVerdict {
    /// At least one reply (and, if `--until-direct`, a direct path was reached) → exit 0.
    Ok,
    /// Nothing replied at all → Go's `"no reply"` error, exit non-zero.
    NoReply,
    /// `--until-direct` was requested but no direct path was ever established → Go's
    /// `"direct connection not established"` error, exit non-zero.
    NoDirect,
}

/// Decide the `ping` exit verdict (Go's end-of-loop logic), pure → unit-testable.
///
/// Go order: no reply at all → `"no reply"`; otherwise if `--until-direct` was set but the path
/// never went direct → `"direct connection not established"`; otherwise success.
fn ping_verdict(received: u32, went_direct: bool, until_direct: bool) -> PingVerdict {
    if received == 0 {
        PingVerdict::NoReply
    } else if until_direct && !went_direct {
        PingVerdict::NoDirect
    } else {
        PingVerdict::Ok
    }
}

/// Render the `via …` path descriptor for a ping result line. `Some(endpoint)` ⇒ a direct path
/// (Go prints `via <ip:port>`); `None` ⇒ the overlay is DERP-relayed (Go prints `via DERP`). Pure.
fn ping_via(endpoint: Option<&str>) -> String {
    match endpoint {
        Some(ep) => format!("via {ep}"),
        None => "via DERP".to_string(),
    }
}

/// The `seq N` / `seq N/M` attempt label for a ping line. An infinite run (`count == 0`) has no
/// denominator, so it shows just the attempt number; a finite run shows `N/M`. Pure.
fn ping_seq_label(seq: u32, count: u32) -> String {
    if count == 0 {
        format!("{seq}")
    } else {
        format!("{seq}/{count}")
    }
}

/// Format a successful-pong result line: the peer IP, the path (`via …`), the RTT, and the attempt
/// label. Pure → unit-testable. (Go also prints the node name; our `Response::Ping` carries only the
/// IP, so the IP stands in — the path + RTT, the operationally meaningful parts, match Go.)
fn format_ping_line(ip: &str, rtt_ms: f64, endpoint: Option<&str>, seq: u32, count: u32) -> String {
    format!(
        "pong from {ip} {} in {rtt_ms:.1} ms  (seq {})",
        ping_via(endpoint),
        ping_seq_label(seq, count)
    )
}

/// Format a missed-attempt line (a per-attempt failure that does not abort the run). The daemon
/// returns a bare cause (no `ping <ip> failed:` prefix — see [`crate::ipn`]'s `diag::ping`), so this
/// adds the single attempt label + destination IP. Pure → unit-testable.
fn format_ping_miss(ip: &str, message: &str, seq: u32, count: u32) -> String {
    format!(
        "ping {ip} ({}) failed: {message}",
        ping_seq_label(seq, count)
    )
}

/// `metrics` (Go `tailscale metrics`): fetch the Prometheus text, then print or write it. Inline
/// because `write <path>` chooses a file sink over stdout.
async fn run_metrics(socket: &std::path::Path, cmd: Option<MetricsCmd>) -> Result<()> {
    let text = match round_trip(socket, &Request::Metrics).await {
        Ok(Response::Metrics { text }) => text,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to metrics: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying metrics at {}", socket.display()));
        }
    };
    match cmd {
        Some(MetricsCmd::Write { path }) => {
            tokio::fs::write(&path, text.as_bytes())
                .await
                .with_context(|| format!("writing metrics to {}", path.display()))?;
            println!("wrote metrics to {}", path.display());
        }
        // `print` (explicit, Go `metrics print`) and bare `metrics` (no subcommand) both go to stdout.
        Some(MetricsCmd::Print) | None => print!("{text}"),
    }
    Ok(())
}

/// `lock status` (Go `tailscale lock status`): fetch + render the TKA status.
async fn run_lock_status(socket: &std::path::Path, json: bool) -> Result<()> {
    let report = match round_trip(socket, &Request::LockStatus).await {
        Ok(Response::Lock(r)) => r,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to lock status: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying lock status at {}", socket.display()));
        }
    };
    print!("{}", format_lock_status(&report, json));
    Ok(())
}

/// `dns status` (Go `tailscale dns status`): fetch + render the control-pushed MagicDNS config.
async fn run_dns_status(socket: &std::path::Path, json: bool) -> Result<()> {
    let report = match round_trip(socket, &Request::DnsStatus).await {
        Ok(Response::DnsStatus(r)) => r,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to dns status: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying dns status at {}", socket.display()));
        }
    };
    print!("{}", format_dns_status(&report, json));
    Ok(())
}

/// `netcheck` (Go `tailscale netcheck`): fetch + render the net-report (DERP-region latency).
async fn run_netcheck(socket: &std::path::Path, json: bool) -> Result<()> {
    let report = match round_trip(socket, &Request::Netcheck).await {
        Ok(Response::Netcheck(r)) => r,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to netcheck: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying netcheck at {}", socket.display()));
        }
    };
    print!("{}", format_netcheck(&report, json));
    Ok(())
}

/// `cert <domain>` (Go `tailscale cert`): round-trip a [`Request::Cert`], then write the issued
/// cert+key PEMs. File handling mirrors Go's `runCert`: when neither `--cert-file` nor `--key-file`
/// is given, default to `DOMAIN.crt` + `DOMAIN.key` in the cwd (with `*.` → `wildcard_.` so a wildcard
/// domain is a legal filename); `-` writes that PEM to stdout instead of a file. The cert is written
/// `0644` (public), the key `0600` (Go's perms — the private key must not be world-readable). A
/// daemon built without `acme`, a down node, or any ACME failure comes back as a `Response::Error`
/// that we print and exit non-zero on (never a partial write).
async fn run_cert(
    socket: &std::path::Path,
    domain: String,
    cert_file: Option<String>,
    key_file: Option<String>,
) -> Result<()> {
    let (cert_pem, key_pem) = match round_trip(
        socket,
        &Request::Cert {
            domain: domain.clone(),
        },
    )
    .await
    {
        Ok(Response::Cert { cert_pem, key_pem }) => (cert_pem, key_pem),
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to cert: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("requesting cert at {}", socket.display()));
        }
    };

    // Go's default-filename rule: only when BOTH flags are unset. `*.` → `wildcard_.` keeps a wildcard
    // domain a legal path.
    let (cert_path, key_path) = match (cert_file, key_file) {
        (None, None) => {
            let base = domain.replacen("*.", "wildcard_.", 1);
            (Some(format!("{base}.crt")), Some(format!("{base}.key")))
        }
        (c, k) => (c, k),
    };

    // Write one PEM to a path (mode-controlled) or to stdout for "-". A missing path (only one of the
    // two flags was given) skips that output, matching Go (each is written only when its path is set).
    fn emit(path: Option<&str>, pem: &str, mode: u32, label: &str) -> Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        match path {
            None => Ok(()),
            Some("-") => {
                std::io::stdout()
                    .write_all(pem.as_bytes())
                    .with_context(|| format!("writing {label} to stdout"))?;
                Ok(())
            }
            Some(p) => {
                // truncate+create with the exact mode (0644 cert / 0600 key). O_NOFOLLOW refuses to
                // follow a pre-planted symlink at the destination (the daemon — and this CLI — may run
                // as root), so the PEM can't be written through a link to an arbitrary target.
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(mode)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(p)
                    .with_context(|| format!("opening {label} file {p}"))?;
                f.write_all(pem.as_bytes())
                    .with_context(|| format!("writing {label} file {p}"))?;
                // create() does not re-chmod an EXISTING file to `mode`; enforce it explicitly so a
                // pre-existing key file can't stay world-readable.
                f.set_permissions(std::fs::Permissions::from_mode(mode))
                    .with_context(|| format!("setting {label} file mode on {p}"))?;
                // (The "-" case is handled by the earlier arm, so `p` here is always a real path.)
                println!("Wrote {label} to {p}");
                Ok(())
            }
        }
    }

    emit(cert_path.as_deref(), &cert_pem, 0o644, "public cert")?;
    emit(key_path.as_deref(), &key_pem, 0o600, "private key")?;
    Ok(())
}

/// `exit-node list` (Go `tailscale exit-node list`): reuse Status, filter to exit-node peers.
async fn run_exit_node_list(socket: &std::path::Path) -> Result<()> {
    let status = match round_trip(socket, &Request::Status).await {
        Ok(Response::Status(s)) => s,
        Ok(other) => anyhow::bail!("unexpected response to status: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying status at {}", socket.display()));
        }
    };
    print!("{}", format_exit_node_list(&status.peers));
    Ok(())
}

/// `whois` (Go `tailscale whois <ip>`): round-trip Whois for the given tailnet IP, then render the
/// owner. The node name is control-supplied text, so it is run through `sanitize_for_terminal` inside
/// the formatter before printing. The queried `ip` is owned here (it is the not-found line's
/// subject), so the render needs no read-back from the request.
async fn run_whois(socket: &std::path::Path, ip: String) -> Result<()> {
    let response = round_trip(socket, &Request::Whois { ip: ip.clone() })
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;
    match response {
        Response::Whois(w) => {
            print!("{}", format_whois(&w, &ip));
            Ok(())
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to whois request: {other:?}"),
    }
}

/// Taildrop (`tnet file`). The nested subcommand picks the wire `Request`: `cp` and `get` are writes
/// (the daemon reads/consumes a file) and reply `Ok`; `list` is read-only and replies `Files`. The
/// file name in a `list` reply is engine/peer-supplied, so it is run through `sanitize_for_terminal`
/// inside `format_files` before printing (a sender could craft a hostile name).
async fn run_file(socket: &std::path::Path, cmd: FileCmd) -> Result<()> {
    // `cp` has its own handler: it may `--targets`-list, or send 1..N files (a round-trip each), so
    // it does not fit the single-request-then-match shape the other verbs share.
    let request = match cmd {
        FileCmd::Cp {
            args,
            name,
            targets,
        } => return run_file_cp(socket, args, name, targets).await,
        FileCmd::List => Request::FileList,
        FileCmd::Get {
            target,
            dest,
            conflict,
            delete_after,
        } => match dest {
            // Two positionals (`get <name> <dest>`) → the single-file fetch (fork convenience).
            Some(dest) => Request::FileGet {
                name: target,
                dest,
                delete_after,
            },
            // One positional (`get <dir>`) → the Go-faithful inbox drain into a directory.
            None => Request::FileGetDir {
                dir: target,
                conflict: conflict.into(),
            },
        },
    };
    let response = round_trip(socket, &request)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;
    match response {
        // Waiting Taildrop files (`tnet file list`). One line per file; an empty inbox prints a
        // clear placeholder rather than nothing.
        Response::Files { files } => print!("{}", format_files(&files)),
        // Inbox-drain outcomes (`tnet file get <dir>`). Print one line per file; exit non-zero if any
        // file failed (Go returns the last error), so scripts can detect a partial drain.
        Response::FilesGot { results } => {
            print!("{}", format_files_got(&results));
            if results.iter().any(|r| r.error.is_some()) {
                std::process::exit(1);
            }
        }
        Response::Ok { message } => {
            println!("ok: {message}");
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to file request: {other:?}"),
    }
    Ok(())
}

/// `tnet file cp` — the Go `tailscale file cp <files...> <target>:` path, plus `--targets`.
///
/// With `targets` (and no positional args), lists the Taildrop-able peers. Otherwise the LAST arg is
/// the destination peer and MUST end in a colon (Go's disambiguator); the rest are files to send, one
/// `FileCp` round-trip each, with the `--name` override (when given) carried to the daemon so the
/// file is sent under that name. `--name` is rejected with multiple files (matching Go). NOTE: stdin
/// (`-`) is NOT supported by this build — the daemon opens each path itself (same-host); a `-` is
/// rejected by `resolve_cp_file`.
async fn run_file_cp(
    socket: &std::path::Path,
    args: Vec<String>,
    name: Option<String>,
    targets: bool,
) -> Result<()> {
    // `--targets`: list peers, ignore (reject) any positional args — matches Go's `runCpTargets`.
    if targets {
        if !args.is_empty() {
            anyhow::bail!("invalid arguments with --targets");
        }
        return run_file_targets(socket).await;
    }

    // Need at least one file + the `<target>:` (Go: "usage: tailscale file cp <files...> <target>:").
    if args.len() < 2 {
        anyhow::bail!("usage: tnet file cp <files...> <target>:");
    }
    let (files, raw_target) = args.split_at(args.len() - 1);
    let peer = parse_cp_target(&raw_target[0])?;

    // Multi-file guards (Go): --name is single-file only, and stdin can't mix with named files.
    if files.len() > 1 {
        if name.is_some() {
            anyhow::bail!("can't use --name with multiple files");
        }
        if files.iter().any(|f| f == "-") {
            anyhow::bail!("can't use '-' (stdin) together with other files");
        }
    }

    // Send each file as its own transfer. A failure on one file is reported and makes the command
    // exit non-zero, but does not abort the remaining sends (mirrors a best-effort batch).
    let mut had_error = false;
    for file in files {
        let (path, send_name) = resolve_cp_file(file, name.as_deref())?;
        let req = Request::FileCp {
            path,
            peer: peer.clone(),
            // Thread `--name` onto the wire so the daemon actually sends the file under that name
            // (Go `--name`); `None` lets the daemon derive the basename. The multi-file guard above
            // already rejects `--name` with >1 file, so this only ever overrides a single send.
            name: name.clone(),
        };
        match round_trip(socket, &req)
            .await
            .with_context(|| format!("talking to daemon at {}", socket.display()))?
        {
            Response::Ok { message } => println!("ok: {message}"),
            Response::Error { message } => {
                eprintln!("error: sending {send_name}: {message}");
                had_error = true;
            }
            other => anyhow::bail!("unexpected response to file cp: {other:?}"),
        }
    }
    if had_error {
        std::process::exit(1);
    }
    Ok(())
}

/// `tnet file cp --targets`: round-trip [`Request::FileTargets`] and render the peer list.
async fn run_file_targets(socket: &std::path::Path) -> Result<()> {
    match round_trip(socket, &Request::FileTargets)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?
    {
        Response::FileTargets { targets } => {
            print!("{}", format_file_targets(&targets));
            Ok(())
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to file targets: {other:?}"),
    }
}

/// Resolve one `cp` file argument to `(path_to_send, display_name)`. A `-` means stdin, which this
/// daemon's same-host `FileCp` (the daemon opens the path itself) cannot stream, so `-` is rejected
/// with an actionable message rather than silently mis-sent. Pure enough to reason about; the stdin
/// limitation is a fork constraint documented at the call site.
fn resolve_cp_file(file: &str, name: Option<&str>) -> Result<(String, String)> {
    if file == "-" {
        // The daemon opens the file by path (tnet + tailnetd are same-host/same-user); there is no
        // path for stdin to hand it. Rather than fake it, reject clearly. (A future stdin path would
        // need the CLI to stream bytes over the LocalAPI — tracked separately.)
        anyhow::bail!(
            "stdin ('-') is not supported by this build's `file cp`; pass a file path instead"
        );
    }
    // Display name for error/progress lines: the override, else the file's base name.
    let display = name
        .map(str::to_string)
        .unwrap_or_else(|| basename(file).to_string());
    Ok((file.to_string(), display))
}

/// The base name of a path (the final `/`-separated component), for `cp` display. Pure.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Render `tnet lock status` from a [`LockReport`](tailscaled_rs::localapi::LockReport). Human form
/// states whether Tailnet Lock is in use and, if so, the authority head + any pending disablement;
/// `json` emits a small serde object. Pure → unit-testable.
fn format_lock_status(r: &tailscaled_rs::localapi::LockReport, json: bool) -> String {
    if json {
        let mut m = serde_json::Map::new();
        m.insert("enabled".into(), serde_json::json!(r.enabled));
        m.insert("head".into(), serde_json::json!(r.head));
        m.insert("disabled".into(), serde_json::json!(r.disabled));
        return format!(
            "{}\n",
            serde_json::to_string_pretty(&m).unwrap_or_else(|_| "{}".to_string())
        );
    }
    // Status line + a blank line, matching Go `runTailnetLockStatus` (tailnet-lock.go: prints
    // `Tailnet Lock is {ENABLED.|NOT enabled.}` then an unconditional `fmt.Println()`). The wording is
    // byte-for-byte Go's — no "on this tailnet" suffix.
    if !r.enabled {
        return "Tailnet Lock is NOT enabled.\n\n".to_string();
    }
    let mut out = String::from("Tailnet Lock is ENABLED.\n\n");
    // The rich Go sections (this-node key, trusted-keys table, filtered peers) are engine-gated — the
    // engine's read-only `tka_status` carries only the authority head + a pending-disablement signal
    // (ENGINE_ASKS #17). `authority head` is itself a fork-specific extra (Go has no such line).
    if !r.head.is_empty() {
        // `head` is control's AUMHash, copied verbatim from the engine with no daemon-side charset
        // check — sanitize before terminal display (defense-in-depth, like the dns/file formatters).
        out.push_str(&format!(
            "  authority head: {}\n",
            sanitize_for_terminal(&r.head)
        ));
    }
    if r.disabled {
        out.push_str("  status: a disablement is pending (control signalled disable).\n");
    }
    out
}

/// Render `tnet dns status` from a [`DnsStatusReport`](tailscaled_rs::localapi::DnsStatusReport)
/// (Go `tailscale dns status`). Human form prints Go's MagicDNS-configuration sections — MagicDNS
/// on/off, resolvers in preference order, split-DNS routes, search domains, fallback resolvers,
/// certificate domains, additional DNS records, and exit-node-filtered suffixes — each empty section
/// printing a parenthetical none-line, then a one-line honest note that the Go "Use Tailscale DNS"
/// line *here* + the "System DNS configuration" section are not surfaced by this build (no engine
/// OS-DNS accessor). The accept-dns pref itself IS modelled — surfaced via `tnet get accept-dns` (it
/// just isn't echoed in this `dns status` view). `json` emits a REDUCED, fork-specific object — NOT
/// byte-compatible with Go's `jsonoutput.DNSStatusResult`: resolvers/fallback-resolvers are plain
/// `addr:port` STRINGS (Go nests `DNSResolverInfo{Addr, BootstrapResolution}` objects), MagicDNS-on
/// is a top-level `MagicDNS` bool (Go nests it as `CurrentTailnet.MagicDNSEnabled`, with a separate
/// top-level `TailscaleDNS`=accept-dns not surfaced in this `dns status` JSON), `ExtraRecords` is a name→addr map
/// (Go: an array of `{Name,Type,Value}`), and there is no `SystemDNS`/`SystemDNSError`. Built via
/// `serde_json` (escape-safe, 2-space pretty). Pure (returns the string incl. its trailing newline)
/// → unit-testable.
fn format_dns_status(r: &tailscaled_rs::localapi::DnsStatusReport, json: bool) -> String {
    if json {
        use serde_json::{Map, Value, json};
        let mut root = Map::new();
        root.insert("MagicDNS".into(), json!(r.magic_dns));
        root.insert("Resolvers".into(), json!(r.resolvers));
        // Split-DNS routes: a suffix → list-of-addrs object (Go `SplitDNSRoutes`).
        let routes: Map<String, Value> = r
            .routes
            .iter()
            .map(|(suffix, addrs)| (suffix.clone(), json!(addrs)))
            .collect();
        root.insert("SplitDNSRoutes".into(), Value::Object(routes));
        root.insert("SearchDomains".into(), json!(r.search_domains));
        root.insert("FallbackResolvers".into(), json!(r.fallback_resolvers));
        root.insert("CertDomains".into(), json!(r.cert_domains));
        // Extra records: a name → addr object (Go `ExtraRecords`).
        let extra: Map<String, Value> = r
            .extra_records
            .iter()
            .map(|(name, addr)| (name.clone(), json!(addr)))
            .collect();
        root.insert("ExtraRecords".into(), Value::Object(extra));
        root.insert(
            "ExitNodeFilteredSet".into(),
            json!(r.exit_node_filtered_set),
        );
        return format!(
            "{}\n",
            serde_json::to_string_pretty(&root).unwrap_or_else(|_| "{}".to_string())
        );
    }

    let mut out = String::from("=== MagicDNS configuration ===\n");
    if r.magic_dns {
        out.push_str("MagicDNS: enabled tailnet-wide\n");
    } else {
        out.push_str("MagicDNS: disabled tailnet-wide.\n");
    }

    // Every resolver/suffix/domain/record below is CONTROL-PUSHED (from the netmap DNS config), so it
    // is run through `sanitize_for_terminal` before rendering — a malicious/compromised control server
    // could otherwise smuggle ANSI/OSC escape sequences into the operator's terminal. Mirrors the
    // hardening already applied to `format_files`/`format_whois`. The `--json` path is serde-escaped.
    out.push_str("Resolvers (in preference order):\n");
    if r.resolvers.is_empty() {
        out.push_str("  (none configured)\n");
    } else {
        for addr in &r.resolvers {
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(addr)));
        }
    }

    out.push_str("Split DNS Routes:\n");
    if r.routes.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for (suffix, addrs) in &r.routes {
            let suffix = sanitize_for_terminal(suffix);
            if addrs.is_empty() {
                // A negative route (no upstreams) — names under the suffix are not resolved.
                out.push_str(&format!("  - {suffix:<30} -> (no resolvers)\n"));
            } else {
                for addr in addrs {
                    out.push_str(&format!(
                        "  - {suffix:<30} -> {}\n",
                        sanitize_for_terminal(addr)
                    ));
                }
            }
        }
    }

    out.push_str("Search Domains:\n");
    if r.search_domains.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for domain in &r.search_domains {
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(domain)));
        }
    }

    out.push_str("Fallback Resolvers:\n");
    if r.fallback_resolvers.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for addr in &r.fallback_resolvers {
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(addr)));
        }
    }

    out.push_str("Certificate Domains:\n");
    if r.cert_domains.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for domain in &r.cert_domains {
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(domain)));
        }
    }

    out.push_str("Additional DNS Records:\n");
    if r.extra_records.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for (name, addr) in &r.extra_records {
            out.push_str(&format!(
                "  - {} -> {}\n",
                sanitize_for_terminal(name),
                sanitize_for_terminal(addr)
            ));
        }
    }

    out.push_str("Filtered suffixes (exit-node):\n");
    if r.exit_node_filtered_set.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for suffix in &r.exit_node_filtered_set {
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(suffix)));
        }
    }

    out.push_str(
        "(note: the accept-dns pref is shown by `tnet get accept-dns`; the 'Use Tailscale DNS' line \
         here and the 'System DNS configuration' section are not surfaced by this build)\n",
    );
    out
}

/// Render `tnet netcheck` from a [`NetcheckReport`](tailscaled_rs::localapi::NetcheckReport) (Go
/// `tailscale netcheck`). Human form prints a Go-`printNetCheckReport`-flavored block: a `Report:`
/// header, the nearest (preferred) DERP region, and the per-region DERP latency lowest-first (each
/// latency rounded to 0.1ms, e.g. `23.4ms`), with parenthetical none-lines when there is no preferred
/// region / no measured latency. It then prints a one-line honest note that Go's
/// UDP/IPv4/IPv6/`MappingVariesByDestIP`/PortMapping flags are not measured by this build, and that
/// DERP regions are shown by id (the engine carries no region name).
///
/// `json` emits the two fields this build can populate **with Go's field names + value encoding**, so
/// an upstream JSON consumer parses them: `PreferredDERP` is a plain integer (Go's `int`, `0` for
/// unknown — never `null`), and `RegionLatency` is a **map keyed by stringified DERP region id with
/// integer-nanosecond values** (Go's `map[int]time.Duration`, marshalled as ns). The many other Go
/// `Report` fields (UDP/IPv4/IPv6/PortMapping/GlobalV4…) are genuinely not measured by this build and
/// are simply absent — a reduction, not a renamed/reshaped field. Two honest non-byte-exact notes vs
/// Go's `json.MarshalIndent(report, "", "\t")`: the indent is a TAB (matching Go), but JSON object
/// **key order is `serde_json`'s lexicographic string order** (`"10"` before `"2"`), not Go's numeric
/// map order — immaterial, since JSON object key order is non-semantic (and Go marks this format
/// unstable). Pure (returns the string incl. its trailing newline) → unit-testable.
fn format_netcheck(r: &tailscaled_rs::localapi::NetcheckReport, json: bool) -> String {
    if json {
        use serde_json::{Map, Value, json};
        let mut root = Map::new();
        // Go's `PreferredDERP int // or 0 for unknown` — a plain number, 0 when unknown (never null).
        root.insert("PreferredDERP".into(), json!(r.preferred_derp.unwrap_or(0)));
        // Go's `RegionLatency map[int]time.Duration`: a JSON object keyed by the stringified region
        // id, values being the duration as integer NANOSECONDS (how Go marshals `time.Duration`). The
        // engine carries latency as f64 milliseconds, so ns = round(ms * 1e6). A BTreeMap dedups any
        // repeated region_id (last write wins) and gives a deterministic build; the FINAL on-the-wire
        // key order is serde_json's (lexicographic by string), which is fine — object key order is
        // non-semantic.
        let mut region_latency: std::collections::BTreeMap<u32, i64> =
            std::collections::BTreeMap::new();
        for rl in &r.region_latencies {
            region_latency.insert(rl.region_id, (rl.latency_ms * 1_000_000.0).round() as i64);
        }
        let mut latency_obj = Map::new();
        for (id, ns) in &region_latency {
            latency_obj.insert(id.to_string(), json!(ns));
        }
        root.insert("RegionLatency".into(), Value::Object(latency_obj));
        // Tab indent, matching Go's `json.MarshalIndent(report, "", "\t")`.
        return format!(
            "{}\n",
            to_string_pretty_tabs(&root).unwrap_or_else(|_| "{}".to_string())
        );
    }

    let mut out = String::from("Report:\n");
    match r.preferred_derp {
        Some(id) => out.push_str(&format!("  * Nearest DERP: region {id}\n")),
        None => out.push_str("  * Nearest DERP: (none — not measured yet)\n"),
    }
    out.push_str("  * DERP latency:\n");
    if r.region_latencies.is_empty() {
        out.push_str("      (no DERP latency measured)\n");
    } else {
        for rl in &r.region_latencies {
            // Round to 0.1ms (e.g. 23.4ms), matching Go's terse per-region latency rendering.
            out.push_str(&format!(
                "      - region {}: {:.1}ms\n",
                rl.region_id, rl.latency_ms
            ));
        }
    }
    out.push_str(
        "(note: this build's net-report measures DERP-region latency only — Go's \
         UDP/IPv4/IPv6/MappingVariesByDestIP/PortMapping flags are not measured, and DERP regions \
         are shown by id as the engine carries no region name)\n",
    );
    out
}

/// Render `tnet exit-node list`: one line per peer offering to be an exit node (IP, hostname, and
/// online state when known), or a placeholder when none. Country/City columns (Go) are omitted —
/// this fork has no control-supplied Location data. The hostname is control-supplied (netmap), so it
/// is run through `sanitize_for_terminal` before display — both to strip terminal escapes and so an
/// embedded `\n`/`\t` can't forge a fake exit-node row or shift the column (same hardening as
/// `format_file_targets`/`format_whois`; see THREAT_MODEL §4.8). Pure → unit-testable.
fn format_exit_node_list(peers: &[tailscaled_rs::localapi::PeerReport]) -> String {
    let exits: Vec<&tailscaled_rs::localapi::PeerReport> =
        peers.iter().filter(|p| p.is_exit_node).collect();
    if exits.is_empty() {
        return "(no exit nodes available in this tailnet)\n".to_string();
    }
    let mut out = String::from("IP               HOSTNAME\n");
    for p in exits {
        let online = match p.online {
            Some(true) => "  (online)",
            Some(false) => "  (offline)",
            None => "",
        };
        out.push_str(&format!(
            "{:<16} {}{}\n",
            p.ipv4,
            sanitize_for_terminal(&p.name),
            online
        ));
    }
    out
}

/// Render `tnet switch --list`: one line per profile, `* ` marking the current one, then the id and
/// (if different) the display name. Pure → unit-testable.
fn format_profiles(profiles: &[tailscaled_rs::localapi::ProfileEntry]) -> String {
    if profiles.is_empty() {
        return "(no profiles)\n".to_string();
    }
    let mut out = String::new();
    for p in profiles {
        let marker = if p.current { "*" } else { " " };
        // Show the name only when it adds information beyond the id.
        if p.name.is_empty() || p.name == p.id {
            out.push_str(&format!("{marker} {}\n", p.id));
        } else {
            out.push_str(&format!("{marker} {}  ({})\n", p.id, p.name));
        }
    }
    out
}

/// The canonical `(set-flag name, value)` projection of a [`PrefsView`], in the stable order
/// `tnet get` displays. The names match the `tnet set`/`tnet up` flags (Go keys its `get` output by
/// the same set-flag names). Values are kept **typed** (`serde_json::Value`) rather than pre-
/// stringified so the `--json` map emits Go-faithful **bare booleans** (`true`, not `"true"`) and so
/// JSON escaping is handled by serde (a future setting carrying a quote/backslash can't corrupt the
/// output). The plain-text table/single-value path derives display strings from these via
/// [`get_value_display`]. One source so the table, the `--json` map, and single-setting lookup agree.
///
/// This is a SUBSET of Go's `tailscale get` settings (Go derives its list from the full `set` flag
/// set; many of those flags — `hostname`, `nickname`, `auto-update`, … — are not yet modelled by
/// this fork's prefs/engine and so are absent here). One entry, `tun`, is a fork-specific extension
/// (selecting the kernel-TUN vs userspace datapath) that Go's `get` has no counterpart for; it is
/// intentionally surfaced because it is a real `tnet set` flag in this build.
fn get_settings(
    view: &tailscaled_rs::localapi::PrefsView,
) -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::Value;
    vec![
        // An unset hostname is JSON null (the OS hostname is used); the table renders it empty. Go's
        // `get` lists hostname, and the daemon holds it as a pref — surface it.
        (
            "hostname",
            view.hostname
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        // An unset exit-node is JSON null (Go uses the empty/zero value); the table renders it empty.
        (
            "exit-node",
            view.exit_node
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        ("advertise-exit-node", Value::Bool(view.advertise_exit_node)),
        // Routes are a comma-joined string (the `--advertise-routes` arg form), matching how you'd
        // re-pass them to `set`.
        (
            "advertise-routes",
            Value::String(view.advertise_routes.join(",")),
        ),
        (
            "advertise-tags",
            Value::String(view.advertise_tags.join(",")),
        ),
        ("accept-routes", Value::Bool(view.accept_routes)),
        ("accept-dns", Value::Bool(view.accept_dns)),
        ("shields-up", Value::Bool(view.shields_up)),
        ("ssh", Value::Bool(view.ssh)),
        ("tun", Value::Bool(view.tun)),
    ]
}

/// Plain-text display of a setting's [`serde_json::Value`] for the `get` table / single-value output:
/// a bare string for strings (no surrounding quotes), `true`/`false` for bools, empty for null, and
/// the compact JSON form for anything else. Mirrors the value you'd hand back to `tnet set`.
fn get_value_display(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Render every setting as a single re-appliable `tnet set …` flag-argument line (Go
/// `get --set-flags` / `getOutputSetFlags`): `--<name>=<value>` per setting, space-joined. Each
/// value uses the explicit `=value` form (Go's `fmtFlagValueArg`) — `--accept-routes=true`,
/// `--hostname=node-a`, `--exit-node=` for an unset/empty value — so the line is unambiguous and
/// re-pasteable into `tnet set`. Pure → unit-testable. (The names are the canonical set-flag names
/// the `get` table already uses, from [`get_settings`].)
fn format_get_set_flags(view: &tailscaled_rs::localapi::PrefsView) -> String {
    get_settings(view)
        .into_iter()
        .map(|(name, value)| format!("--{name}={}", get_value_display(&value)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render `tnet get` output from a [`PrefsView`] (Go `tailscale get`). `setting` selects a single
/// setting by its set-flag name (`None` or `"all"` = every setting); `json` selects the flattened
/// `{ "name": value }` map form (matching Go `get --json`, a name→value map — NOT a raw prefs-struct
/// dump — with **typed** values: bare booleans, not quoted). Default (no json) is a `NAME  VALUE`
/// table; a single named setting prints just its value. Returns `Err` for an unknown setting name (Go
/// errors too). Pure → unit-testable.
fn format_get(
    view: &tailscaled_rs::localapi::PrefsView,
    setting: Option<&str>,
    json: bool,
) -> Result<String> {
    let settings = get_settings(view);

    // Single named setting (not "all"): print just that value, or error on an unknown name.
    if let Some(name) = setting
        && name != "all"
    {
        let (_, value) = settings.iter().find(|(n, _)| *n == name).ok_or_else(|| {
            anyhow::anyhow!("unknown setting {name:?} (try `tnet get` to list all)")
        })?;
        return Ok(if json {
            // The single value as JSON (bare bool / quoted string / null), serde-encoded so escaping
            // is correct.
            format!("{}\n", serde_json::to_string(value)?)
        } else {
            format!("{}\n", get_value_display(value))
        });
    }

    // All settings.
    if json {
        // Flattened name→value map, built via serde (a `Map` preserves insertion order with the
        // `preserve_order` feature; even without it the keys are stable and the values are correct).
        // Typed values → Go-faithful bare booleans + correct escaping, fixing both the shape and the
        // hand-built-JSON escaping hazard.
        let map: serde_json::Map<String, serde_json::Value> = settings
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect();
        Ok(format!("{}\n", serde_json::to_string_pretty(&map)?))
    } else {
        // NAME/VALUE table. Go `getOutputTable` emits a `NAME\tVALUE` header through a `tabwriter`
        // (tab-elastic columns, 2-space padding); we produce the visually-equivalent layout by
        // space-padding the NAME column to the widest of the header and the setting names (so this is
        // column-faithful to Go, not byte-identical tab output). The `chain(once(4))` guarantees a
        // non-empty iterator, so `max()` is always `Some` (width ≥ 4, never the empty fallback).
        let width = settings
            .iter()
            .map(|(n, _)| n.len())
            .chain(std::iter::once("NAME".len()))
            .max()
            .unwrap_or(4);
        let mut out = format!("{:<width$}  VALUE\n", "NAME");
        for (name, value) in &settings {
            out.push_str(&format!("{name:<width$}  {}\n", get_value_display(value)));
        }
        Ok(out)
    }
}

/// Whether a version's minor number is odd — Go's `version.IsUnstableBuild` rule (an odd minor marks
/// an unstable/development track; even is stable). `minor` is the middle field of `major.minor.patch`.
/// Pure helper so the `unstableBranch` JSON field is unit-testable independent of the crate version.
fn is_unstable_minor(minor: u64) -> bool {
    minor % 2 == 1
}

/// The minor-version number parsed from a `major.minor.patch[-suffix]` string, or `None` if it isn't
/// in that shape. Used to derive `unstableBranch` faithfully (Go reads the minor field).
fn minor_of(version: &str) -> Option<u64> {
    // Strip any pre-release suffix first (the fork has none today, but be faithful to Go's parse).
    let core = version.split('-').next().unwrap_or(version);
    core.split('.').nth(1).and_then(|m| m.parse::<u64>().ok())
}

/// Render `tnet version` output. `client` is this CLI's crate version; `daemon` is the daemon's
/// version when `--daemon` was passed (else `None`); `cap` is the engine's current capability version
/// (Go `version.Meta.cap`). `json` selects the JSON object form. Mirrors Go `tailscale version`:
/// plain prints the bare client version (and a `Client:`/`Daemon:` pair when the daemon was queried);
/// `--json` emits Go's `version.Meta` shape — `majorMinorPatch`/`short`/`long`/`cap` always, plus
/// `unstableBranch` when the minor is odd and `daemonLong` when the daemon was queried. The fork is
/// not git-stamped (no build.rs), so Go's `gitCommit`/`gitDirty`/`gitCommitTime`/`extraGitCommit`/
/// `osVariant`/`tailscaleGoGitHash`/`isDev` Meta fields are honestly omitted rather than faked (a
/// fork git SHA is meaningless against Go's tailscale-repo commit semantics). Pure (returns the
/// string, trailing newline included) so it is unit-testable.
fn format_version(client: &str, daemon: Option<&str>, cap: u16, json: bool) -> String {
    if json {
        // Built via serde so escaping is correct + the two `--json` renderers stay consistent. The
        // fork has no pre-release suffix, so majorMinorPatch == short == long == the crate version
        // (Go's `short`/`long` diverge only when git-stamped, which the fork is not).
        let mut map = serde_json::Map::new();
        map.insert("majorMinorPatch".to_string(), client.into());
        map.insert("short".to_string(), client.into());
        map.insert("long".to_string(), client.into());
        map.insert("cap".to_string(), cap.into());
        // `unstableBranch` only when the minor is odd (Go omitempty — omitted on a stable/even line).
        if minor_of(client).is_some_and(is_unstable_minor) {
            map.insert("unstableBranch".to_string(), true.into());
        }
        // `daemonLong` only when the daemon was queried (Go omitempty).
        if let Some(d) = daemon {
            map.insert("daemonLong".to_string(), d.into());
        }
        // serde_json serialization of a Map<String, Value> cannot fail; fall back defensively.
        format!(
            "{}\n",
            serde_json::to_string_pretty(&map).unwrap_or_else(|_| "{}".to_string())
        )
    } else {
        match daemon {
            // Go prints `Client:`/`Daemon:` when `--daemon` is set.
            Some(d) => format!("Client: {client}\nDaemon: {d}\n"),
            // Plain `version`: just the client version, like Go's bare first line.
            None => format!("{client}\n"),
        }
    }
}

/// Map a daemon pref key (from [`Response::RevertGuard`]) to the `tnet up` flag the operator must
/// re-pass to keep that setting, rendered as a copy-pasteable `--flag` / `--flag=value` token.
///
/// The daemon deliberately speaks pref keys, not flag spellings (it has no notion of `--advertise-
/// routes`); this is the CLI-owned half of that split. Boolean prefs render as a bare `--flag` when
/// their current value is `true` (the only case the guard reports a bool — a `false` bool equals its
/// default and so never trips), and as `--no-flag` defensively otherwise. Value prefs render as
/// `--flag=value`. An unknown key (daemon newer than CLI) falls back to `--key=value` so the message
/// is still actionable rather than dropping the setting silently.
fn revert_pref_to_flag(key: &str, value: &str) -> String {
    match key {
        // Boolean up-managed prefs. The guard only reports these when non-default (i.e. `true`),
        // so the keep-it token is the bare enabling flag; `--no-*` is a defensive fallback.
        "accept_routes" => bool_keep_flag("accept-routes", "no-accept-routes", value),
        "shields_up" => bool_keep_flag("shields-up", "no-shields-up", value),
        "advertise_exit_node" => {
            bool_keep_flag("advertise-exit-node", "no-advertise-exit-node", value)
        }
        "ssh" => bool_keep_flag("ssh", "no-ssh", value),
        "tun" => bool_keep_flag("tun", "no-tun", value),
        // Value-bearing prefs: re-pass the current value verbatim. `advertise_routes` is already a
        // comma-joined list, which `--advertise-routes` accepts directly.
        "advertise_routes" => format!("--advertise-routes={value}"),
        "exit_node" => format!("--exit-node={value}"),
        "hostname" => format!("--hostname={value}"),
        "control_url" => format!("--control-url={value}"),
        "tun_name" => format!("--tun-name={value}"),
        "tun_mtu" => format!("--tun-mtu={value}"),
        // Daemon knows a pref this CLI build doesn't: keep the message actionable.
        other => format!("--{other}={value}"),
    }
}

/// Render a boolean "keep this setting" flag: the bare enabling flag when `value == "true"` (the
/// non-default case the guard reports), else the explicit disabling flag.
fn bool_keep_flag(enable: &str, disable: &str, value: &str) -> String {
    if value == "true" {
        format!("--{enable}")
    } else {
        format!("--{disable}")
    }
}

/// Render the accidental-revert guard message — the Rust analogue of Go's `accidentalUpPrefix`
/// guidance — listing the settings that would be lost and a copy-pasteable command to keep them.
/// Pure (returns the string) so it is unit-testable; the caller prints it to stderr.
fn format_revert_guard(reverts: &[RevertedPref]) -> String {
    // Deterministic order regardless of how the daemon happened to enumerate them.
    let mut flags: Vec<String> = reverts
        .iter()
        .map(|r| revert_pref_to_flag(&r.key, &r.value))
        .collect();
    flags.sort();
    let joined = flags.join(" ");
    let mut out = String::new();
    out.push_str(
        "error: this `tnet up` would revert settings you did not mention back to their defaults.\n",
    );
    out.push_str("To proceed, either re-run mentioning the current value of every non-default\n");
    out.push_str("setting, or pass --reset to accept the reverts:\n\n");
    out.push_str(&format!("    tnet up {joined}\n\n"));
    out.push_str("Or to reset the unmentioned settings to their defaults:\n\n");
    out.push_str("    tnet up --reset ...\n");
    out
}

/// Sanitize a control-plane-supplied string for printing as a **single-line / columnar cell** — the
/// safe default for terminal output.
///
/// Server-supplied text (a peer's `ComputedName`, a DNS resolver/suffix, an AUMHash, a Taildrop file
/// name, …) originates from the control server / a sending peer, which the daemon treats as only
/// semi-trusted. Two distinct injection classes have to be defused:
///
/// 1. **Terminal-escape injection.** Printing the value verbatim would let a malicious or compromised
///    server smuggle ANSI/terminal escape sequences (cursor moves, color, clear-screen, even
///    hyperlink/OSC injection) into the operator's terminal.
/// 2. **Delimiter / column / row injection.** Our human-readable renderers are *structured*:
///    `file cp --targets` prints TAB-separated columns (`<ip>\t<name>\t<status>`), and `whois` /
///    `file list` / `dns status` / `lock status` print one record per line. A control-supplied name
///    containing a literal `\t` could forge an extra column (a fake IP or a fake `offline` status),
///    and an embedded `\n` could forge an entirely fake row/line. Go's `tailscale` does no
///    sanitization here at all and *is* vulnerable to this; this fork is deliberately stricter.
///
/// So this neutralizes **every** C0/C1 control character — including the structural whitespace
/// `\t`/`\n`/`\r` — to a visible `U+FFFD` placeholder. The affected fields (IPs, DNS names, hostnames,
/// hashes) never legitimately contain those bytes, so this is lossless for real data and display
/// hardening only — the wire value is unchanged. For genuinely free-form, possibly multi-line text
/// (the registration-failure `reason`) use [`sanitize_multiline`] instead, which preserves `\t`/`\n`.
fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

/// Sanitize a control-supplied string that is rendered as **free-form, possibly multi-line** text
/// (the registration-failure `reason`, printed as `registration failed: <reason>`).
///
/// Unlike [`sanitize_for_terminal`], this preserves plain whitespace (`\t`, `\n`, `\r`) so a
/// multi-line reason still renders across lines — matching Go, which prints the reason raw. It is safe
/// to keep the newlines here precisely because the reason is *not* structured output: it is not parsed
/// into columns or rows, so an embedded `\n` can only wrap the message, not forge a fake table cell.
/// Every other C0/C1 control (ESC, BEL, …) is still stripped to `U+FFFD`, so escape-sequence injection
/// is defused exactly as in the single-line path. Use this ONLY for free-form message text; anything
/// rendered into a delimited/columnar line MUST use [`sanitize_for_terminal`].
fn sanitize_multiline(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\t' || c == '\n' || c == '\r' {
                c
            } else if c.is_control() {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// Serialize a JSON value pretty-printed with a **TAB** indent, matching Go's
/// `json.MarshalIndent(v, "", "\t")` (the indent `tailscale netcheck --format=json` uses).
/// `serde_json::to_string_pretty` is hard-wired to a two-space indent and cannot be configured, so we
/// drive a `PrettyFormatter::with_indent(b"\t")` directly.
fn to_string_pretty_tabs<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(
        &mut buf,
        serde_json::ser::PrettyFormatter::with_indent(b"\t"),
    );
    value.serialize(&mut ser)?;
    Ok(String::from_utf8(buf).expect("serde_json emits valid UTF-8"))
}

/// Format the `tnet ip` output: this node's tailnet addresses, one per line (IPv4 then IPv6), or a
/// placeholder when the node has no address yet (no netmap received). Pure (returns the string,
/// including its trailing newline) so the formatting is unit-testable; the caller `print!`s it.
//
// `tnet ip` itself renders through `format_ip_filtered` (it always carries an `IpSelect`), so this
// unfiltered variant now has no production call site — it is retained as the tested baseline
// renderer (see the `format_ip` unit tests). `allow(dead_code)` only outside `cfg(test)`.
#[cfg_attr(not(test), allow(dead_code))]
fn format_ip(ipv4: Option<&str>, ipv6: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(v4) = ipv4 {
        out.push_str(v4);
        out.push('\n');
    }
    if let Some(v6) = ipv6 {
        out.push_str(v6);
        out.push('\n');
    }
    if out.is_empty() {
        out.push_str("(no tailnet address yet)\n");
    }
    out
}

/// Format the `tnet ping -c N` summary line: how many were sent vs received, with the loss percent.
/// Pure → unit-testable.
fn format_ping_summary(sent: u32, received: u32) -> String {
    let lost = sent.saturating_sub(received);
    let loss_pct = if sent == 0 {
        0.0
    } else {
        (lost as f64 / sent as f64) * 100.0
    };
    format!("--- {sent} sent, {received} received, {loss_pct:.0}% loss ---")
}

/// Address-family / count selection for `tnet ip` (Go `-4`/`-6`/`-1`). `v4`/`v6` are mutually
/// exclusive (clap enforces). Default = all addresses, both families.
#[derive(Default, Clone, Copy)]
struct IpSelect {
    v4: bool,
    v6: bool,
    first: bool,
}

/// Format `tnet ip` output applying an [`IpSelect`]: `-4` keeps only IPv4, `-6` only IPv6, `-1` only
/// the first selected address (Go's quad-one). With no flags, both families print (IPv4 then IPv6),
/// one per line. A placeholder is printed only when nothing is selectable. Pure → unit-testable.
fn format_ip_filtered(ipv4: Option<&str>, ipv6: Option<&str>, sel: IpSelect) -> String {
    // Apply family filter: -4 drops v6, -6 drops v4; neither keeps both.
    let want_v4 = !sel.v6; // -6 hides v4
    let want_v6 = !sel.v4; // -4 hides v6
    let mut addrs: Vec<&str> = Vec::new();
    if want_v4 && let Some(v4) = ipv4 {
        addrs.push(v4);
    }
    if want_v6 && let Some(v6) = ipv6 {
        addrs.push(v6);
    }
    // -1: only the first (Go's quad-one — the primary address).
    if sel.first {
        addrs.truncate(1);
    }
    if addrs.is_empty() {
        return "(no matching tailnet address)\n".to_string();
    }
    let mut out = String::new();
    for a in addrs {
        out.push_str(a);
        out.push('\n');
    }
    out
}

/// Format the `tnet file list` output: one `"{name}  ({size} bytes)"` line per waiting file, or a
/// placeholder when the inbox is empty (never empty output). Each file name is engine/peer-supplied,
/// so it is passed through [`sanitize_for_terminal`] before rendering (a malicious sender could craft
/// a name with terminal escapes). Pure (returns the string, trailing newline included) so it is
/// unit-testable; the caller `print!`s it.
fn format_files(files: &[tailscaled_rs::localapi::WaitingFileReport]) -> String {
    if files.is_empty() {
        return "(no files waiting)\n".to_string();
    }
    let mut out = String::new();
    for f in files {
        out.push_str(&format!(
            "{}  ({} bytes)\n",
            sanitize_for_terminal(&f.name),
            f.size
        ));
    }
    out
}

/// Render the per-file outcomes of `tnet file get <dir>` (a [`Response::FilesGot`]). One line per
/// file: a success shows where it landed + the byte count (`wrote <name> -> <path> (<n> bytes)`,
/// noting a `rename` that landed at a different name), a failure shows the reason (`error: <name>:
/// <reason>`) and leaves the file in the inbox. An empty inbox prints a clear placeholder. All
/// control-supplied names/paths are sanitized for terminal display. Pure → unit-testable.
fn format_files_got(results: &[tailscaled_rs::localapi::FileGotReport]) -> String {
    if results.is_empty() {
        return "(no files waiting)\n".to_string();
    }
    let mut out = String::new();
    for r in results {
        let name = sanitize_for_terminal(&r.name);
        match (&r.written, &r.error) {
            // Saved but with an error (the "not consumed" case: copied to disk yet the inbox delete
            // failed). Surface BOTH — where it landed AND that it could not be cleared — so the
            // operator knows the file will re-appear on the next drain. Error is checked before the
            // plain-success arm so this never reads as a clean success.
            (Some(path), Some(err)) => {
                out.push_str(&format!(
                    "wrote {name} -> {} ({} bytes), but: {}\n",
                    sanitize_for_terminal(path),
                    r.size,
                    sanitize_for_terminal(err)
                ));
            }
            // Clean success: written, no error. Note the actual path (differs under `rename`).
            (Some(path), None) => {
                out.push_str(&format!(
                    "wrote {name} -> {} ({} bytes)\n",
                    sanitize_for_terminal(path),
                    r.size
                ));
            }
            // Failure: report the reason; the file stays in the inbox.
            (None, Some(err)) => {
                out.push_str(&format!("error: {name}: {}\n", sanitize_for_terminal(err)));
            }
            // Neither (should not happen — the daemon always sets one) — surface defensively.
            (None, None) => {
                out.push_str(&format!("error: {name}: unknown outcome\n"));
            }
        }
    }
    out
}

/// Render the `tnet file cp --targets` peer list (a [`Response::FileTargets`]). One tab-separated line
/// per peer — `<ip>\t<name>[\t<status>]` — mirroring Go's `runCpTargets` (which prints
/// `addr \t ComputedName` plus an `offline`/`unknown-status` detail column). An empty list prints a
/// clear placeholder. The peer name is control-supplied, so it is run through `sanitize_for_terminal`.
/// Pure → unit-testable.
fn format_file_targets(targets: &[tailscaled_rs::localapi::FileTargetReport]) -> String {
    if targets.is_empty() {
        return "(no Taildrop targets)\n".to_string();
    }
    let mut out = String::new();
    for t in targets {
        let name = sanitize_for_terminal(&t.name);
        // Go prints a detail column only when the peer is not known-online: `offline` for an explicit
        // offline, `unknown-status` when control reports no online state. A known-online peer gets no
        // extra column.
        let detail = match t.online {
            Some(true) => String::new(),
            Some(false) => "\toffline".to_string(),
            None => "\tunknown-status".to_string(),
        };
        out.push_str(&format!(
            "{}\t{name}{detail}\n",
            sanitize_for_terminal(&t.ip)
        ));
    }
    out
}

/// Format the `tnet whois` output for a [`WhoisReport`]. If the IP matched no node, a single
/// "no tailnet node owns <ip>" line (the caller passes the queried IP). Otherwise: the owning node's
/// name, its IPv4, the owning user (when control retained it), its liveness (`online`, and a
/// `last-seen` line only when offline — an online node's last-seen is "now", matching `status`), its
/// control-granted ACL `tags` and node-key `key-expiry` (when present), any control-granted node-level
/// capabilities, and the flow-scoped `cap-grants` (Go `WhoIsResponse.CapMap` — the peer-capability
/// grants for this-node → queried-IP, name + values), each on its own line. The node name, tags,
/// node-level capabilities, and every cap-grant name + value are control-supplied, so each is passed
/// through [`sanitize_for_terminal`] before rendering (online/last-seen are a bool + timestamp, not
/// free-form text). Pure (returns the string, trailing newline included) so it is unit-testable; the
/// caller `print!`s it.
fn format_whois(w: &tailscaled_rs::localapi::WhoisReport, ip: &str) -> String {
    if !w.found {
        return format!("no tailnet node owns {ip}\n");
    }
    let mut out = String::new();
    if let Some(name) = w.node_name.as_deref() {
        out.push_str(&format!("node:         {}\n", sanitize_for_terminal(name)));
    }
    if let Some(v4) = w.node_ipv4.as_deref() {
        // Control-supplied like the rest of the whois fields; sanitize uniformly (defense-in-depth —
        // a parsed IP can't hold control bytes today, but the rule is "every off-box field", so there
        // is no per-field judgement call about which ones are "safe enough" to print raw).
        out.push_str(&format!("ipv4:         {}\n", sanitize_for_terminal(v4)));
    }
    if let Some(user) = w.user.as_deref() {
        // `user` originates from control too; sanitize it before printing.
        out.push_str(&format!("user:         {}\n", sanitize_for_terminal(user)));
    }
    // Liveness, following the `status` convention (`peer_status_cell`): show `online:` when the
    // control-connected state is known (omit when `None` = unknown, like status hides
    // unknown-liveness peers), and show `last-seen:` only when the node is OFFLINE and the time is
    // known — an online node's last-seen is "now", so status only surfaces it for offline peers.
    // `online`/`last_seen` are a bool + a chrono timestamp (not free-form control text), so they need
    // no terminal sanitization.
    match w.online {
        Some(true) => out.push_str("online:       yes\n"),
        Some(false) => {
            out.push_str("online:       no\n");
            if let Some(seen) = w.last_seen.as_deref() {
                out.push_str(&format!("last-seen:    {seen}\n"));
            }
        }
        None => {}
    }
    if !w.tags.is_empty() {
        // ACL tags are control-supplied; sanitize each before printing (same as capabilities).
        out.push_str("tags:\n");
        for tag in &w.tags {
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(tag)));
        }
    }
    if let Some(expiry) = w.node_key_expiry.as_deref() {
        // An RFC3339 timestamp (`YYYY-MM-DDTHH:MM:SS+00:00`) from the daemon — not free-form control
        // text, but sanitize defensively anyway (cheap, keeps "every printed node datum is
        // sanitized" uniform).
        out.push_str(&format!(
            "key-expiry:   {}\n",
            sanitize_for_terminal(expiry)
        ));
    }
    if !w.capabilities.is_empty() {
        out.push_str("capabilities:\n");
        for cap in &w.capabilities {
            // Capability names come from control; sanitize each before printing.
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(cap)));
        }
    }
    // Flow-scoped peer-capability grants (Go `WhoIsResponse.CapMap`), distinct from the node-level
    // `capabilities` above — these are the grants control's packet-filter authorizes for traffic from
    // this node to the queried IP, so they carry per-cap arg values (mirroring Go's `tailscale whois`
    // CapMap block). The map is a `BTreeMap`, so iteration is sorted by cap name → deterministic
    // output. Unlike Go, which prints a single `json.MarshalIndent` blob of the values, we render each
    // grant value on its own line, individually sanitized — both the cap name and every value are
    // control-supplied, and one-sanitized-value-per-line is this fork's terminal-injection-safe
    // discipline (no raw control bytes can reach the operator's terminal).
    if !w.cap_map.is_empty() {
        out.push_str("cap-grants:\n");
        for (cap, vals) in &w.cap_map {
            if vals.is_empty() {
                out.push_str(&format!("  - {}\n", sanitize_for_terminal(cap)));
            } else {
                out.push_str(&format!("  - {}:\n", sanitize_for_terminal(cap)));
                for v in vals {
                    out.push_str(&format!("      - {}\n", sanitize_for_terminal(v)));
                }
            }
        }
    }
    out
}

/// Render a [`StatusReport`] to stdout (the shared one-shot + watch formatter).
fn print_status(s: &tailscaled_rs::localapi::StatusReport) {
    print!("{}", format_status(s));
}

/// Render the human-readable `tnet status` text (a [`StatusReport`]). Pure (returns the whole block,
/// trailing newline included) so it is unit-testable — in particular so the sanitization of the
/// control-supplied `self`/`exit-node`/peer names is provable, not just printed. The caller `print!`s
/// it. Every off-box (control/netmap-supplied) name below is run through `sanitize_for_terminal` —
/// single-line cells, so an embedded `\t`/`\n` can neither forge a fake status line / peer row nor
/// break a fixed-width column — except the free-form registration `reason`, which uses
/// `sanitize_multiline` (multi-line message; see THREAT_MODEL §4.8).
fn format_status(s: &tailscaled_rs::localapi::StatusReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    // `writeln!` into a String is infallible; the `let _ =` keeps clippy quiet without `.unwrap()`.
    let _ = writeln!(out, "state:        {}", s.state);
    let _ = writeln!(out, "want_running: {}", s.want_running);
    // `self_name` is this node's control-supplied display name (netmap ComputedName); sanitize it so
    // it can't smuggle terminal escapes or, via an embedded `\n`, forge extra status lines (e.g. a
    // spoofed `registration failed:` / `peers:` line). Same hardening as the peer list; §4.8.
    let _ = writeln!(
        out,
        "self:         {} {}",
        s.self_name
            .as_deref()
            .map(sanitize_for_terminal)
            .unwrap_or_else(|| "(unknown)".to_string()),
        s.self_ipv4.as_deref().unwrap_or("-")
    );
    // Configured posture (the node's persisted prefs), so `tnet status` shows what `up`/`set` left
    // in effect — the analogue of the config Go's `tailscale status` reflects. Each line is printed
    // only when it carries non-default information, to keep a plain node's status uncluttered.
    let p = &s.prefs;
    if let Some(en) = p.exit_node.as_deref() {
        let _ = writeln!(out, "exit-node:    {en}");
    }
    if p.advertise_exit_node {
        let _ = writeln!(out, "advertising:  exit-node");
    }
    if !p.advertise_routes.is_empty() {
        let _ = writeln!(out, "adv-routes:   {}", p.advertise_routes.join(", "));
    }
    if p.accept_routes {
        let _ = writeln!(out, "accept-routes: on");
    }
    if p.shields_up {
        let _ = writeln!(out, "shields-up:   on");
    }
    if p.ssh {
        // Distinguish the *enabled* pref from the server actually *running*. The task can die at
        // bind time (no tailnet IPv4, `listen_ssh` error) while the pref stays on, so flag that
        // honestly rather than imply SSH is serving. Only warn when the node is in a state where the
        // server is expected to be up (Running/Starting) — a deliberately-down node has no task
        // (`ssh_running: false`) and must not be reported as a broken SSH server.
        let node_should_serve = s.state == "Running" || s.state == "Starting";
        if node_should_serve && !p.ssh_running {
            let _ = writeln!(out, "ssh-server:   on (NOT RUNNING — check logs)");
        } else {
            let _ = writeln!(out, "ssh-server:   on");
        }
    }
    if p.tun {
        let _ = writeln!(out, "tun:          on");
    }
    // Interactive login: when the node is waiting for a human to authorize it, the daemon surfaces
    // the control auth URL — make it prominent so the operator can click it.
    if let Some(url) = s.auth_url.as_deref() {
        let _ = writeln!(out);
        let _ = writeln!(out, "To authenticate this node, visit:");
        let _ = writeln!(out, "    {url}");
    }
    // Terminal registration failure: distinct from `auth_url`, this means registration hard-failed
    // and the engine will not retry. Re-running with the same key loops forever, so spell out that
    // the operator must re-authenticate with a fresh key.
    if let Some(reason) = s.error.as_deref() {
        let _ = writeln!(out);
        let _ = writeln!(out, "registration failed: {}", sanitize_multiline(reason));
        let _ = writeln!(
            out,
            "(this is a permanent failure — re-run `tnet up --authkey <NEW_KEY>` with a fresh \
             key; the same key will keep failing)"
        );
    }
    // The exit node currently engaged (Go `ExitNodeStatus`), distinct from the *configured* selector
    // above: this is what traffic actually egresses through right now (the engine's fail-closed answer).
    if let Some(active) = s.active_exit_node.as_deref() {
        // `active_exit_node` resolves to the exit peer's control-supplied display name (netmap), so
        // sanitize before display — same single-line hardening as `self_name`/the peer list (§4.8).
        let _ = writeln!(
            out,
            "exit-node:    {} (active)",
            sanitize_for_terminal(active)
        );
    }
    let _ = writeln!(out, "peers:        {}", s.peers.len());
    for p in &s.peers {
        // `p.name` is the peer's control-supplied hostname: sanitize before display so it cannot
        // smuggle terminal escapes or, via an embedded `\t`/`\n`, forge a fake peer row or break the
        // fixed-width column layout (same hardening as the other listings; §4.8).
        let _ = writeln!(
            out,
            "  - {:<28} {:<16}{}{}",
            sanitize_for_terminal(&p.name),
            p.ipv4,
            if p.is_exit_node { "  [exit]" } else { "" },
            peer_status_cell(p),
        );
    }
    out
}

/// The Go-`printPS`-flavored status cell for a peer: direct-vs-relay + an offline/last-seen suffix.
/// Pure → unit-testable. Empty when there is nothing informative to add (online peer, no path known).
fn peer_status_cell(p: &tailscaled_rs::localapi::PeerReport) -> String {
    let mut parts: Vec<String> = Vec::new();
    // Path: a confirmed direct endpoint, else the DERP relay region (mutually exclusive, like Go's
    // CurAddr-vs-Relay). Quote the relay region to match Go's `relay "nyc"`.
    if let Some(addr) = p.cur_addr.as_deref() {
        parts.push(format!("direct {addr}"));
    } else if let Some(region) = p.relay.as_deref() {
        parts.push(format!("relay {region:?}"));
    }
    // Liveness: only call out offline (online is the unremarkable default), appending last-seen when
    // known — mirrors Go's "; offline, last seen …".
    if p.online == Some(false) {
        match p.last_seen.as_deref() {
            Some(seen) => parts.push(format!("offline, last seen {seen}")),
            None => parts.push("offline".to_string()),
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("  ({})", parts.join("; "))
    }
}

/// Client-side filters for `tnet status` (Go's `--active` / `--peers=false` / `--self=false`),
/// applied to the [`StatusReport`] before either renderer so the human and `--json` outputs honor
/// them identically. Default = show everything.
#[derive(Default, Clone, Copy)]
struct StatusFilter {
    /// Show only "active" peers. Go's `--active` means recent traffic; this fork has no per-peer
    /// traffic signal, so it approximates with the peer's *online* (control-connected) state —
    /// peers whose liveness is unknown (`online: None`) are hidden.
    active_only: bool,
    /// Hide the peer list entirely (Go `--peers=false`).
    hide_peers: bool,
    /// Hide this node's own self info (Go `--self=false`).
    hide_self: bool,
}

impl StatusFilter {
    /// Apply the filters to a [`StatusReport`], returning the projected report. Pure (consumes +
    /// returns), so it is unit-testable. `hide_self` blanks the self fields so both renderers omit
    /// the self line/object; `hide_peers` empties the peer list; `active_only` keeps only peers
    /// reported online.
    fn apply(
        &self,
        mut s: tailscaled_rs::localapi::StatusReport,
    ) -> tailscaled_rs::localapi::StatusReport {
        if self.hide_self {
            s.self_ipv4 = None;
            s.self_name = None;
            s.self_ipv6 = None;
        }
        if self.hide_peers {
            s.peers.clear();
        } else if self.active_only {
            // "active" ≈ online (the only liveness signal we have). Unknown liveness → hidden.
            s.peers.retain(|p| p.online == Some(true));
        }
        s
    }
}

/// Render `tnet status --json` as a Go `ipnstate.Status`-shaped object (a faithful subset). Built via
/// `serde_json` so it is escape-safe and emits bare booleans, 2-space indented like Go.
///
/// We populate only fields we can fill truthfully and use Go's exact key names (`BackendState`,
/// `AuthURL`, `TailscaleIPs`, `Self`, `Peer`, …). `BackendState` is our `state` string, which is
/// already one of Go's canonical `ipn.State` names (`NoState`/`NeedsLogin`/`NeedsMachineAuth`/
/// `Stopped`/`Starting`/`Running`). Each `PeerStatus` carries the subset we know: `HostName`/`DNSName`
/// (our peer name), `TailscaleIPs`, `ExitNodeOption` (our `is_exit_node`), and `Online` when known.
///
/// DEVIATION (documented): Go keys the `Peer` map by the node **public key** (`"nodekey:…"`); this
/// fork keys it by the engine's **StableNodeID** instead, since that is the durable per-peer
/// identifier the daemon surfaces (see [`tailscaled_rs::localapi::PeerReport::stable_id`]). A peer
/// missing a stable id (older daemon) falls back to its name as the key.
fn format_status_json(s: &tailscaled_rs::localapi::StatusReport) -> Result<String> {
    use serde_json::{Map, Value, json};

    // The self/peer TailscaleIPs slice: IPv4 then (if known) IPv6, like Go's TailscaleIPs.
    let self_ips: Vec<&String> = s.self_ipv4.iter().chain(s.self_ipv6.iter()).collect();

    // Self: a PeerStatus subset from the self_* fields.
    let self_node = if !self_ips.is_empty() || s.self_name.is_some() {
        let mut m = Map::new();
        if let Some(name) = &s.self_name {
            m.insert("HostName".into(), json!(name));
            m.insert("DNSName".into(), json!(name));
        }
        m.insert("TailscaleIPs".into(), json!(self_ips));
        Value::Object(m)
    } else {
        Value::Null
    };

    // Peer map, keyed by stable id (Go uses the node public key — see the doc note).
    let mut peers = Map::new();
    for p in &s.peers {
        let key = if p.stable_id.is_empty() {
            p.name.clone()
        } else {
            p.stable_id.clone()
        };
        let mut pm = Map::new();
        pm.insert("HostName".into(), json!(p.name));
        pm.insert("DNSName".into(), json!(p.name));
        // TailscaleIPs: IPv4 then IPv6 (Go's per-peer address slice).
        let ips: Vec<&String> = std::iter::once(&p.ipv4).chain(p.ipv6.iter()).collect();
        pm.insert("TailscaleIPs".into(), json!(ips));
        pm.insert("ExitNodeOption".into(), json!(p.is_exit_node));
        if let Some(online) = p.online {
            pm.insert("Online".into(), json!(online));
        }
        if !p.allowed_routes.is_empty() {
            pm.insert("AllowedIPs".into(), json!(p.allowed_routes));
        }
        if let Some(seen) = &p.last_seen {
            pm.insert("LastSeen".into(), json!(seen));
        }
        if let Some(addr) = &p.cur_addr {
            pm.insert("CurAddr".into(), json!(addr));
        }
        if let Some(region) = &p.relay {
            pm.insert("Relay".into(), json!(region));
        }
        peers.insert(key, Value::Object(pm));
    }

    let mut root = Map::new();
    root.insert("BackendState".into(), json!(s.state));
    // Version (Go `Status.Version`): the daemon's own version, carried on the report. Surfaced here
    // so `status --json | jq .Version` answers the way `version --daemon` does.
    if let Some(v) = &s.version {
        root.insert("Version".into(), json!(v));
    }
    // TUN (Go `Status.TUN`): whether the node runs on a kernel TUN interface vs the userspace
    // netstack. We report the configured pref (the human `status` already prints it); Go reports the
    // runtime reality. These agree on every success path (netstack default → false; `--tun` up → true)
    // and diverge only if a requested `--tun` failed to initialize (pref true, datapath netstack) —
    // the fork has no `tun_running` liveness signal today, so the pref is the answer. Go emits the
    // bare bool always.
    root.insert("TUN".into(), json!(s.prefs.tun));
    // HaveNodeKey (Go `Status.HaveNodeKey`, omitempty): whether a node key is on disk — taken from the
    // daemon's `have_node_key` (the analogue of Go's `hasNodeKeyLocked`, read from the key file), NOT
    // inferred from `state` (an expired node reports `NeedsLogin` but still holds its key). Go omits it
    // when false, so only emit it when true.
    if s.have_node_key {
        root.insert("HaveNodeKey".into(), json!(true));
    }
    // AuthURL: Go emits the field always (empty when none); mirror that.
    root.insert("AuthURL".into(), json!(s.auth_url.as_deref().unwrap_or("")));
    root.insert("TailscaleIPs".into(), json!(self_ips));
    root.insert("Self".into(), self_node);
    if let Some(suffix) = &s.magic_dns_suffix {
        root.insert("MagicDNSSuffix".into(), json!(suffix));
    }
    // ExitNodeStatus: Go nests the active exit node under an object keyed by its ID. We carry the
    // resolved name/id, so emit the same shape (just the ID field) when one is engaged.
    if let Some(active) = &s.active_exit_node {
        root.insert("ExitNodeStatus".into(), json!({ "ID": active }));
    }
    root.insert("Peer".into(), Value::Object(peers));

    Ok(format!("{}\n", serde_json::to_string_pretty(&root)?))
}

/// Stream status: send `Request::Watch` and print each [`StatusReport`] the daemon pushes (an
/// initial snapshot, then one per state transition) until the connection ends or the user
/// interrupts (Ctrl-C). The daemon closes the stream when the device is torn down. A `---` rule
/// separates successive snapshots so transitions are visually distinct.
async fn watch_status(socket: &std::path::Path) -> Result<()> {
    let stream = UnixStream::connect(socket)
        .await
        .context("connect (is tailnetd running?)")?;
    let (read_half, mut write_half) = stream.into_split();

    let mut line = serde_json::to_vec(&Request::Watch)?;
    line.push(b'\n');
    write_half.write_all(&line).await?;
    write_half.flush().await?;

    let mut reader = BufReader::new(read_half);
    let mut buf = String::new();
    let mut first = true;
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf).await?;
        if n == 0 {
            // Daemon closed the stream (device torn down / shutdown).
            break;
        }
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Response>(trimmed)
            .with_context(|| format!("parsing daemon stream line: {trimmed:?}"))?
        {
            Response::Status(s) => {
                if !first {
                    println!("---");
                }
                first = false;
                print_status(&s);
            }
            Response::Error { message } => {
                eprintln!("error: {message}");
                std::process::exit(1);
            }
            // The watch stream only carries Status frames; any other reply (an `Ok`, or one of the
            // diagnostic Ip/Whois/Ping replies) is unexpected on this connection but harmless — note
            // it and keep streaming.
            other => eprintln!("warning: unexpected reply on status stream: {other:?}"),
        }
    }
    Ok(())
}

/// Interval between `status` polls while [`wait_for_running`] waits for the node to come up.
const WAIT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Block until the node reaches `Running` with a tailnet IP, then return `Ok(())` (exit 0). Mirrors
/// Go `tailscale wait`'s exit-code contract. Three exit conditions: **Running** → `Ok(())`; a
/// **terminal registration error** → `Err` with the reason (fail fast — the engine will not retry,
/// so it does not wait out the timeout; see [`wait_decision`]); **timeout** → `Err`. `timeout_secs`
/// of `None`/`Some(0)` waits forever; otherwise it bounds the wait. Shared by `tnet wait` and
/// `tnet up --timeout` (both want the same "wait for Running, bounded, fail-fast-on-error" semantics).
///
/// We poll `Request::Status` rather than stream the IPN bus: it reuses the existing one-shot
/// round-trip, and the daemon's derived `state` is authoritative. Go additionally waits for the
/// kernel TUN interface to actually carry the IP — but this daemon defaults to the userspace
/// netstack (no OS interface to observe), which is exactly the case Go *also* short-circuits ("if
/// `!st.TUN` return immediately"), so polling to `Running` + a tailnet IP is the faithful condition.
async fn wait_for_running(socket: &std::path::Path, timeout_secs: Option<u64>) -> Result<()> {
    // `None` or `0` → wait forever (Go's "0 means wait indefinitely").
    let deadline = match timeout_secs {
        Some(secs) if secs > 0 => {
            Some(tokio::time::Instant::now() + std::time::Duration::from_secs(secs))
        }
        _ => None,
    };
    loop {
        // A failed round-trip (daemon not up yet / socket missing) is NOT fatal — keep waiting, like
        // Go's backoff loop while tailscaled comes up. The per-poll meaning is decided by the pure
        // `wait_decision`: a terminal registration error fails fast (the engine won't retry — the
        // analogue of Go surfacing a backend error promptly rather than burning the whole timeout;
        // bead tsd-lr6), `Running` succeeds, everything else keeps waiting until the deadline. The
        // failure reason is control-influenced, so sanitize it at the bail site (the decision fn
        // stays a pure classifier returning the raw reason — same split as `classify_auth`).
        if let Ok(Response::Status(s)) = round_trip(socket, &Request::Status).await {
            match wait_decision(&s) {
                WaitStep::Done => return Ok(()),
                WaitStep::Failed(reason) => {
                    anyhow::bail!("node registration failed: {}", sanitize_multiline(&reason))
                }
                WaitStep::Keep => {}
            }
        }
        if let Some(deadline) = deadline
            && tokio::time::Instant::now() >= deadline
        {
            anyhow::bail!(
                "timed out waiting for the node to reach Running (waited {}s)",
                timeout_secs.unwrap_or(0)
            );
        }
        tokio::time::sleep(WAIT_POLL_INTERVAL).await;
    }
}

/// The per-poll decision [`wait_for_running`] makes from a single [`StatusReport`]. Split out as a
/// pure function ([`wait_decision`]) so the precedence — Running wins over a terminal error, a
/// terminal error fails fast, everything else (incl. a transient `auth_url`) keeps waiting — is
/// unit-testable without a live socket.
#[derive(Debug, PartialEq, Eq)]
enum WaitStep {
    /// The node reached `Running` with a tailnet IP — the wait succeeded.
    Done,
    /// A terminal registration failure, carrying control's **raw** reason (the caller sanitizes it
    /// at the print/bail site, like [`classify_auth`]). Fail fast; the engine will not retry, so
    /// waiting longer is futile.
    Failed(String),
    /// Nothing actionable yet — keep polling until the deadline. Covers both "not up yet" and a
    /// pending interactive login (`auth_url` set, which is transient, not a failure).
    Keep,
}

/// Decide what a single poll's [`StatusReport`] means for [`wait_for_running`]. **Pure** (no I/O), so
/// the precedence is unit-testable: `Running` short-circuits to [`Done`](WaitStep::Done) FIRST (a
/// Running node never carries a terminal error); otherwise a `Some(error)` is a terminal failure
/// ([`Failed`](WaitStep::Failed), the raw reason — the caller sanitizes); otherwise — including a
/// pending `auth_url` (interactive login is transient, not a failure) — we [`Keep`](WaitStep::Keep)
/// waiting.
fn wait_decision(s: &tailscaled_rs::localapi::StatusReport) -> WaitStep {
    if s.state == "Running" && s.self_ipv4.is_some() {
        return WaitStep::Done;
    }
    if let Some(reason) = s.error.as_deref() {
        return WaitStep::Failed(reason.to_string());
    }
    WaitStep::Keep
}

/// Maximum time to wait, after an interactive `up`, for the control auth URL to appear. Measured
/// against the real control plane, the engine takes ~10s to register, be told "needs auth", and
/// propagate `DeviceState::NeedsLogin(url)`, so a too-short poll silently misses it; 20s gives
/// comfortable margin while still bounding a `tnet up` that will never get a URL (e.g. offline).
const AUTH_URL_POLL: std::time::Duration = std::time::Duration::from_secs(20);
/// Interval between `status` polls while waiting for the auth URL.
const AUTH_URL_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// The outcome of an interactive-`up` poll, distinguishing the three terminal cases the caller must
/// render differently: a login URL arrived, registration *terminally failed*, or nothing actionable
/// surfaced before the deadline.
enum AuthOutcome {
    /// The control auth URL the operator must visit to authorize the node.
    Url(String),
    /// Registration hard-failed (terminal `error`); the reason is control's Display string. The
    /// operator must re-authenticate with a fresh key — re-running with the same one loops forever.
    Failed(String),
    /// Nothing to prompt: the node authorized instantly (pre-approved / `Running`) or no URL/error
    /// appeared before the deadline. The operator can re-run `tnet status`.
    None,
}

/// Classify a single [`StatusReport`] into an [`AuthOutcome`]. Pure (no I/O) so the bail logic is
/// unit-testable. Precedence: a terminal `error` wins over everything (it is the permanent state),
/// then a pending `auth_url`, then a node already past login (`Running`); otherwise keep waiting.
fn classify_auth(s: &tailscaled_rs::localapi::StatusReport) -> AuthOutcome {
    // Terminal failure is checked first: if both somehow co-occur, the permanent error must win
    // over a stale/pending URL (re-running with the same key would loop forever).
    if let Some(reason) = s.error.as_deref() {
        return AuthOutcome::Failed(reason.to_owned());
    }
    if let Some(url) = s.auth_url.as_deref() {
        return AuthOutcome::Url(url.to_owned());
    }
    // Already past NeedsLogin (authorized / running) — nothing to prompt.
    AuthOutcome::None
}

/// After an interactive (authkey-less) `up`, poll `status` for up to [`AUTH_URL_POLL`] to surface
/// either the control auth URL or a terminal registration failure. The engine reaches
/// `NeedsLogin(url)` ~10s after registration begins, so we wait a generous 20s for a URL; but a
/// permanent failure (`error`) short-circuits immediately — there is no point dwelling the full
/// window for a login that will never help. If the node authorizes instantly (pre-approved) or
/// never needs login, returns [`AuthOutcome::None`] and the operator can re-run `tnet status`.
///
/// Prints a one-time "contacting…" line on the first poll so an interactive `up` doesn't look
/// frozen during the ~10s the engine needs.
async fn poll_for_auth_url(socket: &std::path::Path) -> AuthOutcome {
    let deadline = tokio::time::Instant::now() + AUTH_URL_POLL;
    let mut announced = false;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Response::Status(s)) = round_trip(socket, &Request::Status).await {
            match classify_auth(&s) {
                // A pending URL or a terminal failure are both decisive — return at once. The
                // failure case is the early-bail: we do NOT keep polling the full window.
                outcome @ (AuthOutcome::Url(_) | AuthOutcome::Failed(_)) => return outcome,
                // Already authorized / running before any URL appeared — nothing to prompt.
                AuthOutcome::None if s.state == "Running" => return AuthOutcome::None,
                // Still in flight (e.g. NoState/Starting and no URL yet) — keep polling.
                AuthOutcome::None => {}
            }
        }
        if !announced {
            announced = true;
            println!("contacting the control server… (run `tnet status` for the latest state)");
        }
        tokio::time::sleep(AUTH_URL_POLL_INTERVAL).await;
    }
    AuthOutcome::None
}

/// Resolve the pre-auth key from the available sources, in precedence order:
/// `--authkey-file` > `--authkey` > `$TS_AUTH_KEY`. Returns the secret wrapped so it is zeroized
/// on drop and kept out of any debug/log output; `None` means no key was supplied (interactive
/// login). `--authkey` and `--authkey-file` are mutually exclusive at the clap layer.
async fn resolve_authkey(
    authkey: Option<String>,
    authkey_file: Option<PathBuf>,
) -> Result<Option<SecretString>> {
    if let Some(path) = authkey_file {
        // Read from the file, then trim a single trailing newline so a here-doc / `echo > key`
        // file works without smuggling whitespace into the key. Async read for consistency with
        // the rest of the CLI's I/O.
        let contents = tokio::fs::read_to_string(&path)
            .await
            .with_context(|| format!("reading auth key from {}", path.display()))?;
        return Ok(Some(SecretString::from(contents.trim().to_owned())));
    }
    if let Some(key) = authkey {
        return Ok(Some(SecretString::from(key)));
    }
    // Fall back to the env var (read manually rather than via clap `env` so it never surfaces in
    // `--help` and so the precedence above stays explicit).
    match std::env::var(AUTHKEY_ENV) {
        Ok(key) if !key.is_empty() => Ok(Some(SecretString::from(key))),
        _ => Ok(None),
    }
}

/// Send one request, read one newline-delimited JSON response.
async fn round_trip(socket: &std::path::Path, request: &Request) -> Result<Response> {
    let stream = UnixStream::connect(socket)
        .await
        .context("connect (is tailnetd running?)")?;
    let (read_half, mut write_half) = stream.into_split();

    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    write_half.write_all(&line).await?;
    write_half.flush().await?;

    let mut reader = BufReader::new(read_half);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await?;
    // A zero-byte read leaves the buffer empty: the daemon closed the connection without replying
    // (connection cap hit, or the handler crashed). Surface that plainly instead of falling through
    // to a confusing "parsing daemon response: EOF" from the empty-string parse below.
    if response_line.is_empty() {
        anyhow::bail!(
            "daemon closed the connection without a reply (is it overloaded, or did the request crash it?)"
        );
    }
    let response = serde_json::from_str(response_line.trim())
        .with_context(|| format!("parsing daemon response: {response_line:?}"))?;
    Ok(response)
}

/// HTML-escape a string for safe inclusion in `status --web` page text. Control-server-/peer-supplied
/// values (node/peer names, relay codes, the MagicDNS suffix) flow into the page, so they must never
/// be able to inject markup/script — map the five HTML-significant characters to entities. Pure.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Render a [`StatusReport`](tailscaled_rs::localapi::StatusReport) as a self-contained HTML status
/// page — the body `status --web` serves (the analogue of Go `ipnstate.Status.WriteHTML`, faithful in
/// content rather than a byte-copy of Go's template). A header block (state, version, TUN, this node's
/// name + IPs, MagicDNS suffix, active exit node) plus a peer table (name, IPs, online, exit-node,
/// relay, last-seen). Every control-/peer-supplied string is [`html_escape`]d. Pure → unit-testable.
fn render_status_html(s: &tailscaled_rs::localapi::StatusReport) -> String {
    let mut h = String::new();
    h.push_str("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">");
    h.push_str("<title>tailnetd status</title>");
    h.push_str(
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;}\
         table{border-collapse:collapse;margin-top:1rem;}\
         th,td{border:1px solid #ccc;padding:4px 10px;text-align:left;}\
         th{background:#f4f4f4;}.k{color:#555;}</style></head><body>",
    );
    h.push_str("<h1>tailnetd status</h1>");
    h.push_str("<table>");
    let row = |h: &mut String, k: &str, v: String| {
        h.push_str(&format!("<tr><td class=\"k\">{k}</td><td>{v}</td></tr>"));
    };
    row(&mut h, "state", html_escape(&s.state));
    if let Some(v) = &s.version {
        row(&mut h, "version", html_escape(v));
    }
    row(&mut h, "TUN", s.prefs.tun.to_string());
    if let Some(n) = &s.self_name {
        row(&mut h, "self", html_escape(n));
    }
    let mut ips = Vec::new();
    if let Some(v4) = &s.self_ipv4 {
        ips.push(v4.clone());
    }
    if let Some(v6) = &s.self_ipv6 {
        ips.push(v6.clone());
    }
    if !ips.is_empty() {
        row(&mut h, "addresses", html_escape(&ips.join(", ")));
    }
    if let Some(suffix) = &s.magic_dns_suffix {
        row(&mut h, "magic-dns-suffix", html_escape(suffix));
    }
    if let Some(exit) = &s.active_exit_node {
        row(&mut h, "exit-node", html_escape(exit));
    }
    h.push_str("</table>");

    h.push_str(&format!("<h2>peers ({})</h2>", s.peers.len()));
    if s.peers.is_empty() {
        h.push_str("<p>no peers</p>");
    } else {
        h.push_str(
            "<table><tr><th>name</th><th>ipv4</th><th>ipv6</th><th>online</th>\
             <th>exit-node</th><th>relay</th><th>last-seen</th></tr>",
        );
        for p in &s.peers {
            let online = match p.online {
                Some(true) => "yes",
                Some(false) => "no",
                None => "?",
            };
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&p.name),
                html_escape(&p.ipv4),
                html_escape(p.ipv6.as_deref().unwrap_or("")),
                online,
                if p.is_exit_node { "yes" } else { "" },
                html_escape(p.relay.as_deref().unwrap_or("")),
                html_escape(p.last_seen.as_deref().unwrap_or("")),
            ));
        }
        h.push_str("</table>");
    }
    h.push_str("</body></html>");
    h
}

/// Parse the method + target from an HTTP request line (`GET / HTTP/1.1`) → `(method, path)`. Returns
/// `None` for a malformed line (fewer than the two leading tokens). Pure → unit-testable; the
/// `status --web` serve loop routes only the exact path `/`.
fn parse_request_target(request_line: &str) -> Option<(&str, &str)> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    Some((method, path))
}

/// Max concurrent in-flight `status --web` connection handlers. Defense-in-depth against a connection
/// flood: each accepted connection spawns a detached handler, so without a cap a flood of clients
/// could spawn handlers (and leak fds) without bound. The per-handler 5s read-deadline already bounds
/// a *slow* client; this bounds the COUNT. At cap a new connection is dropped (shed, not queued).
/// This is a local diagnostic server (default `127.0.0.1`), so 64 is far above normal single-user use.
const MAX_WEB_CONNECTIONS: usize = 64;

/// `tnet status --web`: serve an HTML status page from an embedded HTTP server (Go `tailscale status
/// --web`). Binds a TCP listener on `listen` (default `127.0.0.1:8384`), optionally opens a browser at
/// the URL, then accepts connections until interrupted: each request re-fetches the live status
/// ([`Request::Status`]) and, for `GET /`, replies `200 text/html` with [`render_status_html`]; any
/// other path is a `404`. Reuses the existing daemon read — no new daemon/engine surface.
///
/// Each connection is handled on its own detached task, bounded by a [`Semaphore`](tokio::sync::Semaphore)
/// cap ([`MAX_WEB_CONNECTIONS`]) so a flood can't leak handler tasks/fds without bound (the count
/// bound; the per-handler 5s read-deadline is the slow-client bound).
async fn run_status_web(socket: &std::path::Path, listen: &str, browser: bool) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding the status web server to {listen}"))?;
    let addr = listener
        .local_addr()
        .context("resolving the listen address")?;
    // The status page has no authentication (matching Go's `tailscale status --web`). On the default
    // 127.0.0.1 bind that's fine; if the operator widened it, warn that the tailnet topology (node
    // name, IPs, peers) is now reachable by anyone who can hit this address.
    if !addr.ip().is_loopback() {
        eprintln!(
            "warning: serving status on {addr}, which is reachable beyond localhost and has NO \
             authentication — this node's name, tailnet IPs, and peer topology are exposed to \
             anyone who can reach this address."
        );
    }
    let url = format!("http://{addr}");
    println!("Serving Tailscale status at {url} ... (Ctrl-C to stop)");
    if browser {
        open_browser_best_effort(&url);
    }
    // Cap concurrent connection handlers; a permit is held for a handler's whole lifetime. Defense-in-
    // depth against a flood (the count bound — the 5s read-deadline in the handler is the slow-client
    // bound). At cap, a new connection is dropped (shed, not queued).
    let conn_limit = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_WEB_CONNECTIONS));
    loop {
        let (conn, _peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("status --web: accept failed: {e}");
                continue;
            }
        };
        // Acquire a handler permit BEFORE spawning; if the cap is exhausted, drop the connection
        // (closing it) rather than spawning unboundedly. Moved into the task, released when it ends.
        let Ok(permit) = std::sync::Arc::clone(&conn_limit).try_acquire_owned() else {
            eprintln!("status --web: connection cap reached; dropping connection");
            continue;
        };
        // Handle each connection on its own task. Go's `http.Serve` is goroutine-per-connection, so a
        // single slow or silent client can't head-of-line-block every other status request; the read
        // deadline inside the handler is what actually bounds a stalled client.
        let socket = socket.to_path_buf();
        tokio::spawn(async move {
            let _permit = permit;
            serve_status_connection(conn, &socket).await;
        });
    }
}

/// Serve one HTTP/1.1 connection for the `status --web` server: read the request line, route `GET /`
/// to a fresh status fetch, write the response, and close. Best-effort throughout — any read/write
/// error or timeout just drops the connection (this is a diagnostic server, not a hardened endpoint).
///
/// The request-line read is bounded in BOTH bytes (8 KiB cap) and time (a 5s deadline): TCP can split
/// the line across segments so a single read isn't enough, but a client that dribbles or never sends
/// must not park the task forever.
async fn serve_status_connection(mut conn: tokio::net::TcpStream, socket: &std::path::Path) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let read_line = async {
        loop {
            let n = conn.read(&mut chunk).await?;
            if n == 0 {
                break; // EOF before a full line — treat as no request.
            }
            buf.extend_from_slice(&chunk[..n]);
            // Stop once we have the end of the request line, or cap buffering from a hostile client.
            if buf.contains(&b'\n') || buf.len() >= 8192 {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    };
    match tokio::time::timeout(std::time::Duration::from_secs(5), read_line).await {
        Ok(Ok(())) => {}
        // Timed out, or a read error: drop the connection silently.
        _ => return,
    }
    if buf.is_empty() {
        return;
    }
    let request_line = String::from_utf8_lossy(&buf);
    let first_line = request_line.lines().next().unwrap_or("");
    let (status, body) = match parse_request_target(first_line) {
        Some(("GET", "/")) => match round_trip(socket, &Request::Status).await {
            Ok(Response::Status(s)) => ("200 OK", render_status_html(&s)),
            // Both the wrong-variant and the error case collapse to a 500; on a real error, log the
            // cause first so the failure isn't swallowed (the page itself stays generic).
            other => {
                if let Err(e) = other {
                    eprintln!("status --web: status fetch failed: {e}");
                }
                (
                    "500 Internal Server Error",
                    "<!DOCTYPE html><html><body>status unavailable</body></html>".to_string(),
                )
            }
        },
        _ => (
            "404 Not Found",
            "<!DOCTYPE html><html><body>not found</body></html>".to_string(),
        ),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = conn.write_all(resp.as_bytes()).await;
    let _ = conn.flush().await;
}

/// Best-effort open `url` in the OS browser (macOS `open`, Linux `xdg-open`). Never fatal — a failure
/// (no browser, headless host) is logged and ignored; the served URL was already printed.
fn open_browser_best_effort(url: &str) {
    #[cfg(target_os = "macos")]
    let prog = "open";
    #[cfg(not(target_os = "macos"))]
    let prog = "xdg-open";
    if let Err(e) = std::process::Command::new(prog).arg(url).spawn() {
        eprintln!("(could not open a browser via `{prog}`: {e} — open {url} manually)");
    }
}

/// `tnet nc <host> <port>`: open a connection through the daemon and pipe stdin/stdout over it.
///
/// Protocol: send `Request::Nc`, read ONE ack line — `Ok` means the overlay connection is live (the
/// daemon has switched that socket into raw splice mode), `Error` means the connect failed (printed +
/// exit 1, the connection was never hijacked). On `Ok`, copy concurrently in both directions until
/// EOF: local stdin → socket (→ peer) and socket (← peer) → local stdout. A clean EOF on either side
/// ends the session (exit 0).
async fn run_nc(socket: &std::path::Path, host: &str, port: u16) -> Result<()> {
    let stream = UnixStream::connect(socket)
        .await
        .context("connect (is tailnetd running?)")?;
    let (read_half, mut write_half) = stream.into_split();

    // Send the nc request line.
    let mut line = serde_json::to_vec(&Request::Nc {
        host: host.to_string(),
        port,
    })?;
    line.push(b'\n');
    write_half.write_all(&line).await?;
    write_half.flush().await?;

    // Read exactly the one-line ack (the daemon writes nothing more before we send, so the BufReader
    // holds no peer payload past the newline — any subsequent bytes are the peer's, read below).
    let mut reader = BufReader::new(read_half);
    let mut ack = String::new();
    reader.read_line(&mut ack).await?;
    match serde_json::from_str::<Response>(ack.trim())
        .with_context(|| format!("parsing nc ack: {ack:?}"))?
    {
        Response::Ok { .. } => {} // connection live — proceed to pipe
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected nc ack: {other:?}"),
    }

    // Splice local stdio <-> the socket. stdin → socket (→ peer); socket (← peer) → stdout. Run both
    // until EOF; the first side to close ends its copy, and we return once both finish.
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let stdin_to_peer = async {
        let r = tokio::io::copy(&mut stdin, &mut write_half).await;
        let _ = write_half.shutdown().await; // half-close so the peer sees our EOF
        r
    };
    let peer_to_stdout = async {
        let r = tokio::io::copy(&mut reader, &mut stdout).await;
        let _ = stdout.flush().await;
        r
    };
    let (_s2p, _p2s) = tokio::join!(stdin_to_peer, peer_to_stdout);
    Ok(())
}

/// Normalize a `serve --tcp` forward target: a bare port `5000` → `127.0.0.1:5000`; a `host:port`
/// passes through. Mirrors Go's `ExpandProxyTargetValue(target, ["tcp"], "tcp")` host extraction.
fn normalize_serve_target(target: &str) -> String {
    if target.parse::<u16>().is_ok() {
        format!("127.0.0.1:{target}")
    } else {
        target.to_string()
    }
}

/// Clean a `--set-path` mount point, faithful to Go `serve`'s `cleanURLPath`: empty → `/`; ensure a
/// leading `/`; `path.Clean`; accept only if the cleaned form equals the (slash-prefixed) input or
/// that input with a single trailing slash (so `/foo/` is allowed but `/foo/../bar` / `//foo` are
/// rejected). Returns the mount string or an "invalid mount point" error.
fn clean_url_path(url_path: &str) -> Result<String> {
    if url_path.is_empty() {
        return Ok("/".to_string());
    }
    let with_slash = if url_path.starts_with('/') {
        url_path.to_string()
    } else {
        format!("/{url_path}")
    };
    let cleaned = clean_path(&with_slash);
    if with_slash == cleaned || with_slash == format!("{cleaned}/") {
        Ok(with_slash)
    } else {
        anyhow::bail!("invalid mount point {with_slash:?}")
    }
}

/// Minimal `path.Clean` for absolute URL paths (lexical): resolve `.`/`..`, collapse `//`, no trailing
/// slash except the root. Matches Go `path.Clean` for the absolute-path inputs `clean_url_path` feeds
/// it (always starts with `/`).
fn clean_path(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    format!("/{}", out.join("/"))
}

/// The path suffix shown in a `serving …` line: empty for the default `/` mount, else the mount.
fn mount_suffix(set_path: &Option<String>) -> String {
    match set_path.as_deref() {
        None | Some("") | Some("/") => String::new(),
        Some(m) => clean_url_path(m).unwrap_or_else(|_| m.to_string()),
    }
}

/// Build a [`TcpPortHandler`](tailscaled_rs::localapi::TcpPortHandler) for a `serve https`/`http` web
/// entry and insert it into `cfg` at `port`, replacing any existing handler on that port. `target` is
/// either `text:<body>` (a fixed-body handler) or a proxy backend (`host:port` / bare port). When
/// `set_path` names a non-root mount, the handler is stored as a path mount (so multiple mounts can
/// coexist on the port); otherwise it is the bare web handler. `tls` selects `https` (true) vs `http`.
/// The existing web handlers on a port, as a mount map — migrating a **bare root** handler (a `text`
/// body or an `https`/`http` proxy `tcp_forward`) into a `/` mount so it survives when a new
/// `--set-path` mount is added to the same port (Go `SetWebHandler` accretes; the root is the `/`
/// handler). Returns the port's existing `mounts` as-is when it already is a mux. A non-web handler
/// (plain TCP forward / TLS-terminated) yields no web mounts.
/// The existing Go-`Web`-map handlers for `host:port`, MIGRATING any legacy per-handler bodies
/// (text/redirect/mounts/tcp_forward on the `TcpPortHandler`) into the equivalent `HttpHandler` map
/// so root + path mounts ACCRETE across `tnet serve` calls (Go `SetWebHandler` keeps both on the
/// port's `WebServerConfig.Handlers`). Prefers an already-present `Web[host:port]` entry; else folds a
/// legacy handler's bodies into a `/`-keyed (or per-mount) `HttpHandler` map. Empty when the port has
/// no web entry yet.
fn existing_web_handlers(
    cfg: &tailscaled_rs::localapi::ServeConfig,
    host: &str,
    port: u16,
) -> std::collections::BTreeMap<String, tailscaled_rs::localapi::HttpHandler> {
    use tailscaled_rs::localapi::{HttpHandler, WebMount};
    let hostport = format!("{host}:{port}");
    // Already migrated to the Web map → reuse it.
    if let Some(wsc) = cfg.web.get(&hostport) {
        return wsc.handlers.clone();
    }
    // Else migrate the legacy per-handler bodies on this port.
    let mut handlers = std::collections::BTreeMap::new();
    let Some(h) = cfg.tcp.get(&port.to_string()) else {
        return handlers;
    };
    let mount_to_handler = |m: &WebMount| match m {
        WebMount::Proxy { to } => HttpHandler {
            proxy: to.clone(),
            ..Default::default()
        },
        WebMount::Text { body } => HttpHandler {
            text: body.clone(),
            ..Default::default()
        },
        WebMount::Redirect { to, status } => HttpHandler {
            redirect: format!("{status}:{to}"),
            ..Default::default()
        },
    };
    if !h.mounts.is_empty() {
        for (mount, m) in &h.mounts {
            handlers.insert(mount.clone(), mount_to_handler(m));
        }
    } else if let Some(body) = &h.text {
        handlers.insert(
            "/".to_string(),
            HttpHandler {
                text: body.clone(),
                ..Default::default()
            },
        );
    } else if let Some(r) = &h.redirect {
        handlers.insert(
            "/".to_string(),
            HttpHandler {
                redirect: format!("{}:{}", r.status, r.to),
                ..Default::default()
            },
        );
    } else if (h.https || h.http) && !h.tcp_forward.is_empty() {
        handlers.insert(
            "/".to_string(),
            HttpHandler {
                proxy: h.tcp_forward.clone(),
                ..Default::default()
            },
        );
    }
    handlers
}

/// Build a web serve into Go's top-level `Web` map (Go `SetWebHandler`): set `TCP[port]={HTTPS|HTTP}`
/// (a flag pointing at `Web`, NO body on the handler) and write the handler under
/// `Web["{host}:{port}"].Handlers[mount]`. `host` is the node's MagicDNS name (resolved by the caller
/// from `status`). Root + path mounts accrete via [`existing_web_handlers`] (migrating any legacy
/// bodies on the way). A lone `/` mount stays a bare handler set; a `--set-path` adds a mux entry.
fn build_web_serve(
    mut cfg: tailscaled_rs::localapi::ServeConfig,
    host: &str,
    port: u16,
    target: &str,
    set_path: Option<&str>,
    tls: bool,
) -> Result<tailscaled_rs::localapi::ServeConfig> {
    use tailscaled_rs::localapi::{HttpHandler, TcpPortHandler, WebServerConfig};

    // Resolve `--set-path` to a cleaned mount; None / "/" mean the root.
    let mount = match set_path {
        None | Some("") | Some("/") => "/".to_string(),
        Some(m) => clean_url_path(m)?,
    };

    // Parse the target: `text:<body>` → a text handler; anything else → a proxy backend.
    let is_text = target.strip_prefix("text:");
    if let Some(body) = is_text
        && body.is_empty()
    {
        anyhow::bail!("unable to serve; text cannot be an empty string");
    }
    let entry = match is_text {
        Some(body) => HttpHandler {
            text: body.to_string(),
            ..Default::default()
        },
        None => HttpHandler {
            proxy: normalize_serve_target(target),
            ..Default::default()
        },
    };

    // Accrete onto the port's existing handlers (migrating any legacy bodies), then add/replace ours.
    let mut handlers = existing_web_handlers(&cfg, host, port);
    handlers.insert(mount, entry);

    // The port handler is just the HTTPS/HTTP flag (Go shape); the body lives in the Web map.
    cfg.tcp.insert(
        port.to_string(),
        TcpPortHandler {
            https: tls,
            http: !tls,
            ..Default::default()
        },
    );
    cfg.web
        .insert(format!("{host}:{port}"), WebServerConfig { handlers });
    Ok(cfg)
}

/// Drive `tnet serve <sub>`: `tcp`/`https`/`http`/`redirect` and `reset` read-modify-write the
/// ServeConfig (GET → mutate → SET); `status` GETs + renders. The ServeConfig is replaced wholesale on
/// SET (matching Go's SetServeConfig), so each set first fetches the current config and adds its entry.
/// Resolve the node's MagicDNS name (the `host` part of a Go `Web` key, and the shared TLS cert
/// name) by querying `status`. A web serve needs it before the node has a name yet — fail with a
/// clear message rather than authoring a `Web` key with an empty/placeholder host. Mirrors
/// `run_funnel`'s resolution.
async fn serve_host(socket: &std::path::Path) -> Result<String> {
    let status = match round_trip(socket, &Request::Status).await {
        Ok(Response::Status(s)) => s,
        Ok(other) => anyhow::bail!("unexpected response to status request: {other:?}"),
        Err(e) => return Err(e).context("querying status"),
    };
    match status.self_name.as_deref().filter(|h| !h.is_empty()) {
        Some(h) => Ok(h.trim_end_matches('.').to_string()),
        None => anyhow::bail!(
            "no MagicDNS name yet (state: {}); bring the node up before configuring a web serve",
            status.state
        ),
    }
}

async fn run_serve(socket: &std::path::Path, cmd: ServeCmd) -> Result<()> {
    use tailscaled_rs::localapi::ServeConfig;
    // Fetch the current config (GetServeConfig is read-only; always replies ServeConfig).
    let get_cfg = || async {
        match round_trip(socket, &Request::GetServeConfig).await {
            Ok(Response::ServeConfig(c)) => Ok(c),
            Ok(other) => anyhow::bail!("unexpected response to get serve config: {other:?}"),
            Err(e) => Err(e).context("getting serve config"),
        }
    };
    match cmd {
        ServeCmd::Status { json } => {
            let cfg = get_cfg().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&cfg)?);
            } else {
                print!("{}", format_serve_status(&cfg, false));
            }
            Ok(())
        }
        ServeCmd::Tcp { port, target } => {
            let mut cfg = get_cfg().await?;
            let fwd = normalize_serve_target(&target);
            cfg.tcp.insert(
                port.to_string(),
                tailscaled_rs::localapi::TcpPortHandler {
                    tcp_forward: fwd.clone(),
                    ..Default::default()
                },
            );
            send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
            println!("serving tailnet :{port} -> {fwd}");
            Ok(())
        }
        ServeCmd::Https {
            port,
            target,
            set_path,
        } => {
            let host = serve_host(socket).await?;
            let cfg = get_cfg().await?;
            let cfg = build_web_serve(cfg, &host, port, &target, set_path.as_deref(), true)?;
            send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
            println!(
                "serving https://{host}:{port}{} -> {target}",
                mount_suffix(&set_path)
            );
            Ok(())
        }
        ServeCmd::Http {
            port,
            target,
            set_path,
        } => {
            let host = serve_host(socket).await?;
            let cfg = get_cfg().await?;
            let cfg = build_web_serve(cfg, &host, port, &target, set_path.as_deref(), false)?;
            send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
            println!(
                "serving http://{host}:{port}{} -> {target}",
                mount_suffix(&set_path)
            );
            Ok(())
        }
        ServeCmd::Redirect { port, to, status } => {
            if to.trim().is_empty() {
                anyhow::bail!("redirect target must not be empty");
            }
            if !(300..=399).contains(&status) {
                anyhow::bail!("redirect status must be in 300..=399 (got {status})");
            }
            if to.contains(['\r', '\n']) {
                anyhow::bail!("redirect target must not contain CR or LF");
            }
            let host = serve_host(socket).await?;
            let mut cfg = get_cfg().await?;
            // Write into the Go Web map: TCP[port]={HTTPS:true} flag + a `/` redirect handler in the
            // Go string form `<status>:<to>`, accreting onto any existing handlers on the port.
            let mut handlers = existing_web_handlers(&cfg, &host, port);
            handlers.insert(
                "/".to_string(),
                tailscaled_rs::localapi::HttpHandler {
                    redirect: format!("{status}:{to}"),
                    ..Default::default()
                },
            );
            cfg.tcp.insert(
                port.to_string(),
                tailscaled_rs::localapi::TcpPortHandler {
                    https: true,
                    ..Default::default()
                },
            );
            cfg.web.insert(
                format!("{host}:{port}"),
                tailscaled_rs::localapi::WebServerConfig { handlers },
            );
            send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
            println!("serving https://{host}:{port} -> redirect {status} -> {to}");
            Ok(())
        }
        ServeCmd::Reset => {
            send_ok_or_die(
                socket,
                Request::SetServeConfig {
                    config: ServeConfig::default(),
                },
            )
            .await?;
            println!("serve config cleared");
            Ok(())
        }
    }
}

/// Drive `tnet funnel <port> {on|off}` (Go `tailscale funnel`): resolve this node's MagicDNS name
/// (the Funnel `HostPort` key), then read-modify-write the ServeConfig's `AllowFunnel` via
/// [`serve::set_funnel`]. On `on` for a port with no serve handler, prints a Go-faithful warning
/// (Funnel exposes a serve, so a bare funnel-on does nothing until `serve https <port> …` is set).
async fn run_funnel(socket: &std::path::Path, port: u16, on_off: &str) -> Result<()> {
    let on = on_off == "on";
    // The node's MagicDNS name (from Status.self_name) is the Funnel HostPort key. Without it we
    // can't build the `host:port` key Go uses, so require the node to be up + named.
    let status = match round_trip(socket, &Request::Status).await {
        Ok(Response::Status(s)) => s,
        Ok(other) => anyhow::bail!("unexpected response to status request: {other:?}"),
        Err(e) => return Err(e).context("querying status"),
    };
    let Some(host) = status.self_name.as_deref().filter(|h| !h.is_empty()) else {
        anyhow::bail!(
            "no MagicDNS name yet (state: {}); bring the node up before enabling funnel",
            status.state
        );
    };

    let mut cfg = match round_trip(socket, &Request::GetServeConfig).await {
        Ok(Response::ServeConfig(c)) => c,
        Ok(other) => anyhow::bail!("unexpected response to get serve config: {other:?}"),
        Err(e) => return Err(e).context("getting serve config"),
    };
    tailscaled_rs::ipn::serve::set_funnel(&mut cfg, host, port, on);

    // Warn when funnel is on for a port the daemon can't actually expose. The funnel lane proxies a
    // raw TLS-terminated stream to the port's `tcp_forward` backend, so it needs a web entry WITH a
    // proxy backend — match that exact arming condition (a `text`/`redirect`/`mounts`-only serve has
    // no backend to splice to, so it would silently never arm). Stricter than Go's "any serve config"
    // check because our funnel lane only splices a proxy backend.
    let has_proxy_backend = cfg
        .tcp
        .get(&port.to_string())
        .is_some_and(|h| tailscaled_rs::ipn::serve::is_web_serve(h) && !h.tcp_forward.is_empty());
    send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
    if on {
        println!("funnel enabled for {host}:{port}");
        if !has_proxy_backend {
            eprintln!(
                "warning: funnel=on for {host}:{port}, but no proxy backend on that port — run \
                 `tnet serve https {port} <target>` so there is something to expose (funnel splices to \
                 the serve's proxy backend)"
            );
        }
    } else {
        println!("funnel disabled for {host}:{port}");
    }
    Ok(())
}

/// Truncate a string for `serve status` display, faithful to Go `serve`'s `elipticallyTruncate`:
/// `<= max` bytes returned unchanged, else `s[..max-3] + "..."` (ASCII dots, total length `max`). Uses
/// a char-boundary-safe slice so multibyte UTF-8 is not split (a benign divergence from Go's byte
/// slice — we never panic on a multibyte boundary).
fn elliptically_truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let cut = max.saturating_sub(3);
    let mut end = cut;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// One-line description of a Go-shaped [`HttpHandler`](tailscaled_rs::localapi::HttpHandler) for
/// `serve status` (proxy / text / redirect / filesystem-path), mirroring the legacy `WebMount` render.
/// Control-supplied fields are terminal-sanitized; a long text body is elliptically truncated.
fn web_handler_desc(h: &tailscaled_rs::localapi::HttpHandler) -> String {
    if !h.proxy.is_empty() {
        format!("proxy -> {}", sanitize_for_terminal(&h.proxy))
    } else if !h.text.is_empty() {
        format!("text \"{}\"", elliptically_truncate(&h.text, 20))
    } else if !h.redirect.is_empty() {
        format!("redirect -> {}", sanitize_for_terminal(&h.redirect))
    } else if !h.path.is_empty() {
        format!(
            "path {} (filesystem serving NOT supported by this build)",
            sanitize_for_terminal(&h.path)
        )
    } else {
        "(empty handler)".to_string()
    }
}

/// Render `tnet serve status` from a [`ServeConfig`](tailscaled_rs::localapi::ServeConfig). Lists each
/// served entry: plain TCP forwards (the daemon's own accept loop), HTTPS/HTTP web entries (proxy /
/// text / redirect / path-mux — Go's top-level `Web` map, or the legacy per-handler bodies — served by
/// engine delegation), and TLS-terminated raw-TCP forwards (`--tls-terminated-tcp`, also
/// engine-delegated). A `TerminateTLS` entry with no backend, or one requesting PROXY-protocol (which
/// the engine `Proxy` target can't write), is flagged "NOT served". `_json` is handled by the caller.
/// Pure → unit-testable.
fn format_serve_status(cfg: &tailscaled_rs::localapi::ServeConfig, _json: bool) -> String {
    use tailscaled_rs::localapi::WebMount;
    // Go's `isServeConfigEmpty` (cmd/tailscale/cli/serve_status.go) is empty iff `len(TCP)==0 &&
    // len(Web)==0 && len(Services)==0 && len(AllowFunnel)==0`. This wire model carries `tcp` + `web`
    // + `allow_funnel` (no `Services` — see the ServeConfig DTO + bead tsd-6p4); checking those three
    // is exhaustive over everything this build can represent (a funnel-only or Web-only config is
    // correctly NOT empty). ⚠️ If `Services` is ever added, this `&&` MUST extend or a service-only
    // config would silently print "No serve config". Message matches Go's exact `No serve config`.
    if cfg.tcp.is_empty() && cfg.web.is_empty() && cfg.allow_funnel.is_empty() {
        return "No serve config\n".to_string();
    }
    let mut out = String::new();
    for (port, h) in &cfg.tcp {
        let scheme = if h.http { "http" } else { "https" };
        // Go-shaped Web-map handlers take precedence over the legacy per-handler bodies (when both
        // somehow coexist, the Web map is the authoritative target — it's what Stage B's translation
        // serves). Match the port's `Web[host:port]` entry by the `:port` suffix (the key carries the
        // real MagicDNS host, which we render instead of the `<node>` placeholder).
        let web_entry = (h.https || h.http)
            .then(|| {
                let suffix = format!(":{port}");
                cfg.web.iter().find(|(k, _)| k.ends_with(&suffix))
            })
            .flatten();
        if let Some((hostport, wsc)) = web_entry {
            let host = sanitize_for_terminal(hostport);
            if wsc.handlers.len() == 1
                && let Some(h0) = wsc.handlers.get("/")
            {
                out.push_str(&format!("{scheme}://{host} -> {}\n", web_handler_desc(h0)));
            } else {
                out.push_str(&format!("{scheme}://{host} (path mux)\n"));
                for (mount, hh) in &wsc.handlers {
                    out.push_str(&format!(
                        "  {} -> {}\n",
                        sanitize_for_terminal(mount),
                        web_handler_desc(hh)
                    ));
                }
            }
        } else if !h.mounts.is_empty() {
            // Legacy path-mux: one line per mount (sorted by the BTreeMap key).
            out.push_str(&format!("{scheme}://<node>:{port} (path mux)\n"));
            for (mount, m) in &h.mounts {
                let desc = match m {
                    WebMount::Proxy { to } => format!("proxy -> {to}"),
                    WebMount::Text { body } => {
                        format!("text \"{}\"", elliptically_truncate(body, 20))
                    }
                    WebMount::Redirect { to, status } => format!("redirect {status} -> {to}"),
                };
                out.push_str(&format!("  {mount} -> {desc}\n"));
            }
        } else if let Some(body) = &h.text {
            out.push_str(&format!(
                "{scheme}://<node>:{port} -> text \"{}\"\n",
                elliptically_truncate(body, 20)
            ));
        } else if let Some(r) = &h.redirect {
            out.push_str(&format!(
                "{scheme}://<node>:{port} -> redirect {} -> {}\n",
                r.status, r.to
            ));
        } else if (h.https || h.http) && !h.tcp_forward.is_empty() {
            out.push_str(&format!("{scheme}://<node>:{port} -> {}\n", h.tcp_forward));
        } else if !h.tcp_forward.is_empty() && !h.https && !h.http && h.terminate_tls.is_empty() {
            out.push_str(&format!("tcp :{port} -> {}\n", h.tcp_forward));
        } else if !h.terminate_tls.is_empty() && !h.tcp_forward.is_empty() && h.proxy_protocol == 0
        {
            // Servable TLS-terminated raw-TCP forward (engine terminates TLS + splices to the backend).
            out.push_str(&format!(
                "tls+tcp :{port} -> {} (TLS-terminated)\n",
                h.tcp_forward
            ));
        } else if !h.terminate_tls.is_empty() {
            // Not servable: no backend to splice to, or proxy-protocol requested (engine `Proxy`
            // doesn't write the PROXY header).
            let why = if h.tcp_forward.is_empty() {
                "no backend"
            } else {
                "proxy-protocol not supported"
            };
            out.push_str(&format!(
                "tcp :{port} -> {} (TLS-terminated; NOT served — {why})\n",
                h.tcp_forward
            ));
        } else if h.https || h.http {
            // A web flag with no backend to proxy to — can't be served.
            let kind = if h.https { "HTTPS" } else { "HTTP" };
            out.push_str(&format!(
                ":{port} {kind} web (NOT served — no proxy target configured)\n"
            ));
        } else {
            out.push_str(&format!(":{port} (empty handler)\n"));
        }
    }
    // Funnel summary: ports exposed to the PUBLIC internet (Go's "# Funnel on:" section). Listed
    // after the serve entries so the per-port lines stay clean; a funnel port should also appear
    // above as an https serve (funnel exposes a serve). The `host:port` key carries the real MagicDNS
    // name, so render that (not a `<node>` placeholder, unlike the per-port serve lines whose host the
    // config doesn't carry).
    let funnel = tailscaled_rs::ipn::serve::funnel_host_ports(cfg);
    if !funnel.is_empty() {
        out.push_str("Funnel (on the public internet):\n");
        for (host, port) in &funnel {
            // `host` is the control-assigned MagicDNS name — sanitize before terminal display.
            out.push_str(&format!(
                "  https://{}:{port}\n",
                sanitize_for_terminal(host)
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tailscaled_rs::localapi::{StatusReport, WhoisReport};

    /// Build a minimal `StatusReport` in the given state with no auth_url/error, no peers.
    fn report(state: &str) -> StatusReport {
        StatusReport {
            state: state.to_string(),
            want_running: true,
            ..Default::default()
        }
    }

    #[test]
    fn classify_auth_url() {
        let mut s = report("NeedsLogin");
        s.auth_url = Some("https://login.example.com/a/abc123".to_string());
        match classify_auth(&s) {
            AuthOutcome::Url(url) => assert_eq!(url, "https://login.example.com/a/abc123"),
            _ => panic!("expected Url"),
        }
    }

    #[test]
    fn classify_auth_failed() {
        // Terminal registration failure → Failed, the early-bail case.
        let mut s = report("NeedsLogin");
        s.error = Some("authentication rejected by control: invalid key".to_string());
        match classify_auth(&s) {
            AuthOutcome::Failed(reason) => {
                assert_eq!(reason, "authentication rejected by control: invalid key");
            }
            _ => panic!("expected Failed"),
        }
    }

    #[test]
    fn classify_auth_none() {
        // No URL, no error → nothing to prompt yet.
        match classify_auth(&report("Running")) {
            AuthOutcome::None => {}
            _ => panic!("expected None"),
        }
    }

    #[test]
    fn classify_auth_error_wins_over_url() {
        // If both somehow co-occur, the permanent error must win over a pending URL.
        let mut s = report("NeedsLogin");
        s.auth_url = Some("https://login.example.com/a/stale".to_string());
        s.error = Some("node key expired; re-authentication required".to_string());
        match classify_auth(&s) {
            AuthOutcome::Failed(reason) => {
                assert_eq!(reason, "node key expired; re-authentication required");
            }
            _ => panic!("expected Failed to win over Url"),
        }
    }

    #[test]
    fn resolve_exit_node_set_wins() {
        // A set value maps to Some(Some(_)); it also wins if a clear is somehow also present (clap
        // forbids that via conflicts_with, but the mapping must still be unambiguous).
        assert_eq!(
            resolve_exit_node(Some("100.64.0.9".to_string()), false),
            Some(Some("100.64.0.9".to_string()))
        );
        assert_eq!(
            resolve_exit_node(Some("exit-1".to_string()), true),
            Some(Some("exit-1".to_string())),
            "an explicit selector wins over the clear flag"
        );
    }

    #[test]
    fn resolve_exit_node_clear_and_unchanged() {
        // `--clear-exit-node` → Some(None) (stop using one); neither flag → None (unchanged).
        assert_eq!(resolve_exit_node(None, true), Some(None));
        assert_eq!(resolve_exit_node(None, false), None);
    }

    #[test]
    fn resolve_advertise_exit_node_tristate() {
        // Enable → Some(true); disable → Some(false); neither → None (unchanged).
        assert_eq!(resolve_advertise_exit_node(true, false), Some(true));
        assert_eq!(resolve_advertise_exit_node(false, true), Some(false));
        assert_eq!(resolve_advertise_exit_node(false, false), None);
        // Enable wins if both are somehow set (clap's conflicts_with prevents this in practice).
        assert_eq!(resolve_advertise_exit_node(true, true), Some(true));
    }

    #[test]
    fn resolve_accept_routes_tristate() {
        // Enable → Some(true); disable → Some(false); neither → None (unchanged).
        assert_eq!(resolve_accept_routes(true, false), Some(true));
        assert_eq!(resolve_accept_routes(false, true), Some(false));
        assert_eq!(resolve_accept_routes(false, false), None);
        // Enable wins if both are somehow set (clap's conflicts_with prevents this in practice).
        assert_eq!(resolve_accept_routes(true, true), Some(true));
    }

    #[test]
    fn resolve_ephemeral_tristate() {
        // --ephemeral → Some(true); --no-ephemeral → Some(false); neither → None (unchanged, so a
        // fresh node keeps the persistent default).
        assert_eq!(resolve_ephemeral(true, false), Some(true));
        assert_eq!(resolve_ephemeral(false, true), Some(false));
        assert_eq!(resolve_ephemeral(false, false), None);
        assert_eq!(resolve_ephemeral(true, true), Some(true));
    }

    #[test]
    fn resolve_shields_up_tristate() {
        // Enable → Some(true); disable → Some(false); neither → None (unchanged).
        assert_eq!(resolve_shields_up(true, false), Some(true));
        assert_eq!(resolve_shields_up(false, true), Some(false));
        assert_eq!(resolve_shields_up(false, false), None);
        // Enable wins if both are somehow set (clap's conflicts_with prevents this in practice).
        assert_eq!(resolve_shields_up(true, true), Some(true));
    }

    #[test]
    fn resolve_ssh_tristate() {
        // `--ssh` → Some(true) (run the SSH server); `--no-ssh` → Some(false); neither → None
        // (leave the persisted pref unchanged).
        assert_eq!(resolve_ssh(true, false), Some(true));
        assert_eq!(resolve_ssh(false, true), Some(false));
        assert_eq!(resolve_ssh(false, false), None);
        // Enable wins if both are somehow set (clap's conflicts_with prevents this in practice).
        assert_eq!(resolve_ssh(true, true), Some(true));
    }

    #[test]
    fn is_tailscale_ip_matches_go_tsaddr() {
        use std::net::IpAddr;
        let v = |s: &str| s.parse::<IpAddr>().unwrap();
        // CGNAT 100.64.0.0/10 → Tailscale.
        assert!(is_tailscale_ip(v("100.64.0.1")));
        assert!(is_tailscale_ip(v("100.127.255.255")));
        // ChromeOS-VM 100.115.92.0/23 is EXCLUDED (Go IsTailscaleIPv4 && !ChromeOSVMRange).
        assert!(!is_tailscale_ip(v("100.115.92.1")));
        assert!(!is_tailscale_ip(v("100.115.93.250")));
        // ...but the rest of 100.115/16 (outside the /23) is still CGNAT/Tailscale.
        assert!(is_tailscale_ip(v("100.115.94.1")));
        // Tailscale ULA fd7a:115c:a1e0::/48 → Tailscale.
        assert!(is_tailscale_ip(v("fd7a:115c:a1e0::1")));
        // Outside CGNAT (octet1 top bits 0b10), a /32-not-/48 ULA, loopback, public → NOT Tailscale.
        assert!(!is_tailscale_ip(v("100.128.0.1")));
        assert!(!is_tailscale_ip(v("fd7a:115c:beef::1")));
        assert!(!is_tailscale_ip(v("192.168.1.1")));
        assert!(!is_tailscale_ip(v("::1")));
        assert!(!is_tailscale_ip(v("8.8.8.8")));
    }

    #[test]
    fn ssh_client_is_tailscale_parses_first_token() {
        // SSH_CLIENT = "<client-ip> <client-port> <server-port>"; only the first token matters.
        assert!(ssh_client_is_tailscale("100.64.0.7 12345 22"));
        assert!(ssh_client_is_tailscale("fd7a:115c:a1e0::9 50000 22"));
        assert!(!ssh_client_is_tailscale("8.8.8.8 1 22")); // public client → not over tailnet
        assert!(!ssh_client_is_tailscale("100.115.92.5 1 22")); // ChromeOS-VM excluded
        assert!(!ssh_client_is_tailscale("")); // not an SSH session
        assert!(!ssh_client_is_tailscale("garbage")); // unparseable
    }

    #[test]
    fn risk_accepted_matches_go_isriskaccepted() {
        // Comma list; accept on exact name or the catch-all `all`. Matched RAW (no trim), like Go's
        // isRiskAccepted (strings.SplitSeq members compared verbatim).
        assert!(risk_accepted("lose-ssh", "lose-ssh"));
        assert!(risk_accepted("all", "lose-ssh"));
        assert!(risk_accepted("foo,lose-ssh", "lose-ssh")); // no-space comma list member
        assert!(risk_accepted("foo,all", "lose-ssh")); // `all` anywhere in the list
        // A space-padded member does NOT match (faithful to Go — the token is " lose-ssh").
        assert!(!risk_accepted("foo, lose-ssh", "lose-ssh"));
        assert!(!risk_accepted("", "lose-ssh"));
        assert!(!risk_accepted("other", "lose-ssh"));
    }

    #[test]
    fn force_reauth_over_ssh_refusal_predicate() {
        // The exact gate the Up handler applies: refuse iff force_reauth AND over-tailnet-SSH AND not
        // accepted. Pin all the corners of that 3-way composition (the env read is factored out via
        // `ssh_client_is_tailscale`, so this is fully deterministic).
        let refuse = |force_reauth: bool, ssh_client: &str, accept: &str| {
            force_reauth
                && ssh_client_is_tailscale(ssh_client)
                && !risk_accepted(accept, "lose-ssh")
        };
        // Refuse: force-reauth, over tailnet SSH, not accepted.
        assert!(refuse(true, "100.64.0.7 1 22", ""));
        // Allow: not a force-reauth.
        assert!(!refuse(false, "100.64.0.7 1 22", ""));
        // Allow: not over a tailnet SSH session (public client / no session).
        assert!(!refuse(true, "8.8.8.8 1 22", ""));
        assert!(!refuse(true, "", ""));
        // Allow: the operator pre-accepted the risk (by name or `all`).
        assert!(!refuse(true, "100.64.0.7 1 22", "lose-ssh"));
        assert!(!refuse(true, "100.64.0.7 1 22", "all"));
    }

    #[test]
    fn ssh_toggle_refusal_decision() {
        // The pure ssh-toggle risk decision (Go presentSSHToggleRisk): None = allow, Some(true) =
        // refuse-an-enable, Some(false) = refuse-a-disable. over_ssh + accepted are the modifiers.
        // Allow: toggle not mentioned.
        assert_eq!(ssh_toggle_refusal(None, false, true, ""), None);
        assert_eq!(ssh_toggle_refusal(None, true, true, ""), None);
        // Allow: no-op toggle (want == have).
        assert_eq!(ssh_toggle_refusal(Some(true), true, true, ""), None);
        assert_eq!(ssh_toggle_refusal(Some(false), false, true, ""), None);
        // Allow: not over a Tailscale SSH session.
        assert_eq!(ssh_toggle_refusal(Some(true), false, false, ""), None);
        // Allow: risk pre-accepted (by name or `all`).
        assert_eq!(
            ssh_toggle_refusal(Some(true), false, true, "lose-ssh"),
            None
        );
        assert_eq!(ssh_toggle_refusal(Some(false), true, true, "all"), None);
        // Refuse ENABLE: want SSH on, currently off, over SSH, not accepted → Some(true).
        assert_eq!(ssh_toggle_refusal(Some(true), false, true, ""), Some(true));
        // Refuse DISABLE: want SSH off, currently on, over SSH, not accepted → Some(false).
        assert_eq!(ssh_toggle_refusal(Some(false), true, true, ""), Some(false));
    }

    #[tokio::test]
    async fn ssh_toggle_gate_short_circuits_without_a_round_trip() {
        // The load-bearing guarantee: the gate must NOT hit the daemon on the common path. We point it
        // at a dead socket — a real GetPrefs round-trip would return Err (connect fails) — and assert
        // Ok(()), which proves the short-circuit returned before the round-trip. Cases that must skip:
        let dead = std::path::Path::new("/tmp/tnet-ssh-toggle-nope.sock");
        // (a) toggle not mentioned (want_ssh None) → no round-trip.
        assert!(
            refuse_ssh_toggle_risk_if_needed(dead, None, None)
                .await
                .is_ok(),
            "no --ssh/--no-ssh must skip the round-trip"
        );
        // (b) toggle mentioned + risk pre-accepted → no round-trip (accepted short-circuits).
        assert!(
            refuse_ssh_toggle_risk_if_needed(dead, Some(true), Some("lose-ssh"))
                .await
                .is_ok(),
            "an accepted risk must skip the round-trip"
        );
        // (c) toggle mentioned but NOT over a Tailscale SSH session → no round-trip. In a normal test
        // process SSH_CLIENT is unset (or not a tailnet IP), so is_ssh_over_tailscale() is false; the
        // gate returns Ok before the round-trip. (This relies on the test env not being an actual
        // Tailscale SSH session, which CI/dev shells are not.)
        if !is_ssh_over_tailscale() {
            assert!(
                refuse_ssh_toggle_risk_if_needed(dead, Some(true), None)
                    .await
                    .is_ok(),
                "not over Tailscale SSH must skip the round-trip"
            );
        }
    }

    #[test]
    fn command_set_maps_to_request_set_fields() {
        // A representative invocation: rename + set an exit node + accept routes, leaving the
        // advertise-* prefs untouched. Built from the same resolver helpers the `Command::Set` arm
        // in `main` uses, so the wire mapping is covered without spawning the CLI. The unset prefs
        // must map to `None` (unchanged), not a silent clear.
        let req = Request::Set {
            hostname: Some("laptop".to_string()),
            accept_routes: resolve_accept_routes(true, false),
            accept_dns: resolve_accept_dns(false, false),
            shields_up: resolve_shields_up(false, false),
            exit_node: resolve_exit_node(Some("100.64.0.9".to_string()), false),
            advertise_exit_node: resolve_advertise_exit_node(false, false),
            advertise_routes: resolve_advertise_routes(vec![], false),
            advertise_tags: None,
            ssh: resolve_ssh(false, false),
        };
        match req {
            Request::Set {
                hostname,
                accept_routes,
                accept_dns,
                shields_up,
                exit_node,
                advertise_exit_node,
                advertise_routes,
                advertise_tags: _,
                ssh,
            } => {
                assert_eq!(hostname, Some("laptop".to_string()));
                assert_eq!(accept_routes, Some(true));
                assert_eq!(accept_dns, None, "unset → unchanged, not flipped");
                assert_eq!(shields_up, None, "unset → unchanged, not flipped");
                assert_eq!(exit_node, Some(Some("100.64.0.9".to_string())));
                assert_eq!(advertise_exit_node, None, "unset → unchanged, not flipped");
                assert_eq!(advertise_routes, None, "unset → unchanged, not cleared");
                assert_eq!(ssh, None, "unset → unchanged, not flipped");
            }
            other => panic!("expected Request::Set, got {other:?}"),
        }
    }

    #[test]
    fn command_up_maps_accept_routes_tristate() {
        // `tnet up` now carries `--accept-routes`/`--no-accept-routes` (Go parity), reusing the same
        // `resolve_accept_routes` tri-state helper as `set`. Pin all three states map into the wire
        // `Request::Up.accept_routes`: enable → Some(true), disable → Some(false), neither → None
        // (leave unchanged). Built from the same resolver the `Command::Up` arm in `main` uses.
        let enabled = Request::Up {
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
            accept_routes: resolve_accept_routes(true, false),
            accept_dns: None,
            shields_up: None,
            ssh: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
        };
        match enabled {
            Request::Up { accept_routes, .. } => {
                assert_eq!(accept_routes, Some(true), "--accept-routes → Some(true)")
            }
            other => panic!("expected Request::Up, got {other:?}"),
        }

        let disabled = Request::Up {
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
            accept_routes: resolve_accept_routes(false, true),
            accept_dns: None,
            shields_up: None,
            ssh: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
        };
        match disabled {
            Request::Up { accept_routes, .. } => {
                assert_eq!(
                    accept_routes,
                    Some(false),
                    "--no-accept-routes → Some(false)"
                )
            }
            other => panic!("expected Request::Up, got {other:?}"),
        }

        let unchanged = Request::Up {
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
            accept_routes: resolve_accept_routes(false, false),
            accept_dns: None,
            shields_up: None,
            ssh: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
        };
        match unchanged {
            Request::Up { accept_routes, .. } => assert_eq!(
                accept_routes, None,
                "neither flag → None (leave the persisted pref unchanged)"
            ),
            other => panic!("expected Request::Up, got {other:?}"),
        }
    }

    #[test]
    fn command_up_maps_shields_up_tristate() {
        // `tnet up` carries `--shields-up`/`--no-shields-up` (Go parity), reusing the same
        // `resolve_shields_up` tri-state helper as `set`. Pin all three states map into the wire
        // `Request::Up.shields_up`: enable → Some(true), disable → Some(false), neither → None
        // (leave unchanged). Built from the same resolver the `Command::Up` arm in `main` uses.
        let enabled = Request::Up {
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
            shields_up: resolve_shields_up(true, false),
            ssh: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
        };
        match enabled {
            Request::Up { shields_up, .. } => {
                assert_eq!(shields_up, Some(true), "--shields-up → Some(true)")
            }
            other => panic!("expected Request::Up, got {other:?}"),
        }

        let disabled = Request::Up {
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
            shields_up: resolve_shields_up(false, true),
            ssh: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
        };
        match disabled {
            Request::Up { shields_up, .. } => {
                assert_eq!(shields_up, Some(false), "--no-shields-up → Some(false)")
            }
            other => panic!("expected Request::Up, got {other:?}"),
        }

        let unchanged = Request::Up {
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
            shields_up: resolve_shields_up(false, false),
            ssh: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
        };
        match unchanged {
            Request::Up { shields_up, .. } => assert_eq!(
                shields_up, None,
                "neither flag → None (leave the persisted pref unchanged)"
            ),
            other => panic!("expected Request::Up, got {other:?}"),
        }
    }

    #[test]
    fn command_set_maps_clears_distinctly_from_unset() {
        // The "clear" flags must produce the present-but-empty sentinels (`Some(None)` /
        // `Some(vec![])`), distinct from the absent (`None`) case above — that's the whole reason
        // the clear flags exist. Built via the same resolvers as `main`'s `Command::Set` arm.
        let req = Request::Set {
            hostname: None,
            accept_routes: resolve_accept_routes(false, true),
            accept_dns: resolve_accept_dns(false, false),
            shields_up: resolve_shields_up(true, false),
            exit_node: resolve_exit_node(None, true),
            advertise_exit_node: resolve_advertise_exit_node(false, true),
            advertise_routes: resolve_advertise_routes(vec![], true),
            advertise_tags: None,
            ssh: resolve_ssh(true, false),
        };
        match req {
            Request::Set {
                hostname,
                accept_routes,
                accept_dns,
                shields_up,
                exit_node,
                advertise_exit_node,
                advertise_routes,
                advertise_tags: _,
                ssh,
            } => {
                assert_eq!(hostname, None);
                assert_eq!(accept_routes, Some(false));
                assert_eq!(
                    accept_dns, None,
                    "neither --accept-dns flag → None (unchanged)"
                );
                assert_eq!(shields_up, Some(true), "--shields-up → Some(true)");
                assert_eq!(exit_node, Some(None), "--clear-exit-node → Some(None)");
                assert_eq!(advertise_exit_node, Some(false));
                assert_eq!(
                    advertise_routes,
                    Some(vec![]),
                    "--advertise-routes-clear → Some(vec![])"
                );
                assert_eq!(ssh, Some(true), "--ssh → Some(true)");
            }
            other => panic!("expected Request::Set, got {other:?}"),
        }
    }

    #[test]
    fn resolve_advertise_routes_set_clear_unchanged() {
        // A non-empty list replaces the set.
        assert_eq!(
            resolve_advertise_routes(
                vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()],
                false
            ),
            Some(vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()])
        );
        // No routes + clear flag → advertise none (empty set).
        assert_eq!(resolve_advertise_routes(vec![], true), Some(vec![]));
        // Neither → leave the persisted set unchanged.
        assert_eq!(resolve_advertise_routes(vec![], false), None);
        // A passed list takes precedence over the clear flag.
        assert_eq!(
            resolve_advertise_routes(vec!["172.16.0.0/12".to_string()], true),
            Some(vec!["172.16.0.0/12".to_string()]),
            "an explicit list wins over the clear flag"
        );
    }

    #[test]
    fn format_ip_renders_addresses_and_placeholder() {
        use tailscaled_rs::localapi::Response;

        // Both addresses → IPv4 then IPv6, one per line.
        assert_eq!(
            format_ip(Some("100.70.22.12"), Some("fd7a:115c:a1e0::1")),
            "100.70.22.12\nfd7a:115c:a1e0::1\n"
        );
        // IPv4 only (the common case — this fork is IPv4-first).
        assert_eq!(format_ip(Some("100.70.22.12"), None), "100.70.22.12\n");
        // No address yet (no netmap received) → a clear placeholder, never empty output.
        assert_eq!(format_ip(None, None), "(no tailnet address yet)\n");

        // The formatter consumes exactly what the `Response::Ip` arm feeds it (`as_deref()` of the
        // wire's `Option<String>` fields), so a populated wire reply renders as above.
        let resp = Response::Ip {
            ipv4: Some("100.70.22.12".to_string()),
            ipv6: None,
        };
        match resp {
            Response::Ip { ipv4, ipv6 } => {
                assert_eq!(
                    format_ip(ipv4.as_deref(), ipv6.as_deref()),
                    "100.70.22.12\n"
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn format_files_empty_prints_placeholder() {
        // An empty Taildrop inbox must print a clear placeholder, never empty output.
        assert_eq!(format_files(&[]), "(no files waiting)\n");
    }

    #[test]
    fn format_files_renders_one_line_per_file() {
        use tailscaled_rs::localapi::{Response, WaitingFileReport};

        let files = vec![
            WaitingFileReport {
                name: "report.pdf".to_string(),
                size: 2048,
            },
            WaitingFileReport {
                name: "notes.txt".to_string(),
                size: 17,
            },
        ];
        assert_eq!(
            format_files(&files),
            "report.pdf  (2048 bytes)\nnotes.txt  (17 bytes)\n"
        );

        // The formatter consumes exactly what the `Response::Files` arm feeds it (`&files`).
        let resp = Response::Files {
            files: vec![WaitingFileReport {
                name: "one.bin".to_string(),
                size: 1,
            }],
        };
        match resp {
            Response::Files { files } => assert_eq!(format_files(&files), "one.bin  (1 bytes)\n"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn format_files_sanitizes_peer_supplied_name() {
        use tailscaled_rs::localapi::WaitingFileReport;

        // The file name arrives from the sending peer (untrusted); a hostile name must not smuggle
        // terminal escapes through `tnet file list`. `format_files` runs it through
        // `sanitize_for_terminal`, so the raw ESC/BEL bytes are stripped.
        let files = vec![WaitingFileReport {
            name: "evil\x1b[2J\x07name.txt".to_string(),
            size: 9,
        }];
        let out = format_files(&files);
        assert!(!out.contains('\x1b'), "ESC must be stripped from file name");
        assert!(!out.contains('\x07'), "BEL must be stripped from file name");
        // The readable parts survive (just the control bytes become the replacement char).
        assert!(out.contains("evil") && out.contains("name.txt"));
        assert!(out.contains("(9 bytes)"));
    }

    #[test]
    fn command_file_subcommands_map_to_requests() {
        // `list`/`get` select the right wire `Request` (built the same way `main`'s `Command::File`
        // arm builds them). `cp` is no longer a simple request-map (it parses the colon target, may
        // `--targets`-list, and sends 1..N files via `run_file_cp`), so its logic is covered by the
        // `parse_cp_target` / `basename` / `format_file_targets` unit tests instead.
        let list = match FileCmd::List {
            FileCmd::List => Request::FileList,
            _ => unreachable!(),
        };
        match list {
            Request::FileList => {}
            other => panic!("expected Request::FileList, got {other:?}"),
        }

        // `get` has two shapes, decided by whether a second positional (DEST) is present — this is the
        // exact branch in `run_file`. Replicate it so both map to the right wire request.
        let build_get = |target: String, dest: Option<String>, conflict: ConflictArg, da: bool| {
            // Mirror run_file's match on `dest`.
            match (FileCmd::Get {
                target,
                dest,
                conflict,
                delete_after: da,
            }) {
                FileCmd::Get {
                    target,
                    dest,
                    conflict,
                    delete_after,
                } => match dest {
                    Some(dest) => Request::FileGet {
                        name: target,
                        dest,
                        delete_after,
                    },
                    None => Request::FileGetDir {
                        dir: target,
                        conflict: conflict.into(),
                    },
                },
                _ => unreachable!(),
            }
        };

        // Two positionals (`get <name> <dest> --delete-after`) → single-file FileGet.
        match build_get(
            "report.pdf".to_string(),
            Some("/tmp/out.pdf".to_string()),
            ConflictArg::Skip,
            true,
        ) {
            Request::FileGet {
                name,
                dest,
                delete_after,
            } => {
                assert_eq!(name, "report.pdf");
                assert_eq!(dest, "/tmp/out.pdf");
                assert!(delete_after, "--delete-after → true");
            }
            other => panic!("expected Request::FileGet, got {other:?}"),
        }

        // One positional (`get <dir> --conflict=rename`) → directory-drain FileGetDir.
        match build_get(
            "/tmp/downloads".to_string(),
            None,
            ConflictArg::Rename,
            false,
        ) {
            Request::FileGetDir { dir, conflict } => {
                assert_eq!(dir, "/tmp/downloads");
                assert_eq!(
                    conflict,
                    tailscaled_rs::localapi::ConflictPolicy::Rename,
                    "--conflict=rename maps to the wire policy"
                );
            }
            other => panic!("expected Request::FileGetDir, got {other:?}"),
        }
    }

    #[test]
    fn parse_cp_target_requires_colon_and_strips_it() {
        // A bare name + colon → the name (Go's trailing-colon disambiguator).
        assert_eq!(parse_cp_target("peer-b:").unwrap(), "peer-b");
        assert_eq!(parse_cp_target("100.64.0.9:").unwrap(), "100.64.0.9");
        // Missing colon → error (Go: "must end in colon").
        assert!(
            parse_cp_target("peer-b").is_err(),
            "no colon must be rejected"
        );
        // Empty peer (`:` or `[]:`) → error (can't resolve an empty selector).
        assert!(parse_cp_target(":").is_err(), "empty peer must be rejected");
        assert!(
            parse_cp_target("[]:").is_err(),
            "empty bracketed peer must be rejected"
        );
    }

    #[test]
    fn parse_cp_target_ipv6_bracket_rules_match_go() {
        // A bracketed IPv6 literal → the inner address (brackets + colon stripped).
        assert_eq!(parse_cp_target("[fd7a::1]:").unwrap(), "fd7a::1");
        // A bare (unbracketed) IPv6 literal → error, pointing at the bracketed form.
        let err = parse_cp_target("fd7a::1:").unwrap_err().to_string();
        assert!(err.contains("must be written as ["), "got: {err}");
        // Brackets around a NON-IPv6 (a name or v4) → error (Go rejects unexpected brackets).
        assert!(
            parse_cp_target("[peer-b]:").is_err(),
            "brackets around a non-IPv6 must be rejected"
        );
        assert!(
            parse_cp_target("[1.2.3.4]:").is_err(),
            "brackets around a v4 literal must be rejected"
        );
    }

    #[test]
    fn basename_takes_final_component() {
        assert_eq!(basename("/tmp/a/b.txt"), "b.txt");
        assert_eq!(basename("b.txt"), "b.txt");
        assert_eq!(basename("/trailing/"), "");
    }

    #[test]
    fn format_file_targets_renders_status_columns_like_go() {
        use tailscaled_rs::localapi::FileTargetReport;
        let targets = vec![
            FileTargetReport {
                ip: "100.64.0.2".to_string(),
                name: "laptop".to_string(),
                online: Some(true),
            },
            FileTargetReport {
                ip: "100.64.0.3".to_string(),
                name: "desktop".to_string(),
                online: Some(false),
            },
            FileTargetReport {
                ip: "100.64.0.4".to_string(),
                name: "phone".to_string(),
                online: None,
            },
        ];
        let out = format_file_targets(&targets);
        // Online peer: just ip \t name, no detail column.
        assert!(out.contains("100.64.0.2\tlaptop\n"), "{out}");
        // Offline / unknown peers get the detail column.
        assert!(out.contains("100.64.0.3\tdesktop\toffline\n"), "{out}");
        assert!(out.contains("100.64.0.4\tphone\tunknown-status\n"), "{out}");
        // Empty → placeholder.
        assert_eq!(format_file_targets(&[]), "(no Taildrop targets)\n");
    }

    #[test]
    fn format_file_targets_sanitizes_peer_name() {
        use tailscaled_rs::localapi::FileTargetReport;
        // The peer name is control-supplied; terminal escapes must be stripped.
        let targets = vec![FileTargetReport {
            ip: "100.64.0.2".to_string(),
            name: "evil\x1b[2J\x07".to_string(),
            online: Some(true),
        }];
        let out = format_file_targets(&targets);
        assert!(!out.contains('\x1b') && !out.contains('\x07'), "{out}");
    }

    #[test]
    fn format_file_targets_resists_column_and_row_injection() {
        use tailscaled_rs::localapi::FileTargetReport;
        // `file cp --targets` renders TAB-separated columns, one peer per line. A malicious control
        // server could set a peer's ComputedName to embed a TAB (forging a fake `offline`/IP column)
        // or a newline (forging an entire fake peer row). The name MUST NOT be able to introduce a
        // structural delimiter — only the renderer itself emits `\t`/`\n`.
        let targets = vec![FileTargetReport {
            ip: "100.64.0.2".to_string(),
            name: "real\toffline\n100.64.0.99\tfake-peer".to_string(),
            online: Some(true),
        }];
        let out = format_file_targets(&targets);
        // Exactly ONE row (one trailing newline, no interior newline forged by the name).
        assert_eq!(out.matches('\n').count(), 1, "forged extra row: {out:?}");
        // A single online peer → exactly ONE column separator (ip<TAB>name, no status column, and the
        // name contributed no extra TAB).
        assert_eq!(out.matches('\t').count(), 1, "forged extra column: {out:?}");
        // The forged literals survive as inert visible text (neutralized to U+FFFD), so nothing is
        // silently dropped — the operator still sees the suspicious name.
        assert!(
            out.contains('\u{FFFD}'),
            "delimiters not neutralized: {out:?}"
        );
        assert!(out.contains("fake-peer"), "name text lost: {out:?}");
    }

    #[test]
    fn sanitizers_split_on_structural_whitespace() {
        // The single-line/columnar default neutralizes ALL control chars, INCLUDING `\t`/`\n`/`\r`,
        // so it can never forge a column or row.
        let s = sanitize_for_terminal("a\tb\nc\rd\x1be");
        assert!(
            !s.contains('\t') && !s.contains('\n') && !s.contains('\r') && !s.contains('\x1b'),
            "{s:?}"
        );
        assert_eq!(s, "a\u{FFFD}b\u{FFFD}c\u{FFFD}d\u{FFFD}e");

        // The free-form multiline variant keeps `\t`/`\n`/`\r` (so a multi-line reason stays legible)
        // but still strips other C0/C1 escapes like ESC.
        let m = sanitize_multiline("a\tb\nc\rd\x1be");
        assert!(
            m.contains('\t') && m.contains('\n') && m.contains('\r'),
            "{m:?}"
        );
        assert!(!m.contains('\x1b'), "{m:?}");
        assert_eq!(m, "a\tb\nc\rd\u{FFFD}e");
    }

    #[test]
    fn format_files_got_renders_success_and_failure_lines() {
        use tailscaled_rs::localapi::FileGotReport;
        // A drain with one success (written elsewhere under rename), one failure (left in inbox).
        let results = vec![
            FileGotReport {
                name: "a.txt".to_string(),
                size: 12,
                written: Some("/tmp/dl/a (1).txt".to_string()),
                error: None,
            },
            FileGotReport {
                name: "b.txt".to_string(),
                size: 0,
                written: None,
                error: Some("refusing to overwrite /tmp/dl/b.txt: file already exists".to_string()),
            },
        ];
        let out = format_files_got(&results);
        assert!(
            out.contains("wrote a.txt -> /tmp/dl/a (1).txt (12 bytes)"),
            "success line: {out}"
        );
        assert!(
            out.contains("error: b.txt: refusing to overwrite"),
            "failure line: {out}"
        );
        // Empty drain → placeholder.
        assert_eq!(format_files_got(&[]), "(no files waiting)\n");
    }

    #[test]
    fn format_files_got_shows_saved_but_not_consumed_as_error() {
        use tailscaled_rs::localapi::FileGotReport;
        // The "not consumed" case: written to disk AND an error (inbox delete failed). The line must
        // surface BOTH — where it landed and that it could not be cleared — and must NOT read as a
        // clean success (so a script sees the non-zero exit the CLI derives from `error.is_some()`).
        let results = vec![FileGotReport {
            name: "c.txt".to_string(),
            size: 7,
            written: Some("/tmp/dl/c.txt".to_string()),
            error: Some("saved but could not be removed from the inbox: Io(...)".to_string()),
        }];
        let out = format_files_got(&results);
        assert!(
            out.contains("wrote c.txt -> /tmp/dl/c.txt (7 bytes)"),
            "{out}"
        );
        assert!(
            out.contains("but:"),
            "must surface the delete failure: {out}"
        );
        assert!(
            out.contains("could not be removed from the inbox"),
            "must name the reason: {out}"
        );
    }

    #[test]
    fn format_files_got_sanitizes_peer_supplied_name() {
        use tailscaled_rs::localapi::FileGotReport;
        // The inbox name comes from the sending peer (untrusted); terminal escapes must be stripped.
        let results = vec![FileGotReport {
            name: "evil\x1b[2J\x07.txt".to_string(),
            size: 1,
            written: Some("/tmp/evil\x1b[2J.txt".to_string()),
            error: None,
        }];
        let out = format_files_got(&results);
        assert!(!out.contains('\x1b'), "ESC stripped from drain line");
        assert!(!out.contains('\x07'), "BEL stripped from drain line");
    }

    #[test]
    fn format_whois_not_found_names_the_ip() {
        let w = WhoisReport {
            found: false,
            ..Default::default()
        };
        assert_eq!(
            format_whois(&w, "100.64.0.9"),
            "no tailnet node owns 100.64.0.9\n"
        );
    }

    #[test]
    fn format_whois_renders_node_user_and_capabilities() {
        let w = WhoisReport {
            found: true,
            node_name: Some("peer-b.example.ts.net".to_string()),
            node_ipv4: Some("100.64.0.2".to_string()),
            user: Some("alice@example.com".to_string()),
            capabilities: vec![
                "https://tailscale.com/cap/is-admin".to_string(),
                "funnel".to_string(),
            ],
            // Flow-scoped peer-cap grants (Go `WhoIsResponse.CapMap`): one cap WITH a raw-JSON value
            // and one value-less cap, to exercise both render shapes.
            cap_map: std::collections::BTreeMap::from([
                (
                    "https://tailscale.com/cap/file-sharing".to_string(),
                    vec!["{\"foo\":1}".to_string()],
                ),
                ("cap/is-admin".to_string(), vec![]),
            ]),
            tags: vec!["tag:server".to_string(), "tag:ci".to_string()],
            node_key_expiry: Some("2026-09-01 12:00:00 UTC".to_string()),
            // Offline + a known last-seen: status convention is to show BOTH the `online: no` line
            // and the `last-seen:` line (an online node's last-seen is "now", so it's only shown
            // when offline).
            online: Some(false),
            last_seen: Some("2026-06-11 05:19:14 UTC".to_string()),
        };
        let out = format_whois(&w, "100.64.0.2");
        assert!(out.contains("peer-b.example.ts.net"), "node name present");
        assert!(out.contains("100.64.0.2"), "node ipv4 present");
        assert!(out.contains("alice@example.com"), "user present when Some");
        assert!(
            out.contains("https://tailscale.com/cap/is-admin") && out.contains("funnel"),
            "every capability present"
        );
        // Flow-scoped grants render under their own `cap-grants:` header (distinct from the
        // node-level `capabilities:` block), with the cap name and — for a cap that has values —
        // each value on its own indented line.
        assert!(
            out.contains("cap-grants:"),
            "cap-grants header present when cap_map non-empty"
        );
        assert!(
            out.contains("https://tailscale.com/cap/file-sharing") && out.contains("cap/is-admin"),
            "every cap-grant name present (value-bearing and value-less)"
        );
        // `cap_map` is a BTreeMap, so the render order is the keys' sorted order (deterministic — the
        // production renderer relies on this for stable output). Within the `cap-grants:` section,
        // `cap/is-admin` < `https://…/cap/file-sharing` lexicographically, so the value-less cap
        // renders before the value-bearing one. (Compare positions WITHIN the cap-grants block: the
        // node-level `capabilities:` block above also contains a `.../cap/is-admin` entry, so anchor
        // the search at the `cap-grants:` header to avoid matching that earlier occurrence.)
        let grants = out.split_once("cap-grants:").unwrap().1;
        assert!(
            grants.find("cap/is-admin").unwrap() < grants.find("cap/file-sharing").unwrap(),
            "cap-grants render in BTreeMap-sorted key order"
        );
        assert!(
            out.contains("{\"foo\":1}"),
            "the cap-grant's raw-JSON value renders on its own line"
        );
        // ACL tags render under a `tags:` header, one bullet each (Go parity).
        assert!(
            out.contains("tags:"),
            "tags header present when tags non-empty"
        );
        assert!(
            out.contains("tag:server") && out.contains("tag:ci"),
            "every tag present"
        );
        // Node-key expiry renders as a single line when present.
        assert!(
            out.contains("key-expiry:") && out.contains("2026-09-01 12:00:00 UTC"),
            "node-key expiry present when Some"
        );
        // Liveness: offline → `online: no` AND the last-seen line (offline-only, status convention).
        assert!(
            out.contains("online:       no"),
            "offline node shows online: no"
        );
        assert!(
            out.contains("last-seen:    2026-06-11 05:19:14 UTC"),
            "offline node with known last_seen shows the last-seen line"
        );
    }

    #[test]
    fn format_whois_online_node_shows_online_yes_without_last_seen() {
        // An ONLINE node shows `online: yes` and NO last-seen line (its last-seen is "now" — status
        // only surfaces last-seen for offline peers, and whois mirrors that).
        let w = WhoisReport {
            found: true,
            node_name: Some("peer-b".to_string()),
            node_ipv4: Some("100.64.0.2".to_string()),
            online: Some(true),
            // Even if a last_seen is present, an online node must NOT render the last-seen line.
            last_seen: Some("2026-06-11 05:19:14 UTC".to_string()),
            ..Default::default()
        };
        let out = format_whois(&w, "100.64.0.2");
        assert!(
            out.contains("online:       yes"),
            "online node shows online: yes"
        );
        assert!(
            !out.contains("last-seen:"),
            "an online node must not render a last-seen line (its last-seen is 'now')"
        );
    }

    #[test]
    fn format_whois_omits_absent_optional_fields() {
        // `user` is `None` in this fork by default and capabilities can be empty; neither should
        // emit a stray line. Only the fields that are present render.
        let w = WhoisReport {
            found: true,
            node_name: Some("peer-b".to_string()),
            node_ipv4: Some("100.64.0.2".to_string()),
            user: None,
            capabilities: vec![],
            cap_map: std::collections::BTreeMap::new(),
            tags: vec![],
            node_key_expiry: None,
            online: None,
            last_seen: None,
        };
        let out = format_whois(&w, "100.64.0.2");
        assert!(out.contains("peer-b"));
        assert!(out.contains("100.64.0.2"));
        assert!(!out.contains("user:"), "no user line when user is None");
        assert!(
            !out.contains("capabilities:"),
            "no capabilities header when the set is empty"
        );
        assert!(
            !out.contains("cap-grants:"),
            "no cap-grants header when the flow-scoped cap_map is empty"
        );
        assert!(
            !out.contains("tags:"),
            "no tags header when the set is empty"
        );
        assert!(
            !out.contains("key-expiry:"),
            "no key-expiry line when expiry is None"
        );
        assert!(
            !out.contains("online:"),
            "no online line when liveness is unknown (None)"
        );
    }

    #[test]
    fn format_whois_sanitizes_control_supplied_node_name() {
        // The node name comes from the control server (semi-trusted); a malicious one must not be
        // able to smuggle terminal escapes through `tnet whois`. `format_whois` runs it through
        // `sanitize_for_terminal`, so the raw ESC/BEL bytes are stripped.
        let w = WhoisReport {
            found: true,
            node_name: Some("evil\x1b[2J\x07name".to_string()),
            node_ipv4: Some("100.64.0.2".to_string()),
            user: None,
            capabilities: vec![],
            // Flow-scoped cap grants are control-supplied too — BOTH the cap NAME and each grant VALUE
            // must be sanitized. Smuggle a terminal escape into a cap name AND into a value.
            cap_map: std::collections::BTreeMap::from([(
                "cap/\x1b]0;pwned\x07evil".to_string(),
                vec!["bad\x1b[2Jvalue".to_string()],
            )]),
            // Tags are also control-supplied — a hostile one must be sanitized just like the name.
            tags: vec!["tag:\x1bevil\x07".to_string()],
            node_key_expiry: None,
            online: None,
            last_seen: None,
        };
        let out = format_whois(&w, "100.64.0.2");
        assert!(
            !out.contains('\x1b'),
            "ESC must be stripped from node name + tags + cap-grant name/value"
        );
        assert!(
            !out.contains('\x07'),
            "BEL must be stripped from node name + tags + cap-grant name/value"
        );
        // The readable parts survive (just the control bytes become the replacement char).
        assert!(out.contains("evil"));
        assert!(out.contains("name"));
        // The cap-grant's readable fragments survive sanitization too (control bytes replaced).
        assert!(
            out.contains("value"),
            "cap-grant value's readable text survives"
        );
    }

    #[test]
    fn sanitize_strips_terminal_escapes_keeps_plain_text() {
        // The registration-failure reason is the one free-form, possibly multi-line field, so it is
        // printed via `sanitize_multiline`: ANSI/terminal escapes must be neutralized so a malicious
        // control server can't drive the operator's terminal, but plain text AND ordinary whitespace
        // (so a multi-line message stays legible) survive unchanged.
        let evil = "auth rejected\x1b[2J\x1b[31mFAKE PROMPT\x07 token=\x00secret";
        let clean = sanitize_multiline(evil);
        assert!(
            !clean.contains('\x1b'),
            "ESC must be stripped, got {clean:?}"
        );
        assert!(!clean.contains('\x07'), "BEL must be stripped");
        assert!(!clean.contains('\x00'), "NUL must be stripped");
        // The readable words are preserved (just the control bytes become the replacement char).
        assert!(clean.contains("auth rejected"));
        assert!(clean.contains("token="));

        // Ordinary text and whitespace pass through verbatim in the multi-line reason path.
        let benign = "authentication rejected by control: key not found\n\tretry later";
        assert_eq!(
            sanitize_multiline(benign),
            benign,
            "plain text + tab/newline must be unchanged in a free-form reason"
        );
    }

    #[test]
    fn revert_pref_to_flag_maps_keys_to_their_up_flags() {
        // Value prefs render as `--flag=value`; the daemon's `advertise_routes` value is already
        // comma-joined and re-passed verbatim.
        assert_eq!(
            revert_pref_to_flag("advertise_routes", "10.0.0.0/8,192.168.1.0/24"),
            "--advertise-routes=10.0.0.0/8,192.168.1.0/24"
        );
        assert_eq!(
            revert_pref_to_flag("exit_node", "100.64.0.9"),
            "--exit-node=100.64.0.9"
        );
        assert_eq!(
            revert_pref_to_flag("hostname", "node-a"),
            "--hostname=node-a"
        );
        // Boolean prefs: the guard only reports them when non-default (true), so the keep-it token is
        // the bare enabling flag.
        assert_eq!(revert_pref_to_flag("ssh", "true"), "--ssh");
        assert_eq!(
            revert_pref_to_flag("accept_routes", "true"),
            "--accept-routes"
        );
        assert_eq!(revert_pref_to_flag("shields_up", "true"), "--shields-up");
        assert_eq!(revert_pref_to_flag("tun", "true"), "--tun");
        // Defensive: a false bool renders the disabling flag (shouldn't occur from the guard).
        assert_eq!(revert_pref_to_flag("ssh", "false"), "--no-ssh");
        // Unknown key (daemon newer than CLI): still actionable, not dropped.
        assert_eq!(revert_pref_to_flag("future_pref", "x"), "--future_pref=x");
    }

    #[test]
    fn format_licenses_is_fork_true_and_local() {
        let out = format_licenses();
        // Names THIS fork + its license + repo (not Tailscale's hosted URL), and points at the
        // offline cargo dependency-license path. Pure/local — no network or daemon involved.
        assert!(out.contains("tailscaled-rs"), "{out}");
        assert!(out.contains("BSD-3-Clause"), "{out}");
        assert!(
            out.contains("github.com/GeiserX/tailscaled-rs"),
            "must point at this fork's repo, not tailscale.com: {out}"
        );
        assert!(
            !out.contains("tailscale.com/licenses"),
            "must NOT point at Tailscale's hosted licenses page (wrong dep set): {out}"
        );
        assert!(out.contains("cargo about"), "{out}");
    }

    #[test]
    fn format_version_shapes() {
        // Plain, no daemon → bare client version line (Go's first line). `cap` is irrelevant to the
        // human form (a stable even minor here so no unstable marker anyway).
        assert_eq!(format_version("0.10.0", None, 130, false), "0.10.0\n");
        // Plain, with daemon → Client:/Daemon: pair (Go's --daemon form).
        assert_eq!(
            format_version("0.10.0", Some("0.10.0"), 130, false),
            "Client: 0.10.0\nDaemon: 0.10.0\n"
        );
        // JSON, no daemon → Go version.Meta shape. Parse it and assert the keys/values.
        let j: serde_json::Value =
            serde_json::from_str(format_version("0.10.0", None, 130, true).trim()).unwrap();
        assert_eq!(j["majorMinorPatch"], "0.10.0");
        assert_eq!(j["short"], "0.10.0");
        assert_eq!(j["long"], "0.10.0");
        assert_eq!(j["cap"], 130, "cap = the engine capability version");
        assert!(
            j.get("daemonLong").is_none(),
            "no daemonLong without --daemon"
        );
        assert!(
            j.get("unstableBranch").is_none(),
            "even minor (10) is stable → unstableBranch omitted"
        );
        // JSON, with daemon → daemonLong present (the queried daemon version).
        let jd: serde_json::Value =
            serde_json::from_str(format_version("0.10.0", Some("0.8.0"), 130, true).trim())
                .unwrap();
        assert_eq!(jd["majorMinorPatch"], "0.10.0");
        assert_eq!(jd["daemonLong"], "0.8.0");
        // JSON, odd minor → unstableBranch:true (Go IsUnstableBuild).
        let ju: serde_json::Value =
            serde_json::from_str(format_version("0.11.0", None, 130, true).trim()).unwrap();
        assert_eq!(ju["unstableBranch"], true, "odd minor (11) is unstable");
    }

    #[test]
    fn version_unstable_minor_and_parse() {
        // Go IsUnstableBuild: odd minor = unstable, even = stable.
        assert!(is_unstable_minor(11));
        assert!(is_unstable_minor(1));
        assert!(!is_unstable_minor(10));
        assert!(!is_unstable_minor(0));
        // minor_of parses the middle field, tolerating a (currently-unused) pre-release suffix.
        assert_eq!(minor_of("0.32.0"), Some(32));
        assert_eq!(minor_of("1.2.3"), Some(2));
        assert_eq!(minor_of("0.31.0-dev"), Some(31));
        assert_eq!(minor_of("garbage"), None);
    }

    #[test]
    fn format_get_set_flags_emits_reappliable_line() {
        use tailscaled_rs::localapi::PrefsView;
        let view = PrefsView {
            hostname: Some("node-a".into()),
            exit_node: None,
            advertise_exit_node: false,
            advertise_routes: vec!["10.0.0.0/8".into()],
            advertise_tags: vec![],
            accept_routes: true,
            accept_dns: false,
            shields_up: true,
            ssh: false,
            ssh_running: false,
            tun: false,
        };
        let line = format_get_set_flags(&view);
        // Every setting is `--name=value`, space-joined (Go getOutputSetFlags / fmtFlagValueArg).
        assert!(line.contains("--hostname=node-a"), "{line}");
        assert!(line.contains("--accept-routes=true"), "{line}");
        assert!(line.contains("--accept-dns=false"), "{line}");
        assert!(line.contains("--shields-up=true"), "{line}");
        assert!(line.contains("--advertise-routes=10.0.0.0/8"), "{line}");
        // Unset/empty values render as a bare `--name=` (Go's explicit empty form), not omitted.
        assert!(
            line.contains("--exit-node= "),
            "unset exit-node → empty: {line}"
        );
        assert!(
            line.contains("--advertise-tags= "),
            "empty tags → empty: {line}"
        );
        // It's a single space-joined line (no newlines), re-pasteable into `tnet set`.
        assert!(!line.contains('\n'), "must be one line: {line}");
    }

    #[test]
    fn format_get_shapes() {
        use tailscaled_rs::localapi::PrefsView;
        let view = PrefsView {
            hostname: Some("node-a".into()),
            exit_node: Some("100.64.0.9".into()),
            advertise_exit_node: false,
            advertise_routes: vec!["10.0.0.0/8".into(), "192.168.1.0/24".into()],
            advertise_tags: vec![],
            accept_routes: true,
            accept_dns: true,
            shields_up: true,
            ssh: true,
            ssh_running: true,
            tun: false,
        };

        // Default table: a `NAME  VALUE` header line (Go `getOutputTable`) then one line per setting.
        let table = format_get(&view, None, false).unwrap();
        // First line is the header.
        assert!(
            table.starts_with("NAME") && table.lines().next().unwrap().contains("VALUE"),
            "the table must lead with a NAME/VALUE header, like Go: {table}"
        );
        assert!(table.contains("accept-routes"), "{table}");
        assert!(table.contains("shields-up"), "{table}");
        assert!(table.contains("true"), "{table}");
        assert!(
            table.contains("advertise-routes") && table.contains("10.0.0.0/8,192.168.1.0/24"),
            "{table}"
        );
        assert!(table.contains("advertise-tags"), "{table}");
        assert!(table.contains("accept-dns"), "{table}");
        assert!(
            table.contains("hostname") && table.contains("node-a"),
            "hostname must be listed with its value: {table}"
        );
        // 1 header + 10 settings (hostname, exit-node, advertise-exit-node, advertise-routes,
        // advertise-tags, accept-routes, accept-dns, shields-up, ssh, tun) → 11 lines.
        assert_eq!(table.lines().count(), 11, "{table}");

        // --json: flattened name→value map keyed by set-flag name, with GO-FAITHFUL TYPED values —
        // booleans are bare JSON `true`/`false` (NOT quoted strings), strings are strings. Parse it
        // and assert on the typed values (more robust than string-matching, and proves the shape).
        let j = format_get(&view, None, true).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&j).expect("get --json must be valid JSON");
        assert_eq!(
            parsed["accept-routes"],
            serde_json::json!(true),
            "bare bool: {j}"
        );
        assert_eq!(
            parsed["shields-up"],
            serde_json::json!(true),
            "bare bool: {j}"
        );
        assert_eq!(parsed["ssh"], serde_json::json!(true), "{j}");
        assert_eq!(
            parsed["advertise-exit-node"],
            serde_json::json!(false),
            "{j}"
        );
        assert_eq!(parsed["exit-node"], serde_json::json!("100.64.0.9"), "{j}");
        assert_eq!(
            parsed["advertise-routes"],
            serde_json::json!("10.0.0.0/8,192.168.1.0/24"),
            "{j}"
        );

        // Single named setting → just its value (plain).
        assert_eq!(
            format_get(&view, Some("accept-routes"), false).unwrap(),
            "true\n"
        );
        assert_eq!(
            format_get(&view, Some("advertise-routes"), false).unwrap(),
            "10.0.0.0/8,192.168.1.0/24\n"
        );
        // Single setting --json → the typed JSON value (bare bool for a boolean setting).
        assert_eq!(format_get(&view, Some("ssh"), true).unwrap(), "true\n");
        assert_eq!(
            format_get(&view, Some("exit-node"), true).unwrap(),
            "\"100.64.0.9\"\n"
        );

        // "all" behaves like None (all settings).
        assert_eq!(format_get(&view, Some("all"), false).unwrap(), table);

        // Unknown setting → error (Go errors too).
        assert!(format_get(&view, Some("no-such-setting"), false).is_err());
    }

    #[test]
    fn format_lock_status_human_and_json() {
        use tailscaled_rs::localapi::LockReport;
        // Not enabled: Go's exact wording (no "on this tailnet" suffix) + the trailing blank line Go
        // prints unconditionally after the status line.
        let off = LockReport::default();
        assert_eq!(
            format_lock_status(&off, false),
            "Tailnet Lock is NOT enabled.\n\n",
            "must byte-match Go's `Tailnet Lock is NOT enabled.` + blank line"
        );
        // Enabled with a head + pending disablement.
        let on = LockReport {
            enabled: true,
            head: "tka-aumhash-abc".into(),
            disabled: true,
        };
        let h = format_lock_status(&on, false);
        // Status line is byte-exact Go wording, followed by the blank line.
        assert!(h.starts_with("Tailnet Lock is ENABLED.\n\n"), "{h}");
        assert!(h.contains("tka-aumhash-abc"), "{h}");
        assert!(h.contains("disablement is pending"), "{h}");
        // JSON shape (typed bools).
        let j = format_lock_status(&on, true);
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["enabled"], serde_json::json!(true));
        assert_eq!(v["head"], serde_json::json!("tka-aumhash-abc"));
        assert_eq!(v["disabled"], serde_json::json!(true));
    }

    #[test]
    fn format_dns_status_populated_human_and_json() {
        use tailscaled_rs::localapi::DnsStatusReport;
        let report = DnsStatusReport {
            magic_dns: true,
            search_domains: vec!["user.ts.net".into()],
            resolvers: vec!["100.100.100.100:53".into(), "8.8.8.8:53".into()],
            routes: std::collections::BTreeMap::from([(
                "corp.example.com".to_string(),
                vec!["10.0.0.53:53".to_string()],
            )]),
            fallback_resolvers: vec!["1.1.1.1:53".into()],
            cert_domains: vec!["host.user.ts.net".into()],
            extra_records: vec![("printer.user.ts.net".into(), "100.64.0.7".into())],
            exit_node_filtered_set: vec![".internal".into()],
        };
        // Human form: the populated resolver/route/search lines appear, MagicDNS reads enabled, and
        // the honest omission note is present.
        let h = format_dns_status(&report, false);
        assert!(h.contains("MagicDNS: enabled tailnet-wide"), "{h}");
        assert!(h.contains("  - 100.100.100.100:53"), "{h}");
        assert!(h.contains("  - 8.8.8.8:53"), "{h}");
        assert!(h.contains("corp.example.com"), "{h}");
        assert!(h.contains("-> 10.0.0.53:53"), "{h}");
        assert!(h.contains("  - user.ts.net"), "{h}");
        assert!(h.contains("  - 1.1.1.1:53"), "{h}");
        assert!(h.contains("host.user.ts.net"), "{h}");
        assert!(h.contains("printer.user.ts.net -> 100.64.0.7"), "{h}");
        assert!(h.contains(".internal"), "{h}");
        assert!(
            h.contains("not surfaced by this build"),
            "the honest omission note must be present: {h}"
        );
        // JSON form: Go-shaped keys + a bare MagicDNS bool, escape-safe via serde.
        let j = format_dns_status(&report, true);
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["MagicDNS"], serde_json::json!(true));
        assert_eq!(
            v["Resolvers"],
            serde_json::json!(["100.100.100.100:53", "8.8.8.8:53"])
        );
        assert_eq!(
            v["SplitDNSRoutes"]["corp.example.com"],
            serde_json::json!(["10.0.0.53:53"])
        );
        assert_eq!(v["SearchDomains"], serde_json::json!(["user.ts.net"]));
        assert_eq!(v["FallbackResolvers"], serde_json::json!(["1.1.1.1:53"]));
        assert_eq!(v["CertDomains"], serde_json::json!(["host.user.ts.net"]));
        assert_eq!(
            v["ExtraRecords"]["printer.user.ts.net"],
            serde_json::json!("100.64.0.7")
        );
        assert_eq!(v["ExitNodeFilteredSet"], serde_json::json!([".internal"]));
    }

    #[test]
    fn format_dns_status_empty_renders_none_lines() {
        use tailscaled_rs::localapi::DnsStatusReport;
        // The no-netmap / default report: MagicDNS disabled + every section a parenthetical none-line.
        let empty = DnsStatusReport::default();
        let h = format_dns_status(&empty, false);
        assert!(h.contains("MagicDNS: disabled tailnet-wide"), "{h}");
        assert!(
            h.contains("Resolvers (in preference order):\n  (none configured)"),
            "{h}"
        );
        assert!(h.contains("Split DNS Routes:\n  (none)"), "{h}");
        assert!(h.contains("Search Domains:\n  (none)"), "{h}");
        assert!(h.contains("Fallback Resolvers:\n  (none)"), "{h}");
        assert!(h.contains("Certificate Domains:\n  (none)"), "{h}");
        assert!(h.contains("Additional DNS Records:\n  (none)"), "{h}");
        assert!(
            h.contains("Filtered suffixes (exit-node):\n  (none)"),
            "{h}"
        );
        assert!(h.contains("not surfaced by this build"), "{h}");
        // JSON: a default report still carries a bare MagicDNS:false + empty collections.
        let v: serde_json::Value = serde_json::from_str(&format_dns_status(&empty, true)).unwrap();
        assert_eq!(v["MagicDNS"], serde_json::json!(false));
        assert_eq!(v["Resolvers"], serde_json::json!([]));
    }

    #[test]
    fn format_netcheck_populated_human_and_json() {
        use tailscaled_rs::localapi::{NetcheckReport, RegionLatencyView};
        // Region 10 included DELIBERATELY: it distinguishes serde's lexicographic key order
        // ("1" < "10" < "7") from numeric order (1 < 7 < 10), so the ordering assertion below is not
        // vacuous. A duplicate region_id (7) is included to pin the BTreeMap's dedup (last write wins).
        let report = NetcheckReport {
            preferred_derp: Some(1),
            region_latencies: vec![
                RegionLatencyView {
                    region_id: 1,
                    latency_ms: 23.42,
                },
                RegionLatencyView {
                    region_id: 7,
                    latency_ms: 99.9, // superseded by the dedup entry below
                },
                RegionLatencyView {
                    region_id: 10,
                    latency_ms: 5.0,
                },
                RegionLatencyView {
                    region_id: 7,
                    latency_ms: 41.7, // last write for region 7 wins
                },
            ],
        };
        // Human form: the preferred region, per-region latency lines (formatted to 0.1ms), and the
        // honest omission note.
        let h = format_netcheck(&report, false);
        assert!(h.contains("Report:"), "{h}");
        assert!(h.contains("* Nearest DERP: region 1"), "{h}");
        assert!(h.contains("- region 1: 23.4ms"), "{h}");
        assert!(h.contains("- region 10: 5.0ms"), "{h}");
        assert!(
            h.contains("DERP-region latency only"),
            "the honest reduced-scope note must be present: {h}"
        );
        // JSON form: Go's field names + value encoding — a bare numeric PreferredDERP and a
        // RegionLatency map keyed by stringified region id with integer-NANOSECOND values
        // (`map[int]time.Duration` marshalled as ns). 23.42ms = 23_420_000ns; 41.7ms = 41_700_000ns.
        let j = format_netcheck(&report, true);
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["PreferredDERP"], serde_json::json!(1));
        assert_eq!(v["RegionLatency"]["1"], serde_json::json!(23_420_000_i64));
        // Dedup: region 7's LAST entry (41.7ms) wins over the earlier 99.9ms.
        assert_eq!(v["RegionLatency"]["7"], serde_json::json!(41_700_000_i64));
        assert_eq!(v["RegionLatency"]["10"], serde_json::json!(5_000_000_i64));
        // Exactly 3 distinct keys (the duplicate 7 was deduped).
        assert_eq!(v["RegionLatency"].as_object().unwrap().len(), 3, "{j}");
        // Key order is serde_json's LEXICOGRAPHIC string order ("1" < "10" < "7"), NOT numeric — and
        // that is fine (JSON object key order is non-semantic). Pin the real behavior so the claim and
        // the test agree: "10" precedes "7" in the emitted bytes.
        assert!(
            j.find("\"10\":").unwrap() < j.find("\"7\":").unwrap(),
            "RegionLatency keys are serde lexicographic order (\"10\" before \"7\"): {j}"
        );
        // Indent is a TAB, matching Go's `json.MarshalIndent(report, "", \"\\t\")`.
        assert!(
            j.contains("\n\t\"PreferredDERP\""),
            "netcheck JSON must use tab indent like Go: {j:?}"
        );
    }

    #[test]
    fn format_netcheck_empty_renders_none_lines() {
        use tailscaled_rs::localapi::NetcheckReport;
        // The pre-measurement / default report: no preferred region + no measured latency → the two
        // none-lines, plus the honest note.
        let empty = NetcheckReport::default();
        let h = format_netcheck(&empty, false);
        assert!(h.contains("Report:"), "{h}");
        assert!(
            h.contains("* Nearest DERP: (none — not measured yet)"),
            "{h}"
        );
        assert!(h.contains("(no DERP latency measured)"), "{h}");
        assert!(h.contains("DERP-region latency only"), "{h}");
        // JSON: a default report carries PreferredDERP 0 (Go's "0 for unknown", NOT null) + an empty
        // RegionLatency object (Go's `map[int]time.Duration`, empty → `{}`, not `[]`).
        let v: serde_json::Value = serde_json::from_str(&format_netcheck(&empty, true)).unwrap();
        assert_eq!(v["PreferredDERP"], serde_json::json!(0));
        assert_eq!(v["RegionLatency"], serde_json::json!({}));
    }

    #[test]
    fn format_exit_node_list_filters_and_placeholder() {
        use tailscaled_rs::localapi::PeerReport;
        // None offering → placeholder.
        let none = vec![PeerReport {
            name: "plain".into(),
            ipv4: "100.64.0.2".into(),
            is_exit_node: false,
            ..Default::default()
        }];
        assert!(format_exit_node_list(&none).contains("no exit nodes"));
        // Mixed → only exit-node peers listed, with online state.
        let peers = vec![
            PeerReport {
                name: "exit-a".into(),
                ipv4: "100.64.0.9".into(),
                is_exit_node: true,
                online: Some(true),
                ..Default::default()
            },
            PeerReport {
                name: "plain-b".into(),
                ipv4: "100.64.0.3".into(),
                is_exit_node: false,
                ..Default::default()
            },
            PeerReport {
                name: "exit-c".into(),
                ipv4: "100.64.0.10".into(),
                is_exit_node: true,
                online: Some(false),
                ..Default::default()
            },
        ];
        let out = format_exit_node_list(&peers);
        assert!(out.contains("exit-a") && out.contains("(online)"), "{out}");
        assert!(out.contains("exit-c") && out.contains("(offline)"), "{out}");
        assert!(
            !out.contains("plain-b"),
            "non-exit peer must not appear: {out}"
        );
    }

    #[test]
    fn format_exit_node_list_resists_row_injection() {
        use tailscaled_rs::localapi::PeerReport;
        // The hostname is control-supplied (netmap); a name with an embedded newline must not be able
        // to forge a second exit-node row (header line + one row per real exit, nothing more).
        let peers = vec![PeerReport {
            name: "real\n100.64.0.99  fake-exit".into(),
            ipv4: "100.64.0.9".into(),
            is_exit_node: true,
            online: Some(true),
            ..Default::default()
        }];
        let out = format_exit_node_list(&peers);
        // Header line + exactly one peer row = two newlines, no forged third line.
        assert_eq!(out.matches('\n').count(), 2, "forged extra row: {out:?}");
        assert!(out.contains('\u{FFFD}'), "newline not neutralized: {out:?}");
    }

    #[test]
    fn format_status_sanitizes_control_supplied_names() {
        use tailscaled_rs::localapi::{PeerReport, StatusReport};
        // `self_name`, `active_exit_node`, and each peer `name` are control-supplied (netmap display
        // names). A `\n` in any of them must not be able to forge a fake status line / peer row, and
        // terminal escapes must be stripped — `format_status` runs each through `sanitize_for_terminal`.
        let s = StatusReport {
            state: "Running".into(),
            want_running: true,
            self_name: Some("me\x1b[2J\n injected: yes".into()),
            self_ipv4: Some("100.64.0.1".into()),
            active_exit_node: Some("exit\nfake-line: spoofed".into()),
            peers: vec![PeerReport {
                name: "peer\n  - 100.64.0.99  forged".into(),
                ipv4: "100.64.0.2".into(),
                is_exit_node: false,
                online: Some(true),
                ..Default::default()
            }],
            ..Default::default()
        };
        let out = format_status(&s);
        // No escape survives.
        assert!(!out.contains('\x1b'), "ESC must be stripped: {out:?}");
        // None of the injected newlines created a real line: every line must start with one of the
        // known fixed labels or the `  - ` peer-row prefix. A forged `injected:`/`fake-line:`/`forged`
        // line would NOT, so this catches row/line injection structurally.
        for line in out.lines() {
            let ok = line.is_empty()
                || line.starts_with("  - ")
                || ["state:", "want_running:", "self:", "exit-node:", "peers:"]
                    .iter()
                    .any(|lbl| line.starts_with(lbl));
            assert!(ok, "forged/unexpected status line: {line:?}\nfull:\n{out}");
        }
        // The neutralized text is still visibly present (nothing silently dropped).
        assert!(
            out.contains('\u{FFFD}'),
            "delimiters not neutralized: {out:?}"
        );
    }

    #[test]
    fn format_profiles_marks_current() {
        use tailscaled_rs::localapi::ProfileEntry;
        let out = format_profiles(&[
            ProfileEntry {
                id: "default".into(),
                name: "default".into(),
                current: false,
            },
            ProfileEntry {
                id: "work".into(),
                name: "Work tailnet".into(),
                current: true,
            },
        ]);
        // Current profile marked with `*`; name shown only when it differs from the id.
        assert!(out.contains("* work  (Work tailnet)"), "{out}");
        assert!(out.contains("  default\n"), "{out}");
        assert!(!out.contains("* default"), "{out}");
        // Empty → placeholder.
        assert_eq!(format_profiles(&[]), "(no profiles)\n");
    }

    #[test]
    fn normalize_serve_target_expands_bare_port() {
        assert_eq!(normalize_serve_target("5000"), "127.0.0.1:5000");
        assert_eq!(normalize_serve_target("10.0.0.5:22"), "10.0.0.5:22");
        assert_eq!(normalize_serve_target("localhost:8080"), "localhost:8080");
    }

    #[test]
    fn format_serve_status_lists_and_flags() {
        use tailscaled_rs::localapi::{ServeConfig, TcpPortHandler};
        // Empty → placeholder, with Go's exact wording (no trailing period).
        let empty = format_serve_status(&ServeConfig::default(), false);
        assert_eq!(
            empty, "No serve config\n",
            "must match Go's exact empty message"
        );

        // A funnel-only config (AllowFunnel set, no TCP handler) is NOT empty in Go's
        // `isServeConfigEmpty`, so it must NOT print the placeholder.
        let mut funnel_only = ServeConfig::default();
        funnel_only
            .allow_funnel
            .insert("node:443".to_string(), true);
        assert!(
            !format_serve_status(&funnel_only, false).contains("No serve config"),
            "a funnel-only config is not empty (Go isServeConfigEmpty), must not show the placeholder"
        );

        let mut cfg = ServeConfig::default();
        // Plain TCP forward (daemon's own accept loop) — served.
        cfg.tcp.insert(
            "8443".to_string(),
            TcpPortHandler {
                tcp_forward: "127.0.0.1:5000".into(),
                ..Default::default()
            },
        );
        // HTTPS web with a backend (engine delegation) — served.
        cfg.tcp.insert(
            "443".to_string(),
            TcpPortHandler {
                https: true,
                tcp_forward: "127.0.0.1:3000".into(),
                ..Default::default()
            },
        );
        // HTTP web with a backend — served.
        cfg.tcp.insert(
            "80".to_string(),
            TcpPortHandler {
                http: true,
                tcp_forward: "127.0.0.1:8080".into(),
                ..Default::default()
            },
        );
        // HTTPS flag with NO backend — can't be served.
        cfg.tcp.insert(
            "8444".to_string(),
            TcpPortHandler {
                https: true,
                ..Default::default()
            },
        );
        // TLS-terminated raw TCP with a backend (no proxy-protocol) — SERVED via engine delegation.
        cfg.tcp.insert(
            "9000".to_string(),
            TcpPortHandler {
                tcp_forward: "127.0.0.1:9".into(),
                terminate_tls: "host.ts.net".into(),
                ..Default::default()
            },
        );
        // TLS-terminated requesting PROXY-protocol — NOT served (engine `Proxy` can't write the header).
        cfg.tcp.insert(
            "9001".to_string(),
            TcpPortHandler {
                tcp_forward: "127.0.0.1:10".into(),
                terminate_tls: "host.ts.net".into(),
                proxy_protocol: 1,
                ..Default::default()
            },
        );
        let out = format_serve_status(&cfg, false);
        // Plain forward is served.
        assert!(out.contains("tcp :8443 -> 127.0.0.1:5000"), "{out}");
        // HTTPS/HTTP web entries with a backend are served (engine delegation).
        assert!(
            out.contains("https://<node>:443 -> 127.0.0.1:3000"),
            "{out}"
        );
        assert!(out.contains("http://<node>:80 -> 127.0.0.1:8080"), "{out}");
        // HTTPS flag with no proxy target can't be served.
        assert!(
            out.contains("8444") && out.contains("no proxy target"),
            "{out}"
        );
        // TLS-terminated raw TCP with a backend IS served now (engine TLS-terminate + splice).
        assert!(
            out.contains("tls+tcp :9000 -> 127.0.0.1:9 (TLS-terminated)"),
            "{out}"
        );
        // The proxy-protocol terminate-tls entry is NOT served (with the reason).
        assert!(
            out.contains("9001") && out.contains("NOT served") && out.contains("proxy-protocol"),
            "{out}"
        );
    }

    #[test]
    fn clean_url_path_matches_go() {
        assert_eq!(clean_url_path("").unwrap(), "/");
        assert_eq!(clean_url_path("/").unwrap(), "/");
        assert_eq!(clean_url_path("foo").unwrap(), "/foo"); // leading slash added
        assert_eq!(clean_url_path("/foo").unwrap(), "/foo");
        assert_eq!(clean_url_path("/foo/").unwrap(), "/foo/"); // trailing slash allowed
        assert_eq!(clean_url_path("/foo/bar").unwrap(), "/foo/bar");
        // Uncleaned forms are rejected.
        assert!(clean_url_path("/foo/../bar").is_err());
        assert!(clean_url_path("//foo").is_err());
    }

    #[test]
    fn elliptically_truncate_matches_go() {
        assert_eq!(elliptically_truncate("short", 20), "short");
        // Exactly 20 bytes is unchanged.
        let twenty = "12345678901234567890";
        assert_eq!(elliptically_truncate(twenty, 20), twenty);
        // Longer → s[..17] + "..." (total 20).
        let long = "this is a long greeting message";
        let t = elliptically_truncate(long, 20);
        assert_eq!(t, "this is a long gr...");
        assert_eq!(t.len(), 20);
    }

    // The build_web_serve tests now author Go's `Web` map: TCP[port]={HTTPS flag} (no body) + the
    // handler under web["{host}:{port}"].handlers[mount]. `H` is the host the CLI resolves from status.
    const H: &str = "host.ts.net";

    #[test]
    fn build_web_serve_text_and_proxy_root() {
        use tailscaled_rs::localapi::ServeConfig;
        // text: target → a text handler at "/" in the Web map; the TCP handler is the bare HTTPS flag.
        let cfg =
            build_web_serve(ServeConfig::default(), H, 443, "text:hi there", None, true).unwrap();
        let th = cfg.tcp.get("443").unwrap();
        assert!(
            th.https && th.tcp_forward.is_empty(),
            "TCP handler is the flag, no body"
        );
        let wh = &cfg.web["host.ts.net:443"].handlers["/"];
        assert_eq!(wh.text, "hi there");
        assert!(wh.proxy.is_empty());

        // proxy target (bare port normalized) at root → proxy handler.
        let cfg = build_web_serve(ServeConfig::default(), H, 443, "3000", None, true).unwrap();
        assert_eq!(
            cfg.web["host.ts.net:443"].handlers["/"].proxy,
            "127.0.0.1:3000"
        );

        // empty text body is rejected (Go parity).
        assert!(build_web_serve(ServeConfig::default(), H, 443, "text:", None, true).is_err());
    }

    #[test]
    fn build_web_serve_set_path_mounts_accumulate() {
        use tailscaled_rs::localapi::ServeConfig;
        // First mount at /api, then /web on the same port — must accumulate in the Web map, not clobber.
        let cfg =
            build_web_serve(ServeConfig::default(), H, 443, "3000", Some("/api"), true).unwrap();
        let cfg = build_web_serve(cfg, H, 443, "text:hello", Some("/web"), true).unwrap();
        let h = &cfg.web["host.ts.net:443"].handlers;
        assert_eq!(h.len(), 2, "mounts should accumulate");
        assert_eq!(h["/api"].proxy, "127.0.0.1:3000");
        assert_eq!(h["/web"].text, "hello");
    }

    #[test]
    fn build_web_serve_bare_root_then_mount_accretes() {
        use tailscaled_rs::localapi::ServeConfig;
        // A bare root proxy, then a --set-path mount on the SAME port: the root must survive as the
        // "/" handler (Go SetWebHandler accretes — must NOT be clobbered).
        let cfg = build_web_serve(ServeConfig::default(), H, 443, "3000", None, true).unwrap();
        let cfg = build_web_serve(cfg, H, 443, "text:hi", Some("/api"), true).unwrap();
        let h = &cfg.web["host.ts.net:443"].handlers;
        assert_eq!(h.len(), 2, "root + /api should coexist");
        assert_eq!(
            h["/"].proxy, "127.0.0.1:3000",
            "the bare root proxy stayed as /"
        );
        assert_eq!(h["/api"].text, "hi");
    }

    #[test]
    fn build_web_serve_mount_then_bare_root_accretes() {
        use tailscaled_rs::localapi::ServeConfig;
        // The reverse: a --set-path mount, then a bare root serve on the same port. The root folds in
        // as the "/" handler rather than wiping the existing mount.
        let cfg =
            build_web_serve(ServeConfig::default(), H, 443, "3000", Some("/api"), true).unwrap();
        let cfg = build_web_serve(cfg, H, 443, "9000", None, true).unwrap();
        let h = &cfg.web["host.ts.net:443"].handlers;
        assert_eq!(h.len(), 2, "/api + new root should coexist");
        assert_eq!(h["/api"].proxy, "127.0.0.1:3000");
        assert_eq!(h["/"].proxy, "127.0.0.1:9000");
    }

    #[test]
    fn build_web_serve_migrates_legacy_handler_to_web_map() {
        use tailscaled_rs::localapi::{ServeConfig, TcpPortHandler};
        // A legacy on-disk config (body on the TCP handler). A new serve on that port must MIGRATE the
        // legacy body into the Web map (accrete), not silently drop it.
        let mut cfg = ServeConfig::default();
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                tcp_forward: "127.0.0.1:3000".into(),
                ..Default::default()
            },
        );
        let cfg = build_web_serve(cfg, H, 443, "text:hi", Some("/api"), true).unwrap();
        let h = &cfg.web["host.ts.net:443"].handlers;
        assert_eq!(
            h["/"].proxy, "127.0.0.1:3000",
            "legacy root proxy migrated to /"
        );
        assert_eq!(h["/api"].text, "hi");
    }

    #[test]
    fn format_serve_status_renders_text_redirect_mux() {
        use tailscaled_rs::localapi::{RedirectSpec, ServeConfig, TcpPortHandler, WebMount};
        let mut cfg = ServeConfig::default();
        // Text handler.
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                text: Some("hello".into()),
                ..Default::default()
            },
        );
        // Redirect handler.
        cfg.tcp.insert(
            "8443".into(),
            TcpPortHandler {
                https: true,
                redirect: Some(RedirectSpec {
                    to: "https://dest.ts.net/".into(),
                    status: 301,
                }),
                ..Default::default()
            },
        );
        // Path mux.
        let mut mounts = std::collections::BTreeMap::new();
        mounts.insert(
            "/api".to_string(),
            WebMount::Proxy {
                to: "127.0.0.1:3000".into(),
            },
        );
        cfg.tcp.insert(
            "9443".into(),
            TcpPortHandler {
                https: true,
                mounts,
                ..Default::default()
            },
        );
        let out = format_serve_status(&cfg, false);
        assert!(
            out.contains("https://<node>:443 -> text \"hello\""),
            "{out}"
        );
        assert!(
            out.contains("redirect 301 -> https://dest.ts.net/"),
            "{out}"
        );
        assert!(out.contains("9443 (path mux)"), "{out}");
        assert!(out.contains("/api -> proxy -> 127.0.0.1:3000"), "{out}");
    }

    #[test]
    fn format_serve_status_renders_go_web_map() {
        // A Go-shaped config (target in the top-level Web map) must render as served, using the real
        // host from the Web key — and a Web-only config must NOT print "No serve config".
        let cfg: tailscaled_rs::localapi::ServeConfig = serde_json::from_str(
            r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"host.ts.net:443":{"Handlers":{"/":{"Proxy":"127.0.0.1:3000"}}}}}"#,
        )
        .unwrap();
        let out = format_serve_status(&cfg, false);
        assert!(
            !out.contains("No serve config"),
            "Web-only config is not empty: {out}"
        );
        assert!(
            out.contains("https://host.ts.net:443 -> proxy -> 127.0.0.1:3000"),
            "the Web-map proxy must render with its real host: {out}"
        );

        // Multi-mount Web entry → path mux, rendered from the Web map.
        let mux: tailscaled_rs::localapi::ServeConfig = serde_json::from_str(
            r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"h:443":{"Handlers":{"/":{"Proxy":"127.0.0.1:3000"},"/old":{"Redirect":"301:https://h/new"}}}}}"#,
        )
        .unwrap();
        let out = format_serve_status(&mux, false);
        assert!(out.contains("https://h:443 (path mux)"), "{out}");
        assert!(out.contains("/ -> proxy -> 127.0.0.1:3000"), "{out}");
        assert!(
            out.contains("/old -> redirect -> 301:https://h/new"),
            "{out}"
        );
    }

    #[test]
    fn format_serve_status_annotates_funnel_ports() {
        use tailscaled_rs::ipn::serve;
        use tailscaled_rs::localapi::{ServeConfig, TcpPortHandler};
        let mut cfg = ServeConfig::default();
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                tcp_forward: "127.0.0.1:3000".into(),
                ..Default::default()
            },
        );
        // No funnel yet → no funnel section.
        assert!(!format_serve_status(&cfg, false).contains("Funnel"));
        // Enable funnel on 443 → the funnel section appears.
        serve::set_funnel(&mut cfg, "host.example.ts.net", 443, true);
        let out = format_serve_status(&cfg, false);
        assert!(out.contains("Funnel (on the public internet):"), "{out}");
        assert!(out.contains("https://<node>:443"), "{out}");
    }

    #[test]
    fn format_ping_summary_counts_and_loss() {
        assert_eq!(
            format_ping_summary(3, 3),
            "--- 3 sent, 3 received, 0% loss ---"
        );
        assert_eq!(
            format_ping_summary(4, 1),
            "--- 4 sent, 1 received, 75% loss ---"
        );
        assert_eq!(
            format_ping_summary(2, 0),
            "--- 2 sent, 0 received, 100% loss ---"
        );
    }

    #[test]
    fn resolve_until_direct_defaults_true_like_go() {
        // Go's `--until-direct` is a bool flag defaulting to true: neither flag → on.
        assert!(
            resolve_until_direct(false, false),
            "default must be on (Go)"
        );
        // The bare flag → on (redundant with the default, but a user may pass it).
        assert!(resolve_until_direct(true, false));
        // `--no-until-direct` is the only way to turn it off.
        assert!(!resolve_until_direct(false, true));
    }

    #[test]
    fn ping_verdict_matches_go_end_of_loop() {
        // No reply at all → "no reply" (regardless of until_direct).
        assert_eq!(ping_verdict(0, false, true), PingVerdict::NoReply);
        assert_eq!(ping_verdict(0, false, false), PingVerdict::NoReply);
        // Replies but never went direct, and --until-direct was asked → "direct not established".
        assert_eq!(ping_verdict(3, false, true), PingVerdict::NoDirect);
        // Replies and went direct → ok, even with --until-direct.
        assert_eq!(ping_verdict(2, true, true), PingVerdict::Ok);
        // Replies, no direct, but --until-direct OFF → ok (we weren't waiting for direct).
        assert_eq!(ping_verdict(5, false, false), PingVerdict::Ok);
    }

    #[test]
    fn ping_via_distinguishes_direct_and_derp() {
        // A direct endpoint → `via <ip:port>`; no endpoint → `via DERP` (relayed).
        assert_eq!(ping_via(Some("100.64.0.2:41641")), "via 100.64.0.2:41641");
        assert_eq!(ping_via(None), "via DERP");
    }

    #[test]
    fn ping_seq_label_omits_denominator_when_infinite() {
        // Finite run shows N/M; infinite (`-c 0`) shows just the attempt number.
        assert_eq!(ping_seq_label(2, 10), "2/10");
        assert_eq!(ping_seq_label(7, 0), "7");
    }

    #[test]
    fn format_ping_line_reports_path_and_rtt() {
        // Direct path.
        assert_eq!(
            format_ping_line("100.64.0.2", 12.34, Some("100.64.0.2:41641"), 1, 10),
            "pong from 100.64.0.2 via 100.64.0.2:41641 in 12.3 ms  (seq 1/10)"
        );
        // DERP-relayed path, infinite count (no denominator).
        assert_eq!(
            format_ping_line("100.64.0.2", 50.0, None, 3, 0),
            "pong from 100.64.0.2 via DERP in 50.0 ms  (seq 3)"
        );
    }

    #[test]
    fn format_ping_miss_labels_attempt() {
        // The daemon returns a bare cause (no `ping <ip> failed:` prefix), so the CLI line carries
        // the IP + attempt label exactly once — no doubled `ping … failed: ping … failed:`.
        assert_eq!(
            format_ping_miss("100.64.0.2", "timed out", 2, 10),
            "ping 100.64.0.2 (2/10) failed: timed out"
        );
        // Infinite run: attempt label has no denominator.
        assert_eq!(
            format_ping_miss("100.64.0.2", "unreachable", 3, 0),
            "ping 100.64.0.2 (3) failed: unreachable"
        );
    }

    #[test]
    fn format_ip_filtered_selects_family_and_first() {
        let v4 = Some("100.64.0.1");
        let v6 = Some("fd7a::1");

        // No flags → both, v4 then v6.
        assert_eq!(
            format_ip_filtered(v4, v6, IpSelect::default()),
            "100.64.0.1\nfd7a::1\n"
        );
        // -4 → only v4.
        assert_eq!(
            format_ip_filtered(
                v4,
                v6,
                IpSelect {
                    v4: true,
                    ..Default::default()
                }
            ),
            "100.64.0.1\n"
        );
        // -6 → only v6.
        assert_eq!(
            format_ip_filtered(
                v4,
                v6,
                IpSelect {
                    v6: true,
                    ..Default::default()
                }
            ),
            "fd7a::1\n"
        );
        // -1 → only the first (v4, since both present).
        assert_eq!(
            format_ip_filtered(
                v4,
                v6,
                IpSelect {
                    first: true,
                    ..Default::default()
                }
            ),
            "100.64.0.1\n"
        );
        // -6 -1 → first of the v6-only set.
        assert_eq!(
            format_ip_filtered(
                v4,
                v6,
                IpSelect {
                    v6: true,
                    first: true,
                    ..Default::default()
                }
            ),
            "fd7a::1\n"
        );
        // -4 with only v6 available → nothing matches.
        assert_eq!(
            format_ip_filtered(
                None,
                v6,
                IpSelect {
                    v4: true,
                    ..Default::default()
                }
            ),
            "(no matching tailnet address)\n"
        );
    }

    #[test]
    fn status_filter_active_self_peers() {
        use tailscaled_rs::localapi::{PeerReport, PrefsView, StatusReport};
        let base = || StatusReport {
            state: "Running".to_string(),
            want_running: true,
            self_ipv4: Some("100.70.22.12".to_string()),
            self_name: Some("node-a".to_string()),
            auth_url: None,
            error: None,
            prefs: PrefsView::default(),
            self_ipv6: None,
            active_exit_node: None,
            magic_dns_suffix: None,
            peers: vec![
                PeerReport {
                    name: "online-peer".to_string(),
                    ipv4: "100.64.0.2".to_string(),
                    is_exit_node: false,
                    stable_id: "n1".to_string(),
                    online: Some(true),
                    ..Default::default()
                },
                PeerReport {
                    name: "offline-peer".to_string(),
                    ipv4: "100.64.0.3".to_string(),
                    is_exit_node: false,
                    stable_id: "n2".to_string(),
                    online: Some(false),
                    ..Default::default()
                },
                PeerReport {
                    name: "unknown-peer".to_string(),
                    ipv4: "100.64.0.4".to_string(),
                    is_exit_node: false,
                    stable_id: "n3".to_string(),
                    online: None,
                    ..Default::default()
                },
            ],
            version: None,
            have_node_key: true,
        };

        // No filter → everything.
        let all = StatusFilter::default().apply(base());
        assert_eq!(all.peers.len(), 3);
        assert!(all.self_name.is_some());

        // --no-peers → peer list emptied, self kept.
        let np = StatusFilter {
            hide_peers: true,
            ..Default::default()
        }
        .apply(base());
        assert!(np.peers.is_empty());
        assert!(np.self_name.is_some());

        // --no-self → self blanked, peers kept.
        let ns = StatusFilter {
            hide_self: true,
            ..Default::default()
        }
        .apply(base());
        assert!(ns.self_name.is_none() && ns.self_ipv4.is_none());
        assert_eq!(ns.peers.len(), 3);

        // --active → only online==Some(true) peers (offline + unknown hidden).
        let act = StatusFilter {
            active_only: true,
            ..Default::default()
        }
        .apply(base());
        assert_eq!(act.peers.len(), 1);
        assert_eq!(act.peers[0].name, "online-peer");

        // --no-peers wins over --active (no peers at all).
        let both = StatusFilter {
            active_only: true,
            hide_peers: true,
            ..Default::default()
        }
        .apply(base());
        assert!(both.peers.is_empty());
    }

    #[test]
    fn format_status_json_is_go_shaped() {
        use tailscaled_rs::localapi::{PeerReport, PrefsView, StatusReport};
        let report = StatusReport {
            state: "Running".to_string(),
            want_running: true,
            self_ipv4: Some("100.70.22.12".to_string()),
            self_name: Some("node-a".to_string()),
            auth_url: None,
            error: None,
            prefs: PrefsView::default(),
            self_ipv6: Some("fd7a:115c:a1e0::1".to_string()),
            active_exit_node: Some("peer-b".to_string()),
            magic_dns_suffix: Some("tail0123.ts.net".to_string()),
            peers: vec![
                PeerReport {
                    name: "peer-b".to_string(),
                    ipv4: "100.64.0.2".to_string(),
                    is_exit_node: true,
                    stable_id: "nABC123".to_string(),
                    online: Some(true),
                    ipv6: Some("fd7a:115c:a1e0::2".to_string()),
                    allowed_routes: vec!["100.64.0.2/32".to_string(), "0.0.0.0/0".to_string()],
                    cur_addr: Some("192.0.2.5:41641".to_string()),
                    ..Default::default()
                },
                PeerReport {
                    name: "peer-c".to_string(),
                    ipv4: "100.64.0.3".to_string(),
                    is_exit_node: false,
                    stable_id: String::new(), // missing id → keyed by name (fallback)
                    online: Some(false),
                    relay: Some("nyc".to_string()),
                    last_seen: Some("2026-06-11 05:19:14 UTC".to_string()),
                    ..Default::default()
                },
            ],
            version: Some("0.36.0".to_string()),
            have_node_key: true,
        };
        let out = format_status_json(&report).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&out).expect("status --json must be valid JSON");

        // Go key names + the exact BackendState string.
        assert_eq!(v["BackendState"], serde_json::json!("Running"));
        assert_eq!(v["AuthURL"], serde_json::json!("")); // always present, empty when none
        // TailscaleIPs now carries IPv4 then IPv6.
        assert_eq!(
            v["TailscaleIPs"],
            serde_json::json!(["100.70.22.12", "fd7a:115c:a1e0::1"])
        );
        assert_eq!(v["MagicDNSSuffix"], serde_json::json!("tail0123.ts.net"));
        assert_eq!(v["ExitNodeStatus"]["ID"], serde_json::json!("peer-b"));
        // Version (Go `Status.Version`) + TUN (Go `Status.TUN`) now surfaced; HaveNodeKey true once
        // past the pre-login states (this report is Running). All Go-cased field names.
        assert_eq!(v["Version"], serde_json::json!("0.36.0"));
        assert_eq!(v["TUN"], serde_json::json!(false)); // PrefsView::default() → netstack
        assert_eq!(v["HaveNodeKey"], serde_json::json!(true));
        // Self subset.
        assert_eq!(v["Self"]["HostName"], serde_json::json!("node-a"));
        assert_eq!(
            v["Self"]["TailscaleIPs"],
            serde_json::json!(["100.70.22.12", "fd7a:115c:a1e0::1"])
        );
        // Peer map keyed by stable_id (with name-fallback for the id-less peer).
        assert_eq!(
            v["Peer"]["nABC123"]["HostName"],
            serde_json::json!("peer-b")
        );
        assert_eq!(
            v["Peer"]["nABC123"]["ExitNodeOption"],
            serde_json::json!(true)
        );
        assert_eq!(v["Peer"]["nABC123"]["Online"], serde_json::json!(true));
        assert_eq!(
            v["Peer"]["nABC123"]["TailscaleIPs"],
            serde_json::json!(["100.64.0.2", "fd7a:115c:a1e0::2"])
        );
        assert_eq!(
            v["Peer"]["nABC123"]["AllowedIPs"],
            serde_json::json!(["100.64.0.2/32", "0.0.0.0/0"])
        );
        assert_eq!(
            v["Peer"]["nABC123"]["CurAddr"],
            serde_json::json!("192.0.2.5:41641")
        );
        assert_eq!(v["Peer"]["peer-c"]["HostName"], serde_json::json!("peer-c"));
        assert_eq!(v["Peer"]["peer-c"]["Online"], serde_json::json!(false));
        assert_eq!(v["Peer"]["peer-c"]["Relay"], serde_json::json!("nyc"));
        assert_eq!(
            v["Peer"]["peer-c"]["LastSeen"],
            serde_json::json!("2026-06-11 05:19:14 UTC")
        );
    }

    #[test]
    fn format_status_json_omits_have_node_key_when_false() {
        use tailscaled_rs::localapi::StatusReport;
        // The omitempty half of Go-fidelity: HaveNodeKey is OMITTED when the node holds no key (Go's
        // `json:",omitempty"`), while TUN is ALWAYS present (Go's bare bool) — even on a keyless node.
        let report = StatusReport {
            state: "NeedsLogin".to_string(),
            have_node_key: false,
            version: Some("0.36.0".to_string()),
            ..Default::default()
        };
        let out = format_status_json(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(
            v.get("HaveNodeKey").is_none(),
            "HaveNodeKey must be omitted when false (Go omitempty): {out}"
        );
        assert_eq!(
            v["TUN"],
            serde_json::json!(false),
            "TUN is always present even when HaveNodeKey is omitted (Go bare bool)"
        );
    }

    #[test]
    fn html_escape_neutralizes_markup() {
        assert_eq!(
            html_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&#39;f"
        );
        assert_eq!(html_escape("plain"), "plain");
    }

    #[test]
    fn render_status_html_includes_fields_and_escapes_peers() {
        use tailscaled_rs::localapi::{PeerReport, StatusReport};
        let report = StatusReport {
            state: "Running".to_string(),
            self_name: Some("node-a".to_string()),
            self_ipv4: Some("100.64.0.1".to_string()),
            magic_dns_suffix: Some("tail0123.ts.net".to_string()),
            version: Some("0.37.0".to_string()),
            peers: vec![PeerReport {
                // A hostile, control-supplied peer name must render inert (no raw <script>).
                name: "<script>alert(1)</script>".to_string(),
                ipv4: "100.64.0.2".to_string(),
                online: Some(true),
                ..Default::default()
            }],
            have_node_key: true,
            ..Default::default()
        };
        let html = render_status_html(&report);
        assert!(html.starts_with("<!DOCTYPE html>"), "well-formed page");
        assert!(html.contains("Running") && html.contains("0.37.0") && html.contains("node-a"));
        assert!(html.contains("tail0123.ts.net") && html.contains("100.64.0.1"));
        // The peer is listed, but its hostile name is escaped — no raw <script> tag.
        assert!(html.contains("100.64.0.2"), "peer ip present");
        assert!(
            !html.contains("<script>"),
            "a hostile peer name must be HTML-escaped, not rendered as markup: {html}"
        );
        assert!(html.contains("&lt;script&gt;"), "escaped form present");

        // An empty / not-yet-running report still renders a valid page (no panic).
        let empty = StatusReport {
            state: "NeedsLogin".to_string(),
            ..Default::default()
        };
        let empty_html = render_status_html(&empty);
        assert!(empty_html.starts_with("<!DOCTYPE html>"));
        assert!(empty_html.contains("NeedsLogin") && empty_html.contains("no peers"));
    }

    #[test]
    fn parse_request_target_extracts_method_and_path() {
        assert_eq!(parse_request_target("GET / HTTP/1.1"), Some(("GET", "/")));
        assert_eq!(
            parse_request_target("GET /foo HTTP/1.1"),
            Some(("GET", "/foo"))
        );
        assert_eq!(parse_request_target("POST / HTTP/1.0"), Some(("POST", "/")));
        // Malformed (no path token) → None; the serve loop treats that as 404.
        assert_eq!(parse_request_target("GET"), None);
        assert_eq!(parse_request_target(""), None);
    }

    #[test]
    fn peer_status_cell_renders_path_and_offline() {
        use tailscaled_rs::localapi::PeerReport;
        // Direct path → "direct <addr>".
        let direct = PeerReport {
            cur_addr: Some("192.0.2.5:41641".to_string()),
            online: Some(true),
            ..Default::default()
        };
        assert_eq!(peer_status_cell(&direct), "  (direct 192.0.2.5:41641)");
        // No direct path, DERP relay → relay "region" (quoted, like Go).
        let relayed = PeerReport {
            relay: Some("nyc".to_string()),
            online: Some(true),
            ..Default::default()
        };
        assert_eq!(peer_status_cell(&relayed), r#"  (relay "nyc")"#);
        // Offline with last-seen → appended suffix; relay still shown.
        let offline = PeerReport {
            relay: Some("fra".to_string()),
            online: Some(false),
            last_seen: Some("2026-06-11 05:19:14 UTC".to_string()),
            ..Default::default()
        };
        assert_eq!(
            peer_status_cell(&offline),
            r#"  (relay "fra"; offline, last seen 2026-06-11 05:19:14 UTC)"#
        );
        // Online peer with no known path → empty cell.
        let plain = PeerReport {
            online: Some(true),
            ..Default::default()
        };
        assert_eq!(peer_status_cell(&plain), "");
    }

    #[tokio::test]
    async fn wait_times_out_against_a_dead_socket() {
        // With a short timeout and no daemon listening, `wait` must give up and return Err (→ the
        // CLI's non-zero exit), not hang forever. A non-existent socket path makes every poll's
        // round-trip fail (which `wait` tolerates), so only the timeout ends the loop.
        let dead = std::path::Path::new("/tmp/tnet-wait-nope-does-not-exist.sock");
        let start = tokio::time::Instant::now();
        let r = wait_for_running(dead, Some(1)).await;
        assert!(
            r.is_err(),
            "wait against a dead socket must time out to Err"
        );
        assert!(
            r.unwrap_err().to_string().contains("timed out"),
            "the error should say it timed out"
        );
        // It should give up promptly after ~1s, not run away.
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "wait should honor the ~1s timeout, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn up_timeout_flag_parses_into_command_up() {
        // `tnet up --timeout 30` parses to `Command::Up { timeout: Some(30), .. }`; omitting the flag
        // leaves it `None` (the fire-and-return default — no wait). This is the CLI-side contract the
        // post-`up` path keys on (`up_timeout = timeout`), so pin it at the parse boundary.
        // `Command` doesn't derive Debug, so extract the field with a helper closure rather than a
        // `match … => panic!("{other:?}")` arm (which would need Debug).
        let up_timeout_of = |argv: &[&str]| -> Option<u64> {
            match Cli::try_parse_from(argv).expect("parses").command {
                Command::Up { timeout, .. } => timeout,
                _ => panic!("expected Command::Up from {argv:?}"),
            }
        };
        assert_eq!(up_timeout_of(&["tnet", "up", "--timeout", "30"]), Some(30));
        assert_eq!(
            up_timeout_of(&["tnet", "up"]),
            None,
            "no --timeout → None (don't wait)"
        );
        // `--timeout 0` is the explicit "wait forever" value (Go's 0 = wait indefinitely); it must
        // parse as Some(0), distinct from absent (None) — `wait_for_running` maps both to no deadline.
        assert_eq!(up_timeout_of(&["tnet", "up", "--timeout", "0"]), Some(0));
    }

    #[test]
    fn id_token_command_parses_audience() {
        // `tnet id-token <aud>` parses to Command::IdToken { audience } (the subcommand spelling is
        // the hyphenated `id-token`, matching Go); the audience positional is required.
        match Cli::try_parse_from(["tnet", "id-token", "https://example.com"])
            .expect("parses")
            .command
        {
            Command::IdToken { audience } => assert_eq!(audience, "https://example.com"),
            _ => panic!("expected Command::IdToken"),
        }
        // Missing the required audience is a parse error (not a panic / empty token).
        assert!(
            Cli::try_parse_from(["tnet", "id-token"]).is_err(),
            "audience is required"
        );
    }

    #[test]
    fn accept_risk_flag_parses_on_up_and_set() {
        // `--accept-risk <risk>` parses on both `up` and `set` (Go --accept-risk); omitted → None.
        match Cli::try_parse_from(["tnet", "up", "--accept-risk", "lose-ssh"])
            .expect("parses")
            .command
        {
            Command::Up { accept_risk, .. } => assert_eq!(accept_risk.as_deref(), Some("lose-ssh")),
            _ => panic!("expected Command::Up"),
        }
        match Cli::try_parse_from(["tnet", "up"]).expect("parses").command {
            Command::Up { accept_risk, .. } => assert_eq!(accept_risk, None),
            _ => panic!("expected Command::Up"),
        }
        match Cli::try_parse_from(["tnet", "set", "--accept-risk", "all"])
            .expect("parses")
            .command
        {
            Command::Set { accept_risk, .. } => assert_eq!(accept_risk.as_deref(), Some("all")),
            _ => panic!("expected Command::Set"),
        }
    }

    #[tokio::test]
    async fn wait_forever_does_not_return_promptly_against_a_dead_socket() {
        // `--timeout 0` (and `None`) = wait forever: `wait_for_running` must NOT compute a deadline,
        // so against a never-Running dead socket it keeps polling rather than erroring out. We can't
        // wait forever in a test, so assert it is STILL running after a short bound (i.e. it did not
        // immediately return an Err the way a finite timeout would). Complements
        // `wait_times_out_against_a_dead_socket`, which covers the finite-timeout Err path.
        let dead = std::path::Path::new("/tmp/tnet-wait-forever-nope.sock");
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            wait_for_running(dead, Some(0)),
        )
        .await;
        assert!(
            res.is_err(),
            "timeout:0 means wait forever — wait_for_running must still be polling (not returned) \
             after 300ms against a dead socket, so the outer tokio timeout should elapse"
        );
    }

    #[test]
    fn wait_decision_precedence_running_error_authurl_keep() {
        use tailscaled_rs::localapi::StatusReport;

        // (a) Running + a tailnet IP → Done (the wait succeeded).
        let running = StatusReport {
            state: "Running".to_string(),
            self_ipv4: Some("100.64.0.1".to_string()),
            ..Default::default()
        };
        assert_eq!(wait_decision(&running), WaitStep::Done);

        // Running short-circuits even if (impossibly) an error were also set — Running wins.
        let running_with_stale_error = StatusReport {
            state: "Running".to_string(),
            self_ipv4: Some("100.64.0.1".to_string()),
            error: Some("stale".to_string()),
            ..Default::default()
        };
        assert_eq!(wait_decision(&running_with_stale_error), WaitStep::Done);

        // (b) A terminal error (and not yet Running) → Failed, carrying the reason.
        let failed = StatusReport {
            state: "NeedsLogin".to_string(),
            error: Some("authkey expired".to_string()),
            ..Default::default()
        };
        assert_eq!(
            wait_decision(&failed),
            WaitStep::Failed("authkey expired".to_string()),
            "a terminal registration error must fail fast with the reason"
        );

        // (c) auth_url present but NO error → Keep (interactive login is pending = transient, NOT a
        // failure — failing here would break every interactive `up --timeout`).
        let pending_login = StatusReport {
            state: "NeedsLogin".to_string(),
            auth_url: Some("https://login.example/a/abc123".to_string()),
            error: None,
            ..Default::default()
        };
        assert_eq!(
            wait_decision(&pending_login),
            WaitStep::Keep,
            "a pending auth_url is transient — keep waiting, do not fail"
        );

        // (d) A bare not-yet-Running status (no error, no auth_url) → Keep.
        let starting = StatusReport {
            state: "Starting".to_string(),
            ..Default::default()
        };
        assert_eq!(wait_decision(&starting), WaitStep::Keep);

        // (e) A hostile error string (control-influenced): `wait_decision` carries the RAW reason
        // (it's a pure classifier — the caller sanitizes at the bail site, like `classify_auth`).
        // Assert the raw reason round-trips here, AND that the caller's sanitize step — the registration
        // `reason` is free-form text, so `wait_for_running` applies `sanitize_multiline` — strips the
        // ESC/BEL while preserving the legible newline. The full two-step contract, not just one half.
        let hostile = StatusReport {
            state: "NeedsLogin".to_string(),
            error: Some("evil\x1b[2J\x07reason\nsecond line".to_string()),
            ..Default::default()
        };
        match wait_decision(&hostile) {
            WaitStep::Failed(reason) => {
                assert_eq!(
                    reason, "evil\x1b[2J\x07reason\nsecond line",
                    "wait_decision carries the RAW reason (caller sanitizes)"
                );
                // The caller's sanitize step (mirrors wait_for_running's bail site) neutralizes the
                // escapes but, because a registration reason is free-form, keeps the newline so a
                // multi-line server message still renders across lines (matching Go's raw print).
                let shown = sanitize_multiline(&reason);
                assert!(!shown.contains('\x1b'), "ESC stripped at the bail site");
                assert!(!shown.contains('\x07'), "BEL stripped at the bail site");
                assert!(
                    shown.contains('\n'),
                    "multiline reason keeps its newline: {shown:?}"
                );
                assert!(shown.contains("evil") && shown.contains("second line"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn version_command_client_matches_crate_version() {
        // The client version `tnet version` prints is the crate version — guards against drift if the
        // print path ever stops using CARGO_PKG_VERSION.
        assert_eq!(
            format_version(env!("CARGO_PKG_VERSION"), None, 130, false),
            format!("{}\n", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn format_revert_guard_renders_sorted_copy_pasteable_command() {
        // The canonical case: `tnet up --ssh` on a node that already advertises routes + accepts
        // routes. The daemon reports the two reverts; the message must list a `tnet up` line that
        // re-mentions both, in a deterministic (sorted) order, and offer `--reset`.
        let reverts = vec![
            RevertedPref {
                key: "advertise_routes".to_string(),
                value: "10.0.0.0/8".to_string(),
            },
            RevertedPref {
                key: "accept_routes".to_string(),
                value: "true".to_string(),
            },
        ];
        let out = format_revert_guard(&reverts);
        // Both keep-flags present, sorted: "--accept-routes" < "--advertise-routes=...".
        assert!(
            out.contains("tnet up --accept-routes --advertise-routes=10.0.0.0/8"),
            "expected a sorted copy-pasteable command, got:\n{out}"
        );
        assert!(
            out.contains("--reset"),
            "must mention the --reset escape hatch"
        );
        // It is framed as an error (non-zero exit at the call site) and explains the revert.
        assert!(out.starts_with("error:"));
        assert!(out.contains("revert"));
    }

    #[test]
    #[cfg(unix)]
    fn reset_sigpipe_sets_default_disposition() {
        // The fix for the broken-pipe panic: `reset_sigpipe()` must actually restore SIGPIPE to
        // SIG_DFL (Rust's runtime installs SIG_IGN, which is what makes `print!` to a closed pipe
        // panic). Prove it by reading the handler back via sigaction after calling the helper — so a
        // refactor that drops or breaks the reset is caught. (Pure libc introspection; no piping.)
        super::reset_sigpipe();
        // SAFETY: sigaction with a null `act` only READS the current handler into `oldact`; no
        // preconditions, no mutation. `MaybeUninit` is fully written by the call on success.
        let mut oldact = std::mem::MaybeUninit::<libc::sigaction>::uninit();
        let rc = unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), oldact.as_mut_ptr()) };
        assert_eq!(rc, 0, "sigaction read must succeed");
        let handler = unsafe { oldact.assume_init() }.sa_sigaction;
        assert_eq!(
            handler,
            libc::SIG_DFL,
            "reset_sigpipe must leave SIGPIPE at SIG_DFL (so a broken pipe terminates cleanly, \
             not a print panic); got {handler:?} (SIG_IGN={:?})",
            libc::SIG_IGN
        );
    }
}
