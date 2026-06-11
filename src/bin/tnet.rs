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
        /// `up`; a malformed URL fails loudly rather than silently using the default.
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
        /// Output as JSON (`{ "client": "..", "daemon": ".." }`; `daemon` present only with
        /// `--daemon`). Mirrors Go `--json`.
        #[arg(long)]
        json: bool,
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
        #[arg(long)]
        json: bool,
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
    /// Ping a tailnet peer over the overlay and report the round-trip time.
    Ping {
        /// The tailnet IP of the peer to ping.
        #[arg(value_name = "IP")]
        ip: String,
        /// Per-attempt timeout in milliseconds (omit for a sensible default).
        #[arg(long, value_name = "MS")]
        timeout: Option<u64>,
        /// Number of pings to send (Go `-c`). Default 1. Prints one result line per attempt, then a
        /// summary; a failed attempt is counted but does not abort the rest.
        #[arg(short = 'c', long, value_name = "N", default_value_t = 1)]
        count: u32,
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
    /// Tailnet Lock (TKA) commands. Currently `status` (read-only): whether lock is in use, the
    /// authority head, and any pending disablement. Mirrors Go `tailscale lock status`.
    Lock {
        #[command(subcommand)]
        cmd: LockCmd,
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
    Bugreport,
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

/// `tnet metrics` subcommands. Bare `tnet metrics` prints to stdout; `write <path>` writes a file.
#[derive(Subcommand)]
enum MetricsCmd {
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
    /// Send a local file to a tailnet peer (by IP or MagicDNS name).
    Cp {
        /// Local filesystem path of the file to send.
        #[arg(value_name = "PATH")]
        path: String,
        /// Destination peer: a tailnet IP or MagicDNS name (e.g. `100.64.0.9` or `peer-b`).
        #[arg(value_name = "PEER")]
        peer: String,
    },
    /// List files waiting in the Taildrop inbox.
    List,
    /// Fetch a waiting file by name and write it locally.
    Get {
        /// The waiting file's base name (as shown by `tnet file list`).
        #[arg(value_name = "NAME")]
        name: String,
        /// Local destination path to write the fetched file to.
        #[arg(value_name = "DEST")]
        dest: String,
        /// Delete the file from the Taildrop inbox after a successful fetch (Go's default behavior).
        #[arg(long)]
        delete_after: bool,
    },
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let socket = cli.socket.unwrap_or_else(tailscaled_rs::socket_path);

    // Track whether this is an `up` with no auth key — the interactive-login case, where after a
    // successful bring-up we follow with a `status` to surface the control auth URL the operator
    // must visit (it isn't known at `up`-time; it arrives once the engine reaches `NeedsLogin`).
    let mut interactive_up = false;
    // Track whether the user asked for `status --json`, so the (generic) `Response::Status` render
    // site below emits the Go `ipnstate.Status`-shaped JSON instead of the human table.
    let mut status_json = false;
    // `status` filtering flags (--active / --no-peers / --self), applied client-side to the report
    // before either renderer. Default = show everything.
    let mut status_filter = StatusFilter::default();
    let request = match cli.command {
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
            ssh,
            no_ssh,
            reset,
        } => {
            // Resolve the secret through the precedence chain and hold it as a `SecretString`
            // (zeroized on drop, never `Debug`-printed). Expose it only here, at the moment we
            // serialize the wire `Request` — the field on the wire stays a plain `Option<String>`.
            let authkey = resolve_authkey(authkey, authkey_file).await?;
            interactive_up = authkey.is_none();
            Request::Up {
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
                advertise_routes: resolve_advertise_routes(
                    advertise_routes,
                    advertise_routes_clear,
                ),
                // Passed tags replace the set; `--clear-advertise-tags` empties it; neither leaves it
                // unchanged. Reuses the same Vec+clear→Option resolver as advertise-routes.
                advertise_tags: resolve_advertise_routes(advertise_tags, advertise_tags_clear),
                // `--accept-routes`/`--no-accept-routes` tri-state (mirrors `--tun`); reuses the same
                // resolver as the `set` arm.
                accept_routes: resolve_accept_routes(accept_routes, no_accept_routes),
                // `--ssh`/`--no-ssh` tri-state (mirrors `--tun`).
                ssh: resolve_ssh(ssh, no_ssh),
                // `--reset`: reset unmentioned settings to default + bypass the accidental-revert
                // guard. A plain bool flag (Go's `--reset`), passed straight through.
                reset,
            }
        }
        Command::Set {
            hostname,
            accept_routes,
            no_accept_routes,
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
        } => Request::Set {
            hostname,
            // `--accept-routes`/`--no-accept-routes` tri-state (mirrors `--tun`).
            accept_routes: resolve_accept_routes(accept_routes, no_accept_routes),
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
        },
        Command::Bugreport => Request::BugReport,
        // `nc` hijacks its connection (the daemon splices to the overlay after a one-line ack), so it
        // is handled by a dedicated piping path, not the generic round-trip.
        Command::Nc { host, port } => {
            return run_nc(&socket, &host, port)
                .await
                .with_context(|| format!("nc to {host}:{port} via {}", socket.display()));
        }
        // `serve`: read-modify-write the ServeConfig (tcp/reset) or render it (status). Inline because
        // tcp/reset must GET the current config, mutate, then SET it.
        Command::Serve { cmd } => {
            return run_serve(&socket, cmd)
                .await
                .with_context(|| format!("serve via {}", socket.display()));
        }
        // `funnel <port> on|off`: GET status (for the node's MagicDNS name → the HostPort key) + the
        // current ServeConfig, toggle AllowFunnel, SET it back. Inline (read-modify-write, like serve).
        Command::Funnel { port, on_off } => {
            return run_funnel(&socket, port, &on_off)
                .await
                .with_context(|| format!("funnel via {}", socket.display()));
        }
        Command::Down => Request::Down,
        Command::Logout => Request::Logout,
        // `switch` (Go `tailscale switch`): --list renders a table; `remove <id>` deletes; a bare
        // `<target>` switches. Handled inline — `--list` renders the Profiles reply, and the three
        // modes map to different requests.
        Command::Switch { list, target, cmd } => {
            // `switch remove <id>` (subcommand) takes precedence.
            if let Some(SwitchCmd::Remove { target }) = cmd {
                return send_ok_or_die(&socket, Request::DeleteProfile { target }).await;
            }
            if list {
                match round_trip(&socket, &Request::ProfileList).await {
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
                        return Err(e)
                            .with_context(|| format!("listing profiles at {}", socket.display()));
                    }
                }
            }
            match target {
                Some(target) => {
                    return send_ok_or_die(&socket, Request::SwitchProfile { target }).await;
                }
                None => {
                    eprintln!("usage: tnet switch <profile> | --list | remove <profile>");
                    std::process::exit(1);
                }
            }
        }
        // `version` answers from the CLI's own crate version. WITHOUT `--daemon` it never contacts
        // the daemon (Go also prints the client version with no LocalAPI call) — handle it here and
        // return. WITH `--daemon` it round-trips `Request::Version` to learn the daemon's version,
        // then renders both; we do that inline here (rather than falling through to the generic
        // response printer) so the client/daemon pairing + `--json` shape stay in one place.
        Command::Version { daemon, json } => {
            let client_version = env!("CARGO_PKG_VERSION");
            let daemon_version = if daemon {
                match round_trip(&socket, &Request::Version).await {
                    Ok(Response::Version { version }) => Some(version),
                    Ok(other) => {
                        anyhow::bail!("unexpected response to version request: {other:?}")
                    }
                    Err(e) => {
                        return Err(e).with_context(|| {
                            format!("querying daemon version at {}", socket.display())
                        });
                    }
                }
            } else {
                None
            };
            print_version(client_version, daemon_version.as_deref(), json);
            return Ok(());
        }
        // `get` (Go `tailscale get`): round-trip GetPrefs, then render. Handled inline (early return)
        // because its `setting`/`json` args shape the output and are not part of the wire request —
        // keeping the projection→render in one place, like `version`.
        Command::Get { setting, json } => {
            let view = match round_trip(&socket, &Request::GetPrefs).await {
                Ok(Response::Prefs(v)) => v,
                Ok(Response::Error { message }) => {
                    eprintln!("error: {message}");
                    std::process::exit(1);
                }
                Ok(other) => anyhow::bail!("unexpected response to get request: {other:?}"),
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("getting prefs at {}", socket.display()));
                }
            };
            match format_get(&view, setting.as_deref(), json) {
                Ok(out) => print!("{out}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
            return Ok(());
        }
        // `wait` (Go `tailscale wait`): poll until the node is Running with a tailnet IP, honoring an
        // optional timeout. Handled inline (it loops + has its own exit-code contract), not a
        // one-shot request.
        Command::Wait { timeout } => {
            return wait_for_running(&socket, timeout).await.with_context(|| {
                format!("waiting for the node to come up at {}", socket.display())
            });
        }
        // `whoami` (Go `tailscale whoami`): resolve this node's own identity — Status to learn the
        // self tailnet IP, then Whois on that IP. Handled inline because it chains two requests and
        // its `--json` shape is the whois record. Reuses the same `format_whois` renderer as `whois`.
        Command::Whoami { json } => {
            let status = match round_trip(&socket, &Request::Status).await {
                Ok(Response::Status(s)) => s,
                Ok(other) => anyhow::bail!("unexpected response to status request: {other:?}"),
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("querying status at {}", socket.display()));
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
                &socket,
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
                    return Ok(());
                }
                Ok(Response::Error { message }) => {
                    eprintln!("error: {message}");
                    std::process::exit(1);
                }
                Ok(other) => anyhow::bail!("unexpected response to whois request: {other:?}"),
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("resolving self identity at {}", socket.display())
                    });
                }
            }
        }
        // `status --watch` is a long-lived stream, not a one-shot round-trip — handle it here and
        // return. Plain `status` falls through to the one-shot path below.
        Command::Status {
            watch,
            json,
            active,
            no_peers,
            no_self,
        } => {
            if watch {
                return watch_status(&socket)
                    .await
                    .with_context(|| format!("watching status at {}", socket.display()));
            }
            status_json = json;
            status_filter = StatusFilter {
                active_only: active,
                hide_peers: no_peers,
                hide_self: no_self,
            };
            Request::Status
        }
        // `ip` (Go `tailscale ip`): self addresses by default, or a peer's if named, with -4/-6/-1
        // filters. Handled inline because the filters + the optional peer lookup shape the output
        // (and the peer case fetches Status to resolve by name/IP against the netmap).
        Command::Ip {
            v4,
            v6,
            first,
            peer,
        } => {
            let sel = IpSelect { v4, v6, first };
            let out = if let Some(peer) = peer {
                // Peer address: resolve the named peer against the status peer set (by MagicDNS name
                // or tailnet IP). We fetch Status (not whois, which is IP-only) so a NAME also works.
                let status = match round_trip(&socket, &Request::Status).await {
                    Ok(Response::Status(s)) => s,
                    Ok(other) => anyhow::bail!("unexpected response to status request: {other:?}"),
                    Err(e) => {
                        return Err(e)
                            .with_context(|| format!("querying status at {}", socket.display()));
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
                match round_trip(&socket, &Request::Ip).await {
                    Ok(Response::Ip { ipv4, ipv6 }) => {
                        format_ip_filtered(ipv4.as_deref(), ipv6.as_deref(), sel)
                    }
                    Ok(Response::Error { message }) => {
                        eprintln!("error: {message}");
                        std::process::exit(1);
                    }
                    Ok(other) => anyhow::bail!("unexpected response to ip request: {other:?}"),
                    Err(e) => {
                        return Err(e)
                            .with_context(|| format!("querying ip at {}", socket.display()));
                    }
                }
            };
            print!("{out}");
            return Ok(());
        }
        Command::Whois { ip } => Request::Whois { ip },
        // `ping` (Go `tailscale ping [-c N]`): the engine pings one-at-a-time, so `-c` is a CLI-side
        // loop over `Request::Ping`. Handled inline (the loop + summary + exit-code contract); each
        // attempt prints a result line, a failure is counted but does not abort the rest, and the
        // command exits non-zero only if NOTHING was received.
        Command::Ping { ip, timeout, count } => {
            let n = count.max(1);
            let mut received = 0u32;
            for seq in 1..=n {
                match round_trip(
                    &socket,
                    &Request::Ping {
                        ip: ip.clone(),
                        timeout_ms: timeout,
                    },
                )
                .await
                {
                    Ok(Response::Ping { rtt_ms, ip }) => {
                        received += 1;
                        println!("pong from {ip} in {rtt_ms:.1} ms  (seq {seq}/{n})");
                    }
                    Ok(Response::Error { message }) => {
                        eprintln!("ping {seq}/{n} failed: {message}");
                    }
                    Ok(other) => anyhow::bail!("unexpected response to ping: {other:?}"),
                    Err(e) => {
                        return Err(e).with_context(|| format!("pinging at {}", socket.display()));
                    }
                }
                // Pace at ~1 ping/second like Go `tailscale ping`, so `-c N` is a steady stream
                // rather than a burst. Skip the wait after the final attempt.
                if seq < n {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
            // Only print a summary for a multi-ping run (a single ping's one line is self-explanatory).
            if n > 1 {
                println!("{}", format_ping_summary(n, received));
            }
            // Exit non-zero only if nothing came back at all (Go: success if any reply).
            if received == 0 {
                std::process::exit(1);
            }
            return Ok(());
        }
        // Taildrop. The nested subcommand picks which wire `Request` to send: `cp` and `get` are
        // writes (the daemon reads/consumes a file) and reply `Ok`; `list` is read-only and replies
        // `Files`.
        // `metrics` (Go `tailscale metrics`): fetch the Prometheus text, then print or write it.
        // Inline because `write <path>` chooses a file sink over stdout.
        Command::Metrics { cmd } => {
            let text = match round_trip(&socket, &Request::Metrics).await {
                Ok(Response::Metrics { text }) => text,
                Ok(Response::Error { message }) => {
                    eprintln!("error: {message}");
                    std::process::exit(1);
                }
                Ok(other) => anyhow::bail!("unexpected response to metrics: {other:?}"),
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("querying metrics at {}", socket.display()));
                }
            };
            match cmd {
                Some(MetricsCmd::Write { path }) => {
                    tokio::fs::write(&path, text.as_bytes())
                        .await
                        .with_context(|| format!("writing metrics to {}", path.display()))?;
                    println!("wrote metrics to {}", path.display());
                }
                None => print!("{text}"),
            }
            return Ok(());
        }
        // `lock status` (Go `tailscale lock status`): fetch + render the TKA status.
        Command::Lock {
            cmd: LockCmd::Status { json },
        } => {
            let report = match round_trip(&socket, &Request::LockStatus).await {
                Ok(Response::Lock(r)) => r,
                Ok(Response::Error { message }) => {
                    eprintln!("error: {message}");
                    std::process::exit(1);
                }
                Ok(other) => anyhow::bail!("unexpected response to lock status: {other:?}"),
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("querying lock status at {}", socket.display()));
                }
            };
            print!("{}", format_lock_status(&report, json));
            return Ok(());
        }
        // `exit-node list` (Go `tailscale exit-node list`): reuse Status, filter to exit-node peers.
        Command::ExitNode {
            cmd: ExitNodeCmd::List,
        } => {
            let status = match round_trip(&socket, &Request::Status).await {
                Ok(Response::Status(s)) => s,
                Ok(other) => anyhow::bail!("unexpected response to status: {other:?}"),
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("querying status at {}", socket.display()));
                }
            };
            print!("{}", format_exit_node_list(&status.peers));
            return Ok(());
        }
        Command::File { cmd } => match cmd {
            FileCmd::Cp { path, peer } => Request::FileCp { path, peer },
            FileCmd::List => Request::FileList,
            FileCmd::Get {
                name,
                dest,
                delete_after,
            } => Request::FileGet {
                name,
                dest,
                delete_after,
            },
        },
    };

    let response = round_trip(&socket, &request)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;

    match response {
        Response::Status(s) => {
            // Apply the client-side --active / --no-peers / --no-self filters before rendering, so
            // both the human and --json paths honor them identically.
            let s = status_filter.apply(s);
            if status_json {
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
        }
        // This node's own tailnet addresses (`tnet ip`), one per line; a node with no address yet
        // (no netmap received) prints a clear placeholder rather than nothing.
        // `ip` is handled inline above (early return) so its -4/-6/-1/peer logic stays in one place;
        // this arm is exhaustiveness-only. Render unfiltered defensively if one ever reaches here.
        Response::Ip { ipv4, ipv6 } => print!("{}", format_ip(ipv4.as_deref(), ipv6.as_deref())),
        // The owner of a tailnet IP (`tnet whois`). The node name is control-supplied text, so it is
        // run through `sanitize_for_terminal` inside the formatter before printing. The queried IP
        // (needed for the not-found line) is read back from the still-owned `request`.
        Response::Whois(w) => {
            let queried_ip = match &request {
                Request::Whois { ip } => ip.as_str(),
                // The daemon only sends Whois in reply to a Whois request; fall back gracefully.
                _ => "",
            };
            print!("{}", format_whois(&w, queried_ip));
        }
        // Round-trip time of an overlay ping (`tnet ping`).
        // `ping` is handled inline above (the -c loop); this arm is exhaustiveness-only.
        Response::Ping { rtt_ms, ip } => println!("pong from {ip} in {rtt_ms:.1} ms"),
        // Waiting Taildrop files (`tnet file list`). One line per file; an empty inbox prints a
        // clear placeholder rather than nothing. The file name is engine/peer-supplied, so it is run
        // through `sanitize_for_terminal` before printing (a sender could craft a hostile name).
        Response::Files { files } => print!("{}", format_files(&files)),
        Response::Ok { message } => {
            println!("ok: {message}");
            // Interactive login: an authkey-less `up` succeeds at the daemon, but the node now needs
            // a human to authorize it. The auth URL isn't known yet at `up`-time — it arrives once
            // the engine reaches `NeedsLogin` — so poll `status` briefly to surface it (or a
            // terminal registration failure).
            if interactive_up {
                match poll_for_auth_url(&socket).await {
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
                        eprintln!("registration failed: {}", sanitize_for_terminal(&reason));
                        eprintln!(
                            "(this is a permanent failure — re-run `tnet up --authkey <NEW_KEY>` \
                             with a fresh key; the same key will keep failing)"
                        );
                        std::process::exit(1);
                    }
                    AuthOutcome::None => {}
                }
            }
        }
        // The daemon refused an `up` that would silently revert non-default settings the command did
        // not mention (Go's accidental-revert guard). Render Go's guidance with a copy-pasteable
        // command and exit non-zero — nothing was changed on the node.
        Response::RevertGuard { reverts } => {
            eprint!("{}", format_revert_guard(&reverts));
            std::process::exit(1);
        }
        // `version` is fully handled inline above (it early-returns before this match, whether or not
        // `--daemon` was passed), so a `Response::Version` never reaches here. This arm exists only
        // for match exhaustiveness; treat a stray one defensively rather than panicking.
        Response::Version { version } => println!("{version}"),
        // `get` is likewise handled inline above (early return); this arm is only for exhaustiveness.
        // Render the all-prefs table defensively if one ever reaches here.
        Response::Prefs(view) => print!("{}", format_get(&view, None, false).unwrap_or_default()),
        // `switch --list` is handled inline above; this arm is exhaustiveness-only.
        Response::Profiles { profiles } => print!("{}", format_profiles(&profiles)),
        // `metrics`/`lock status` are handled inline above; these arms are exhaustiveness-only.
        Response::Metrics { text } => print!("{text}"),
        Response::Lock(report) => print!("{}", format_lock_status(&report, false)),
        // `serve` is handled inline above (read-modify-write); this arm is exhaustiveness-only.
        Response::ServeConfig(cfg) => print!("{}", format_serve_status(&cfg, false)),
        // `bugreport`: print the local marker + a one-line honesty note (no logs were uploaded).
        Response::BugReport { marker } => {
            println!("{marker}");
            eprintln!(
                "(local diagnostic marker — this client uploads no logs; quote it when reporting an issue)"
            );
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
    }
    Ok(())
}

/// Print `tnet version` output (thin wrapper over [`format_version`], which is pure + unit-tested).
fn print_version(client: &str, daemon: Option<&str>, json: bool) {
    print!("{}", format_version(client, daemon, json));
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
    if !r.enabled {
        return "Tailnet Lock is NOT enabled on this tailnet.\n".to_string();
    }
    let mut out = String::from("Tailnet Lock is ENABLED.\n");
    if !r.head.is_empty() {
        out.push_str(&format!("  authority head: {}\n", r.head));
    }
    if r.disabled {
        out.push_str("  status: a disablement is pending (control signalled disable).\n");
    }
    out
}

/// Render `tnet exit-node list`: one line per peer offering to be an exit node (IP, hostname, and
/// online state when known), or a placeholder when none. Country/City columns (Go) are omitted —
/// this fork has no control-supplied Location data. Pure → unit-testable.
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
        out.push_str(&format!("{:<16} {}{}\n", p.ipv4, p.name, online));
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
fn get_settings(
    view: &tailscaled_rs::localapi::PrefsView,
) -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::Value;
    vec![
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
        // NAME  VALUE table, column-aligned to the widest name.
        let width = settings.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
        let mut out = String::new();
        for (name, value) in &settings {
            out.push_str(&format!("{name:<width$}  {}\n", get_value_display(value)));
        }
        Ok(out)
    }
}

/// Render `tnet version` output. `client` is this CLI's crate version; `daemon` is the daemon's
/// version when `--daemon` was passed (else `None`). `json` selects the JSON object form. Mirrors Go
/// `tailscale version`: plain prints the bare client version (and a `Client:`/`Daemon:` pair when the
/// daemon was queried); `--json` emits `{ "client": "..", "daemon": ".." }` with `daemon` present
/// only when queried. Pure (returns the string, trailing newline included) so it is unit-testable.
fn format_version(client: &str, daemon: Option<&str>, json: bool) -> String {
    if json {
        // Built via serde so escaping is correct (version strings are tame today, but this removes
        // the latent hand-built-JSON hazard and keeps the two `--json` renderers consistent).
        // `daemon` key present only when queried.
        let mut map = serde_json::Map::new();
        map.insert("client".to_string(), client.into());
        if let Some(d) = daemon {
            map.insert("daemon".to_string(), d.into());
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

/// Sanitize a control-plane-supplied string before printing it to the terminal.
///
/// The registration-failure `reason` (and, defensively, any other server-supplied text) originates
/// from the control server, which the daemon treats as only semi-trusted. Printing it verbatim would
/// let a malicious or compromised control server smuggle ANSI/terminal escape sequences (cursor
/// moves, color, clear-screen, even hyperlink/OSC injection) into the operator's terminal. We strip
/// every C0/C1 control character except plain whitespace (`\t`, `\n`, `\r`) so the reason renders as
/// inert text. This is display hardening only — the wire value is unchanged.
fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\t' || c == '\n' || c == '\r' {
                c
            } else if c.is_control() {
                // C0 (incl. ESC 0x1B) and C1 controls → a visible placeholder, never the raw byte.
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// Format the `tnet ip` output: this node's tailnet addresses, one per line (IPv4 then IPv6), or a
/// placeholder when the node has no address yet (no netmap received). Pure (returns the string,
/// including its trailing newline) so the formatting is unit-testable; the caller `print!`s it.
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

/// Format the `tnet whois` output for a [`WhoisReport`]. If the IP matched no node, a single
/// "no tailnet node owns <ip>" line (the caller passes the queried IP). Otherwise: the owning node's
/// name, its IPv4, the owning user (when control retained it), and any control-granted capabilities,
/// each on its own line. The node name is control-supplied, so it is passed through
/// [`sanitize_for_terminal`] before rendering. Pure (returns the string, trailing newline included)
/// so it is unit-testable; the caller `print!`s it.
fn format_whois(w: &tailscaled_rs::localapi::WhoisReport, ip: &str) -> String {
    if !w.found {
        return format!("no tailnet node owns {ip}\n");
    }
    let mut out = String::new();
    if let Some(name) = w.node_name.as_deref() {
        out.push_str(&format!("node:         {}\n", sanitize_for_terminal(name)));
    }
    if let Some(v4) = w.node_ipv4.as_deref() {
        out.push_str(&format!("ipv4:         {v4}\n"));
    }
    if let Some(user) = w.user.as_deref() {
        // `user` originates from control too; sanitize it before printing.
        out.push_str(&format!("user:         {}\n", sanitize_for_terminal(user)));
    }
    if !w.capabilities.is_empty() {
        out.push_str("capabilities:\n");
        for cap in &w.capabilities {
            // Capability names come from control; sanitize each before printing.
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(cap)));
        }
    }
    out
}

/// Render a [`StatusReport`] to stdout (the shared one-shot + watch formatter).
fn print_status(s: &tailscaled_rs::localapi::StatusReport) {
    println!("state:        {}", s.state);
    println!("want_running: {}", s.want_running);
    println!(
        "self:         {} {}",
        s.self_name.as_deref().unwrap_or("(unknown)"),
        s.self_ipv4.as_deref().unwrap_or("-")
    );
    // Configured posture (the node's persisted prefs), so `tnet status` shows what `up`/`set` left
    // in effect — the analogue of the config Go's `tailscale status` reflects. Each line is printed
    // only when it carries non-default information, to keep a plain node's status uncluttered.
    let p = &s.prefs;
    if let Some(en) = p.exit_node.as_deref() {
        println!("exit-node:    {en}");
    }
    if p.advertise_exit_node {
        println!("advertising:  exit-node");
    }
    if !p.advertise_routes.is_empty() {
        println!("adv-routes:   {}", p.advertise_routes.join(", "));
    }
    if p.accept_routes {
        println!("accept-routes: on");
    }
    if p.ssh {
        // Distinguish the *enabled* pref from the server actually *running*. The task can die at
        // bind time (no tailnet IPv4, `listen_ssh` error) while the pref stays on, so flag that
        // honestly rather than imply SSH is serving. Only warn when the node is in a state where the
        // server is expected to be up (Running/Starting) — a deliberately-down node has no task
        // (`ssh_running: false`) and must not be reported as a broken SSH server.
        let node_should_serve = s.state == "Running" || s.state == "Starting";
        if node_should_serve && !p.ssh_running {
            println!("ssh-server:   on (NOT RUNNING — check logs)");
        } else {
            println!("ssh-server:   on");
        }
    }
    if p.tun {
        println!("tun:          on");
    }
    // Interactive login: when the node is waiting for a human to authorize it, the daemon surfaces
    // the control auth URL — make it prominent so the operator can click it.
    if let Some(url) = s.auth_url.as_deref() {
        println!();
        println!("To authenticate this node, visit:");
        println!("    {url}");
    }
    // Terminal registration failure: distinct from `auth_url`, this means registration hard-failed
    // and the engine will not retry. Re-running with the same key loops forever, so spell out that
    // the operator must re-authenticate with a fresh key.
    if let Some(reason) = s.error.as_deref() {
        println!();
        println!("registration failed: {}", sanitize_for_terminal(reason));
        println!(
            "(this is a permanent failure — re-run `tnet up --authkey <NEW_KEY>` with a fresh \
             key; the same key will keep failing)"
        );
    }
    println!("peers:        {}", s.peers.len());
    for p in &s.peers {
        println!(
            "  - {:<28} {:<16}{}",
            p.name,
            p.ipv4,
            if p.is_exit_node { "  [exit]" } else { "" }
        );
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

    // Self: a PeerStatus subset from the self_* fields.
    let self_node = if s.self_ipv4.is_some() || s.self_name.is_some() {
        let mut m = Map::new();
        if let Some(name) = &s.self_name {
            m.insert("HostName".into(), json!(name));
            m.insert("DNSName".into(), json!(name));
        }
        m.insert(
            "TailscaleIPs".into(),
            json!(s.self_ipv4.iter().collect::<Vec<_>>()),
        );
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
        pm.insert("TailscaleIPs".into(), json!([p.ipv4]));
        pm.insert("ExitNodeOption".into(), json!(p.is_exit_node));
        if let Some(online) = p.online {
            pm.insert("Online".into(), json!(online));
        }
        peers.insert(key, Value::Object(pm));
    }

    let mut root = Map::new();
    root.insert("BackendState".into(), json!(s.state));
    // AuthURL: Go emits the field always (empty when none); mirror that.
    root.insert("AuthURL".into(), json!(s.auth_url.as_deref().unwrap_or("")));
    root.insert(
        "TailscaleIPs".into(),
        json!(s.self_ipv4.iter().collect::<Vec<_>>()),
    );
    root.insert("Self".into(), self_node);
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
/// Go `tailscale wait`'s exit-code contract: success on Running, a non-zero exit (here an `Err`) on
/// timeout. `timeout_secs` of `None`/`Some(0)` waits forever; otherwise it bounds the wait.
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
        // Go's backoff loop while tailscaled comes up. Only the timeout ends the wait unsuccessfully.
        if let Ok(Response::Status(s)) = round_trip(socket, &Request::Status).await
            && s.state == "Running"
            && s.self_ipv4.is_some()
        {
            return Ok(());
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
    let response = serde_json::from_str(response_line.trim())
        .with_context(|| format!("parsing daemon response: {response_line:?}"))?;
    Ok(response)
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
fn existing_as_mounts(
    h: &tailscaled_rs::localapi::TcpPortHandler,
) -> std::collections::BTreeMap<String, tailscaled_rs::localapi::WebMount> {
    use tailscaled_rs::localapi::WebMount;
    if !h.mounts.is_empty() {
        return h.mounts.clone();
    }
    let mut mounts = std::collections::BTreeMap::new();
    if let Some(body) = &h.text {
        mounts.insert("/".to_string(), WebMount::Text { body: body.clone() });
    } else if let Some(r) = &h.redirect {
        mounts.insert(
            "/".to_string(),
            WebMount::Redirect {
                to: r.to.clone(),
                status: r.status,
            },
        );
    } else if (h.https || h.http) && !h.tcp_forward.is_empty() {
        mounts.insert(
            "/".to_string(),
            WebMount::Proxy {
                to: h.tcp_forward.clone(),
            },
        );
    }
    mounts
}

fn build_web_serve(
    mut cfg: tailscaled_rs::localapi::ServeConfig,
    port: u16,
    target: &str,
    set_path: Option<&str>,
    tls: bool,
) -> Result<tailscaled_rs::localapi::ServeConfig> {
    use tailscaled_rs::localapi::{TcpPortHandler, WebMount};

    // Resolve `--set-path` to a cleaned mount; None / "/" mean the root (bare handler, no mux).
    let mount = match set_path {
        None | Some("") | Some("/") => None,
        Some(m) => Some(clean_url_path(m)?),
    };

    // Parse the target: `text:<body>` → a text handler; anything else → a proxy backend.
    let is_text = target.strip_prefix("text:");
    if let Some(body) = is_text
        && body.is_empty()
    {
        anyhow::bail!("unable to serve; text cannot be an empty string");
    }

    let mut handler = TcpPortHandler {
        https: tls,
        http: !tls,
        ..Default::default()
    };

    // The new handler's web target, as a mount entry (used when this serve participates in a mux).
    let entry = match is_text {
        Some(body) => WebMount::Text {
            body: body.to_string(),
        },
        None => WebMount::Proxy {
            to: normalize_serve_target(target),
        },
    };

    // Carry over an existing handler on this port so root + path mounts ACCRETE rather than clobber
    // (Go `SetWebHandler` keeps both on the port's `WebServerConfig.Handlers`). Any existing bare
    // root handler (text / https-http proxy) is migrated into a `/` mount so it survives alongside a
    // new `--set-path` mount, and vice-versa.
    let existing_mounts = cfg.tcp.get(&port.to_string()).map(existing_as_mounts);

    match mount {
        // Non-root mount: merge into the port's existing mounts (migrating any bare root to `/`).
        Some(m) => {
            handler.mounts = existing_mounts.unwrap_or_default();
            handler.mounts.insert(m, entry);
        }
        // Root mount: if the port already has mounts, fold this in as the `/` mount (stay a mux);
        // otherwise it's a plain bare handler on the port.
        None => match existing_mounts {
            Some(mut mounts) if !mounts.is_empty() => {
                mounts.insert("/".to_string(), entry);
                handler.mounts = mounts;
            }
            _ => match is_text {
                Some(body) => handler.text = Some(body.to_string()),
                None => handler.tcp_forward = normalize_serve_target(target),
            },
        },
    }

    cfg.tcp.insert(port.to_string(), handler);
    Ok(cfg)
}

/// Drive `tnet serve <sub>`: `tcp`/`https`/`http`/`redirect` and `reset` read-modify-write the
/// ServeConfig (GET → mutate → SET); `status` GETs + renders. The ServeConfig is replaced wholesale on
/// SET (matching Go's SetServeConfig), so each set first fetches the current config and adds its entry.
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
            let cfg = get_cfg().await?;
            let cfg = build_web_serve(cfg, port, &target, set_path.as_deref(), true)?;
            send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
            println!(
                "serving https://<node>:{port}{} -> {target}",
                mount_suffix(&set_path)
            );
            Ok(())
        }
        ServeCmd::Http {
            port,
            target,
            set_path,
        } => {
            let cfg = get_cfg().await?;
            let cfg = build_web_serve(cfg, port, &target, set_path.as_deref(), false)?;
            send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
            println!(
                "serving http://<node>:{port}{} -> {target}",
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
            let mut cfg = get_cfg().await?;
            cfg.tcp.insert(
                port.to_string(),
                tailscaled_rs::localapi::TcpPortHandler {
                    https: true,
                    redirect: Some(tailscaled_rs::localapi::RedirectSpec {
                        to: to.clone(),
                        status,
                    }),
                    ..Default::default()
                },
            );
            send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
            println!("serving https://<node>:{port} -> redirect {status} -> {to}");
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

/// Render `tnet serve status` from a [`ServeConfig`](tailscaled_rs::localapi::ServeConfig). Lists each
/// served entry: plain TCP forwards (the daemon's own accept loop) and HTTPS/HTTP web entries (proxy /
/// text / redirect / path-mux, served by engine delegation). A `TerminateTLS` raw-TCP entry has no
/// engine analogue at this pin and is flagged "not served by this build". `_json` is handled by the
/// caller. Pure → unit-testable.
fn format_serve_status(cfg: &tailscaled_rs::localapi::ServeConfig, _json: bool) -> String {
    use tailscaled_rs::localapi::WebMount;
    if cfg.tcp.is_empty() {
        return "No serve config.\n".to_string();
    }
    let mut out = String::new();
    for (port, h) in &cfg.tcp {
        let scheme = if h.http { "http" } else { "https" };
        // Web entries (served via engine delegation) first, richest kind first, so a web entry never
        // falls through to the bare-flag "not served" branch.
        if !h.mounts.is_empty() {
            // Path-mux: one line per mount (sorted by the BTreeMap key).
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
        } else if !h.terminate_tls.is_empty() {
            out.push_str(&format!(
                "tcp :{port} -> {} (TLS-terminated; NOT served by this build)\n",
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
            out.push_str(&format!("  https://{host}:{port}\n"));
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
            self_ipv4: None,
            self_name: None,
            auth_url: None,
            error: None,
            prefs: Default::default(),
            peers: vec![],
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
    fn command_set_maps_to_request_set_fields() {
        // A representative invocation: rename + set an exit node + accept routes, leaving the
        // advertise-* prefs untouched. Built from the same resolver helpers the `Command::Set` arm
        // in `main` uses, so the wire mapping is covered without spawning the CLI. The unset prefs
        // must map to `None` (unchanged), not a silent clear.
        let req = Request::Set {
            hostname: Some("laptop".to_string()),
            accept_routes: resolve_accept_routes(true, false),
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
                exit_node,
                advertise_exit_node,
                advertise_routes,
                advertise_tags: _,
                ssh,
            } => {
                assert_eq!(hostname, Some("laptop".to_string()));
                assert_eq!(accept_routes, Some(true));
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
            ssh: None,
            reset: false,
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
            ssh: None,
            reset: false,
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
            ssh: None,
            reset: false,
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
    fn command_set_maps_clears_distinctly_from_unset() {
        // The "clear" flags must produce the present-but-empty sentinels (`Some(None)` /
        // `Some(vec![])`), distinct from the absent (`None`) case above — that's the whole reason
        // the clear flags exist. Built via the same resolvers as `main`'s `Command::Set` arm.
        let req = Request::Set {
            hostname: None,
            accept_routes: resolve_accept_routes(false, true),
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
                exit_node,
                advertise_exit_node,
                advertise_routes,
                advertise_tags: _,
                ssh,
            } => {
                assert_eq!(hostname, None);
                assert_eq!(accept_routes, Some(false));
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
        // The three `tnet file` subcommands each select the right wire `Request`. Built the same way
        // `main`'s `Command::File` arm builds them, so the dispatch mapping is covered without
        // spawning the CLI. `cp`/`get` are writes (reply `Ok`); `list` is read-only (reply `Files`).
        let cp = match (FileCmd::Cp {
            path: "/tmp/a.txt".to_string(),
            peer: "peer-b".to_string(),
        }) {
            FileCmd::Cp { path, peer } => Request::FileCp { path, peer },
            _ => unreachable!(),
        };
        match cp {
            Request::FileCp { path, peer } => {
                assert_eq!(path, "/tmp/a.txt");
                assert_eq!(peer, "peer-b");
            }
            other => panic!("expected Request::FileCp, got {other:?}"),
        }

        let list = match FileCmd::List {
            FileCmd::List => Request::FileList,
            _ => unreachable!(),
        };
        match list {
            Request::FileList => {}
            other => panic!("expected Request::FileList, got {other:?}"),
        }

        // `--delete-after` threads straight through to the wire field; omitting it sends `false`.
        let get = match (FileCmd::Get {
            name: "report.pdf".to_string(),
            dest: "/tmp/out.pdf".to_string(),
            delete_after: true,
        }) {
            FileCmd::Get {
                name,
                dest,
                delete_after,
            } => Request::FileGet {
                name,
                dest,
                delete_after,
            },
            _ => unreachable!(),
        };
        match get {
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
        };
        let out = format_whois(&w, "100.64.0.2");
        assert!(out.contains("peer-b.example.ts.net"), "node name present");
        assert!(out.contains("100.64.0.2"), "node ipv4 present");
        assert!(out.contains("alice@example.com"), "user present when Some");
        assert!(
            out.contains("https://tailscale.com/cap/is-admin") && out.contains("funnel"),
            "every capability present"
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
        };
        let out = format_whois(&w, "100.64.0.2");
        assert!(out.contains("peer-b"));
        assert!(out.contains("100.64.0.2"));
        assert!(!out.contains("user:"), "no user line when user is None");
        assert!(
            !out.contains("capabilities:"),
            "no capabilities header when the set is empty"
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
        };
        let out = format_whois(&w, "100.64.0.2");
        assert!(!out.contains('\x1b'), "ESC must be stripped from node name");
        assert!(!out.contains('\x07'), "BEL must be stripped from node name");
        // The readable parts survive (just the control bytes become the replacement char).
        assert!(out.contains("evil"));
        assert!(out.contains("name"));
    }

    #[test]
    fn sanitize_strips_terminal_escapes_keeps_plain_text() {
        // A control-supplied failure reason is only semi-trusted; before we print it, ANSI/terminal
        // escapes must be neutralized so a malicious control server can't drive the operator's
        // terminal. Plain text + ordinary whitespace survive unchanged.
        let evil = "auth rejected\x1b[2J\x1b[31mFAKE PROMPT\x07 token=\x00secret";
        let clean = sanitize_for_terminal(evil);
        assert!(
            !clean.contains('\x1b'),
            "ESC must be stripped, got {clean:?}"
        );
        assert!(!clean.contains('\x07'), "BEL must be stripped");
        assert!(!clean.contains('\x00'), "NUL must be stripped");
        // The readable words are preserved (just the control bytes become the replacement char).
        assert!(clean.contains("auth rejected"));
        assert!(clean.contains("token="));

        // Ordinary text and whitespace pass through verbatim.
        let benign = "authentication rejected by control: key not found\n\tretry later";
        assert_eq!(
            sanitize_for_terminal(benign),
            benign,
            "plain text + tab/newline must be unchanged"
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
        assert_eq!(revert_pref_to_flag("tun", "true"), "--tun");
        // Defensive: a false bool renders the disabling flag (shouldn't occur from the guard).
        assert_eq!(revert_pref_to_flag("ssh", "false"), "--no-ssh");
        // Unknown key (daemon newer than CLI): still actionable, not dropped.
        assert_eq!(revert_pref_to_flag("future_pref", "x"), "--future_pref=x");
    }

    #[test]
    fn format_version_shapes() {
        // Plain, no daemon → bare client version line (Go's first line).
        assert_eq!(format_version("0.9.0", None, false), "0.9.0\n");
        // Plain, with daemon → Client:/Daemon: pair (Go's --daemon form).
        assert_eq!(
            format_version("0.9.0", Some("0.9.0"), false),
            "Client: 0.9.0\nDaemon: 0.9.0\n"
        );
        // JSON, no daemon → object with only client.
        let j = format_version("0.9.0", None, true);
        assert!(j.contains("\"client\": \"0.9.0\""), "{j}");
        assert!(!j.contains("daemon"), "no daemon key without --daemon: {j}");
        // JSON, with daemon → object with both; valid-enough to parse the two fields.
        let jd = format_version("0.9.0", Some("0.8.0"), true);
        assert!(jd.contains("\"client\": \"0.9.0\""), "{jd}");
        assert!(jd.contains("\"daemon\": \"0.8.0\""), "{jd}");
    }

    #[test]
    fn format_get_shapes() {
        use tailscaled_rs::localapi::PrefsView;
        let view = PrefsView {
            exit_node: Some("100.64.0.9".into()),
            advertise_exit_node: false,
            advertise_routes: vec!["10.0.0.0/8".into(), "192.168.1.0/24".into()],
            advertise_tags: vec![],
            accept_routes: true,
            ssh: true,
            ssh_running: true,
            tun: false,
        };

        // Default table: one NAME VALUE line per setting, all settings present.
        let table = format_get(&view, None, false).unwrap();
        assert!(table.contains("accept-routes"), "{table}");
        assert!(table.contains("true"), "{table}");
        assert!(
            table.contains("advertise-routes") && table.contains("10.0.0.0/8,192.168.1.0/24"),
            "{table}"
        );
        assert!(table.contains("advertise-tags"), "{table}");
        // 7 settings → 7 lines (exit-node, advertise-exit-node, advertise-routes, advertise-tags,
        // accept-routes, ssh, tun).
        assert_eq!(table.lines().count(), 7, "{table}");

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
        // Not enabled.
        let off = LockReport::default();
        assert!(format_lock_status(&off, false).contains("NOT enabled"));
        // Enabled with a head + pending disablement.
        let on = LockReport {
            enabled: true,
            head: "tka-aumhash-abc".into(),
            disabled: true,
        };
        let h = format_lock_status(&on, false);
        assert!(h.contains("ENABLED"), "{h}");
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
        // Empty → placeholder.
        assert!(format_serve_status(&ServeConfig::default(), false).contains("No serve config"));

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
        // TLS-terminated raw TCP — no engine analogue, not served.
        cfg.tcp.insert(
            "9000".to_string(),
            TcpPortHandler {
                tcp_forward: "127.0.0.1:9".into(),
                terminate_tls: "host.ts.net".into(),
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
        // TLS-terminated raw TCP is flagged as not served by this build.
        assert!(
            out.contains("9000") && out.contains("TLS-terminated"),
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

    #[test]
    fn build_web_serve_text_and_proxy_root() {
        use tailscaled_rs::localapi::ServeConfig;
        // text: target → text handler, no proxy backend.
        let cfg =
            build_web_serve(ServeConfig::default(), 443, "text:hi there", None, true).unwrap();
        let h = cfg.tcp.get("443").unwrap();
        assert_eq!(h.text.as_deref(), Some("hi there"));
        assert!(h.tcp_forward.is_empty());
        assert!(h.https);

        // proxy target (bare port normalized) at root → tcp_forward backend.
        let cfg = build_web_serve(ServeConfig::default(), 443, "3000", None, true).unwrap();
        let h = cfg.tcp.get("443").unwrap();
        assert_eq!(h.tcp_forward, "127.0.0.1:3000");
        assert!(h.text.is_none());

        // empty text body is rejected (Go parity).
        assert!(build_web_serve(ServeConfig::default(), 443, "text:", None, true).is_err());
    }

    #[test]
    fn build_web_serve_set_path_mounts_accumulate() {
        use tailscaled_rs::localapi::{ServeConfig, WebMount};
        // First mount at /api.
        let cfg = build_web_serve(ServeConfig::default(), 443, "3000", Some("/api"), true).unwrap();
        // Second mount at /web on the same port — must accumulate, not clobber.
        let cfg = build_web_serve(cfg, 443, "text:hello", Some("/web"), true).unwrap();
        let h = cfg.tcp.get("443").unwrap();
        assert_eq!(h.mounts.len(), 2, "mounts should accumulate");
        assert_eq!(
            h.mounts.get("/api"),
            Some(&WebMount::Proxy {
                to: "127.0.0.1:3000".into()
            })
        );
        assert_eq!(
            h.mounts.get("/web"),
            Some(&WebMount::Text {
                body: "hello".into()
            })
        );
    }

    #[test]
    fn build_web_serve_bare_root_then_mount_accretes() {
        use tailscaled_rs::localapi::{ServeConfig, WebMount};
        // A bare root proxy, then a --set-path mount on the SAME port: the root must survive as the
        // "/" mount (Go SetWebHandler accretes — it must NOT be clobbered).
        let cfg = build_web_serve(ServeConfig::default(), 443, "3000", None, true).unwrap();
        let cfg = build_web_serve(cfg, 443, "text:hi", Some("/api"), true).unwrap();
        let h = cfg.tcp.get("443").unwrap();
        assert_eq!(h.mounts.len(), 2, "root + /api should coexist");
        assert_eq!(
            h.mounts.get("/"),
            Some(&WebMount::Proxy {
                to: "127.0.0.1:3000".into()
            }),
            "the bare root proxy migrated into the / mount"
        );
        assert_eq!(
            h.mounts.get("/api"),
            Some(&WebMount::Text { body: "hi".into() })
        );
        // The bare fields are cleared once it becomes a mux (the mounts are the source of truth).
        assert!(h.tcp_forward.is_empty());
        assert!(h.text.is_none());
    }

    #[test]
    fn build_web_serve_mount_then_bare_root_accretes() {
        use tailscaled_rs::localapi::{ServeConfig, WebMount};
        // The reverse: a --set-path mount, then a bare root serve on the same port. The root folds in
        // as the "/" mount rather than wiping the existing mount.
        let cfg = build_web_serve(ServeConfig::default(), 443, "3000", Some("/api"), true).unwrap();
        let cfg = build_web_serve(cfg, 443, "9000", None, true).unwrap();
        let h = cfg.tcp.get("443").unwrap();
        assert_eq!(h.mounts.len(), 2, "/api + new root should coexist");
        assert_eq!(
            h.mounts.get("/api"),
            Some(&WebMount::Proxy {
                to: "127.0.0.1:3000".into()
            })
        );
        assert_eq!(
            h.mounts.get("/"),
            Some(&WebMount::Proxy {
                to: "127.0.0.1:9000".into()
            })
        );
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
            peers: vec![
                PeerReport {
                    name: "online-peer".to_string(),
                    ipv4: "100.64.0.2".to_string(),
                    is_exit_node: false,
                    stable_id: "n1".to_string(),
                    online: Some(true),
                },
                PeerReport {
                    name: "offline-peer".to_string(),
                    ipv4: "100.64.0.3".to_string(),
                    is_exit_node: false,
                    stable_id: "n2".to_string(),
                    online: Some(false),
                },
                PeerReport {
                    name: "unknown-peer".to_string(),
                    ipv4: "100.64.0.4".to_string(),
                    is_exit_node: false,
                    stable_id: "n3".to_string(),
                    online: None,
                },
            ],
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
            peers: vec![
                PeerReport {
                    name: "peer-b".to_string(),
                    ipv4: "100.64.0.2".to_string(),
                    is_exit_node: true,
                    stable_id: "nABC123".to_string(),
                    online: Some(true),
                },
                PeerReport {
                    name: "peer-c".to_string(),
                    ipv4: "100.64.0.3".to_string(),
                    is_exit_node: false,
                    stable_id: String::new(), // missing id → keyed by name (fallback)
                    online: None,
                },
            ],
        };
        let out = format_status_json(&report).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&out).expect("status --json must be valid JSON");

        // Go key names + the exact BackendState string.
        assert_eq!(v["BackendState"], serde_json::json!("Running"));
        assert_eq!(v["AuthURL"], serde_json::json!("")); // always present, empty when none
        assert_eq!(v["TailscaleIPs"], serde_json::json!(["100.70.22.12"]));
        // Self subset.
        assert_eq!(v["Self"]["HostName"], serde_json::json!("node-a"));
        assert_eq!(
            v["Self"]["TailscaleIPs"],
            serde_json::json!(["100.70.22.12"])
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
        assert_eq!(v["Peer"]["peer-c"]["HostName"], serde_json::json!("peer-c"));
        // The id-less peer has no Online key (None → skipped).
        assert!(v["Peer"]["peer-c"].get("Online").is_none());
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
    fn version_command_client_matches_crate_version() {
        // The client version `tnet version` prints is the crate version — guards against drift if the
        // print path ever stops using CARGO_PKG_VERSION.
        assert_eq!(
            format_version(env!("CARGO_PKG_VERSION"), None, false),
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
}
