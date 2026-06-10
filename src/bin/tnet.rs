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
    },
    /// Show this node's tailnet IP addresses.
    Ip,
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
    },
    /// Send and receive files over Taildrop (Go `tailscale file`).
    File {
        #[command(subcommand)]
        cmd: FileCmd,
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
            // `--ssh`/`--no-ssh` tri-state (mirrors `--tun`).
            ssh: resolve_ssh(ssh, no_ssh),
        },
        Command::Down => Request::Down,
        Command::Logout => Request::Logout,
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
        // `status --watch` is a long-lived stream, not a one-shot round-trip — handle it here and
        // return. Plain `status` falls through to the one-shot path below.
        Command::Status { watch } => {
            if watch {
                return watch_status(&socket)
                    .await
                    .with_context(|| format!("watching status at {}", socket.display()));
            }
            Request::Status
        }
        Command::Ip => Request::Ip,
        Command::Whois { ip } => Request::Whois { ip },
        // `--timeout` (ms) maps straight to the wire's `timeout_ms`; omitting it sends `None`, which
        // the daemon reads as "use a sensible default".
        Command::Ping { ip, timeout } => Request::Ping {
            ip,
            timeout_ms: timeout,
        },
        // Taildrop. The nested subcommand picks which wire `Request` to send: `cp` and `get` are
        // writes (the daemon reads/consumes a file) and reply `Ok`; `list` is read-only and replies
        // `Files`.
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
        Response::Status(s) => print_status(&s),
        // This node's own tailnet addresses (`tnet ip`), one per line; a node with no address yet
        // (no netmap received) prints a clear placeholder rather than nothing.
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

/// The canonical `(set-flag name, value-string)` projection of a [`PrefsView`], in the stable order
/// `tnet get` displays. The names match the `tnet set`/`tnet up` flags (Go keys its `get` output by
/// the same set-flag names), and the value strings are what you'd pass back to `set` (a bare CIDR
/// list for routes, `true`/`false` for bools, the selector for exit-node, empty for an unset
/// optional). One source so the table, the `--json` map, and single-setting lookup all agree.
fn get_settings(view: &tailscaled_rs::localapi::PrefsView) -> Vec<(&'static str, String)> {
    vec![
        ("exit-node", view.exit_node.clone().unwrap_or_default()),
        ("advertise-exit-node", view.advertise_exit_node.to_string()),
        ("advertise-routes", view.advertise_routes.join(",")),
        ("accept-routes", view.accept_routes.to_string()),
        ("ssh", view.ssh.to_string()),
        ("tun", view.tun.to_string()),
    ]
}

/// Render `tnet get` output from a [`PrefsView`] (Go `tailscale get`). `setting` selects a single
/// setting by its set-flag name (`None` or `"all"` = every setting); `json` selects the flattened
/// `{ "name": "value" }` map form (matching Go `get --json`, which is a name→value map, NOT a raw
/// prefs-struct dump). Default (no json) is a `NAME  VALUE` table; a single named setting prints just
/// its raw value. Returns `Err` for an unknown setting name (Go errors too). Pure → unit-testable.
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
            format!("\"{value}\"\n")
        } else {
            format!("{value}\n")
        });
    }

    // All settings.
    if json {
        // Flattened name→value map, stable order, hand-built so the shape is dependency-free and
        // matches Go's name-keyed map (string values, like the set-flag args).
        let mut out = String::from("{\n");
        for (i, (name, value)) in settings.iter().enumerate() {
            let comma = if i + 1 < settings.len() { "," } else { "" };
            out.push_str(&format!("  \"{name}\": \"{value}\"{comma}\n"));
        }
        out.push_str("}\n");
        Ok(out)
    } else {
        // NAME  VALUE table, column-aligned to the widest name.
        let width = settings.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
        let mut out = String::new();
        for (name, value) in &settings {
            out.push_str(&format!("{name:<width$}  {value}\n"));
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
        // Hand-built so the shape is stable and dependency-free; `daemon` omitted unless queried.
        match daemon {
            Some(d) => format!("{{\n  \"client\": \"{client}\",\n  \"daemon\": \"{d}\"\n}}\n"),
            None => format!("{{\n  \"client\": \"{client}\"\n}}\n"),
        }
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
            ssh: resolve_ssh(false, false),
        };
        match req {
            Request::Set {
                hostname,
                accept_routes,
                exit_node,
                advertise_exit_node,
                advertise_routes,
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
            ssh: resolve_ssh(true, false),
        };
        match req {
            Request::Set {
                hostname,
                accept_routes,
                exit_node,
                advertise_exit_node,
                advertise_routes,
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
        // 6 settings → 6 lines.
        assert_eq!(table.lines().count(), 6, "{table}");

        // --json: flattened name→value map (string values), every setting keyed by set-flag name.
        let j = format_get(&view, None, true).unwrap();
        assert!(j.contains("\"accept-routes\": \"true\""), "{j}");
        assert!(j.contains("\"exit-node\": \"100.64.0.9\""), "{j}");
        assert!(
            j.trim_start().starts_with('{') && j.trim_end().ends_with('}'),
            "{j}"
        );

        // Single named setting → just its value.
        assert_eq!(
            format_get(&view, Some("accept-routes"), false).unwrap(),
            "true\n"
        );
        assert_eq!(
            format_get(&view, Some("advertise-routes"), false).unwrap(),
            "10.0.0.0/8,192.168.1.0/24\n"
        );
        // Single setting --json → quoted value.
        assert_eq!(format_get(&view, Some("ssh"), true).unwrap(), "\"true\"\n");

        // "all" behaves like None (all settings).
        assert_eq!(format_get(&view, Some("all"), false).unwrap(), table);

        // Unknown setting → error (Go errors too).
        assert!(format_get(&view, Some("no-such-setting"), false).is_err());
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
