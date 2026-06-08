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

use tailscaled_rs::localapi::{Request, Response};

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
    },
    /// Disconnect the node without logging out.
    Down,
    /// Show daemon and netmap status.
    Status,
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
                tun: match (tun, no_tun) {
                    (true, _) => Some(true),
                    (_, true) => Some(false),
                    _ => None,
                },
                tun_name,
                tun_mtu,
            }
        }
        Command::Down => Request::Down,
        Command::Status => Request::Status,
    };

    let response = round_trip(&socket, &request)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;

    match response {
        Response::Status(s) => {
            println!("state:        {}", s.state);
            println!("want_running: {}", s.want_running);
            println!(
                "self:         {} {}",
                s.self_name.as_deref().unwrap_or("(unknown)"),
                s.self_ipv4.as_deref().unwrap_or("-")
            );
            // Interactive login: when the node is waiting for a human to authorize it (an `up` with
            // no usable auth key), the daemon surfaces the control auth URL. Make it prominent so the
            // operator can click it; registration retries until they do.
            if let Some(url) = s.auth_url.as_deref() {
                println!();
                println!("To authenticate this node, visit:");
                println!("    {url}");
            }
            println!("peers:        {}", s.peers.len());
            for p in s.peers {
                println!(
                    "  - {:<28} {:<16}{}",
                    p.name,
                    p.ipv4,
                    if p.is_exit_node { "  [exit]" } else { "" }
                );
            }
        }
        Response::Ok { message } => {
            println!("ok: {message}");
            // Interactive login: an authkey-less `up` succeeds at the daemon, but the node now needs
            // a human to authorize it. The auth URL isn't known yet at `up`-time — it arrives once
            // the engine reaches `NeedsLogin` — so poll `status` briefly to surface it.
            if interactive_up && let Some(url) = poll_for_auth_url(&socket).await {
                println!();
                println!("To authenticate this node, visit:");
                println!("    {url}");
                println!();
                println!(
                    "(the node will finish connecting automatically once authorized; \
                          run `tnet status` to check)"
                );
            }
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
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

/// After an interactive (authkey-less) `up`, poll `status` for up to [`AUTH_URL_POLL`] to surface
/// the control auth URL. The engine reaches `NeedsLogin(url)` ~10s after registration begins, so we
/// wait a generous 20s; if the node authorizes instantly (pre-approved) or never needs login,
/// returns `None` and the operator can always re-run `tnet status`.
///
/// Prints a one-time "waiting…" line on the first poll so an interactive `up` doesn't look frozen
/// during the ~10s the engine needs.
async fn poll_for_auth_url(socket: &std::path::Path) -> Option<String> {
    let deadline = tokio::time::Instant::now() + AUTH_URL_POLL;
    let mut announced = false;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Response::Status(s)) = round_trip(socket, &Request::Status).await {
            if s.auth_url.is_some() {
                return s.auth_url;
            }
            // Already past NeedsLogin (authorized / running) — nothing to prompt.
            if s.state == "Running" {
                return None;
            }
        }
        if !announced {
            announced = true;
            // Softened wording: on a permanent registration failure the daemon currently maps to
            // NeedsLogin-without-URL, so this poll can run its full window without a URL ever
            // arriving. Don't promise a URL is coming; point the operator at `tnet status`.
            println!("contacting the control server… (run `tnet status` for the latest state)");
        }
        tokio::time::sleep(AUTH_URL_POLL_INTERVAL).await;
    }
    None
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
