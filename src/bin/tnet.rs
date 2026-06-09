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
        /// node. Replaces the whole advertised set. Use `--advertise-routes-clear` to advertise
        /// none; passing neither leaves the persisted set unchanged.
        #[arg(long, value_name = "CIDR,...", value_delimiter = ',')]
        advertise_routes: Vec<String>,
        /// Stop advertising any subnet routes (clears the advertised set). Use this instead of an
        /// empty `--advertise-routes`, since clap can't distinguish "advertise none" from the flag
        /// being unset.
        #[arg(long)]
        advertise_routes_clear: bool,
    },
    /// Disconnect the node without logging out.
    Down,
    /// Show daemon and netmap status.
    Status {
        /// Stream status continuously, re-printing on every state transition, until interrupted
        /// (Ctrl-C). Like `tailscale status --watch`.
        #[arg(long)]
        watch: bool,
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
            }
        }
        Command::Down => Request::Down,
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
    };

    let response = round_trip(&socket, &request)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;

    match response {
        Response::Status(s) => print_status(&s),
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
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
    }
    Ok(())
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

/// Render a [`StatusReport`] to stdout (the shared one-shot + watch formatter).
fn print_status(s: &tailscaled_rs::localapi::StatusReport) {
    println!("state:        {}", s.state);
    println!("want_running: {}", s.want_running);
    println!(
        "self:         {} {}",
        s.self_name.as_deref().unwrap_or("(unknown)"),
        s.self_ipv4.as_deref().unwrap_or("-")
    );
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
            // The watch stream only carries Status frames; an Ok is unexpected but harmless.
            Response::Ok { message } => println!("ok: {message}"),
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
    use tailscaled_rs::localapi::StatusReport;

    /// Build a minimal `StatusReport` in the given state with no auth_url/error, no peers.
    fn report(state: &str) -> StatusReport {
        StatusReport {
            state: state.to_string(),
            want_running: true,
            self_ipv4: None,
            self_name: None,
            auth_url: None,
            error: None,
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
}
