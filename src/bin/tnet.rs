//! `tnet` — the thin CLI client.
//!
//! Carries no node logic: every command marshals a [`Request`] to the daemon's LocalAPI socket and
//! renders the [`Response`]. This mirrors how Tailscale's `tailscale` CLI is a thin front-end over
//! `tailscaled`'s LocalAPI.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use tailscaled_rs::localapi::{Request, Response};

#[derive(Parser)]
#[command(name = "tnet", about = "Control client for the tailnetd daemon")]
struct Cli {
    /// Path to the daemon's LocalAPI socket (defaults to the daemon's resolved path).
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bring the node up and connect to the tailnet.
    Up {
        /// Pre-auth key for non-interactive registration.
        #[arg(long)]
        authkey: Option<String>,
        /// Requested hostname.
        #[arg(long)]
        hostname: Option<String>,
        /// Control server URL override (captured but not yet applied in the MVP).
        #[arg(long)]
        control_url: Option<String>,
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

    let request = match cli.command {
        Command::Up {
            authkey,
            hostname,
            control_url,
        } => Request::Up {
            authkey,
            control_url,
            hostname,
        },
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
        Response::Ok { message } => println!("ok: {message}"),
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
    }
    Ok(())
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
