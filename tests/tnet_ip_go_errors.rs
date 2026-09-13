//! `tnet ip` must fail where `tailscale ip` fails, with Go's text and nothing added to it.
//!
//! Upstream is `cmd/tailscale/cli/ip.go` (`runIP`) and `cmd/tailscale/tailscale.go` (`main`) @
//! `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8` (v1.102.4). Two behaviours are pinned here:
//!
//! 1. Once `runIP` has resolved the address list — this node's, a peer's or a Service's — it returns
//!    `no current Tailscale IPs; state: %v` when that list is empty, before `-1` and the family
//!    filter run. That is an error: stderr and exit 1, not a placeholder on stdout and exit 0.
//! 2. Go's `main` prints a returned error with `fmt.Fprintln(os.Stderr, err)` and exits 1, so stderr
//!    is exactly the error text. An `Error: ` prefix breaks a script matching on it.
//!
//! The unit tests next to `format_ip_filtered` (src/bin/tnet.rs) pin the decisions. What they cannot
//! see is the process: its exit status, the exact stderr bytes, and which requests reached the
//! daemon. Each test here runs the built `tnet` against a stub daemon on a Unix socket.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tailscaled_rs::localapi::{PeerReport, Request, Response, StatusReport};

/// Per-process-unique counter so tests running in parallel never share a socket path.
static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// A stub daemon: it answers a fixed queue of replies, one per connection (the CLI opens a fresh
/// connection per request), and records every request it was sent.
struct StubDaemon {
    socket: PathBuf,
    seen: Arc<Mutex<Vec<Request>>>,
}

impl StubDaemon {
    /// Start the stub, serving `replies` in order on a socket of its own.
    fn start(replies: Vec<Response>) -> StubDaemon {
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let socket = std::env::temp_dir().join(format!("tnet-ip-{}-{n}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("bind the stub daemon socket");
        let seen = Arc::new(Mutex::new(Vec::new()));

        let thread_seen = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut replies = replies.into_iter();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut line = String::new();
                if BufReader::new(stream.try_clone().expect("clone the accepted stub stream"))
                    .read_line(&mut line)
                    .is_err()
                {
                    break;
                }
                if let Ok(req) = serde_json::from_str::<Request>(line.trim()) {
                    thread_seen.lock().expect("stub request log").push(req);
                }
                let reply = replies.next().unwrap_or(Response::Error {
                    message: "stub daemon: no reply queued for this request".into(),
                });
                let mut body = serde_json::to_vec(&reply).expect("serialize the stub reply");
                body.push(b'\n');
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });

        StubDaemon { socket, seen }
    }

    /// Run the built `tnet` against this stub.
    fn tnet(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tnet"))
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .output()
            .expect("the `tnet` binary built for this test should run")
    }

    /// The requests the stub was sent, in order.
    fn requests(&self) -> Vec<Request> {
        self.seen.lock().expect("stub request log").clone()
    }
}

impl Drop for StubDaemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn status(state: &str, peers: Vec<PeerReport>) -> Response {
    Response::Status(StatusReport {
        state: state.into(),
        peers,
        ..Default::default()
    })
}

/// `tnet ip -6` on an IPv4-only node: Go's stderr is exactly `no Tailscale IPv6 address`, with no
/// `Error: ` in front of it, and the exit status is 1.
#[test]
fn a_missing_family_is_reported_as_gos_bare_text() {
    let daemon = StubDaemon::start(vec![Response::Ip {
        ipv4: Some("100.64.0.1".into()),
        ipv6: None,
    }]);
    let out = daemon.tnet(&["ip", "-6"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(stderr(&out), "no Tailscale IPv6 address\n");
    assert_eq!(stdout(&out), "");
}

/// A node with no address yet is refused with its backend state, whatever selector was given: Go
/// checks the empty list before `-1` and before the family filter.
#[test]
fn a_node_with_no_address_is_refused_with_its_backend_state() {
    for args in [&["ip"][..], &["ip", "-4"], &["ip", "-6"], &["ip", "-1"]] {
        let daemon = StubDaemon::start(vec![
            Response::Ip {
                ipv4: None,
                ipv6: None,
            },
            status("NeedsLogin", vec![]),
        ]);
        let out = daemon.tnet(args);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{args:?}: stdout {:?}",
            stdout(&out)
        );
        assert_eq!(
            stderr(&out),
            "no current Tailscale IPs; state: NeedsLogin\n",
            "{args:?}"
        );
        assert_eq!(stdout(&out), "", "{args:?}");
    }
}

/// A named peer with no address gets the same refusal, and its state comes from the one `Status`
/// the peer lookup already read.
#[test]
fn an_addressless_peer_is_refused_from_the_status_already_read() {
    let peer = PeerReport {
        name: "addressless.tail0123.ts.net".into(),
        stable_id: "n2".into(),
        ..Default::default()
    };
    let daemon = StubDaemon::start(vec![status("Starting", vec![peer])]);
    let out = daemon.tnet(&["ip", "addressless.tail0123.ts.net"]);
    assert_eq!(out.status.code(), Some(1), "stdout {:?}", stdout(&out));
    assert_eq!(stderr(&out), "no current Tailscale IPs; state: Starting\n");
    assert_eq!(stdout(&out), "");
    let requests = daemon.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert!(matches!(requests[0], Request::Status), "{requests:?}");
}

/// A node that holds an address prints it and never asks for `Status`: the state is fetched only
/// for the refusal that names it.
#[test]
fn a_node_with_an_address_needs_no_status_round_trip() {
    let daemon = StubDaemon::start(vec![Response::Ip {
        ipv4: Some("100.64.0.1".into()),
        ipv6: Some("fd7a:115c:a1e0::1".into()),
    }]);
    let out = daemon.tnet(&["ip"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "100.64.0.1\nfd7a:115c:a1e0::1\n");
    let requests = daemon.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert!(matches!(requests[0], Request::Ip), "{requests:?}");
}
