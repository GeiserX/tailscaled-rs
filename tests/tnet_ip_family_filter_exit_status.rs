//! `tnet ip -4` / `tnet ip -6` must fail the way `tailscale ip` fails when the family is empty.
//!
//! Upstream is `cmd/tailscale/cli/ip.go` (`runIP`) @
//! `53a0d659afa51835dd7a9283873cca44261454f8`. Its match loop sets `match` only when it printed an
//! address, and the function ends:
//!
//! ```go
//! if !match {
//!     if ipArgs.want4 { return errors.New("no Tailscale IPv4 address") }
//!     if ipArgs.want6 { return errors.New("no Tailscale IPv6 address") }
//! }
//! return nil
//! ```
//!
//! Those are `errors.New` returns, not `outln` calls, and that is the point: the CLI turns a
//! returned error into a stderr line and a non-zero exit, so `tailscale ip -6 host` is a predicate a
//! script can test with `if`. A build that instead prints a placeholder on stdout and exits 0 tells
//! such a script the opposite of the truth — it reports success for a node holding no address in the
//! family that was asked for.
//!
//! The unit tests next to `format_ip_filtered` (src/bin/tnet.rs) pin WHICH state is an error. What
//! they cannot see is the surface the script hits: the process exit status, which stream the text
//! goes to, and whether stdout stayed empty. Each test here runs the built `tnet` against a stub
//! daemon on a Unix socket and inspects the process result.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tailscaled_rs::localapi::{Request, Response};

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
        let socket =
            std::env::temp_dir().join(format!("tnet-ipfam-{}-{n}.sock", std::process::id()));
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

/// This node's addresses, as the daemon reports them.
fn ip_reply(ipv4: Option<&str>, ipv6: Option<&str>) -> Response {
    Response::Ip {
        ipv4: ipv4.map(str::to_string),
        ipv6: ipv6.map(str::to_string),
    }
}

/// One `Request::Ip` and nothing else: the family filter is applied to what the daemon answered, so
/// the round trip has to happen before the error can.
fn asked_for_the_addresses_once(stub: &StubDaemon) {
    let seen = stub.requests();
    assert!(
        matches!(seen.as_slice(), [Request::Ip]),
        "expected exactly one ip request; got {seen:?}"
    );
}

/// The control the negative cases lean on: the same stub, the same flag shape, an answer the node
/// CAN give. Without it, a mistyped socket path or a binary failing for an unrelated reason would
/// satisfy every "exits non-zero" assertion below vacuously.
#[test]
fn ip_prints_the_address_and_exits_zero_when_the_family_is_there() {
    let stub = StubDaemon::start(vec![ip_reply(
        Some("100.64.0.1"),
        Some("fd7a:115c:a1e0::1"),
    )]);
    let out = stub.tnet(&["ip", "-4"]);
    assert!(
        out.status.success(),
        "`tnet ip -4` on a node WITH an IPv4 must exit 0; stderr:\n{}",
        stderr(&out)
    );
    assert_eq!(stdout(&out), "100.64.0.1\n");
    asked_for_the_addresses_once(&stub);
}

/// The case the audit found: an IPv4-only node asked for its IPv6.
#[test]
fn ip_v6_on_an_ipv4_only_node_exits_non_zero_with_gos_message() {
    let stub = StubDaemon::start(vec![ip_reply(Some("100.64.0.1"), None)]);
    let out = stub.tnet(&["ip", "-6"]);
    assert!(
        !out.status.success(),
        "Go returns `no Tailscale IPv6 address` as an error, so the exit status must be non-zero — \
         a script testing it is the reason upstream wrote an error and not an `outln`; stdout:\n{}",
        stdout(&out)
    );
    assert_eq!(
        stdout(&out),
        "",
        "and nothing may reach stdout: a placeholder line there is what made `tnet ip -6` read as \
         success"
    );
    assert!(
        stderr(&out).contains("no Tailscale IPv6 address"),
        "Go's own text belongs on stderr; got:\n{}",
        stderr(&out)
    );
    asked_for_the_addresses_once(&stub);
}

/// Its mirror: an IPv6-only node (an IPv4-disabled tailnet) asked for its IPv4.
#[test]
fn ip_v4_on_an_ipv6_only_node_exits_non_zero_with_gos_message() {
    let stub = StubDaemon::start(vec![ip_reply(None, Some("fd7a:115c:a1e0::1"))]);
    let out = stub.tnet(&["ip", "-4"]);
    assert!(
        !out.status.success(),
        "`tnet ip -4` on a node with no IPv4 must exit non-zero; stdout:\n{}",
        stdout(&out)
    );
    assert_eq!(stdout(&out), "");
    assert!(
        stderr(&out).contains("no Tailscale IPv4 address"),
        "expected Go's `no Tailscale IPv4 address`; got:\n{}",
        stderr(&out)
    );
    asked_for_the_addresses_once(&stub);
}

/// With neither `-4` nor `-6`, Go's `!match` tail returns nil — both families were wanted, so an
/// empty answer is not a family miss. That state stays exit 0, so the error path above cannot have
/// turned a plain `tnet ip` on an address-less node into a failure by accident.
#[test]
fn ip_without_a_family_flag_still_exits_zero_on_an_empty_answer() {
    let stub = StubDaemon::start(vec![ip_reply(None, None)]);
    let out = stub.tnet(&["ip"]);
    assert!(
        out.status.success(),
        "no family was asked for, so Go's family errors do not apply; stderr:\n{}",
        stderr(&out)
    );
    assert_eq!(stdout(&out), "(no matching tailnet address)\n");
}
