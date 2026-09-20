//! `tnet ip` must resolve its argument the way `tailscale ip` resolves it, and fail where it fails,
//! with Go's text and nothing added to it.
//!
//! Upstream is `cmd/tailscale/cli/ip.go` (`runIP`, `peerMatchingIP`),
//! `cmd/tailscale/cli/ping.go` (`tailscaleIPFromArg`) and `cmd/tailscale/tailscale.go` (`main`) @
//! `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8` (v1.102.4). Two behaviours are pinned here:
//!
//! 1. Once `runIP` has resolved the address list — this node's, a peer's or a Service's — it returns
//!    `no current Tailscale IPs; state: %v` when that list is empty, before `-1` and the family
//!    filter run. That is an error: stderr and exit 1, not a placeholder on stdout and exit 0.
//! 2. Go's `main` prints a returned error with `fmt.Fprintln(os.Stderr, err)` and exits 1, so stderr
//!    is exactly the error text. An `Error: ` prefix breaks a script matching on it.
//! 3. `--assert` reports the asserted address AND the list it was compared against
//!    (`assertion failed: IP %q not found among %v`), so a failed assertion says what the node does
//!    hold — `[]` when it holds nothing.
//!
//! The unit tests next to `format_ip_filtered` (src/bin/tnet.rs) pin the decisions. What they cannot
//! see is the process: its exit status, the exact stderr bytes, and which requests reached the
//! daemon. Each test here runs the built `tnet` against a daemon on a Unix socket.
//!
//! Most use [`StubDaemon`], which serves a scripted reply per connection — the only way to put the
//! node in a chosen netmap state without a tailnet. A stub can also serve a reply the real daemon
//! never would, though, and that is exactly how the `no current Tailscale IPs` path came to be
//! pinned against a fiction: the stub answered `ip` with an empty address pair while the production
//! daemon refused the request outright on a node with no engine. So the empty-address case is
//! pinned twice — once against the stub for the selector matrix, and once against the REAL
//! [`RealDaemon`] (`Backend::load` + `server::serve`, offline), which is the node a `tnet ip` on a
//! Stopped or NeedsLogin machine actually talks to.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tailscaled_rs::ipn::Backend;
use tailscaled_rs::localapi::{PeerReport, Request, Response, StatusReport};
use tailscaled_rs::server;

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

/// A peer NAMED on the command line that carries no address is refused by Go's
/// `tailscaleIPFromArg`, which runs before `runIP`'s empty-list check and has its own text:
/// `node found but lacks an IP`. One `Status` answers the whole lookup.
#[test]
fn a_named_addressless_peer_gets_gos_node_found_but_lacks_an_ip() {
    let peer = PeerReport {
        name: "addressless.tail0123.ts.net".into(),
        stable_id: "n2".into(),
        ..Default::default()
    };
    let daemon = StubDaemon::start(vec![status("Starting", vec![peer])]);
    let out = daemon.tnet(&["ip", "addressless.tail0123.ts.net"]);
    assert_eq!(out.status.code(), Some(1), "stdout {:?}", stdout(&out));
    assert_eq!(stderr(&out), "node found but lacks an IP\n");
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

/// A netmap with this node and one peer, both addressed, and a MagicDNS suffix — enough for the
/// name arms of Go's `tailscaleIPFromArg`.
fn named_netmap() -> Response {
    Response::Status(StatusReport {
        state: "Running".into(),
        self_name: Some("my-desktop.tail0123.ts.net".into()),
        self_ipv4: Some("100.64.0.1".into()),
        self_ipv6: Some("fd7a:115c:a1e0::1".into()),
        magic_dns_suffix: Some("tail0123.ts.net".into()),
        peers: vec![PeerReport {
            name: "my-laptop.tail0123.ts.net".into(),
            ipv4: "100.64.0.2".into(),
            ipv6: Some("fd7a:115c:a1e0::2".into()),
            stable_id: "n1".into(),
            ..Default::default()
        }],
        ..Default::default()
    })
}

/// `tailscale ip <this node's own name>` prints this node's addresses: Go's `tailscaleIPFromArg`
/// falls through the peer loop to `if match(st.Self) && len(st.Self.TailscaleIPs) > 0`, and
/// `peerMatchingIP` then finds this node again by the address that returned. Matching the argument
/// against peers only, the node could not name itself.
#[test]
fn this_nodes_own_name_prints_this_nodes_addresses() {
    for arg in ["my-desktop", "MY-DESKTOP", "my-desktop.tail0123.ts.net"] {
        let daemon = StubDaemon::start(vec![named_netmap()]);
        let out = daemon.tnet(&["ip", arg]);
        assert!(out.status.success(), "{arg}: {}", stderr(&out));
        assert_eq!(stdout(&out), "100.64.0.1\nfd7a:115c:a1e0::1\n", "{arg}");
        // `-1` is Go's quad-one over the matched node's own list.
        let daemon = StubDaemon::start(vec![named_netmap()]);
        let out = daemon.tnet(&["ip", "-1", arg]);
        assert!(out.status.success(), "{arg}: {}", stderr(&out));
        assert_eq!(stdout(&out), "100.64.0.1\n", "{arg}");
    }
}

/// Go matches a peer by its SHORT MagicDNS name, case-insensitively
/// (`strings.EqualFold(hostOrIP, dnsOrQuoteHostname(st, ps))`), as well as by its full DNS name.
/// Comparing the argument against the stored FQDN answered only the second.
#[test]
fn a_short_or_miscased_peer_name_resolves_like_go() {
    for arg in [
        "my-laptop",
        "MY-LAPTOP",
        "my-laptop.tail0123.ts.net",
        "my-laptop.tail0123.ts.net.",
    ] {
        let daemon = StubDaemon::start(vec![named_netmap()]);
        let out = daemon.tnet(&["ip", arg]);
        assert!(out.status.success(), "{arg}: {}", stderr(&out));
        assert_eq!(stdout(&out), "100.64.0.2\nfd7a:115c:a1e0::2\n", "{arg}");
        let requests = daemon.requests();
        assert_eq!(requests.len(), 1, "{arg}: {requests:?}");
        assert!(
            matches!(requests[0], Request::Status),
            "{arg}: {requests:?}"
        );
    }
}

/// Go echoes the string `tailscaleIPFromArg` returned — for an address literal, the argument
/// untouched — in `no peer or service found with IP %v`. Re-printing a parsed address instead
/// answers a question about `fd7a:115c:a1e0:0::99` by naming a different spelling of it.
#[test]
fn an_unmatched_literal_is_echoed_as_the_operator_typed_it() {
    let daemon = StubDaemon::start(vec![
        named_netmap(),
        Response::Services { services: vec![] },
    ]);
    let out = daemon.tnet(&["ip", "fd7a:115c:a1e0:0::99"]);
    assert_eq!(out.status.code(), Some(1), "stdout {:?}", stdout(&out));
    assert_eq!(
        stderr(&out),
        "no peer or service found with IP fd7a:115c:a1e0:0::99\n"
    );
    assert_eq!(stdout(&out), "");
    let requests = daemon.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(matches!(requests[1], Request::Services), "{requests:?}");
}

/// A name no node in the netmap carries is Go's last arm: `net.Resolver.LookupHost`, whose first
/// answer goes back through `peerMatchingIP` and the Service lookup. `localhost` comes from the
/// machine's own hosts file, so this exercises the fallback without a name server: the address it
/// resolves to belongs to no node and no Service, and the refusal names THAT address — proof the
/// lookup happened, where the old code stopped at the name.
#[test]
fn a_name_in_no_netmap_reaches_the_host_resolver() {
    let daemon = StubDaemon::start(vec![
        named_netmap(),
        Response::Services { services: vec![] },
    ]);
    let out = daemon.tnet(&["ip", "localhost"]);
    assert_eq!(out.status.code(), Some(1), "stdout {:?}", stdout(&out));
    let err = stderr(&out);
    let resolved = err
        .trim_end()
        .strip_prefix("no peer or service found with IP ")
        .unwrap_or_else(|| panic!("unexpected stderr: {err:?}"))
        .parse::<std::net::IpAddr>()
        .unwrap_or_else(|e| panic!("stderr must echo the resolved address, got {err:?}: {e}"));
    assert!(resolved.is_loopback(), "localhost resolved to {resolved}");
    assert_eq!(stdout(&out), "");
}

/// The REAL daemon, offline: `Backend::load` over a fresh state dir plus the real `server::serve`
/// on a socket of its own. No engine, no network, no auth key — `Backend::load` reads `prefs.json`
/// and constructs with `device: None`, which is precisely the addressless node (`NoState`,
/// `Stopped`, `NeedsLogin`) whose `ip` reply the stub above can only guess at.
///
/// It runs on a thread of its own with its own current-thread runtime, so the test body stays
/// synchronous and can block on `Command::output()` without starving the server.
struct RealDaemon {
    state_dir: PathBuf,
    socket: PathBuf,
    /// Fire to ask `serve` to stop; taken in `Drop`.
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// The thread running the server's runtime; joined in `Drop` so no daemon outlives its test.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl RealDaemon {
    /// Start the daemon over a fresh state dir. `prefs` is written to `prefs.json` before the load
    /// when given, which is how a test picks the backend state the refusal has to name: absent
    /// prefs is a never-configured node (`NoState`), `want_running` with no engine is `NeedsLogin`.
    fn start(prefs: Option<&str>) -> RealDaemon {
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        // Terse on purpose: a Unix socket path is capped at `SUN_LEN` (104 bytes on macOS,
        // 108 on Linux) INCLUDING the temp dir, and `bind` fails outright once the whole path
        // exceeds it. The daemon's socket lives inside this directory, so both names stay short.
        let state_dir = std::env::temp_dir().join(format!("tid-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state_dir);
        std::fs::create_dir_all(&state_dir).expect("create the daemon state dir");
        if let Some(prefs) = prefs {
            std::fs::write(state_dir.join("prefs.json"), prefs).expect("seed prefs.json");
        }
        let socket = state_dir.join("d.sock");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let serve_socket = socket.clone();
        let serve_dir = state_dir.clone();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build the daemon's runtime");
            runtime.block_on(async move {
                let backend = Backend::load(&serve_dir)
                    .await
                    .expect("Backend::load must succeed offline (file read only)");
                let backend = Arc::new(tokio::sync::Mutex::new(backend));
                server::serve(&serve_socket, backend, async {
                    shutdown_rx.await.ok();
                })
                .await
                .expect("serve returned an error");
            });
        });

        // `serve` binds inside itself, so readiness is observed by connecting. Bounded: a daemon
        // that never comes up fails the test instead of hanging it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::os::unix::net::UnixStream::connect(&socket).is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "the daemon never bound {}",
                socket.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        RealDaemon {
            state_dir,
            socket,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        }
    }

    /// Run the built `tnet` against this daemon.
    fn tnet(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tnet"))
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .output()
            .expect("the `tnet` binary built for this test should run")
    }
}

impl Drop for RealDaemon {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_dir_all(&self.state_dir);
    }
}

/// A node with no engine is the addressless node this error text exists for, and the PRODUCTION
/// daemon has to answer it the way Go's `Status` does: with an empty address list, not a refusal.
/// Go's `runIP` reads `ips` and `BackendState` out of one `Status`, so a `Stopped`/`NeedsLogin`
/// node prints `no current Tailscale IPs; state: <state>`. While the daemon answered the split-out
/// `ip` request with `node is not up`, `tnet ip` printed `error: node is not up` and exited before
/// the state line could be reached — on exactly the node the message is about.
#[test]
fn the_real_addressless_daemon_reports_gos_state_line() {
    for (prefs, state) in [
        // Never configured: no prefs file at all.
        (None, "NoState"),
        // Wants to be up but has no engine — Go's `NeedsLogin`.
        (Some(r#"{"want_running":true}"#), "NeedsLogin"),
    ] {
        let daemon = RealDaemon::start(prefs);
        for args in [&["ip"][..], &["ip", "-4"], &["ip", "-6"], &["ip", "-1"]] {
            let out = daemon.tnet(args);
            assert_eq!(
                out.status.code(),
                Some(1),
                "{state} {args:?}: stdout {:?}",
                stdout(&out)
            );
            assert_eq!(
                stderr(&out),
                format!("no current Tailscale IPs; state: {state}\n"),
                "{state} {args:?}"
            );
            assert_eq!(stdout(&out), "", "{state} {args:?}");
        }
    }
}

/// `--assert` on that same real addressless node: Go compares against `st.TailscaleIPs` before the
/// empty-list check, so it reports the assertion — and reports the empty list with it. This asked
/// the daemon for `ip` too, so it failed with `error: node is not up` for the same reason.
#[test]
fn the_real_addressless_daemon_fails_an_assertion_with_an_empty_list() {
    let daemon = RealDaemon::start(None);
    let out = daemon.tnet(&["ip", "--assert", "100.64.0.1"]);
    assert_eq!(out.status.code(), Some(1), "stdout {:?}", stdout(&out));
    assert_eq!(
        stderr(&out),
        "assertion failed: IP \"100.64.0.1\" not found among []\n"
    );
    assert_eq!(stdout(&out), "");
}

/// Go's `runIP` counts `-1`, `-4` and `-6` and refuses as soon as two are set, before `--assert`
/// and before any daemon call. Go's `main` then prints that error with `fmt.Fprintln(os.Stderr,
/// err)`: the bare line. Returning it through `main`'s `Result` instead prefixed it with `Error: `,
/// which every other error path in this command had already stopped doing.
#[test]
fn mutually_exclusive_selectors_are_refused_in_gos_bare_words() {
    for args in [
        &["ip", "-1", "-4"][..],
        &["ip", "-1", "-6"],
        &["ip", "-4", "-6"],
        &["ip", "-1", "-4", "-6"],
        // The refusal runs first, so neither a peer argument nor `--assert` changes it.
        &["ip", "-4", "-6", "my-laptop"],
        &["ip", "-1", "-4", "--assert", "100.64.0.1"],
    ] {
        let daemon = StubDaemon::start(vec![]);
        let out = daemon.tnet(args);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{args:?}: stdout {:?}",
            stdout(&out)
        );
        assert_eq!(
            stderr(&out),
            "tnet ip -1, -4, and -6 are mutually exclusive\n",
            "{args:?}"
        );
        assert_eq!(stdout(&out), "", "{args:?}");
        // Go refuses before `localClient.Status`, so an unusable invocation costs no round trip and
        // answers the same whether or not a daemon is listening.
        assert!(
            daemon.requests().is_empty(),
            "{args:?}: {:?}",
            daemon.requests()
        );
    }
}

/// A failed `--assert` on a node that DOES hold addresses names both operands of Go's error: the
/// asserted address, quoted as typed, and the list it was compared against. Naming only the wanted
/// address left the operator of a failed assertion unable to see what the node actually holds.
#[test]
fn a_failed_assertion_names_the_addresses_the_node_does_hold() {
    let daemon = StubDaemon::start(vec![Response::Ip {
        ipv4: Some("100.64.0.1".into()),
        ipv6: Some("fd7a:115c:a1e0::1".into()),
    }]);
    let out = daemon.tnet(&["ip", "--assert", "203.0.113.9"]);
    assert_eq!(out.status.code(), Some(1), "stdout {:?}", stdout(&out));
    assert_eq!(
        stderr(&out),
        "assertion failed: IP \"203.0.113.9\" not found among [100.64.0.1 fd7a:115c:a1e0::1]\n"
    );
    assert_eq!(stdout(&out), "");
}

/// The other side of the predicate, unchanged by the new text: a match prints nothing and exits 0.
#[test]
fn a_held_address_asserts_silently() {
    let daemon = StubDaemon::start(vec![Response::Ip {
        ipv4: Some("100.64.0.1".into()),
        ipv6: Some("fd7a:115c:a1e0::1".into()),
    }]);
    let out = daemon.tnet(&["ip", "--assert", "fd7a:115c:a1e0::1"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert_eq!(stderr(&out), "");
}
