//! `tnet cert` must read its positional arguments the way Go's `runCert` reads them.
//!
//! Go (`cmd/tailscale/cli/cert.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`) takes the
//! `--serve-demo` branch FIRST, before any argument check: that mode certifies nothing up front — its
//! TLS config is `GetCertificate: localClient.GetCertificate`, one LocalAPI cert call per ClientHello
//! — so it needs no domain, takes the listen address as an OPTIONAL positional defaulting to `:443`,
//! and refuses two or more with "too many arguments; max 1 allowed with --serve-demo (the listen
//! address)". Only outside that branch does it require exactly one argument, the domain, and answer
//! `Usage: tailscale cert [flags] <domain>` plus a hint naming the tailnet's cert domains.
//!
//! This fork used to require the domain in both modes and spell the listen address `--listen`, so
//! `tailscale cert --serve-demo` and `tailscale cert --serve-demo :8443` — both valid Go command
//! lines — died at the parser, and Go's argument-count refusal had no analogue at all.
//!
//! The unit tests next to [`cert_invocation`](../src/bin/tnet.rs) pin the pure grammar. What they
//! cannot see is the surface an operator hits: what the built binary accepts, what it prints, what it
//! exits with, and — for `--serve-demo` — that it binds its listener WITHOUT first asking the daemon
//! for a certificate. Those are checked here, against a stub daemon speaking the LocalAPI's one-line
//! JSON, in the style of `tests/tnet_down_reason_and_risk.rs`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A socket path that is never created, so an invocation either fails before the daemon round trip or
/// fails *at* it — never against whatever daemon happens to be running on the build machine. Keyed by
/// test name + pid so concurrent test binaries cannot collide.
fn unused_socket_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tnet-cert-{name}-{}.sock", std::process::id()))
}

fn tnet_with(socket: &PathBuf, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tnet"))
        .arg("--socket")
        .arg(socket)
        .args(args)
        .output()
        .expect("the `tnet` binary built for this test should run")
}

fn tnet(name: &str, args: &[&str]) -> Output {
    tnet_with(&unused_socket_path(name), args)
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A stand-in daemon: serves exactly `replies.len()` connections of the LocalAPI's one-line JSON
/// protocol (read one request line, write one response line, close), then hands the request lines
/// back over the channel — so a command that skips or adds a round trip is visible in what it served.
fn stub_daemon(name: &str, replies: &[&str]) -> (PathBuf, mpsc::Receiver<Vec<String>>) {
    let path = unused_socket_path(name);
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind the stub daemon socket");
    listener
        .set_nonblocking(true)
        .expect("stub listener must be pollable");
    let replies: Vec<String> = replies.iter().map(|r| (*r).to_string()).collect();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(20);
        for reply in replies {
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break Some(stream),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            break None;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("stub daemon accept failed: {e}"),
                }
            };
            let Some(mut stream) = stream else { break };
            stream
                .set_nonblocking(false)
                .expect("stub connection must block for the request line");
            let mut line = String::new();
            BufReader::new(stream.try_clone().expect("clone the stub connection"))
                .read_line(&mut line)
                .expect("read the request line");
            seen.push(line.trim().to_string());
            writeln!(stream, "{reply}").expect("write the stub reply");
            stream.flush().expect("flush the stub reply");
        }
        let _ = tx.send(seen);
    });
    (path, rx)
}

fn requests(rx: &mpsc::Receiver<Vec<String>>) -> Vec<String> {
    rx.recv_timeout(Duration::from_secs(30))
        .expect("the stub daemon should report the requests it served")
}

/// `tailscale cert --serve-demo` with NO domain is a valid Go command line, and the demo it starts
/// asks the daemon for nothing until a connection arrives (Go's per-ClientHello `GetCertificate`).
///
/// Both halves are checked at once by pointing the CLI at a socket that does not exist: if the
/// command still needed a domain it would die at the parser, and if it fetched a certificate up front
/// it would die at the round trip. It does neither — it binds, and says where.
#[test]
fn serve_demo_needs_no_domain_and_binds_before_asking_for_a_certificate() {
    let socket = unused_socket_path("demo");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tnet"))
        .arg("--socket")
        .arg(&socket)
        // Port 0: the OS picks a free port, so this never collides with anything on the machine (and
        // never needs the root that Go's default `:443` would).
        .args(["cert", "--serve-demo", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the `tnet` binary built for this test should run");

    // The startup line arrives on stdout; read it on a thread so a regression that never prints one
    // fails the test instead of hanging it.
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(line);
    });
    let line = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("`cert --serve-demo` should announce its listener");
    let _ = child.kill();
    let _ = child.wait();

    let addr = line
        .trim()
        .strip_prefix("running TLS server on ")
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_default()
        .to_string();
    let addr: std::net::SocketAddr = addr
        .parse()
        .unwrap_or_else(|_| panic!("the startup line should name the bound address: {line:?}"));
    assert_eq!(addr.ip().to_string(), "127.0.0.1", "{line:?}");
    assert_ne!(addr.port(), 0, "the OS-assigned port should be reported");
}

/// Go's `switch len(args)` refuses two or more arguments under `--serve-demo`, in these words. The
/// check is Go's own, so it happens before any daemon round trip.
#[test]
fn serve_demo_refuses_a_second_argument_in_gos_words() {
    let out = tnet(
        "toomany",
        &["cert", "--serve-demo", "host.user.ts.net", ":8443"],
    );
    assert!(
        !out.status.success(),
        "a refused command line must not exit 0"
    );
    assert!(
        stderr(&out)
            .contains("too many arguments; max 1 allowed with --serve-demo (the listen address)"),
        "expected Go's refusal; got:\n{}",
        stderr(&out)
    );
}

/// The listen address is Go's positional. A `--listen` flag on `cert` is a spelling Go does not have,
/// so a command line using it must not quietly work.
#[test]
fn cert_has_no_listen_flag() {
    let out = tnet("listen", &["cert", "--serve-demo", "--listen", ":8443"]);
    assert!(
        !out.status.success(),
        "`cert --listen` is not a Go spelling and must not be accepted"
    );
}

/// Go answers a domainless `cert` with its usage line plus a hint built from the node's status: the
/// tailnet's cert domains, Go-quoted, so the operator can copy one.
#[test]
fn a_missing_domain_prints_gos_usage_line_and_the_tailnets_cert_domains() {
    let (socket, rx) = stub_daemon(
        "hint",
        &[
            r#"{"kind":"dns_status","magic_dns":true,"cert_domains":["a.user.ts.net","b.user.ts.net"]}"#,
        ],
    );
    let out = tnet_with(&socket, &["cert"]);
    let served = requests(&rx);
    let _ = std::fs::remove_file(&socket);

    assert!(!out.status.success(), "a usage error must not exit 0");
    let err = stderr(&out);
    assert!(
        err.contains("Usage: tnet cert [flags] <domain>"),
        "expected Go's usage line; got:\n{err}"
    );
    assert!(
        err.contains(r#"Valid domain options: ["a.user.ts.net" "b.user.ts.net"]"#),
        "expected Go's `%q` list of cert domains; got:\n{err}"
    );
    assert_eq!(
        served.len(),
        1,
        "the hint costs one read-only round trip, as Go's status call does: {served:?}"
    );
    assert!(
        served[0].contains(r#""cmd":"dns_status""#),
        "the cert domains are read off the DNS status: {}",
        served[0]
    );
}

/// Go's other hint branch: a node that is not running has no cert domains to name.
#[test]
fn a_missing_domain_says_the_node_is_not_running_when_the_daemon_says_so() {
    let (socket, rx) = stub_daemon("down", &[r#"{"kind":"error","message":"node is not up"}"#]);
    let out = tnet_with(&socket, &["cert"]);
    let _ = requests(&rx);
    let _ = std::fs::remove_file(&socket);

    let err = stderr(&out);
    assert!(!out.status.success());
    assert!(
        err.contains("Usage: tnet cert [flags] <domain>")
            && err.contains("The node is not running."),
        "expected Go's not-running hint; got:\n{err}"
    );
}

/// Go binds `--min-validity` with `fs.DurationVar`, so a NEGATIVE duration parses and the certificate
/// is issued anyway (nothing is less valid than "already expired"). The value reaches the daemon as
/// the zero minimum it means, rather than failing a command line Go accepts.
#[test]
fn a_negative_min_validity_still_issues_a_certificate() {
    let (socket, rx) = stub_daemon(
        "negative",
        &[
            r#"{"kind":"cert","cert_pem":"-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n","key_pem":"-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----\n"}"#,
        ],
    );
    // Both PEMs to stdout, so the test writes no files into the build directory.
    let out = tnet_with(
        &socket,
        &[
            "cert",
            "--min-validity",
            "-1h",
            "--cert-file",
            "-",
            "--key-file",
            "-",
            "host.user.ts.net",
        ],
    );
    let served = requests(&rx);
    let _ = std::fs::remove_file(&socket);

    assert!(
        out.status.success(),
        "a negative minimum must not fail a command Go accepts; stderr:\n{}",
        stderr(&out)
    );
    assert_eq!(served.len(), 1, "{served:?}");
    assert!(
        served[0].contains(r#""cmd":"cert""#)
            && served[0].contains(r#""domain":"host.user.ts.net""#)
            && served[0].contains(r#""min_validity_secs":0"#),
        "a negative minimum is carried as the zero minimum it means: {}",
        served[0]
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("BEGIN CERTIFICATE"),
        "the issued certificate should still be written out"
    );
}
