//! `tnet web` must take Go's `--cgi` and `--origin`, so a `tailscale web --cgi --origin=…` command
//! line does not die at the parser.
//!
//! Go's `web` (`cmd/tailscale/cli/web.go` @ bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8, v1.102.4)
//! registers five flags: `--listen`, `--prefix`, `--readonly`, `--cgi` ("run as CGI script") and
//! `--origin` ("origin at which the web UI is served (if behind a reverse proxy or used with cgi)").
//! This fork carried the first three; the last two are what this file guards.
//!
//! Go's `--origin` is stored verbatim, with no validation, and read only by `csrfProtect`'s Host
//! comparison (`client/web/web.go`) — never for the URL `runWeb` prints. So no value may be refused
//! here, and none may move the printed URL. Go's `runWeb` also branches on `--cgi` before it ever
//! reads `--listen`, so the two together run normally with the address unused.
//!
//! `--cgi` is a serving *mode*, not a flag rename: instead of binding a listener, the process serves
//! one request out of the CGI/1.1 environment, writes the response to stdout and exits. That makes
//! it testable end-to-end here without any daemon at all — the 404 route never reaches one, and an
//! unreachable socket is exactly the 500 route. The unit tests in `src/bin/tnet.rs` cover the pure
//! pieces (routing, the environment precedence, the URL the listener reports); this file checks
//! that the real binary wires them together.
//!
//! One step of Go's `runWeb` comes BEFORE the CGI branch (`cmd/tailscale/cli/web.go` @
//! bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8, v1.102.4): unless `--readonly` is given or the daemon's
//! `RunWebClient` pref is already on, it logs `starting tailscaled web client at http://…` to stderr
//! and turns that pref on, returning `starting web client in tailscaled: …` if it cannot. So the
//! daemon-less CGI requests above are Go's outcome only WITH `--readonly`, which is what
//! [`cgi_request`] passes; the tests at the bottom pin the step itself, against no daemon and
//! against a stub one.
//!
//! That step has one undo and only one: Go's interrupt goroutine. A listener that cannot bind
//! returns the error with the pref left on, because Go's `setRunWebClient(false)` sits in that
//! goroutine and a failed `http.ListenAndServe` returns past it. The last test pins that, so a
//! tidier-looking undo cannot be added without it being a deliberate break with Go.
//!
//! The flag surface is read by running the built `tnet` and parsing `--help` — clap's own parser,
//! not a second copy of the flag list — the way `tests/tnet_up_go_flag_spellings.rs` does.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tailscaled_rs::localapi::{PrefsView, Request, Response, StatusReport};

/// The two flags a Go `web` command line carries that this fork lacked.
const GO_WEB_FLAGS: [&str; 2] = ["--cgi", "--origin"];

/// A socket path nothing is listening on, so a CGI request that does reach the daemon round-trip
/// fails deterministically instead of finding whatever daemon the test host happens to run.
const UNREACHABLE_SOCKET: &str = "/nonexistent/tnet-web-cgi-test.sock";

/// The CGI environment of a request for a path the UI is not mounted at.
const NOT_FOUND_REQUEST: [(&str, &str); 2] = [("REQUEST_METHOD", "GET"), ("REQUEST_URI", "/nope")];

fn tnet(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tnet"));
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output()
        .expect("the `tnet` binary built for this test should run")
}

/// One CGI invocation of `tnet web --readonly --cgi`, with the environment a web server would set.
/// `--readonly` is what makes Go go straight to serving without touching the daemon's prefs.
fn cgi_request(extra_args: &[&str], request_uri: &str) -> Output {
    let mut args = vec!["--socket", UNREACHABLE_SOCKET, "web", "--readonly", "--cgi"];
    args.extend_from_slice(extra_args);
    tnet(
        &args,
        &[("REQUEST_METHOD", "GET"), ("REQUEST_URI", request_uri)],
    )
}

/// Per-process-unique counter so tests running in parallel never share a socket path.
static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// A stub daemon on a Unix socket: it answers `status` with a node at 100.64.0.1, `get-prefs` with
/// the given web client pref, and anything else with `ok`, and records every request it was sent.
struct StubDaemon {
    socket: PathBuf,
    seen: Arc<Mutex<Vec<Request>>>,
}

impl StubDaemon {
    fn start(webclient: bool) -> StubDaemon {
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let socket = std::env::temp_dir().join(format!("tnet-web-{}-{n}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("bind the stub daemon socket");
        let seen = Arc::new(Mutex::new(Vec::new()));

        let thread_seen = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut line = String::new();
                if BufReader::new(stream.try_clone().expect("clone the accepted stub stream"))
                    .read_line(&mut line)
                    .is_err()
                {
                    break;
                }
                let Ok(req) = serde_json::from_str::<Request>(line.trim()) else {
                    continue;
                };
                let reply = match req {
                    Request::Status => Response::Status(StatusReport {
                        state: "Running".to_string(),
                        self_ipv4: Some("100.64.0.1".to_string()),
                        ..Default::default()
                    }),
                    Request::GetPrefs => Response::Prefs(PrefsView {
                        webclient,
                        ..Default::default()
                    }),
                    _ => Response::Ok {
                        message: "ok".to_string(),
                    },
                };
                thread_seen.lock().expect("stub request log").push(req);
                let mut body = serde_json::to_vec(&reply).expect("serialize the stub reply");
                body.push(b'\n');
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });

        StubDaemon { socket, seen }
    }

    fn tnet(&self, args: &[&str]) -> Output {
        let socket = self.socket.to_str().expect("the stub socket path is UTF-8");
        let mut full = vec!["--socket", socket];
        full.extend_from_slice(args);
        tnet(&full, &NOT_FOUND_REQUEST)
    }

    /// The `webclient` value of every `set` the stub was sent, in order.
    fn webclient_sets(&self) -> Vec<Option<bool>> {
        self.seen
            .lock()
            .expect("stub request log")
            .iter()
            .filter_map(|req| match req {
                Request::Set { webclient, .. } => Some(*webclient),
                _ => None,
            })
            .collect()
    }
}

impl Drop for StubDaemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

#[test]
fn web_declares_gos_cgi_and_origin_flags() {
    let out = tnet(&["web", "--help"], &[]);
    assert!(out.status.success(), "`tnet web --help` should exit 0");
    let help = String::from_utf8(out.stdout).expect("clap help should be UTF-8");
    for flag in GO_WEB_FLAGS {
        assert!(
            help.contains(flag),
            "`tnet web --help` should declare `{flag}`; got: {help}"
        );
    }
    // The defect this guards against returning: the whole Go command line dying at argument
    // parsing before anything else can be wrong with it.
    let out = cgi_request(&["--origin=https://ts.example.com/tailscale"], "/nope");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "a Go `web --cgi --origin=…` command line should get past clap; got: {stderr}"
    );
}

#[test]
fn cgi_mode_answers_one_request_on_stdout_and_binds_nothing() {
    // A path the UI is not mounted at is a 404 — and it is answered without any daemon, which is
    // what makes this the honest check that CGI mode really serves rather than listens.
    let out = cgi_request(&["--origin=https://ts.example.com/tailscale"], "/nope");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a CGI script that delivered a response exits 0; stdout: {stdout}"
    );
    assert!(
        stdout.starts_with("Status: 404 Not Found\r\n"),
        "CGI mode must write a CGI response to stdout, status first; got: {stdout}"
    );
    assert!(
        stdout.contains("Content-Type: text/html; charset=utf-8\r\n"),
        "the response must carry its content type; got: {stdout}"
    );
    let body = stdout
        .split_once("\r\n\r\n")
        .expect("headers end with a blank line")
        .1;
    assert!(body.contains("not found"), "got body: {body}");
    // Nothing but the response may reach stdout: the startup line the listener prints would be read
    // by the invoking web server as part of the CGI headers.
    assert!(
        !stdout.contains("Serving Tailscale status"),
        "CGI mode must not print the listener's startup line onto the response: {stdout}"
    );

    // The served path itself, with no daemon behind it: still a well-formed CGI response, carrying
    // the failure as a status rather than as a message on stdout.
    let out = cgi_request(&[], "/");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("Status: 500 Internal Server Error\r\n"),
        "an unreachable daemon must become a 500 response, not a broken one; got: {stdout}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("status fetch failed"),
        "the cause belongs on stderr, where the invoking server logs it"
    );
}

#[test]
fn cgi_mode_takes_gos_prefix_as_the_path_it_answers_on() {
    // `--prefix` names the path this process answers on in BOTH serving modes, with or without an
    // `--origin` beside it.
    let out = cgi_request(
        &["--prefix", "/tailscale", "--origin=https://ts.example.com"],
        "/tailscale",
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("Status: 500 Internal Server Error\r\n"),
        "the prefixed path is the served route (500 here only because no daemon is running); \
         got: {stdout}"
    );
    // The root is NOT served once a prefix is set.
    let out = cgi_request(&["--prefix", "/tailscale"], "/");
    assert!(
        String::from_utf8_lossy(&out.stdout).starts_with("Status: 404 Not Found\r\n"),
        "with `--prefix /tailscale`, `/` is not the served path"
    );
}

#[test]
fn listen_is_accepted_and_ignored_next_to_cgi() {
    // Go's `runWeb` returns from the `webArgs.cgi` branch before it looks at `webArgs.listen`, so
    // `tailscale web --cgi --listen=…` runs normally and the address is simply unused. It has to
    // run here too — and in this mode stdout IS the CGI response body, so a refusal printed there
    // would reach the invoking web server as a malformed response instead of a page.
    let out = cgi_request(&["--listen", "127.0.0.1:8088"], "/nope");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "`--listen` beside `--cgi` is unused, not fatal; stdout: {stdout}"
    );
    assert!(
        stdout.starts_with("Status: 404 Not Found\r\n"),
        "the CGI response must be the whole of stdout; got: {stdout}"
    );
    assert!(
        !stdout.contains("--listen"),
        "nothing but the response may reach a CGI script's stdout; got: {stdout}"
    );
    // Not on stderr either. With `--readonly` Go accepts the pair silently, and stderr here is the
    // invoking web server's error log — a "flag ignored" warning would be a line per request in
    // it. This route (a 404, answered without contacting the daemon) prints nothing at all today,
    // so the whole of stderr is the assertion: a warning in any wording fails it, not just one
    // naming the flag.
    assert!(
        out.stderr.is_empty(),
        "`--listen` beside `--cgi` is ignored the way Go ignores it: silently; got stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn origin_is_taken_verbatim_and_never_refused() {
    // Go's `runWeb` does `if webArgs.origin != "" { opts.OriginOverride = webArgs.origin }` and
    // nothing else with the value: no parse, no trim, no error path. So every one of these — Go's
    // bare host, a `host:port`, and values no URL grammar would call an origin — must serve the
    // request and exit 0, exactly as `tailscale web --cgi --origin=<value>` does.
    for origin in [
        "example.net",
        "192.0.2.10:8088",
        "https://ts.example.com/tailscale",
        "ftp://ts.example.com",
        "/tailscale",
        "https:///tailscale",
        "https://ts.example.com/ui?a=1",
        "ts.example.com/ui#top",
        "user:pw@ts.example.com",
        "http://[not-a-host",
        " ",
        "",
    ] {
        let flag = format!("--origin={origin}");
        let out = cgi_request(&[&flag], "/nope");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(0),
            "Go stores `--origin {origin:?}` unvalidated, so it must not fail; stdout: {stdout}, \
             stderr: {stderr}"
        );
        assert!(
            stdout.starts_with("Status: 404 Not Found\r\n"),
            "`--origin {origin:?}` must serve the request, not refuse it; got: {stdout:?}"
        );
        // Nothing complains about the value anywhere, including the invoking server's error log.
        assert!(
            out.stderr.is_empty(),
            "`--origin {origin:?}` is accepted silently, as in Go; got stderr: {stderr}"
        );
    }
}

/// A child process killed when it goes out of scope, so a failed assertion cannot leak a listener.
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run `tnet web --origin <origin>` on an ephemeral loopback port and return the startup line it
/// prints. The child is killed when the returned value's scope ends, so a failed assertion cannot
/// leak a listener.
///
/// Binding a loopback port sends nothing, and the line is printed before any connection is
/// accepted, so this never waits on the network.
///
/// `--readonly` for the same reason [`cgi_request`] passes it: it is what skips Go's pre-serve
/// step of turning the daemon's web client pref on, which against this unreachable socket would
/// fail the command before it ever bound a listener. The URL under test is unaffected by it.
fn startup_line_with_origin(origin: &str) -> String {
    let child = Command::new(env!("CARGO_BIN_EXE_tnet"))
        .args([
            "--socket",
            UNREACHABLE_SOCKET,
            "web",
            "--readonly",
            "--listen",
            "127.0.0.1:0",
            "--no-browser",
            "--prefix",
            "/tailscale",
            "--origin",
            origin,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the `tnet` binary built for this test should run");
    let mut child = KillOnDrop(child);
    let stdout = child.0.stdout.take().expect("stdout is piped");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(line);
    });
    rx.recv_timeout(std::time::Duration::from_secs(30))
        .expect("`tnet web` should print its startup line once it has bound")
}

#[test]
fn origin_does_not_change_the_url_the_listener_prints() {
    // Go's startup line is `web server running on: urlOfListenAddr(webArgs.listen)`; `--origin`
    // reaches only `csrfProtect`. So the printed (and browser-opened) URL is the listener's own,
    // whatever origin is given — and in every shape Go takes, not only the one that already looks
    // like a URL. `example.net` and `192.0.2.10:8088` are the shapes Go's own tests pass, and they
    // are exactly the ones a URL built from the origin has to invent a scheme for. There is nothing
    // here to invent one for: `urlOfListenAddr` only ever formats the listen address.
    for origin in [
        "https://ts.example.com/outside",
        "ts.example.com",
        "ts.example.com:9999",
    ] {
        let line = startup_line_with_origin(origin);
        assert!(
            line.contains("http://127.0.0.1:") && line.contains("/tailscale"),
            "the printed URL is the bound address plus the served path; got: {line:?}"
        );
        assert!(
            !line.contains("ts.example.com") && !line.contains("/outside"),
            "`--origin {origin}` must not replace the URL the listener prints; got: {line:?}"
        );
    }
}

#[test]
fn origin_does_not_reach_the_page_that_is_served() {
    // The other half of the same divergence: the page itself, not just the startup line. Nothing in
    // Go's UI renders `OriginOverride` — `csrfProtect` is its only reader — so the bytes served
    // with an origin must be the bytes served without one.
    //
    // The CGI route is the one a reverse proxy actually invokes, which is the case `--origin`
    // exists for. It needs a daemon because only the 200 page is rendered at all; the 404 body is a
    // constant and could not carry an origin either way. The stub's web client pref is already on,
    // so Go's pre-serve step is a no-op and stderr stays empty.
    let daemon = StubDaemon::start(true);
    let socket = daemon
        .socket
        .to_str()
        .expect("the stub socket path is UTF-8");
    let page = |extra: &[&str]| {
        let mut args = vec!["--socket", socket, "web", "--cgi"];
        args.extend_from_slice(extra);
        let out = tnet(&args, &[("REQUEST_METHOD", "GET"), ("REQUEST_URI", "/")]);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(0), "{extra:?}; stderr: {stderr}");
        let stdout = String::from_utf8(out.stdout).expect("the served page is UTF-8");
        assert!(
            stdout.starts_with("Status: 200 OK\r\n"),
            "{extra:?} should render the status page; got: {stdout}"
        );
        stdout
    };
    let with_origin = page(&["--origin=https://ts.example.com/outside"]);
    assert!(
        !with_origin.contains("ts.example.com") && !with_origin.contains("rel=\"canonical\""),
        "`--origin` must not state a URL on the page; got: {with_origin}"
    );
    assert_eq!(
        with_origin,
        page(&[]),
        "`--origin` has no effect on what is served, so the two responses are identical"
    );
}

#[test]
fn cgi_without_readonly_logs_the_web_client_start_and_fails_without_a_daemon() {
    // Go's `runWeb` without `--readonly`: the prefs read fails, so the web client counts as off; it
    // logs the start (with the zero `Addr` Go's failed status read leaves) and then fails turning
    // the pref on — all before the CGI branch, so no response is written.
    let out = tnet(
        &["--socket", UNREACHABLE_SOCKET, "web", "--cgi"],
        &NOT_FOUND_REQUEST,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "Go returns `starting web client in tailscaled: …` here; stdout: {stdout}, stderr: {stderr}"
    );
    assert!(
        stdout.is_empty(),
        "the failure comes before the CGI branch, so no response is written; got: {stdout}"
    );
    assert!(
        stderr.contains("starting tailscaled web client at http://invalid AddrPort"),
        "Go logs the start to stderr first; got: {stderr}"
    );
    assert!(
        stderr.contains("starting web client in tailscaled: "),
        "the failure carries Go's wrapping; got: {stderr}"
    );
}

#[test]
fn cgi_without_readonly_turns_the_web_client_on_before_serving() {
    let daemon = StubDaemon::start(false);
    let out = daemon.tnet(&["web", "--cgi"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stdout.starts_with("Status: 404 Not Found\r\n"),
        "once the pref is on, the request is served; got: {stdout}"
    );
    assert!(
        stderr.contains("starting tailscaled web client at http://100.64.0.1:5252"),
        "Go logs the node's first Tailscale IP with the web client port; got: {stderr}"
    );
    // Exactly one `set`, turning it on — a CGI request does not turn it back off, as in Go.
    assert_eq!(daemon.webclient_sets(), vec![Some(true)]);
}

#[test]
fn cgi_is_silent_when_the_web_client_is_already_on_or_readonly_is_given() {
    for (webclient, args) in [
        (true, &["web", "--cgi"][..]),
        (false, &["web", "--readonly", "--cgi"][..]),
    ] {
        let daemon = StubDaemon::start(webclient);
        let out = daemon.tnet(args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).starts_with("Status: 404 Not Found\r\n"),
            "{args:?}"
        );
        assert!(
            out.stderr.is_empty(),
            "{args:?} (pref on: {webclient}) goes straight to serving; got stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            daemon.webclient_sets().is_empty(),
            "{args:?} (pref on: {webclient}) must not edit the pref"
        );
    }
}

#[test]
fn a_failed_listener_leaves_the_web_client_pref_on_as_go_does() {
    let daemon = StubDaemon::start(false);
    // A listen address no host can bind: the port is out of range, so it fails while being parsed.
    // (An address that merely looks unbindable could be bindable on some test host, and this test
    // would then serve until it was killed.)
    let out = daemon.tnet(&["web", "--listen", "127.0.0.1:99999"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a listener that cannot bind fails the command; stderr: {stderr}"
    );
    assert!(
        stderr.contains("serving web UI on 127.0.0.1:99999"),
        "the bind failure is what the command reports; got: {stderr}"
    );
    // The pref this run turned on stays on. Go's `setRunWebClient(false)` runs only from the
    // goroutine watching for an interrupt; a serving failure returns past it.
    assert_eq!(
        daemon.webclient_sets(),
        vec![Some(true)],
        "a failed listener must not edit the pref a second time"
    );
    assert!(
        !stderr.contains("stopping tailscaled web client"),
        "that line belongs to the interrupt path only; got: {stderr}"
    );
}
