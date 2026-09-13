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
//! pieces (routing, the environment precedence, the origin grammar); this file checks that the real
//! binary wires them together.
//!
//! The flag surface is read by running the built `tnet` and parsing `--help` — clap's own parser,
//! not a second copy of the flag list — the way `tests/tnet_up_go_flag_spellings.rs` does.

use std::process::Command;
use std::process::Output;

/// The two flags a Go `web` command line carries that this fork lacked.
const GO_WEB_FLAGS: [&str; 2] = ["--cgi", "--origin"];

/// A socket path nothing is listening on, so a CGI request that does reach the daemon round-trip
/// fails deterministically instead of finding whatever daemon the test host happens to run.
const UNREACHABLE_SOCKET: &str = "/nonexistent/tnet-web-cgi-test.sock";

fn tnet(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tnet"));
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output()
        .expect("the `tnet` binary built for this test should run")
}

/// One CGI invocation of `tnet web --cgi`, with the environment a web server would set.
fn cgi_request(extra_args: &[&str], request_uri: &str) -> Output {
    let mut args = vec!["--socket", UNREACHABLE_SOCKET, "web", "--cgi"];
    args.extend_from_slice(extra_args);
    tnet(
        &args,
        &[("REQUEST_METHOD", "GET"), ("REQUEST_URI", request_uri)],
    )
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
    // Not on stderr either. Go accepts the pair silently, and stderr here is the invoking web
    // server's error log — a "flag ignored" warning would be a line per request in it. This route
    // (a 404, answered without contacting the daemon) prints nothing at all today, so the whole of
    // stderr is the assertion: a warning in any wording fails it, not just one naming the flag.
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

#[test]
fn origin_does_not_change_the_url_the_listener_prints() {
    // Go's startup line is `web server running on: urlOfListenAddr(webArgs.listen)`; `--origin`
    // reaches only `csrfProtect`. So the printed (and browser-opened) URL is the listener's own,
    // whatever origin is given. Binding a loopback port sends nothing, and the line is printed
    // before any connection is accepted, so this never waits on the network.
    use std::io::BufRead as _;
    let child = Command::new(env!("CARGO_BIN_EXE_tnet"))
        .args([
            "--socket",
            UNREACHABLE_SOCKET,
            "web",
            "--listen",
            "127.0.0.1:0",
            "--no-browser",
            "--prefix",
            "/tailscale",
            "--origin",
            "https://ts.example.com/outside",
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
        let _ = std::io::BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(line);
    });
    let line = rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("`tnet web` should print its startup line once it has bound");
    assert!(
        line.contains("http://127.0.0.1:") && line.contains("/tailscale"),
        "the printed URL is the bound address plus the served path; got: {line:?}"
    );
    assert!(
        !line.contains("ts.example.com") && !line.contains("/outside"),
        "`--origin` must not replace the URL the listener prints; got: {line:?}"
    );
}
