//! `tnet web` must take Go's `--cgi` and `--origin`, so a reverse-proxied deployment can say what
//! URL it is really served at — and so a `tailscale web --cgi` command line does not die at the
//! parser.
//!
//! Go's `web` (`cmd/tailscale/cli/web.go` @ 53a0d659afa51835dd7a9283873cca44261454f8) registers five
//! flags: `--listen`, `--prefix`, `--readonly`, `--cgi` ("run as CGI script") and `--origin`
//! ("origin at which the web UI is served (if behind a reverse proxy or used with cgi)"). This fork
//! carried the first three; the last two are what this file guards.
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
    // `--prefix` names the path this process answers on in BOTH serving modes; `--origin` names the
    // URL the outside world reaches, which is the half `--prefix` cannot supply.
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
fn listen_is_refused_next_to_cgi_and_a_bad_origin_is_refused_by_name() {
    // `--cgi` binds nothing, so a `--listen` beside it names an address that will never exist.
    let out = tnet(&["web", "--cgi", "--listen", "127.0.0.1:8088"], &[]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a usage refusal exits 1, like this CLI's others"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("--listen can only be used without --cgi"),
        "the refusal should say which flag is not usable; got: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    // `--origin` needs the two things `--prefix` cannot give: a scheme and a host. A bare hostname
    // is the mistake to expect, and it is refused before anything binds or is contacted.
    let out = tnet(&["web", "--origin", "ts.example.com"], &[]);
    assert!(
        !out.status.success(),
        "a `--origin` that is not an absolute URL must not be accepted"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--origin") && stderr.contains("absolute URL"),
        "the refusal should name the flag and what it wants; got: {stderr}"
    );
}
