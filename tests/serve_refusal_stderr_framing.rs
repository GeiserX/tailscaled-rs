//! `tnet serve` / `tnet funnel` must print each refusal with the framing Go prints it with — and
//! for four of them that means no prefix at all.
//!
//! Upstream is `cmd/tailscale/cli/serve_v2.go` (`runServeCombined`) and `cmd/tailscale/tailscale.go`
//! (`main`) @ `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8` (v1.102.4). `main` prints whatever
//! `cli.Run` returns with a bare `fmt.Fprintln(os.Stderr, err)` and exits 1, so the bytes an
//! operator sees are the error's own text and nothing else. Two of `runServeCombined`'s refusals
//! spell a prefix into the literal themselves — `errors.New("Error: --service flag is not supported
//! with funnel")` — and four do not.
//!
//! What is in front of the sentence is a property of the *process*, not of any function: the unit
//! tests beside `check_serve_flags` pin the sentence, and only running the binary can show what
//! `main` puts around it. That is what this file does. No case here reaches the daemon — every
//! refusal is decided before the socket is touched — so the path handed to `--socket` is one that
//! does not exist, and is named in the expected bytes where `main` happens to print it.

use std::process::{Command, Output};

/// A socket path that is never created. If a refusal checked here ever started contacting the
/// daemon first, `connect` would fail immediately on the missing path rather than hang the run.
fn unused_socket_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("tnet-serve-framing-{}.sock", std::process::id()))
}

/// Run the built `tnet` with a subcommand and its arguments.
fn tnet(args: &[&str]) -> Output {
    let socket = unused_socket_path();
    Command::new(env!("CARGO_BIN_EXE_tnet"))
        .arg(args[0])
        .arg("--socket")
        .arg(&socket)
        .args(&args[1..])
        .output()
        .expect("the `tnet` binary built for this test should run")
}

/// Assert the exact bytes Go's process writes: stderr is `want` and nothing more, stdout is empty,
/// and the status is Go's `os.Exit(1)`.
#[track_caller]
fn assert_refusal(args: &[&str], want: &str) {
    let out = tnet(args);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err, want, "stderr for `tnet {}`", args.join(" "));
    assert!(
        out.stdout.is_empty(),
        "`tnet {}` should print nothing on stdout; got: {:?}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "`tnet {}` should exit 1 like Go's `os.Exit(1)`",
        args.join(" ")
    );
}

/// `fmt.Errorf("failed to clean the mount point: %w", err)` — the first of the four, and the one Go
/// reaches before it has even resolved the listener.
#[test]
fn an_unclean_mount_point_prints_gos_line_with_nothing_in_front() {
    assert_refusal(
        &["serve", "--set-path=/a/../b", "3000"],
        "failed to clean the mount point: invalid mount point \"/a/../b\"\n",
    );
    assert_refusal(
        &["serve", "--set-path=//foo", "3000"],
        "failed to clean the mount point: invalid mount point \"//foo\"\n",
    );
}

/// `fmt.Errorf("PROXY protocol is only supported for TCP forwarding, not HTTP/HTTPS")`, returned
/// plainly and printed bare. The listener may be the defaulted HTTPS/443 or a named HTTP(S) port.
#[test]
fn proxy_protocol_on_a_web_serve_prints_gos_line_with_nothing_in_front() {
    let want = "PROXY protocol is only supported for TCP forwarding, not HTTP/HTTPS\n";
    assert_refusal(&["serve", "--proxy-protocol=1", "3000"], want);
    assert_refusal(
        &["serve", "--https=8443", "--proxy-protocol=1", "3000"],
        want,
    );
    assert_refusal(&["serve", "--http=80", "--proxy-protocol=2", "3000"], want);
    // `funnel` shares `serve_v2.go`, so it shares the framing too.
    assert_refusal(&["funnel", "--proxy-protocol=1", "3000"], want);
}

/// `fmt.Errorf("invalid PROXY protocol version %d; must be 1 or 2", e.proxyProtocol)`, likewise bare.
#[test]
fn an_out_of_range_proxy_protocol_version_prints_gos_line_with_nothing_in_front() {
    assert_refusal(
        &["serve", "--tcp=443", "--proxy-protocol=3", "3000"],
        "invalid PROXY protocol version 3; must be 1 or 2\n",
    );
    assert_refusal(
        &[
            "serve",
            "--tls-terminated-tcp=8443",
            "--proxy-protocol=300",
            "3000",
        ],
        "invalid PROXY protocol version 300; must be 1 or 2\n",
    );
}

/// `errors.New("tun mode is only supported for services")`, likewise bare.
#[test]
fn tun_without_a_service_prints_gos_line_with_nothing_in_front() {
    assert_refusal(
        &["serve", "--tun", "3000"],
        "tun mode is only supported for services\n",
    );
}

/// The other half of the rule that picks the four above — and a divergence this change leaves
/// alone.
///
/// Go spells `Error: ` INTO these two literals itself, which is why the fix above is a rendering
/// change and not an edit to the strings: prefixing every literal to "match Go" would print
/// `Error: Error: …` for these.
///
/// What they print today is neither Go's line nor a single-prefix version of it. `main` wraps every
/// `serve`/`funnel` result in `.with_context(|| format!("serve via {}", socket.display()))`, so the
/// sentence lands under `Caused by:` behind a line naming the socket, while Go prints one bare line.
/// That is a second divergence with a different cause — the context, not the prefix — and it is out
/// of scope here. It is pinned so the shape is on the record and so the change above is shown not to
/// move it.
#[test]
fn the_two_service_refusals_are_left_as_they_were() {
    let socket = unused_socket_path();
    let socket = socket.display();
    assert_refusal(
        &["funnel", "--service=svc:web", "3000"],
        &format!(
            "Error: funnel via {socket}\n\nCaused by:\n    --service flag is not supported with \
             funnel\n"
        ),
    );
    assert_refusal(
        &["serve", "--service=svc:web", "--bg=false", "3000"],
        &format!(
            "Error: serve via {socket}\n\nCaused by:\n    --service flag is only compatible with \
             background mode\n"
        ),
    );
}

/// And the refusal Go frames its own way is untouched by all of the above: `srvTypeAndPortFromFlags`
/// still gets `error: %v\n\n` plus the help hint, with no `Error: ` anywhere.
#[test]
fn a_flag_grammar_refusal_keeps_gos_error_and_help_hint_framing() {
    assert_refusal(
        &["serve", "--https=70000", "3000"],
        "error: port number 70000 is too high for https flag\n\ntry `tnet serve --help` for usage \
         info\n",
    );
}
