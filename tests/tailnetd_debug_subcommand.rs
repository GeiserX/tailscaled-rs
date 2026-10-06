//! `tailnetd debug` must be a real subcommand — one that runs with no daemon, no socket, and no
//! opt-in to experimental software.
//!
//! Go `tailscaled` dispatches `debug` from its `subCommands` map on `os.Args[1]`, at the top of
//! `main`, before its own flag set is parsed and before any startup precondition. That is what makes
//! it usable for the case it exists for: the node will not come up at all, so the CLI-side verbs
//! that speak to a live daemon cannot help. The unit tests next to
//! [`select`](../src/debugmode.rs) pin the dispatch decision and the refusal messages; what only a
//! process can show is the surface an operator hits — that `debug` is a subcommand at all, that it
//! runs *before* the experiment gate and the `--bird-socket`/`--cleanup` handling, which stream each
//! mode writes to, and what it exits with.
//!
//! Upstream: `cmd/tailscaled/debug.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`.

use std::io::Read as _;
use std::process::{Command, Output, Stdio};

/// Run the built `tailnetd` with `TS_RS_EXPERIMENT` **removed** from the environment.
///
/// Removing it is the point of most cases below: `debug` touches no engine, so it must reach its
/// diagnostic or its refusal without the opt-in. If the dispatch ever regressed to run after the
/// gate, every case here would fail with the gate's message instead.
fn tailnetd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tailnetd"))
        .args(args)
        .env_remove("TS_RS_EXPERIMENT")
        .output()
        .expect("the `tailnetd` binary built for this test should run")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// `debug` is on the daemon's own command surface, so a command line copied from Go reaches it
/// instead of clap's "unexpected argument", and its flag set is separate from the daemon's.
#[test]
fn debug_is_a_declared_subcommand_with_its_own_flags() {
    let out = tailnetd(&["--help"]);
    assert!(out.status.success(), "--help should exit 0");
    let help = stdout(&out);
    assert!(
        help.contains("debug"),
        "`tailnetd --help` should list the debug subcommand; got:\n{help}"
    );

    let out = tailnetd(&["debug", "--help"]);
    assert!(out.status.success(), "`debug --help` should exit 0");
    let help = stdout(&out);
    for flag in [
        "--ifconfig",
        "--monitor",
        "--portmap",
        "--get-url",
        "--derp",
    ] {
        assert!(
            help.contains(flag),
            "`tailnetd debug --help` should list {flag}; got:\n{help}"
        );
    }
    // The daemon's startup flags are NOT in the debug flag set (Go's is a separate `flag.FlagSet`),
    // so passing one is an error rather than a silently ignored argument.
    let out = tailnetd(&["debug", "--statedir", "/tmp/x"]);
    assert!(
        !out.status.success(),
        "a daemon flag must not be accepted by the debug flag set; got:\n{}",
        stderr(&out)
    );
}

/// `--ifconfig` dumps the host's network state once, as JSON, and exits 0 — with no daemon running,
/// no socket, and no `TS_RS_EXPERIMENT` opt-in.
#[test]
fn ifconfig_dumps_network_state_json_without_the_experiment_gate() {
    let out = tailnetd(&["debug", "--ifconfig"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "`debug --ifconfig` should exit 0; stderr:\n{}",
        stderr(&out)
    );
    // Go writes the dump to stderr (`os.Stderr.Write(j)`), and so do we.
    let dump = stderr(&out);
    assert!(
        !dump.contains("TS_RS_EXPERIMENT"),
        "must not be gated on the experiment opt-in; got:\n{dump}"
    );
    let state: serde_json::Value = serde_json::from_str(dump.trim())
        .unwrap_or_else(|e| panic!("dump should be JSON: {e}\n{dump}"));
    for key in [
        "InterfaceIPs",
        "Interface",
        "HaveV4",
        "HaveV6",
        "PathRelevantIPs",
    ] {
        assert!(
            state.get(key).is_some(),
            "the dump should carry Go's `{key}`; got:\n{dump}"
        );
    }
    // Every host running this test has a loopback interface, and the dump is UNFILTERED, so it must
    // be there — while the path signal, which is filtered, must not carry it.
    let ips = state["InterfaceIPs"]
        .as_object()
        .expect("InterfaceIPs object");
    assert!(
        ips.values()
            .flat_map(|v| v.as_array().expect("addresses array"))
            .any(|v| v
                .as_str()
                .is_some_and(|s| s.starts_with("127.0.0.1/") || s.starts_with("::1/"))),
        "the unfiltered dump should include loopback; got:\n{dump}"
    );
    assert!(
        state["PathRelevantIPs"]
            .as_array()
            .expect("PathRelevantIPs array")
            .iter()
            .all(|v| v.as_str() != Some("127.0.0.1") && v.as_str() != Some("::1")),
        "the path signal is filtered, so loopback must not be in it; got:\n{dump}"
    );
    // One dump and done: `--ifconfig` is the non-following mode.
    assert_eq!(
        dump.matches("\"InterfaceIPs\"").count(),
        1,
        "--ifconfig prints exactly one state; got:\n{dump}"
    );
}

/// `--monitor` prints the initial state and then keeps running — the difference from `--ifconfig`
/// that the flag exists for.
#[test]
fn monitor_prints_the_initial_state_and_keeps_running() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tailnetd"))
        .args(["debug", "--monitor"])
        .env_remove("TS_RS_EXPERIMENT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the `tailnetd` binary built for this test should run");

    // The initial dump is immediate; give it a moment, then confirm it has NOT exited.
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(
        child.try_wait().expect("try_wait should work").is_none(),
        "--monitor should still be running (that is what makes it different from --ifconfig)"
    );

    child.kill().expect("kill the monitor");
    let mut dump = String::new();
    child
        .stderr
        .take()
        .expect("stderr was piped")
        .read_to_string(&mut dump)
        .expect("read the monitor's stderr");
    let _ = child.wait();

    assert!(
        dump.contains("Starting link change monitor; initial state:"),
        "Go's pre-dump line, printed only in follow mode; got:\n{dump}"
    );
    assert!(
        dump.contains("\"InterfaceIPs\""),
        "the initial state should be dumped; got:\n{dump}"
    );
    assert!(
        dump.contains("Started link change monitor; waiting..."),
        "Go's post-start line; got:\n{dump}"
    );
}

/// A stray non-flag argument is Go's named refusal, not a run of something else.
#[test]
fn a_stray_positional_argument_is_refused_by_name() {
    // `tailnetd debug monitor` is the plausible typo for `--monitor`; it must not dump anything.
    let out = tailnetd(&["debug", "monitor"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a stray argument should exit 1; stderr:\n{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("unknown non-flag debug subcommand arguments"),
        "should carry Go's message; got:\n{}",
        stderr(&out)
    );
    assert!(
        !stderr(&out).contains("\"InterfaceIPs\""),
        "nothing should have been dumped; got:\n{}",
        stderr(&out)
    );
}

/// `tailnetd debug` with no flag at all is an error, not a no-op that exits 0 having done nothing.
#[test]
fn no_mode_flag_is_an_error() {
    let out = tailnetd(&["debug"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "no mode should exit 1; stderr:\n{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("are available at the moment"),
        "should keep the shape of Go's fall-through refusal; got:\n{}",
        stderr(&out)
    );
}

/// `--derp` and `--portmap` are refused by name, with the reason, and exit 1 — never silently.
#[test]
fn unsupported_modes_refuse_with_a_named_reason() {
    let out = tailnetd(&["debug", "--derp", "fra"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "--derp should exit 1; stderr:\n{}",
        stderr(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains("--derp is not supported") && err.contains("\"fra\""),
        "should name the flag and echo the region; got:\n{err}"
    );
    assert!(
        err.contains("DERP client"),
        "should say what is missing; got:\n{err}"
    );

    let out = tailnetd(&["debug", "--portmap"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "--portmap should exit 1; stderr:\n{}",
        stderr(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains("--portmap is not supported") && err.contains("NAT-PMP"),
        "should name the flag and the missing engine capability; got:\n{err}"
    );
}

/// `--get-url` reaches the network, so only its argument handling is exercised here: a missing value
/// is a parse error, and a scheme the client cannot fetch is refused by name rather than deep inside
/// the HTTP stack.
#[test]
fn get_url_argument_handling() {
    let out = tailnetd(&["debug", "--get-url"]);
    assert!(
        !out.status.success(),
        "--get-url with no value should fail; got:\n{}",
        stderr(&out)
    );

    let out = tailnetd(&["debug", "--get-url", "ftp://example.com/x"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "an unfetchable scheme should exit 1; stderr:\n{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("unsupported protocol scheme"),
        "should name the scheme problem; got:\n{}",
        stderr(&out)
    );
}
