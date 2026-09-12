//! `tailnetd --syspolicy-file <path>` — the device-scope system-policy source an admin can write.
//!
//! Go gained this flag in v1.102.3 (`cmd/tailscaled/syspolicy.go`): a JSON file registered as a
//! device-scope policy source, defaulting to `/etc/tailscale/syspolicy.json`
//! (`%ProgramData%\Tailscale\syspolicy.json` on Windows), with an empty value disabling it and a load
//! failure logged rather than fatal. Before it, a non-Windows host had **no** way to supply policy at
//! all, so `syspolicy list` reported an empty set on every platform no matter what the admin did.
//!
//! The unit tests next to [`syspolicy`](../src/ipn/syspolicy.rs) pin parsing, validation, value
//! rendering and the merge, all without touching the process-global source registry. What they
//! cannot see is the surface an operator actually hits, which is what this file covers:
//!
//! 1. the flag exists on `tailnetd`'s own command line, with Go's default path in `--help`;
//! 2. a loaded file reaches the LocalAPI reply `tnet syspolicy list` renders — i.e. registration and
//!    reporting are actually connected — and is APPLIED to the prefs a `Backend::load` comes up
//!    with, over a persisted `prefs.json` that says the opposite;
//! 3. a *broken* file is logged and the daemon still comes up and serves.
//!
//! Case 2 registers into a process-global registry (Go's `rsop` store list is global too), so it is
//! deliberately the ONLY test in this binary that registers a source.
//!
//! Upstream: `cmd/tailscaled/syspolicy.go` + `util/syspolicy/load.go` @
//! `53a0d659afa51835dd7a9283873cca44261454f8`.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use tailscaled_rs::ipn::{Backend, syspolicy};
use tailscaled_rs::localapi::Response;

/// A temp path unique to this test binary's process and the calling line, so a leftover from a
/// previous run (or a sibling test) can never be mistaken for this test's file.
fn temp_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tailnetd-syspolicy-{}-{}", std::process::id(), tag))
}

/// Run the built `tailnetd` and capture its output.
fn tailnetd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tailnetd"))
        .args(args)
        .output()
        .expect("the `tailnetd` binary built for this test should run")
}

/// The flag has to be on `tailnetd`'s own surface: a command line copied from `tailscaled` must
/// reach the policy loader, not clap's "unexpected argument".
#[test]
fn syspolicy_file_is_a_declared_flag_with_gos_default() {
    let out = tailnetd(&["--help"]);
    assert!(out.status.success(), "--help should exit 0");
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("--syspolicy-file"),
        "`tailnetd --help` must list --syspolicy-file:\n{help}"
    );
    // `--help` is where an admin learns *which* file to create, so the default path has to be in it.
    #[cfg(not(windows))]
    assert!(
        help.contains("/etc/tailscale/syspolicy.json"),
        "`tailnetd --help` must show Go's default policy path:\n{help}"
    );
}

/// A policy file the daemon loads must show up in the LocalAPI reply that `tnet syspolicy list`
/// renders — and then actually change the node.
///
/// This drives the real production path end to end: [`syspolicy::load_json_policy_file`] (the body
/// of the flag), then [`Backend::syspolicy_list`] / [`Backend::syspolicy_reload`] (the LocalAPI
/// handlers `server::serve` dispatches to), then [`Backend::load`] (the profile load a daemon start
/// performs, which reconciles the policy into prefs).
///
/// The two halves are one test because registration is process-global (Go's `rsop` store list is
/// too), and this is deliberately the only test in this binary that registers a source.
#[test]
fn a_loaded_policy_file_reaches_the_localapi_report() {
    let path = temp_path("loaded.json");
    std::fs::write(
        &path,
        br#"{
            "Hostname": "documented-node",
            "AlwaysOn.Enabled": true,
            "ExitNodeIP": "192.0.2.10",
            "KeyExpirationNotice": "48h",
            "NetworkDevices": "hide"
        }"#,
    )
    .expect("the temp policy file should be writable");

    let outcome = syspolicy::load_json_policy_file(syspolicy::JSON_FILE_SOURCE_NAME, &path);
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        outcome,
        Ok(syspolicy::LoadOutcome::Registered { settings: 5 }),
        "all five keys should register"
    );

    let Response::Policy(report) = Backend::syspolicy_list() else {
        panic!("syspolicy_list must reply with a policy report");
    };
    assert_eq!(report.scope, "Device", "the CLI resolves the device scope");
    // Sorted by key, every row attributed to the file, values in Go's `%v` spelling — note the
    // duration canonicalised from "48h" by `time.Duration.String()`.
    let rows: Vec<(&str, &str, Option<&str>)> = report
        .settings
        .iter()
        .map(|s| (s.key.as_str(), s.origin.as_str(), s.value.as_deref()))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("AlwaysOn.Enabled", "JSONFile (Device)", Some("true")),
            ("ExitNodeIP", "JSONFile (Device)", Some("192.0.2.10")),
            ("Hostname", "JSONFile (Device)", Some("documented-node")),
            ("KeyExpirationNotice", "JSONFile (Device)", Some("48h0m0s")),
            ("NetworkDevices", "JSONFile (Device)", Some("hide")),
        ]
    );
    assert!(
        report.settings.iter().all(|s| s.error.is_none()),
        "a valid file resolves every row cleanly"
    );

    // `reload` forces a re-read and must report the same thing: Go's JSON store captures the file at
    // construction and never re-reads it, so the two verbs agree for this source by construction.
    let Response::Policy(reloaded) = Backend::syspolicy_reload() else {
        panic!("syspolicy_reload must reply with a policy report");
    };
    assert_eq!(reloaded, report);

    // ---------------------------------------------------------------------------------------
    // ...and is APPLIED to the node's prefs, not merely reported.
    //
    // Go does this in `ipnlocal.applySysPolicy`, reached from every prefs write and every profile
    // load. `Backend::load` IS a profile load, so a daemon starting under this policy file must come
    // up with the administrator's hostname, the administrator's exit node and the node wanting to
    // run — over a persisted `prefs.json` that says the opposite on all three.
    // ---------------------------------------------------------------------------------------
    let state_dir = temp_path("applied-statedir");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).expect("the temp state dir should be creatable");
    let prefs_path = state_dir.join("prefs.json");
    std::fs::write(
        &prefs_path,
        br#"{"want_running": false, "hostname": "operator-chose-this",
             "exit_node": "some-other-peer", "has_logged_in": true}"#,
    )
    .expect("the temp prefs file should be writable");

    let backend = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime should build")
        .block_on(Backend::load(&state_dir))
        .expect("the backend should load the seeded profile");
    let view = backend.prefs_view();
    assert_eq!(
        view.hostname.as_deref(),
        Some("documented-node"),
        "the policy's Hostname must beat the persisted one"
    );
    assert_eq!(
        view.exit_node.as_deref(),
        Some("192.0.2.10"),
        "the policy's ExitNodeIP must beat the operator's exit node"
    );
    assert!(
        backend.wants_running(),
        "AlwaysOn.Enabled must force want_running back to true"
    );

    // A profile load applies in memory and writes NOTHING: this daemon derives "has this node ever
    // been configured?" from the existence of `prefs.json`, so a policy file must never be able to
    // create or rewrite one just by being present.
    let on_disk =
        std::fs::read_to_string(&prefs_path).expect("prefs.json should still be readable");
    assert!(
        on_disk.contains("operator-chose-this"),
        "a profile load must not persist the policy's values:\n{on_disk}"
    );
    let _ = std::fs::remove_dir_all(&state_dir);
}

/// A policy file with a mistake in it is *logged* and the daemon **still comes up** — Go's hook is
/// `log.Printf`, deliberately not `log.Fatal`, because a typo in an MDM file must not be able to
/// keep a node off the tailnet.
///
/// Only a real process can show that: the daemon has to get past the load, bind its LocalAPI socket
/// and serve. So this starts the built binary on a throwaway state dir, waits for the socket to
/// appear, and then stops it.
#[test]
fn a_broken_policy_file_is_logged_and_the_daemon_still_serves() {
    let state_dir = temp_path("statedir");
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).expect("the temp state dir should be creatable");
    let socket = state_dir.join("tailnetd.sock");
    let policy = state_dir.join("syspolicy.json");
    // A key that is not a registered policy setting: Go refuses the whole file for it.
    std::fs::write(&policy, br#"{"Hostnmae": "typo"}"#)
        .expect("the temp policy file should be writable");
    let log_path = state_dir.join("daemon.log");
    let log = std::fs::File::create(&log_path).expect("the temp log file should be creatable");
    let log_err = log.try_clone().expect("the log handle should clone");

    let mut child = Command::new(env!("CARGO_BIN_EXE_tailnetd"))
        .arg("--statedir")
        .arg(&state_dir)
        .arg("--socket")
        .arg(&socket)
        .arg("--syspolicy-file")
        .arg(&policy)
        // The engine's experiment gate would otherwise exit before the daemon ever serves. Nothing
        // here touches the network: a fresh state dir means the persisted intent is "down", so the
        // daemon loads prefs, serves the socket, and never brings an engine up.
        .env("TS_RS_EXPERIMENT", "this_is_unstable_software")
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("the `tailnetd` binary built for this test should start");

    // Wait — bounded — for the daemon to bind its LocalAPI socket. That is the observable proof it
    // survived the bad policy file rather than exiting on it.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut served = false;
    while Instant::now() < deadline {
        if socket.exists() {
            served = true;
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("tailnetd exited ({status}) instead of continuing past the bad policy file");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();

    let mut logged = String::new();
    std::fs::File::open(&log_path)
        .expect("the daemon log should exist")
        .read_to_string(&mut logged)
        .expect("the daemon log should be readable");
    let _ = std::fs::remove_dir_all(&state_dir);

    assert!(
        served,
        "tailnetd should have bound its LocalAPI socket despite the bad policy file; log:\n{logged}"
    );
    // Logged, and specific enough to fix: the failing path and the offending key.
    assert!(
        logged.contains("syspolicy: invalid"),
        "the load failure should be logged; log:\n{logged}"
    );
    assert!(
        logged.contains("unknown policy setting"),
        "the log should name what is wrong with the file; log:\n{logged}"
    );
}
