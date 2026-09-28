//! A malformed operator env file must not stop `tailnetd` from starting.
//!
//! Go's `tailscaled` calls `envknob.ApplyDiskConfig()` for its effect and throws the return value
//! away; the error is stashed in `applyDiskConfigErr` and `run` prints it —
//! `log.Printf("Error reading environment config: %v", err)` — while the daemon comes up anyway.
//! Everything above the bad line is already in the environment by then, because `applyKeyValueEnv`
//! `Setenv`s as it scans.
//!
//! The unit tests in `src/envknob.rs` pin the scan and the file selection. What they cannot see is
//! the surface an operator hits: whether the process that reads the file *survives* it, and whether
//! the file was consulted at all. Both need the built binary, so they are checked here the way
//! `tests/bird_socket_refusal.rs` checks its refusal.
//!
//! `--cleanup` is the vehicle: it is the one command line that runs the whole env-file path and then
//! exits without an engine, a network or a socket — it resolves the state directory (which is where
//! an applied `TAILNETD_STATE_DIR` becomes visible), prints the socket it would have removed, and
//! returns 0 when there is nothing there. `TS_DEBUG_ENV_FILE` points the daemon at a scratch file,
//! which is also how a Linux host uses an env file at all: `platform_env_files` is empty there, as
//! it is in Go.
//!
//! Upstream: `cmd/tailscaled/tailscaled.go` and `envknob/envknob.go` @
//! `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8`.

use std::path::PathBuf;
use std::process::{Command, Output};

/// A scratch path of our own, keyed by pid and tag so parallel test binaries cannot collide.
fn temp_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tailnetd-envfile-{tag}-{}", std::process::id()))
}

/// Run the built `tailnetd --cleanup` against a state directory that has no socket in it, with
/// `TS_DEBUG_ENV_FILE` naming `env_file`.
///
/// `TAILNETD_STATE_DIR` is *removed* from the child's environment on purpose: the only way it can
/// be set when the daemon resolves its state directory is if the env file was read and applied.
/// `TS_RS_EXPERIMENT` is removed too — `--cleanup` deliberately runs ahead of the experiment gate,
/// so a regression that let this reach the gate shows up as a failed assertion here rather than as
/// a daemon that starts and hangs the test run.
fn cleanup_with_env_file(env_file: &PathBuf) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tailnetd"))
        .arg("--cleanup")
        .env("TS_DEBUG_ENV_FILE", env_file)
        .env_remove("TAILNETD_STATE_DIR")
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

/// The whole point: a file with a typo in it costs the operator the bad line, not the daemon.
///
/// The good line above the typo still applies — `TAILNETD_STATE_DIR` is the one this run can
/// observe, and it has to be in effect by the time the state directory is resolved — the process
/// exits 0, and the problem is reported rather than swallowed.
#[test]
fn a_malformed_env_file_is_reported_and_the_daemon_carries_on() {
    let state_dir = temp_path("statedir");
    let env_file = temp_path("malformed.txt");
    std::fs::write(
        &env_file,
        format!(
            "# operator knobs\nTAILNETD_STATE_DIR={}\nTS_DEBUG=\"unterminated\nTS_BELOW=1\n",
            state_dir.display()
        ),
    )
    .expect("write scratch env file");
    let _ = std::fs::remove_dir_all(&state_dir);

    let out = cleanup_with_env_file(&env_file);
    let _ = std::fs::remove_file(&env_file);

    assert!(
        out.status.success(),
        "a malformed env file must not stop startup; got {:?}\nstdout: {}\nstderr: {}",
        out.status,
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stdout(&out).contains(&state_dir.display().to_string()),
        "the line above the bad one must still have applied (state dir {}): {}",
        state_dir.display(),
        stdout(&out)
    );
    assert!(
        stderr(&out).contains("error reading environment config:")
            && stderr(&out).contains("line 3: invalid value in line"),
        "the refused line must be reported with its number: {}",
        stderr(&out)
    );
}

/// The `TS_DEBUG_ENV_FILE` override is read by the real binary, on a host where the platform list is
/// empty — which is every host this fork's CI runs on except macOS, and Linux by design.
#[test]
fn the_override_points_the_daemon_at_a_file_it_would_not_otherwise_read() {
    let state_dir = temp_path("override-statedir");
    let env_file = temp_path("override.txt");
    std::fs::write(
        &env_file,
        format!("TAILNETD_STATE_DIR={}\n", state_dir.display()),
    )
    .expect("write scratch env file");
    let _ = std::fs::remove_dir_all(&state_dir);

    let out = cleanup_with_env_file(&env_file);
    let _ = std::fs::remove_file(&env_file);

    assert!(
        out.status.success(),
        "a well-formed env file must not disturb startup: {}",
        stderr(&out)
    );
    assert!(
        stdout(&out).contains(&state_dir.display().to_string()),
        "TS_DEBUG_ENV_FILE's assignments must reach the process environment: {}",
        stdout(&out)
    );
    assert!(
        !stderr(&out).contains("error reading environment config:"),
        "a clean file has nothing to report: {}",
        stderr(&out)
    );
}

/// A file named in `TS_DEBUG_ENV_FILE` that is not there is Go's one hard error in this path — and
/// it is still not fatal to the daemon.
#[test]
fn a_missing_explicitly_configured_file_is_reported_without_stopping_startup() {
    let env_file = temp_path("gone.txt");
    let _ = std::fs::remove_file(&env_file);

    let out = cleanup_with_env_file(&env_file);

    assert!(
        out.status.success(),
        "a missing TS_DEBUG_ENV_FILE must not stop startup: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("error opening explicitly configured TS_DEBUG_ENV_FILE"),
        "an explicitly named file that is absent must be said out loud: {}",
        stderr(&out)
    );
}
