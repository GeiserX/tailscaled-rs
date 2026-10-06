//! `tailnetd --encrypt-state` / `--hardware-attestation` must refuse *as named refusals*, not die
//! as unknown arguments.
//!
//! Go `tailscaled` takes both flags on a `buildfeatures.HasTPM` build: `--encrypt-state` seals the
//! state file to the device's TPM (Linux and Windows), and `--hardware-attestation` binds the node
//! identity to a hardware-backed key (TPM 2.0, Secure Enclave, Keystore). Both default from a
//! syspolicy key when unset, and `handleTPMFlags` fatals on an explicit flag the device or build
//! cannot honour. This fork has neither a hardware key store nor a state-store provider layer — the
//! node key and prefs are plain files under a `0700` state dir — so both features are recorded as
//! out of scope and both flags refuse the way Go refuses an unsupported one.
//!
//! The unit tests next to [`explicit_tpm_flag_refusal`](../src/bin/tailnetd.rs) pin the decision
//! functions and the policy-driven reporting. What they cannot see is the surface an operator
//! actually hits: whether clap accepts the flags at all, in which spellings, and *where* in startup
//! the refusal fires. Those are checked here by running the built `tailnetd`, the way
//! `tests/bird_socket_refusal.rs` runs it for `--bird-socket`.
//!
//! Upstream: `cmd/tailscaled/tailscaled.go` and `cmd/tailscaled/flag.go` @
//! `53a0d659afa51835dd7a9283873cca44261454f8`.

use std::process::{Command, Output};

/// A socket path that is never created, so `--cleanup` finds nothing to do and exits 0. Keyed by
/// pid so concurrent test binaries cannot collide.
fn unused_socket_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("tailnetd-tpm-test-{}.sock", std::process::id()))
}

/// Run the built `tailnetd` with `TS_RS_EXPERIMENT` **removed** from the environment.
///
/// Removing it is deliberate, exactly as in `bird_socket_refusal`: every case below must terminate
/// on a flag decision made *before* the experiment gate. If a refusal ever regressed into a
/// fall-through, the daemon would hit the gate and exit with the gate's message — a clean assertion
/// failure — instead of coming up and hanging the test run.
fn tailnetd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tailnetd"))
        .args(args)
        .env_remove("TS_RS_EXPERIMENT")
        .output()
        .expect("the `tailnetd` binary built for this test should run")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Both flags are on `tailnetd`'s own surface (clap's `--help`), so a command line copied from a Go
/// unit file reaches the refusal instead of "unexpected argument".
#[test]
fn both_tpm_flags_are_declared_flags() {
    let out = tailnetd(&["--help"]);
    assert!(out.status.success(), "--help should exit 0");
    let help = String::from_utf8_lossy(&out.stdout);
    for flag in ["--encrypt-state", "--hardware-attestation"] {
        assert!(
            help.contains(flag),
            "`tailnetd --help` should list {flag}; got:\n{help}"
        );
    }
}

/// `--encrypt-state` refuses with a message that names the flag and the missing integration, and
/// exits 1 — reached before the experiment gate, so the operator is told about the *flag* rather
/// than about an unrelated environment variable.
#[test]
fn encrypt_state_refuses_with_a_named_reason() {
    let out = tailnetd(&["--encrypt-state"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "--encrypt-state should exit 1; stderr:\n{}",
        stderr(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains("--encrypt-state is not supported"),
        "should refuse by name; got:\n{err}"
    );
    assert!(
        err.contains("no state-store provider layer"),
        "should say why it is unsupported; got:\n{err}"
    );
    assert!(
        err.contains("out of scope"),
        "should state the parity decision; got:\n{err}"
    );
    assert!(
        !err.contains("TS_RS_EXPERIMENT"),
        "the flag refusal must fire before the experiment gate; got:\n{err}"
    );
}

/// The same for `--hardware-attestation`, whose refusal keeps Go's own sentence.
#[test]
fn hardware_attestation_refuses_with_a_named_reason() {
    let out = tailnetd(&["--hardware-attestation"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "--hardware-attestation should exit 1; stderr:\n{}",
        stderr(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains("--hardware-attestation is not supported on this platform or in this build"),
        "should keep Go's refusal sentence; got:\n{err}"
    );
    assert!(
        err.contains("no hardware key store"),
        "should say why it is unsupported; got:\n{err}"
    );
    assert!(
        !err.contains("TS_RS_EXPERIMENT"),
        "the flag refusal must fire before the experiment gate; got:\n{err}"
    );
}

/// Go validates these flags before it reaches its cleanup path, so `--cleanup` must not swallow the
/// refusal — the same ordering `bird_socket_refusal_precedes_cleanup` pins for `--bird-socket`.
#[test]
fn tpm_flag_refusal_precedes_cleanup() {
    let socket = unused_socket_path();
    let out = tailnetd(&[
        "--cleanup",
        "--encrypt-state",
        "--socket",
        socket.to_str().expect("temp path should be UTF-8"),
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "--cleanup must not mask the --encrypt-state refusal; stderr:\n{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("--encrypt-state is not supported"),
        "should be the flag refusal, not a cleanup result; got:\n{}",
        stderr(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "cleanup should never have run, so it should print nothing"
    );
}

/// Go's `handleTPMFlags` switches on `args.X.v`, so an explicitly-off flag matches no arm and is not
/// even validated. Checked end-to-end: startup continues past both flags (here into `--cleanup`,
/// which exits 0 having found no socket to remove).
#[test]
fn explicitly_disabled_tpm_flags_are_inert() {
    let socket = unused_socket_path();
    let out = tailnetd(&[
        "--cleanup",
        "--encrypt-state=false",
        "--hardware-attestation=f",
        "--socket",
        socket.to_str().expect("temp path should be UTF-8"),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "an explicitly-off TPM flag should be inert, letting --cleanup run; stderr:\n{}",
        stderr(&out)
    );
    let err = stderr(&out);
    assert!(
        !err.contains("--encrypt-state") && !err.contains("--hardware-attestation"),
        "an off flag should produce no complaint at all; got:\n{err}"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("cleanup: nothing to do"),
        "cleanup should have run to completion; got:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// A value Go's `strconv.ParseBool` does not accept is a parse error, not a silent "off". Without
/// this, `--encrypt-state=yes` would read as false and look like the operator got what they asked
/// for.
#[test]
fn a_non_go_boolean_value_is_a_parse_error() {
    let out = tailnetd(&["--encrypt-state=yes"]);
    assert_ne!(
        out.status.code(),
        Some(0),
        "--encrypt-state=yes must not be accepted; stderr:\n{}",
        stderr(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains("strconv.ParseBool") && err.contains("invalid syntax"),
        "should report Go's parse error; got:\n{err}"
    );
}
