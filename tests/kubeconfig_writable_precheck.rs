//! `tnet configure kubeconfig` must refuse a kubeconfig it cannot write *before* it reads or merges
//! one, and it must create the whole directory tree the target needs.
//!
//! Both are Go's, from `runConfigureKubeconfig`/`setKubeconfigForPeer`. Go resolves the peer, then
//! calls `checkKubeconfigWritable(kubeconfig)` — a walk from the target up to the first component
//! that exists, probed for writability — and returns `cannot write kubeconfig at %q: %w` having
//! touched nothing. Then `setKubeconfigForPeer` calls `os.MkdirAll(dir, 0755)`, which creates every
//! missing ancestor. This port had neither: an unwritable `~/.kube/config` surfaced at the `open()`
//! after the merge was already computed and was reported as "opening kubeconfig … for writing", and
//! a `$KUBECONFIG` two directories deep failed with a creating-directory error where Go writes the
//! file.
//!
//! The unit tests next to [`check_kubeconfig_writable`](../src/bin/tnet.rs) pin the walk itself.
//! What they cannot see is whether the command WIRES it in — whether the precheck runs at all, and
//! runs before the merge. That needs the real binary, so this runs it against a stub daemon that
//! speaks the LocalAPI's one-line JSON, the same way `tests/tnet_down_reason_and_risk.rs` does.
//!
//! Upstream: `cmd/tailscale/cli/configure-kube.go` @
//! `53a0d659afa51835dd7a9283873cca44261454f8`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

/// The peer the stub daemon advertises, and the argument every invocation resolves against it.
const PEER: &str = "k8s-proxy.tail0123.ts.net";

/// One `Running` status carrying that peer, so `configure kubeconfig k8s-proxy` resolves from the
/// netmap alone and makes exactly one round trip (no `dns status` fallback).
fn status_reply() -> String {
    format!(
        r#"{{"kind":"status","state":"Running","peers":[{{"name":"{PEER}","ipv4":"100.100.0.7","is_exit_node":false}}]}}"#
    )
}

/// Kubeconfig content that is readable but cannot be parsed: the flow sequence is never closed.
///
/// The precheck test needs content the merge chokes on, so that a run which reads before it checks
/// fails with a *different* error than the one that test asserts.
const MALFORMED: &str = "apiVersion: v1\nclusters: [\n";

/// A scratch directory owned by this test alone, keyed by name + pid.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tnet-kubeprecheck-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the scratch directory");
    dir
}

/// A stand-in daemon serving exactly one connection of the LocalAPI's one-line JSON protocol: read
/// the request line, write the reply, close. Accept is polled against a deadline, so a CLI that
/// never connects fails the assertion that follows instead of hanging the test.
fn stub_daemon(name: &str, reply: String) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "tnet-kubeprecheck-{name}-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind the stub daemon socket");
    listener
        .set_nonblocking(true)
        .expect("stub listener must be pollable");
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("stub daemon accept failed: {e}"),
            }
        };
        stream
            .set_nonblocking(false)
            .expect("stub connection must block for the request line");
        let mut line = String::new();
        let _ = BufReader::new(stream.try_clone().expect("clone the stub connection"))
            .read_line(&mut line);
        let _ = writeln!(stream, "{reply}");
        let _ = stream.flush();
    });
    path
}

/// Run the built `tnet` against `socket` with `$KUBECONFIG` pointed at `kubeconfig`.
fn configure_kubeconfig(socket: &Path, kubeconfig: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tnet"))
        .arg("--socket")
        .arg(socket)
        .args(["configure", "kubeconfig", "k8s-proxy"])
        .env("KUBECONFIG", kubeconfig)
        .output()
        .expect("the `tnet` binary built for this test should run")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn an_unwritable_kubeconfig_is_refused_before_the_merge() {
    let dir = scratch("unwritable");
    let kube = dir.join("kube");
    std::fs::create_dir(&kube).unwrap();
    // A kubeconfig that already exists and that the user cannot write. Its content is readable but
    // NOT parseable — an unterminated flow sequence — and that is what makes this an ordering test
    // rather than a writability test. Valid content would let a regression that reads and merges
    // before the precheck still end in `cannot write kubeconfig at`: the merge would succeed and the
    // open would fail, so the assertions below would pass over the very reordering they exist to
    // catch. With MALFORMED content the merge cannot succeed, so any run that reads the file before
    // the precheck dies in `update_kubeconfig` with `invalid kubeconfig` instead.
    // `a_readable_but_malformed_kubeconfig_is_refused_by_the_merge` pins that second half.
    let path = kube.join("config");
    let before = MALFORMED;
    std::fs::write(&path, before).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    if std::fs::OpenOptions::new().write(true).open(&path).is_ok() {
        // Running as root, for which 0400 is not a refusal. Nothing to assert.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    let socket = stub_daemon("unwritable", status_reply());
    let out = configure_kubeconfig(&socket, &path);
    let err = stderr(&out);

    assert!(
        !out.status.success(),
        "an unwritable kubeconfig must fail:\n{err}"
    );
    assert!(
        err.contains("cannot write kubeconfig at"),
        "Go's words are `cannot write kubeconfig at %q`; got:\n{err}"
    );
    assert!(
        !err.contains("opening kubeconfig"),
        "the failure must come from the precheck, not from the open after the merge:\n{err}"
    );
    assert!(
        !err.contains("invalid kubeconfig"),
        "the precheck must run BEFORE the file is read — this is the merge's refusal, so the read \
         happened first:\n{err}"
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        before,
        "a refused run must leave the kubeconfig byte-identical"
    );
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_kubeconfig_several_directories_deep_is_written() {
    // Go's `os.MkdirAll(dir, 0755)`: every missing ancestor is created, so this writes the file
    // rather than reporting the missing parent.
    let dir = scratch("tree");
    let path = dir.join("new/nested/config");

    let socket = stub_daemon("tree", status_reply());
    let out = configure_kubeconfig(&socket, &path);
    let err = stderr(&out);

    assert!(
        out.status.success(),
        "a kubeconfig two directories deep should be created, not refused:\n{err}"
    );
    let written = std::fs::read_to_string(&path).expect("the kubeconfig should have been written");
    assert!(
        written.contains(&format!("server: https://{PEER}")),
        "the resolved peer should be the cluster's server:\n{written}"
    );
    assert!(
        written.contains(&format!("current-context: {PEER}")),
        "the new context should be current:\n{written}"
    );
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "kubeconfig must be written 0600, got {mode:o}");
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_readable_but_malformed_kubeconfig_is_refused_by_the_merge() {
    // The other half of `an_unwritable_kubeconfig_is_refused_before_the_merge`: that test only
    // distinguishes precheck-then-merge from merge-then-precheck because `MALFORMED` is content the
    // merge genuinely refuses. Pin that here, through the same binary and the same code path, with
    // the only difference being that this kubeconfig IS writable. If the parser ever grows lenient
    // enough to accept `MALFORMED`, this fails and says so instead of quietly hollowing out the
    // ordering assertion next door.
    let dir = scratch("malformed");
    let path = dir.join("config");
    std::fs::write(&path, MALFORMED).unwrap();

    let socket = stub_daemon("malformed", status_reply());
    let out = configure_kubeconfig(&socket, &path);
    let err = stderr(&out);

    assert!(
        !out.status.success(),
        "a kubeconfig that cannot be parsed must not be merged into:\n{err}"
    );
    assert!(
        err.contains("invalid kubeconfig"),
        "the merge must be what refuses it, in Go's `errInvalidKubeconfig` words; got:\n{err}"
    );
    assert!(
        !err.contains("cannot write kubeconfig at"),
        "this file is writable, so the precheck must have passed it:\n{err}"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        MALFORMED,
        "a refused merge must leave the kubeconfig byte-identical"
    );
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_dir_all(&dir);
}
