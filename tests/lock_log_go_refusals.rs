//! `tnet lock log` must refuse where `tailscale lock log` refuses.
//!
//! Upstream is `cmd/tailscale/cli/tailnet-lock.go` (`nlLogArgs`, `runTailnetLockLog`,
//! `printTailnetLockLog`) @ `53a0d659afa51835dd7a9283873cca44261454f8`, with the flag's value type in
//! `cmd/tailscale/cli/jsonoutput/jsonoutput.go`. Two of its behaviours are the point of this file:
//!
//! 1. `runTailnetLockLog` reads the lock status FIRST and returns
//!    `errors.New("Tailnet Lock is not enabled")` before it asks for the log — a non-zero exit with
//!    nothing on stdout. A build that instead prints an empty history and exits 0 turns
//!    `tnet lock log` from a check into a rubber stamp: a script running it to assert the lock is on
//!    sees success on a node where it is off.
//! 2. `-json` is a `jsonoutput.SchemaVersion`, not a bool. `--json` and `--json=1` both select
//!    schema version 1, `--json=false` is the human form, and every other version is refused with
//!    `unrecognised version: %d`. The version-1 payload carries the `ResponseEnvelope`'s
//!    `SchemaVersion` field.
//!
//! The unit tests next to `format_lock_log` (src/bin/tnet.rs) pin the rendering and refusal decisions
//! themselves. What they cannot see is the surface an operator hits: whether clap accepts Go's flag
//! spellings at all, what the process exit status is, and whether a refusal reaches the daemon before
//! it fires. Each test here runs the built `tnet` against a stub daemon on a Unix socket and inspects
//! both the process result and the requests the daemon actually received.
//!
//! HONEST SCOPE: the version-1 payload under the envelope is fork-specific, not Go's
//! `Messages`/`AUM` shape — this daemon has no AUM CBOR decoder, so it cannot fill Go's expanded
//! fields. These tests pin the envelope and the flag semantics, not upstream's field names.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tailscaled_rs::localapi::{LockLogEntry, LockLogReport, Request, Response};

/// Per-process-unique counter so tests running in parallel never share a socket path.
static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// A stub daemon: it answers a fixed queue of replies, one per connection (the CLI opens a fresh
/// connection per request), and records every request it was sent.
struct StubDaemon {
    socket: PathBuf,
    seen: Arc<Mutex<Vec<Request>>>,
}

impl StubDaemon {
    /// Start the stub, serving `replies` in order on a socket of its own.
    fn start(replies: Vec<Response>) -> StubDaemon {
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let socket =
            std::env::temp_dir().join(format!("tnet-locklog-{}-{n}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("bind the stub daemon socket");
        let seen = Arc::new(Mutex::new(Vec::new()));

        let thread_seen = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut replies = replies.into_iter();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut line = String::new();
                if BufReader::new(stream.try_clone().expect("clone the accepted stub stream"))
                    .read_line(&mut line)
                    .is_err()
                {
                    break;
                }
                if let Ok(req) = serde_json::from_str::<Request>(line.trim()) {
                    thread_seen.lock().expect("stub request log").push(req);
                }
                let reply = replies.next().unwrap_or(Response::Error {
                    message: "stub daemon: no reply queued for this request".into(),
                });
                let mut body = serde_json::to_vec(&reply).expect("serialize the stub reply");
                body.push(b'\n');
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });

        StubDaemon { socket, seen }
    }

    /// Run the built `tnet` against this stub.
    fn tnet(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tnet"))
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .output()
            .expect("the `tnet` binary built for this test should run")
    }

    /// The requests the stub was sent, in order.
    fn requests(&self) -> Vec<Request> {
        self.seen.lock().expect("stub request log").clone()
    }
}

impl Drop for StubDaemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A log reply from a node where tailnet lock is off — the daemon reports it, it is not an error.
fn lock_off() -> Response {
    Response::LockLog(LockLogReport::default())
}

/// A log reply from a node where the lock is on and one update has synced.
fn one_update() -> Response {
    Response::LockLog(LockLogReport {
        enabled: true,
        entries: vec![LockLogEntry {
            hash: "AAAAQ".into(),
            change: "add-key".into(),
            signer_key_ids: vec!["tlpub:aabb".into()],
            raw: "a1626b76".into(),
        }],
    })
}

/// Go's gate: lock off means a non-zero exit and no log, not an empty history and success. This is
/// the whole difference between `tnet lock log` being usable as an assertion and not.
#[test]
fn a_lock_disabled_node_is_refused_not_reported() {
    let daemon = StubDaemon::start(vec![lock_off()]);
    let out = daemon.tnet(&["lock", "log"]);
    assert!(
        !out.status.success(),
        "lock off must exit non-zero; got {:?} with stdout {:?}",
        out.status,
        stdout(&out)
    );
    assert!(
        stderr(&out).contains("Tailnet Lock is not enabled"),
        "{}",
        stderr(&out)
    );
    // No history, not even an empty one: a script parsing stdout must get nothing to parse.
    assert_eq!(stdout(&out), "", "nothing may be printed on the refusal");
}

/// The refusal holds under `--json` too — Go checks the status before it reaches the printer, so
/// there is no output mode in which a lock-disabled node reports success.
#[test]
fn a_lock_disabled_node_is_refused_under_json_as_well() {
    let daemon = StubDaemon::start(vec![lock_off()]);
    let out = daemon.tnet(&["lock", "log", "--json"]);
    assert!(!out.status.success(), "{:?}", out.status);
    assert!(
        stderr(&out).contains("Tailnet Lock is not enabled"),
        "{}",
        stderr(&out)
    );
    assert_eq!(stdout(&out), "");
}

/// `--json=1` is the spelling a command line copied from Go carries. It has to parse, and to mean
/// exactly what bare `--json` means.
#[test]
fn json_takes_gos_schema_version_as_well_as_the_bare_flag() {
    for flag in ["--json", "--json=1", "--json=true"] {
        let daemon = StubDaemon::start(vec![one_update()]);
        let out = daemon.tnet(&["lock", "log", flag]);
        assert!(out.status.success(), "{flag}: {}", stderr(&out));
        let v: serde_json::Value =
            serde_json::from_str(&stdout(&out)).unwrap_or_else(|e| panic!("{flag}: {e}"));
        // Go's `jsonoutput.ResponseEnvelope`: the schema the payload below it conforms to.
        assert_eq!(v["SchemaVersion"], serde_json::json!("1"), "{flag}");
        assert_eq!(
            v["entries"][0]["hash"],
            serde_json::json!("AAAAQ"),
            "{flag}"
        );
    }
}

/// `--json=false` clears the flag, exactly as in Go: the human form, not an error and not JSON.
#[test]
fn json_false_is_the_human_form() {
    let daemon = StubDaemon::start(vec![one_update()]);
    let out = daemon.tnet(&["lock", "log", "--json=false"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).starts_with("update AAAAQ (add-key)"),
        "{}",
        stdout(&out)
    );
}

/// Any version other than 1 is refused by number, so a script pinning a schema this build does not
/// serve hears about it instead of silently getting version 1.
#[test]
fn an_unrecognised_schema_version_is_refused_by_number() {
    for (flag, want) in [
        ("--json=2", "unrecognised version: 2"),
        ("--json=0", "unrecognised version: 0"),
    ] {
        let daemon = StubDaemon::start(vec![one_update()]);
        let out = daemon.tnet(&["lock", "log", flag]);
        assert!(!out.status.success(), "{flag}: {:?}", out.status);
        assert!(stderr(&out).contains(want), "{flag}: {}", stderr(&out));
        assert_eq!(stdout(&out), "", "{flag}");
    }
}

/// A `--json` value that is neither an integer nor a boolean fails at flag parsing, before the
/// command runs — so the daemon is never contacted, exactly as in Go where `flag.Parse` precedes
/// `Exec`.
#[test]
fn an_unparseable_json_value_fails_before_the_daemon_is_contacted() {
    let daemon = StubDaemon::start(vec![one_update()]);
    let out = daemon.tnet(&["lock", "log", "--json=garbage"]);
    assert!(!out.status.success(), "{:?}", out.status);
    assert!(stderr(&out).contains("parse error"), "{}", stderr(&out));
    assert!(
        daemon.requests().is_empty(),
        "no request may be sent: {:?}",
        daemon.requests()
    );
}

/// Go types the flag with `IsBoolFlag`, so `--json 1` does NOT consume the `1`; `require_equals`
/// gives the same shape here. The `1` is left over as a stray argument rather than silently read as
/// a schema version.
#[test]
fn a_space_separated_json_value_is_not_swallowed() {
    let daemon = StubDaemon::start(vec![one_update()]);
    let out = daemon.tnet(&["lock", "log", "--json", "1"]);
    assert!(
        !out.status.success(),
        "a stray positional must not be accepted: {}",
        stdout(&out)
    );
    assert!(daemon.requests().is_empty(), "{:?}", daemon.requests());
}

/// The command's own help has to carry Go's flag grammar, or a `--json=1` copied from upstream dies
/// at argument parsing with clap's wording instead of reaching the command.
#[test]
fn lock_log_help_advertises_the_versioned_json_flag() {
    let daemon = StubDaemon::start(vec![]);
    let out = daemon.tnet(&["lock", "log", "--help"]);
    assert!(out.status.success(), "--help should exit 0");
    let text = stdout(&out);
    assert!(text.contains("--json"), "{text}");
    assert!(text.contains("--limit"), "{text}");
}
