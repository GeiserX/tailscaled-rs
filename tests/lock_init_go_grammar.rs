//! `tnet lock init` must mean what `tailscale lock init` means.
//!
//! Upstream's command is `tailscale lock init [--gen-disablement-for-support] --gen-disablements N
//! <trusted-key>...` (`cmd/tailscale/cli/tailnet-lock.go` @
//! `53a0d659afa51835dd7a9283873cca44261454f8`): the positionals are the tailnet lock **public keys**
//! initially trusted to sign nodes, the command **mints** the disablement secrets itself and prints
//! them once, and `--confirm` gates the whole thing. This fork took a single `<DISABLEMENT-SECRET>`
//! positional and forwarded it as the lock's disablement secret — the same command name with an
//! incompatible argument meaning, so `tnet lock init tlpub:…` did not fail: it gated the tailnet's
//! lock with a value that is, by construction, public.
//!
//! The unit tests next to `plan_lock_init` (src/bin/tnet.rs) pin the decision function itself. What
//! they cannot see is the surface an operator hits: whether clap accepts Go's flags at all, and —
//! the point of this file — **what actually goes on the wire**. Each test runs the built `tnet`
//! against a stub daemon on a Unix socket and inspects the requests it received, so "a trusted key
//! is never sent as a secret" and "the secret printed is the secret sent" are checked end to end
//! rather than argued.
//!
//! HONEST SCOPE: this daemon can initialize only the subset the engine's `tka_init` supports — this
//! node as the sole trusted key, one disablement secret it derives the value from. The rest of Go's
//! grammar is parsed and refused by name (docs/ENGINE_ASKS.md #36), which is what these tests pin;
//! they do not claim the fork can initialize a chosen key set, because it cannot.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tailscaled_rs::localapi::{LockReport, Request, Response};

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
            std::env::temp_dir().join(format!("tnet-lockinit-{}-{n}.sock", std::process::id()));
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

/// A lock status reply saying the lock is off — the state `lock init` is for.
fn lock_off() -> Response {
    Response::Lock(LockReport::default())
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A 64-hex tailnet lock public key. Not a real key; nothing here verifies one.
const TRUSTED_KEY: &str = "tlpub:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

/// Go's flags have to exist on this surface, or a command line copied from upstream dies at
/// argument parsing with clap's wording instead of reaching the command.
#[test]
fn lock_init_help_carries_gos_argument_grammar() {
    let daemon = StubDaemon::start(vec![]);
    let out = daemon.tnet(&["lock", "init", "--help"]);
    assert!(out.status.success(), "--help should exit 0");
    let help = stdout(&out);
    for expected in [
        "--gen-disablements",
        "--gen-disablement-for-support",
        "--confirm",
        "TRUSTED-KEY",
    ] {
        assert!(
            help.contains(expected),
            "`tnet lock init --help` should mention {expected}; got:\n{help}"
        );
    }
}

/// The bug this change is for: a tailnet lock public key — Go's actual positional — must never be
/// forwarded as the disablement secret. The daemon must see the status query and nothing else.
#[test]
fn a_trusted_key_argument_is_refused_and_never_sent_as_a_secret() {
    let daemon = StubDaemon::start(vec![lock_off()]);
    let out = daemon.tnet(&["lock", "init", "--confirm", TRUSTED_KEY]);
    assert!(
        !out.status.success(),
        "an unhonourable key set must fail, not proceed:\n{}",
        stdout(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains("trusted-key set") && err.contains("ENGINE_ASKS.md #36"),
        "the refusal must say what is missing: {err}"
    );
    assert!(
        matches!(daemon.requests().as_slice(), [Request::LockStatus]),
        "nothing may be initialized: {:?}",
        daemon.requests()
    );
}

/// The fork's old positional — a bare hex secret — now parses as what Go would parse it as: a
/// malformed key. It must not silently keep its old meaning.
#[test]
fn the_old_bare_secret_positional_is_read_as_a_malformed_key() {
    let daemon = StubDaemon::start(vec![lock_off()]);
    let out = daemon.tnet(&[
        "lock",
        "init",
        "--confirm",
        "00112233445566778899aabbccddeeff",
    ]);
    assert!(
        !out.status.success(),
        "the old grammar must not silently work"
    );
    let err = stderr(&out);
    assert!(
        err.contains("parsing key 1") && err.contains("tlpub:"),
        "expected Go's key parse error: {err}"
    );
    assert!(
        matches!(daemon.requests().as_slice(), [Request::LockStatus]),
        "{:?}",
        daemon.requests()
    );
}

/// Without `--confirm`, Go prints what it would do and the exact command to re-run, and changes
/// nothing. The re-run line has to be runnable as printed.
#[test]
fn without_confirm_the_command_only_prints_how_to_re_run_it() {
    let daemon = StubDaemon::start(vec![lock_off()]);
    let out = daemon.tnet(&["lock", "init"]);
    assert!(
        out.status.success(),
        "the two-step preview should exit 0: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("If this is correct, please re-run this command with the --confirm flag:"),
        "{text}"
    );
    assert!(
        text.contains("lock init --confirm --gen-disablements 1"),
        "{text}"
    );
    assert!(
        !text.contains("disablement-secret:"),
        "no secret may be minted before the operator confirms: {text}"
    );
    assert!(
        matches!(daemon.requests().as_slice(), [Request::LockStatus]),
        "{:?}",
        daemon.requests()
    );
}

/// An already-enabled lock is refused in one line, before any init is attempted.
#[test]
fn an_enabled_lock_is_refused() {
    let daemon = StubDaemon::start(vec![Response::Lock(LockReport {
        enabled: true,
        head: "AAAA".into(),
        disabled: false,
    })]);
    let out = daemon.tnet(&["lock", "init", "--confirm"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("tailnet lock is already enabled"),
        "{}",
        stderr(&out)
    );
    assert!(
        matches!(daemon.requests().as_slice(), [Request::LockStatus]),
        "{:?}",
        daemon.requests()
    );
}

/// The confirmed path: the command mints the secret itself, sends *that* secret to the daemon, and
/// prints it once — after the daemon accepts. The printed secret and the sent secret must be the
/// same value, or the operator is holding a secret that disables nothing.
#[test]
fn with_confirm_the_minted_secret_is_both_sent_and_printed_once() {
    let daemon = StubDaemon::start(vec![
        lock_off(),
        Response::Ok {
            message: "Tailnet Lock initialized (stub)".into(),
        },
    ]);
    let out = daemon.tnet(&["lock", "init", "--confirm"]);
    assert!(out.status.success(), "{}", stderr(&out));

    let sent = match daemon.requests().as_slice() {
        [Request::LockStatus, Request::LockInit { secret_hex }] => secret_hex.clone(),
        other => panic!("expected a status query then an init, got {other:?}"),
    };
    assert_eq!(
        sent.len(),
        64,
        "the minted secret must be 32 bytes of hex, like Go's: {sent:?}"
    );
    assert!(
        sent.chars().all(|c| c.is_ascii_hexdigit()),
        "{sent:?} must be hex"
    );

    let text = stdout(&out);
    assert!(
        text.contains(&format!("disablement-secret:{sent}")),
        "the printed secret must be the one sent: printed\n{text}\nsent {sent}"
    );
    assert!(text.contains("they WILL NOT be shown again"), "{text}");
    assert!(
        text.contains("You are initializing tailnet lock with the following trusted signing keys:"),
        "the confirmed path prints the trusted keys too, as upstream does: {text}"
    );
    assert!(text.contains("Initialization complete."), "{text}");
}

/// A supplied secret is the one capability the old positional had; it survives under a name that
/// cannot be confused with Go's positional, and it reaches the daemon verbatim.
#[test]
fn a_supplied_disablement_secret_reaches_the_daemon_verbatim() {
    let daemon = StubDaemon::start(vec![
        lock_off(),
        Response::Ok {
            message: "Tailnet Lock initialized (stub)".into(),
        },
    ]);
    let out = daemon.tnet(&[
        "lock",
        "init",
        "--confirm",
        "--disablement-secret",
        "00ff10",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    match daemon.requests().as_slice() {
        [Request::LockStatus, Request::LockInit { secret_hex }] => {
            assert_eq!(secret_hex, "00ff10");
        }
        other => panic!("expected a status query then an init, got {other:?}"),
    }
}
