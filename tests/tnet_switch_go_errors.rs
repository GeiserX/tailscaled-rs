//! `tnet switch` must print an unmatched target's refusal the way `tailscale switch` prints it.
//!
//! Upstream is `cmd/tailscale/cli/switch.go` (`switchProfile`, `removeProfile`) @
//! `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8` (v1.102.4). Both run `matchProfile` and, on a miss,
//! call `errf("No profile named %q\n", args[0])` then `os.Exit(1)`: stderr is that line and nothing
//! else. The daemon's wording is pinned next to `switch_profile`/`delete_profile` (src/ipn/mod.rs);
//! what those tests cannot see is the process — that `tnet` adds no `error: ` in front, exits 1 and
//! prints nothing on stdout. Each test here runs the built `tnet` against a stub daemon on a Unix
//! socket.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tailscaled_rs::localapi::{Request, Response};

/// Per-process-unique counter so tests running in parallel never share a socket path.
static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// A stub daemon: it answers one fixed reply per connection and records every request it was sent.
struct StubDaemon {
    socket: PathBuf,
    seen: Arc<Mutex<Vec<Request>>>,
}

impl StubDaemon {
    fn start(reply: Response) -> StubDaemon {
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let socket = std::env::temp_dir().join(format!("tnet-sw-{}-{n}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("bind the stub daemon socket");
        let seen = Arc::new(Mutex::new(Vec::new()));

        let thread_seen = Arc::clone(&seen);
        std::thread::spawn(move || {
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
                let mut body = serde_json::to_vec(&reply).expect("serialize the stub reply");
                body.push(b'\n');
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });

        StubDaemon { socket, seen }
    }

    fn tnet(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tnet"))
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .output()
            .expect("the `tnet` binary built for this test should run")
    }

    fn requests(&self) -> Vec<Request> {
        self.seen.lock().expect("stub request log").clone()
    }
}

impl Drop for StubDaemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn no_profile_named(target: &str) -> Response {
    Response::Error {
        message: format!("No profile named \"{target}\""),
    }
}

/// `tnet switch wrok`: stderr is exactly Go's line, exit 1, stdout empty.
#[test]
fn switch_to_an_unmatched_target_prints_gos_bare_refusal() {
    let daemon = StubDaemon::start(no_profile_named("wrok"));
    let out = daemon.tnet(&["switch", "wrok"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert_eq!(stderr, "No profile named \"wrok\"\n");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    let requests = daemon.requests();
    assert!(
        matches!(&requests[..], [Request::SwitchProfile { target }] if target == "wrok"),
        "{requests:?}"
    );
}

/// `tnet switch remove nonesuch`: Go's `removeProfile` refuses with the same bare line.
#[test]
fn remove_of_an_unmatched_target_prints_gos_bare_refusal() {
    let daemon = StubDaemon::start(no_profile_named("nonesuch"));
    let out = daemon.tnet(&["switch", "remove", "nonesuch"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert_eq!(stderr, "No profile named \"nonesuch\"\n");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    let requests = daemon.requests();
    assert!(
        matches!(&requests[..], [Request::DeleteProfile { target }] if target == "nonesuch"),
        "{requests:?}"
    );
}
