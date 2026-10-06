//! `tnet login` must switch to an empty profile before it names or authenticates one.
//!
//! Upstream is `cmd/tailscale/cli/login.go` (`loginCmd.Exec`) @
//! `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8` (v1.102.4): it calls
//! `localClient.SwitchToEmptyProfile` and only then `runUp(ctx, "login", ...)`, which puts
//! `--nickname` in the prefs it starts. So `tailscale login --nickname=work` makes a new profile named
//! `work`, and the one the node was logged in to keeps its name. The daemon half is pinned next to
//! `Backend::switch_to_empty_profile` (src/ipn/mod.rs); what those tests cannot see is the order the
//! built `tnet` sends its requests in, and that a refused switch stops the login. Each test here runs
//! `tnet` against a stub daemon on a Unix socket.

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
        let socket = std::env::temp_dir().join(format!("tnet-li-{}-{n}.sock", std::process::id()));
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
            // `login` refuses over a Tailscale SSH session and reads a key from `$TS_AUTH_KEY`; keep
            // the environment this test runs in from deciding either.
            .env_remove("SSH_CLIENT")
            .env_remove("SUDO_USER")
            .env_remove("TS_AUTH_KEY")
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

fn ok() -> Response {
    Response::Ok {
        message: "ok".to_string(),
    }
}

/// `tnet login --nickname=work`: switch, then name, then authenticate — in that order.
#[test]
fn login_nickname_names_the_profile_it_switched_to() {
    let daemon = StubDaemon::start(ok());
    let out = daemon.tnet(&[
        "login",
        "--authkey",
        "tskey-auth-example",
        "--nickname=work",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let requests = daemon.requests();
    assert!(
        matches!(
            &requests[..],
            [
                Request::SwitchToEmptyProfile,
                Request::Set {
                    nickname: Some(Some(name)),
                    ..
                },
                Request::Up {
                    force_reauth: true,
                    ..
                },
            ] if name == "work"
        ),
        "{requests:?}"
    );
}

/// `tnet login` with no `--nickname` still starts from an empty profile, as Go's does.
#[test]
fn login_without_a_nickname_still_switches_first() {
    let daemon = StubDaemon::start(ok());
    let out = daemon.tnet(&["login", "--authkey", "tskey-auth-example"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let requests = daemon.requests();
    assert!(
        matches!(
            &requests[..],
            [Request::SwitchToEmptyProfile, Request::Up { .. }]
        ),
        "{requests:?}"
    );
}

/// A daemon that refuses the switch (an older one answers `bad request`) stops the login there:
/// nothing is renamed and nothing is authenticated. Go returns the `SwitchToEmptyProfile` error too.
#[test]
fn a_refused_switch_renames_nothing_and_logs_nothing_in() {
    let daemon = StubDaemon::start(Response::Error {
        message: "bad request: unknown variant `switch_to_empty_profile`".to_string(),
    });
    let out = daemon.tnet(&[
        "login",
        "--authkey",
        "tskey-auth-example",
        "--nickname=work",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("switch_to_empty_profile"), "{stderr}");
    let requests = daemon.requests();
    assert!(
        matches!(&requests[..], [Request::SwitchToEmptyProfile]),
        "{requests:?}"
    );
}
