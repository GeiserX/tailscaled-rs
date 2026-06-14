//! Headscale-backed end-to-end test (tsd-7ie): a real join → netmap → down flow against a
//! self-hosted [headscale](https://github.com/juanfont/headscale) control server — ToS-clean,
//! never touching production Tailscale.
//!
//! ## Why this is safe for offline CI
//!
//! This test is BOTH `#[ignore]` (so `cargo test` / CI's `cargo test --all-targets` compiles it but
//! never runs it) AND env-gated: it only does anything when `TAILNETD_HS_URL` and
//! `TAILNETD_HS_AUTHKEY` are set (by someone who has stood up the compose stack in
//! `test-support/headscale/`). With those vars absent it early-returns with an explanation, so even
//! `cargo test -- --ignored` (which would un-skip the `#[ignore]`) makes no network call and cannot
//! fail. The default `cargo test` regime stays fully offline.
//!
//! ## Running it (the full local loop is in `docs/TESTING.md`)
//!
//! ```bash
//! export TS_RS_EXPERIMENT=this_is_unstable_software
//!
//! # 1. Start the self-hosted control server.
//! docker compose -f test-support/headscale/docker-compose.yml up -d
//!
//! # 2. Mint a user + a reusable pre-auth key. In 0.28.0 `preauthkeys --user` is the numeric user
//! #    ID (not the name), so resolve it from `users list` first.
//! docker compose -f test-support/headscale/docker-compose.yml exec headscale \
//!     headscale users create test
//! UID=$(docker compose -f test-support/headscale/docker-compose.yml exec -T headscale \
//!     headscale users list -o json | python3 -c "import sys,json; print(next(u['id'] for u in json.load(sys.stdin) if u['name']=='test'))")
//! KEY=$(docker compose -f test-support/headscale/docker-compose.yml exec -T headscale \
//!     headscale preauthkeys create --user "$UID" --reusable --expiration 24h)
//!
//! # 3. Point the test at it and run the (otherwise-ignored) e2e.
//! export TAILNETD_HS_URL=http://localhost:8080
//! export TAILNETD_HS_AUTHKEY="$KEY"
//! cargo test --test headscale_e2e -- --ignored --nocapture
//! ```
//!
//! Tokens come from the environment only — none are ever read from or written to a committed file.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tailscaled_rs::ipn::Backend;

/// Per-process-unique counter so a re-run never collides on a temp path.
static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// A unique temp state directory for one run (`/tmp/tailnetd-hs-e2e-<pid>-<n>`).
fn unique_state_dir() -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("tailnetd-hs-e2e-{}-{}", std::process::id(), n))
}

/// Real end-to-end against a self-hosted Headscale control server.
///
/// `#[ignore]` keeps it out of the default `cargo test` run; the env gate below additionally makes
/// it a clean *skip* (not a failure) when the control server / key are not provided — so it is inert
/// under `cargo test -- --ignored` too, and only truly executes when an operator has set both vars.
#[tokio::test]
#[ignore = "requires a running headscale (test-support/headscale) + TAILNETD_HS_URL/TAILNETD_HS_AUTHKEY; see docs/TESTING.md"]
async fn headscale_join_netmap_down() {
    // Env gate: both the control URL and a pre-auth key must be present, or we skip cleanly.
    let (hs_url, hs_authkey) = match (
        std::env::var("TAILNETD_HS_URL"),
        std::env::var("TAILNETD_HS_AUTHKEY"),
    ) {
        (Ok(url), Ok(key)) if !url.is_empty() && !key.is_empty() => (url, key),
        _ => {
            eprintln!(
                "SKIP headscale_join_netmap_down: set TAILNETD_HS_URL and TAILNETD_HS_AUTHKEY to \
                 run this. Bring up the control server with \
                 `docker compose -f test-support/headscale/docker-compose.yml up -d`, then create a \
                 user + reusable pre-auth key and export the two env vars. The exact commands \
                 (headscale 0.28's `--user` takes a numeric id) are in docs/TESTING.md and \
                 test-support/headscale/README.md."
            );
            return;
        }
    };

    // The engine refuses to operate without this acknowledgement; surface it as a clear failure
    // rather than a confusing engine-internal error if the operator forgot to export it.
    assert!(
        std::env::var("TS_RS_EXPERIMENT").as_deref() == Ok("this_is_unstable_software"),
        "the engine requires TS_RS_EXPERIMENT=this_is_unstable_software; export it before running \
         this test (see docs/TESTING.md)"
    );

    // Fresh, isolated state dir so the run starts from no prefs / no node key.
    let state_dir = unique_state_dir();
    let _ = tokio::fs::remove_dir_all(&state_dir).await;
    tokio::fs::create_dir_all(&state_dir)
        .await
        .expect("create temp state dir");

    let mut backend = Backend::load(&state_dir)
        .await
        .expect("Backend::load (offline file read) must succeed");

    // Bring the node up, pointing it at the self-hosted control server. Passing `control_url`
    // through `up` persists it into `prefs.control_url`, which is the highest-precedence control
    // source in `Backend::build_config` (prefs > TS_CONTROL_URL > engine default) — so this drives
    // the daemon's real custom-control-server path end-to-end. The auth key is wrapped in a
    // `SecretString` (zeroized on drop, never logged), exactly as the daemon does.
    let authkey = secrecy::SecretString::from(hs_authkey);
    backend
        .up(
            Some(authkey),
            tailscaled_rs::ipn::UpOptions {
                hostname: Some("tailscaled-rs-hs-e2e".to_string()),
                control_url: Some(hs_url.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("up() against headscale {hs_url} failed: {e:?}"));

    // Poll status until the netmap arrives and the node is Running with a self address. A real
    // register + first map poll against headscale typically settles within a few seconds; give it a
    // bounded window so a wedged join fails the test instead of hanging forever.
    //
    // IMPORTANT: wait for the self ADDRESS, not merely for `state == "Running"`. The daemon publishes
    // `Running` the instant the netmap stream attaches, but the self-node address is filled on the
    // *next* status poll (documented in `Backend::status`: "On timeout we report Running with no
    // addresses yet — the next poll fills them"). Breaking on the first `Running` therefore races that
    // fill window and can capture `self_ipv4 == None` even though the node is healthy. So we keep
    // polling until the address is present (the true "netmap arrived" signal), recording `last_state`
    // for the failure message either way.
    let mut last_state = String::new();
    let mut self_ipv4: Option<String> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline {
        let report = backend.status().await;
        last_state = report.state.clone();
        // Settle condition: Running AND the self address has landed in the netmap projection.
        if report.state == "Running" && report.self_ipv4.is_some() {
            self_ipv4 = report.self_ipv4.clone();
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Capture the assertion outcome but ALWAYS tear the node down + clean up before asserting, so a
    // failure can't leave a registered node or a temp dir behind.
    let reached_running = last_state == "Running";
    let self_addr = self_ipv4.clone();

    backend.down().await.expect("down() should succeed");
    backend.shutdown().await;
    let _ = tokio::fs::remove_dir_all(&state_dir).await;

    assert!(
        reached_running,
        "node never reached Running against headscale {hs_url} within 60s (last state: {last_state})"
    );
    let addr = self_addr.expect("a Running node must report a self tailnet IPv4");
    // Headscale hands out addresses from the canonical Tailscale CGNAT range (100.64.0.0/10, per
    // the prefixes in test-support/headscale/config.yaml); a bare sanity check that we got a real
    // dotted-quad self address, not an empty/placeholder string.
    assert!(
        addr.parse::<std::net::Ipv4Addr>().is_ok(),
        "self address {addr:?} should be a valid IPv4 from the tailnet pool"
    );
}

/// Live `debug capture` test: bring a node up against headscale, capture the dataplane to a temp pcap
/// for a couple seconds while driving self-loopback traffic, then assert the file is a valid pcap (the
/// classic LE magic `0xA1B2C3D4`) larger than the 24-byte global header (i.e. ≥1 record was written).
/// Same `#[ignore]` + env gate as the join test — compiles in CI, runs only against a real tailnet.
#[tokio::test]
#[ignore = "requires a running headscale (test-support/headscale) + TAILNETD_HS_URL/TAILNETD_HS_AUTHKEY; see docs/TESTING.md"]
async fn headscale_debug_capture_writes_pcap() {
    let (hs_url, hs_authkey) = match (
        std::env::var("TAILNETD_HS_URL"),
        std::env::var("TAILNETD_HS_AUTHKEY"),
    ) {
        (Ok(u), Ok(k)) if !u.is_empty() && !k.is_empty() => (u, k),
        _ => {
            eprintln!(
                "SKIP headscale_debug_capture_writes_pcap: set TAILNETD_HS_URL and \
                 TAILNETD_HS_AUTHKEY to run it (see docs/TESTING.md)"
            );
            return;
        }
    };
    if std::env::var("TS_RS_EXPERIMENT").as_deref() != Ok("this_is_unstable_software") {
        eprintln!("SKIP headscale_debug_capture_writes_pcap: export TS_RS_EXPERIMENT");
        return;
    }

    let state_dir = unique_state_dir();
    let _ = tokio::fs::remove_dir_all(&state_dir).await;
    tokio::fs::create_dir_all(&state_dir)
        .await
        .expect("state dir");
    let mut backend = Backend::load(&state_dir).await.expect("Backend::load");

    let authkey = secrecy::SecretString::from(hs_authkey);
    backend
        .up(
            Some(authkey),
            tailscaled_rs::ipn::UpOptions {
                hostname: Some("tailscaled-rs-hs-capture".to_string()),
                control_url: Some(hs_url.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("up() against headscale {hs_url} failed: {e:?}"));

    // Wait for Running AND the self address (the datapath is only truly live once the netmap has
    // arrived — `Running` is published a beat earlier; see the note in the join test). We need the
    // self address both to know the datapath is live and to ping it (below).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut running = false;
    let mut self_ipv4: Option<String> = None;
    while tokio::time::Instant::now() < deadline {
        let report = backend.status().await;
        if report.state == "Running" && report.self_ipv4.is_some() {
            running = true;
            self_ipv4 = report.self_ipv4.clone();
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Capture to a temp pcap for ~4s. The engine writes the 24-byte global header on start; dataplane
    // traffic in the window adds records. A freshly-joined, PEERLESS node (this headscale has no other
    // nodes) generates little incidental dataplane traffic, so we DRIVE deterministic traffic: a
    // `ping` puts real ICMP/disco packets onto the tapped dataplane (the capture taps the dataplane
    // packet path, `tstun.Wrapper`-style — empirically a ping during capture grows the pcap past the
    // header even when the ping gets no reply, because the OUTBOUND packets are recorded). MagicDNS
    // queries do NOT suffice (they are answered above the dataplane tap), so ping is the right driver.
    let pcap = state_dir.join("capture.pcap");
    let outcome = if running {
        if let Some(dev) = backend.device_handle() {
            // Spawn the capture, then ping during the window so the dataplane carries packets.
            let dev_cap = std::sync::Arc::clone(&dev);
            let pcap_path = pcap.to_str().unwrap().to_string();
            let cap_handle = tokio::spawn(async move {
                tailscaled_rs::ipn::Backend::debug_capture(&dev_cap, &pcap_path, 4).await
            });
            // Let the capture install its hook, then drive ICMP across the dataplane. Pinging the
            // node's own tailnet IP (and a likely pool address) emits real packets regardless of any
            // reply — that is what reaches the capture tap.
            tokio::time::sleep(Duration::from_millis(400)).await;
            let targets: Vec<String> = self_ipv4
                .iter()
                .cloned()
                .chain(["100.64.0.1".to_string()])
                .collect();
            for _ in 0..3 {
                for t in &targets {
                    let _ = Backend::ping(&dev, t, Some(500)).await;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            cap_handle
                .await
                .unwrap_or(tailscaled_rs::localapi::Response::Error {
                    message: "capture task panicked".into(),
                })
        } else {
            tailscaled_rs::localapi::Response::Error {
                message: "no device handle".into(),
            }
        }
    } else {
        tailscaled_rs::localapi::Response::Error {
            message: "never reached Running".into(),
        }
    };

    // Read the file back BEFORE teardown.
    let bytes = tokio::fs::read(&pcap).await.unwrap_or_default();

    backend.down().await.expect("down()");
    backend.shutdown().await;
    let _ = tokio::fs::remove_dir_all(&state_dir).await;

    assert!(
        running,
        "node never reached Running against headscale {hs_url}"
    );
    assert!(
        matches!(outcome, tailscaled_rs::localapi::Response::Ok { .. }),
        "debug_capture should succeed on a Running node, got {outcome:?}"
    );
    // Classic pcap global header is 24 bytes starting with the LE magic 0xA1B2C3D4.
    assert!(
        bytes.len() >= 24,
        "pcap must contain at least the 24-byte global header, got {} bytes",
        bytes.len()
    );
    assert_eq!(
        &bytes[0..4],
        &[0xD4, 0xC3, 0xB2, 0xA1],
        "pcap must start with the classic little-endian magic 0xA1B2C3D4"
    );
    assert!(
        bytes.len() > 24,
        "expected at least one captured record beyond the global header (got exactly the header)"
    );
}

/// Live `rebind` test (what the link-change monitor calls on a host network-path change): bring a
/// node up against headscale, call `Device::rebind()` directly, and assert it returns Ok and the
/// node stays Running — rebind must be non-disruptive (magicsock re-binds its sockets without
/// tearing down the registration). Same `#[ignore]` + env gate as the join test.
#[tokio::test]
#[ignore = "requires a running headscale (test-support/headscale) + TAILNETD_HS_URL/TAILNETD_HS_AUTHKEY; see docs/TESTING.md"]
async fn headscale_rebind_is_non_disruptive() {
    let (hs_url, hs_authkey) = match (
        std::env::var("TAILNETD_HS_URL"),
        std::env::var("TAILNETD_HS_AUTHKEY"),
    ) {
        (Ok(u), Ok(k)) if !u.is_empty() && !k.is_empty() => (u, k),
        _ => {
            eprintln!(
                "SKIP headscale_rebind_is_non_disruptive: set TAILNETD_HS_URL and \
                 TAILNETD_HS_AUTHKEY to run it (see docs/TESTING.md)"
            );
            return;
        }
    };
    if std::env::var("TS_RS_EXPERIMENT").as_deref() != Ok("this_is_unstable_software") {
        eprintln!("SKIP headscale_rebind_is_non_disruptive: export TS_RS_EXPERIMENT");
        return;
    }

    let state_dir = unique_state_dir();
    let _ = tokio::fs::remove_dir_all(&state_dir).await;
    tokio::fs::create_dir_all(&state_dir)
        .await
        .expect("state dir");
    let mut backend = Backend::load(&state_dir).await.expect("Backend::load");

    backend
        .up(
            Some(secrecy::SecretString::from(hs_authkey)),
            tailscaled_rs::ipn::UpOptions {
                hostname: Some("tailscaled-rs-hs-rebind".to_string()),
                control_url: Some(hs_url.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("up() against headscale {hs_url} failed: {e:?}"));

    // Wait for Running.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut running = false;
    while tokio::time::Instant::now() < deadline {
        if backend.status().await.state == "Running" {
            running = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Call rebind (what the link monitor does on a network change) and check it's non-disruptive.
    let rebind_ok = if running {
        match backend.device_handle() {
            Some(dev) => dev.rebind().await.is_ok(),
            None => false,
        }
    } else {
        false
    };
    // The node must remain Running after a rebind (it re-binds sockets, not the registration).
    let still_running = running && backend.status().await.state == "Running";

    backend.down().await.expect("down()");
    backend.shutdown().await;
    let _ = tokio::fs::remove_dir_all(&state_dir).await;

    assert!(
        running,
        "node never reached Running against headscale {hs_url}"
    );
    assert!(
        rebind_ok,
        "Device::rebind() should return Ok on a Running node"
    );
    assert!(
        still_running,
        "rebind must be non-disruptive — the node should stay Running afterward"
    );
}

/// Live `set` test (the live-vs-rebuild reconcile dispatch): bring a node up against headscale, then
/// drive two `set`s and assert each takes the right reconcile path against the *real* engine:
///
/// 1. **Live-applicable pref** (`--hostname`): `Backend::set` applies it through the engine's runtime
///    setter (`set_hostname`) with NO reconnect, so the node must STAY Running with the SAME tailnet
///    IP — the registration is never torn down. (This is the path manually proven on a Mac Mini:
///    hostname changes live, IP unchanged, node stays Running.)
/// 2. **Rebuild-only pref** (`shields_up`, the immutable `Config.block_incoming`): it has no live
///    setter, so `set` rebuilds the device (a brief reconnect) and the node must RECONVERGE to
///    Running. We assert reconvergence (poll back to Running), not IP-stability, because a rebuild
///    re-registers (headscale may re-issue from the pool); the contract is "stays up", not "same IP".
///
/// This exercises `Backend::begin_set`'s `SetAction::{Live,Rebuild}` decision end-to-end against a
/// live netmap — the dispatch that unit tests can only check in isolation. Same `#[ignore]` + env
/// gate as the join test — compiles in CI, runs only against a real tailnet.
#[tokio::test]
#[ignore = "requires a running headscale (test-support/headscale) + TAILNETD_HS_URL/TAILNETD_HS_AUTHKEY; see docs/TESTING.md"]
async fn headscale_set_live_vs_rebuild_dispatch() {
    let (hs_url, hs_authkey) = match (
        std::env::var("TAILNETD_HS_URL"),
        std::env::var("TAILNETD_HS_AUTHKEY"),
    ) {
        (Ok(u), Ok(k)) if !u.is_empty() && !k.is_empty() => (u, k),
        _ => {
            eprintln!(
                "SKIP headscale_set_live_vs_rebuild_dispatch: set TAILNETD_HS_URL and \
                 TAILNETD_HS_AUTHKEY to run it (see docs/TESTING.md)"
            );
            return;
        }
    };
    if std::env::var("TS_RS_EXPERIMENT").as_deref() != Ok("this_is_unstable_software") {
        eprintln!("SKIP headscale_set_live_vs_rebuild_dispatch: export TS_RS_EXPERIMENT");
        return;
    }

    let state_dir = unique_state_dir();
    let _ = tokio::fs::remove_dir_all(&state_dir).await;
    tokio::fs::create_dir_all(&state_dir)
        .await
        .expect("state dir");
    let mut backend = Backend::load(&state_dir).await.expect("Backend::load");

    backend
        .up(
            Some(secrecy::SecretString::from(hs_authkey)),
            tailscaled_rs::ipn::UpOptions {
                hostname: Some("tailscaled-rs-hs-set".to_string()),
                control_url: Some(hs_url.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("up() against headscale {hs_url} failed: {e:?}"));

    // Wait for the initial Running + capture the tailnet IP the live `set` must preserve.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut running = false;
    let mut ip_before: Option<String> = None;
    while tokio::time::Instant::now() < deadline {
        let report = backend.status().await;
        if report.state == "Running" {
            running = true;
            ip_before = report.self_ipv4.clone();
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // 1. LIVE pref: change the hostname. `set` applies it via the engine's `set_hostname` with no
    //    reconnect, so the node stays Running and the tailnet IP is unchanged.
    let live_set_ok = if running {
        backend
            .set(tailscaled_rs::ipn::SetOptions {
                hostname: Some("tailscaled-rs-hs-set-live".to_string()),
                ..Default::default()
            })
            .await
            .is_ok()
    } else {
        false
    };
    // Read state immediately after the live set — it must NOT have reconnected, so it is Running now
    // (no reconvergence window) and reports the same IP.
    let after_live = backend.status().await;
    let live_still_running = live_set_ok && after_live.state == "Running";
    let ip_after_live = after_live.self_ipv4.clone();

    // 2. REBUILD-only pref: shields_up has no live setter, so `set` rebuilds (brief reconnect). The
    //    node must reconverge to Running. Drive the set, then poll back to Running.
    let rebuild_set_ok = if live_still_running {
        backend
            .set(tailscaled_rs::ipn::SetOptions {
                shields_up: Some(true),
                ..Default::default()
            })
            .await
            .is_ok()
    } else {
        false
    };
    let rebuild_reconverged = if rebuild_set_ok {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let mut ok = false;
        while tokio::time::Instant::now() < deadline {
            if backend.status().await.state == "Running" {
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        ok
    } else {
        false
    };

    // ALWAYS tear down + clean up before asserting, so a failure can't leave a registered node behind.
    backend.down().await.expect("down()");
    backend.shutdown().await;
    let _ = tokio::fs::remove_dir_all(&state_dir).await;

    assert!(
        running,
        "node never reached Running against headscale {hs_url}"
    );
    assert!(live_set_ok, "live `set --hostname` should return Ok");
    assert!(
        live_still_running,
        "a live (hostname) `set` must NOT reconnect — the node must stay Running immediately after"
    );
    // The live path never re-registers, so the self IP must be byte-for-byte unchanged.
    assert_eq!(
        ip_after_live, ip_before,
        "a live `set` must leave the tailnet IP unchanged (no reconnect), before={ip_before:?} \
         after={ip_after_live:?}"
    );
    assert!(
        rebuild_set_ok,
        "rebuild-only `set shields_up` should return Ok"
    );
    assert!(
        rebuild_reconverged,
        "a rebuild-only (shields_up) `set` must reconverge the node back to Running after the brief \
         reconnect"
    );
}

/// Live read-only-diagnostics test: bring a node up against headscale, then exercise the read-only
/// diagnostic surface against the REAL running node + netmap — `dns status`, `netcheck`, `syspolicy
/// list`, and `status` (the data behind `tnet ip`). This is the live counterpart to the unit tests:
/// it proves each diagnostic returns a well-shaped, non-error response when driven against a real
/// engine (not just that the wire types round-trip). Same `#[ignore]` + env gate as the join test.
#[tokio::test]
#[ignore = "requires a running headscale (test-support/headscale) + TAILNETD_HS_URL/TAILNETD_HS_AUTHKEY; see docs/TESTING.md"]
async fn headscale_readonly_diagnostics_on_running_node() {
    let (hs_url, hs_authkey) = match (
        std::env::var("TAILNETD_HS_URL"),
        std::env::var("TAILNETD_HS_AUTHKEY"),
    ) {
        (Ok(u), Ok(k)) if !u.is_empty() && !k.is_empty() => (u, k),
        _ => {
            eprintln!(
                "SKIP headscale_readonly_diagnostics_on_running_node: set TAILNETD_HS_URL and \
                 TAILNETD_HS_AUTHKEY to run it (see docs/TESTING.md)"
            );
            return;
        }
    };
    if std::env::var("TS_RS_EXPERIMENT").as_deref() != Ok("this_is_unstable_software") {
        eprintln!("SKIP headscale_readonly_diagnostics_on_running_node: export TS_RS_EXPERIMENT");
        return;
    }

    let state_dir = unique_state_dir();
    let _ = tokio::fs::remove_dir_all(&state_dir).await;
    tokio::fs::create_dir_all(&state_dir)
        .await
        .expect("state dir");
    let mut backend = Backend::load(&state_dir).await.expect("Backend::load");

    let authkey = secrecy::SecretString::from(hs_authkey);
    backend
        .up(
            Some(authkey),
            tailscaled_rs::ipn::UpOptions {
                hostname: Some("tailscaled-rs-hs-diag".to_string()),
                control_url: Some(hs_url.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("up() against headscale {hs_url} failed: {e:?}"));

    // Wait for Running + the self address (the netmap-arrived signal — see the join test note).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut self_ipv4: Option<String> = None;
    while tokio::time::Instant::now() < deadline {
        let report = backend.status().await;
        if report.state == "Running" && report.self_ipv4.is_some() {
            self_ipv4 = report.self_ipv4.clone();
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Drive each read-only diagnostic against the live node. Capture outcomes, then ALWAYS tear down
    // before asserting (so a failure can't leak a registered node or temp dir).
    use tailscaled_rs::localapi::Response;
    let dns = match backend.device_handle() {
        Some(dev) => Some(Backend::dns_status(&dev).await),
        None => None,
    };
    let netcheck = match backend.device_handle() {
        Some(dev) => Some(Backend::netcheck(&dev).await),
        None => None,
    };
    // syspolicy is node-up-independent (static, no device) — exercise it on the running node anyway.
    let policy = Backend::syspolicy_list();
    // `tnet ip` reads the same self address we already polled.
    let ip = self_ipv4.clone();

    backend.down().await.expect("down()");
    backend.shutdown().await;
    let _ = tokio::fs::remove_dir_all(&state_dir).await;

    // `dns status`: a Running node must answer with a DnsStatus report (not an Error / not down).
    assert!(
        matches!(dns, Some(Response::DnsStatus(_))),
        "dns status on a Running node should return a DnsStatus report, got {dns:?}"
    );
    // `netcheck`: a Running node must answer with a Netcheck report (DERP-region latency view).
    assert!(
        matches!(netcheck, Some(Response::Netcheck(_))),
        "netcheck on a Running node should return a Netcheck report, got {netcheck:?}"
    );
    // `syspolicy list`: always a Policy report; on this (Linux) host it is empty (no store).
    match policy {
        Response::Policy(ref p) => assert!(
            p.settings.is_empty(),
            "no policy store is registered on this platform; settings must be empty, got {:?}",
            p.settings
        ),
        other => panic!("syspolicy list should return a Policy report, got {other:?}"),
    }
    // `ip`: a Running node must have a self tailnet IPv4 from the pool.
    let ip =
        ip.expect("a Running node must report a self tailnet IPv4 (the data behind `tnet ip`)");
    assert!(
        ip.parse::<std::net::Ipv4Addr>().is_ok(),
        "self address {ip:?} should be a valid IPv4 from the tailnet pool"
    );
}
