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
//! # 2. Mint a user + a reusable pre-auth key.
//! docker compose -f test-support/headscale/docker-compose.yml exec headscale \
//!     headscale users create test
//! KEY=$(docker compose -f test-support/headscale/docker-compose.yml exec -T headscale \
//!     headscale preauthkeys create --user test --reusable --expiration 24h)
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
                 run this. Bring up the control server first:\n  \
                 docker compose -f test-support/headscale/docker-compose.yml up -d\n  \
                 docker compose -f test-support/headscale/docker-compose.yml exec headscale \
                 headscale users create test\n  \
                 docker compose -f test-support/headscale/docker-compose.yml exec -T headscale \
                 headscale preauthkeys create --user test --reusable --expiration 24h\n\
                 then export TAILNETD_HS_URL=http://localhost:8080 and TAILNETD_HS_AUTHKEY=<key>. \
                 See docs/TESTING.md."
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
            Some("tailscaled-rs-hs-e2e".to_string()),
            Some(hs_url.clone()),
        )
        .await
        .unwrap_or_else(|e| panic!("up() against headscale {hs_url} failed: {e:?}"));

    // Poll status until the netmap arrives and the node is Running with a self address. A real
    // register + first map poll against headscale typically settles within a few seconds; give it a
    // bounded window so a wedged join fails the test instead of hanging forever.
    let mut last_state = String::new();
    let mut self_ipv4: Option<String> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline {
        let report = backend.status().await;
        last_state = report.state.clone();
        if report.state == "Running" {
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
