//! Always-on mode must actually refuse a disconnect — `tnet down --reason` has to satisfy a rule,
//! not decorate a log line.
//!
//! Go's `ipnauth.CheckDisconnectPolicy` (`ipn/ipnauth/policy.go`) is three refusals in one function,
//! reached from `checkEditPrefsAccessLocked` whenever a prefs edit takes `WantRunning` from true to
//! false — which is both `tailscale down` and `tailscale logout`. Until this change the fork had
//! both *inputs* (the policy file defines `AlwaysOn.Enabled` and `AlwaysOn.OverrideWithReason`; the
//! LocalAPI carries the reason) and neither *rule*: `tnet down` on a policy-managed node succeeded
//! and the administrator's setting did nothing.
//!
//! The unit tests next to [`alwayson`](../src/ipn/alwayson.rs) pin the decision itself over
//! already-resolved policy booleans. What they cannot see is the half that makes it real: that the
//! booleans an admin wrote into a *file* reach the gate, and that the gate sits in front of the
//! teardown rather than after it. That needs a registered policy source, which is process-global
//! (Go's `rsop` store list is too), so — like `tests/syspolicy_file.rs` — this binary holds exactly
//! ONE test and it owns the registry for the whole process.
//!
//! Upstream: `ipn/ipnauth/policy.go` and `ipn/ipnlocal/local.go` (`checkEditPrefsAccessLocked`) @
//! `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8`.

use std::path::{Path, PathBuf};

use tailscaled_rs::ipn::alwayson::Actor;
use tailscaled_rs::ipn::{Backend, syspolicy};

/// A temp directory unique to this test binary's process, so a leftover from a previous run can
/// never be mistaken for this run's state.
fn temp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tailnetd-alwayson-{}-{tag}", std::process::id()))
}

/// Write a policy file and register it as a device-scope source, the way `tailnetd --syspolicy-file`
/// does at startup. Each call adds a source; the merge is last-writer-wins per key (see
/// [`syspolicy`]), which is how one test process can observe two different policies in sequence.
fn register_policy(tag: &str, json: &str) {
    let path = std::env::temp_dir().join(format!(
        "tailnetd-alwayson-policy-{}-{tag}.json",
        std::process::id()
    ));
    std::fs::write(&path, json).expect("write the policy file");
    let outcome = syspolicy::load_json_policy_file(syspolicy::JSON_FILE_SOURCE_NAME, &path)
        .expect("a well-formed policy file should load");
    assert!(
        matches!(outcome, syspolicy::LoadOutcome::Registered { .. }),
        "the policy file must register as a source, got {outcome:?}"
    );
    let _ = std::fs::remove_file(&path);
}

/// A backend on a freshly-created state dir whose persisted prefs say the node is up — the state a
/// disconnect is a disconnect *from*. Written through the prefs file rather than the (private)
/// field, so this is the same load path the daemon takes on boot.
async fn connected_backend(dir: &Path) -> Backend {
    let _ = tokio::fs::remove_dir_all(dir).await;
    tokio::fs::create_dir_all(dir)
        .await
        .expect("create the state dir");
    tokio::fs::write(
        dir.join("prefs.json"),
        br#"{"want_running":true,"has_logged_in":true}"#,
    )
    .await
    .expect("write the persisted prefs");
    Backend::load(dir)
        .await
        .expect("a backend should load from the state dir")
}

/// Whether the node's PERSISTED prefs still say it wants to run — the thing a refusal has to leave
/// untouched. Read off disk, not off the backend, because a refusal that mutated only memory would
/// still be a refusal that half-disconnected.
async fn persisted_want_running(dir: &Path) -> bool {
    let raw = tokio::fs::read_to_string(dir.join("prefs.json"))
        .await
        .expect("the prefs file should still exist");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("prefs should be JSON");
    parsed
        .get("want_running")
        .and_then(serde_json::Value::as_bool)
        .expect("prefs should carry want_running")
}

#[tokio::test(flavor = "current_thread")]
async fn a_policy_file_decides_whether_a_node_may_be_disconnected() {
    // ---------------------------------------------------------------------------------------
    // 1. `AlwaysOn.Enabled` alone: the disconnect is refused outright, reason or no reason.
    // ---------------------------------------------------------------------------------------
    register_policy("always-on", r#"{"AlwaysOn.Enabled": true}"#);

    let dir = temp_dir("refused");
    let mut be = connected_backend(&dir).await;
    let err = be
        .down(Actor::Operator { reason: None })
        .await
        .expect_err("an always-on node must refuse `down`");
    assert_eq!(
        format!("{err:#}"),
        "disconnect not allowed: always-on mode is enabled",
        "the operator must read Go's message, not a wrapped or reworded one"
    );
    // A reason buys nothing while `AlwaysOn.OverrideWithReason` is unset — that is the whole point
    // of the second key.
    let err = be
        .down(Actor::Operator {
            reason: Some("scheduled maintenance"),
        })
        .await
        .expect_err("a reason must not lift a refusal the policy never offered to lift");
    assert_eq!(
        format!("{err:#}"),
        "disconnect not allowed: always-on mode is enabled"
    );
    // `logout` is a disconnect too (Go routes it through the same prefs edit), and its refusal must
    // leave the registration alone.
    tokio::fs::write(&dir.join("node.key.json"), b"{\"key_state\":{}}")
        .await
        .expect("simulate a prior registration");
    let err = be
        .logout(Actor::Operator { reason: None })
        .await
        .expect_err("an always-on node must refuse `logout`");
    assert_eq!(
        format!("{err:#}"),
        "disconnect not allowed: always-on mode is enabled",
        "`logout` must not be the hole in the gate that `down` closed"
    );
    assert!(
        tokio::fs::try_exists(dir.join("node.key.json"))
            .await
            .unwrap(),
        "a refused logout must not have discarded the node key"
    );
    assert!(
        persisted_want_running(&dir).await,
        "a refused disconnect must leave the persisted up-intent exactly as it was"
    );

    // Go gates the TRANSITION, not the state: `mp.WantRunningSet && !mp.WantRunning &&
    // b.pm.CurrentPrefs().WantRunning()`. A node that is already down is not being disconnected, so
    // the same policy must let the idempotent `down` through.
    let already_down = temp_dir("already-down");
    let _ = tokio::fs::remove_dir_all(&already_down).await;
    tokio::fs::create_dir_all(&already_down).await.unwrap();
    tokio::fs::write(
        already_down.join("prefs.json"),
        br#"{"want_running":false}"#,
    )
    .await
    .unwrap();
    let mut stopped = Backend::load(&already_down).await.expect("load");
    stopped
        .down(Actor::Operator { reason: None })
        .await
        .expect("a `down` on an already-down node is not a disconnect and must not be refused");
    let _ = tokio::fs::remove_dir_all(&already_down).await;

    // ---------------------------------------------------------------------------------------
    // 2. Add `AlwaysOn.OverrideWithReason`: the refusal narrows to "say why".
    // ---------------------------------------------------------------------------------------
    // Registered as a second source, which wins per key — the merge `syspolicy` documents.
    register_policy(
        "override",
        r#"{"AlwaysOn.Enabled": true, "AlwaysOn.OverrideWithReason": true}"#,
    );

    let err = be
        .down(Actor::Operator { reason: None })
        .await
        .expect_err("an override policy still refuses a reasonless disconnect");
    assert_eq!(
        format!("{err:#}"),
        "disconnect not allowed: reason required",
        "the second refusal has its own message, because it has its own remedy"
    );
    // Go tests the reason for `== \"\"`, so an empty one is no reason at all.
    let err = be
        .down(Actor::Operator { reason: Some("") })
        .await
        .expect_err("an empty reason is no reason");
    assert_eq!(
        format!("{err:#}"),
        "disconnect not allowed: reason required"
    );
    assert!(
        persisted_want_running(&dir).await,
        "the narrowed refusal must still leave the node up"
    );

    // ---------------------------------------------------------------------------------------
    // 3. …and a real reason gets through, all the way to a persisted disconnect.
    // ---------------------------------------------------------------------------------------
    be.down(Actor::Operator {
        reason: Some("scheduled maintenance"),
    })
    .await
    .expect("a reasoned disconnect must be permitted under an override policy");
    assert!(
        !persisted_want_running(&dir).await,
        "the permitted disconnect must actually have brought the node down"
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}
