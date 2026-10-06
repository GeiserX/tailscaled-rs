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
//! The same is true of the *window* a permitted disconnect opens: that `ReconnectAfter` written into
//! the file reaches the arming, and that the disconnect then survives a reconcile point, can only be
//! seen with a real policy source registered — so it is the last section of the one test here.
//!
//! Upstream: `ipn/ipnauth/policy.go` and `ipn/ipnlocal/local.go` (`checkEditPrefsAccessLocked`,
//! `onEditPrefsLocked`, `startReconnectTimerLocked`) @
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

    // A node whose prefs say it is DOWN is not "already down" once the policy has been reconciled:
    // a profile load applies the effective policy (`syspolicy::apply_to_prefs`), and
    // `AlwaysOn.Enabled` re-asserts the up-intent in memory before any command runs. So the same
    // refusal applies to it — which is the re-connect half of always-on mode, observed from outside.
    // Go does this too: `reconcilePrefs` runs `applySysPolicy` on every profile load, so its
    // `b.pm.CurrentPrefs().WantRunning()` is already true by the time the gate reads it.
    let stopped_dir = temp_dir("persisted-down");
    let _ = tokio::fs::remove_dir_all(&stopped_dir).await;
    tokio::fs::create_dir_all(&stopped_dir).await.unwrap();
    tokio::fs::write(stopped_dir.join("prefs.json"), br#"{"want_running":false}"#)
        .await
        .unwrap();
    let mut stopped = Backend::load(&stopped_dir).await.expect("load");
    let err = stopped
        .down(Actor::Operator { reason: None })
        .await
        .expect_err("the profile load re-asserted the up-intent, so this IS a disconnect");
    assert_eq!(
        format!("{err:#}"),
        "disconnect not allowed: always-on mode is enabled"
    );
    let _ = tokio::fs::remove_dir_all(&stopped_dir).await;

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

    // Go gates the TRANSITION, not the state: `mp.WantRunningSet && !mp.WantRunning &&
    // b.pm.CurrentPrefs().WantRunning()`. Here is where a node is genuinely already down under an
    // always-on policy — inside the window Go's `overrideAlwaysOn` flag holds open. A second,
    // reasonless `down` in that window is idempotent, not a disconnect, and must not be refused.
    be.down(Actor::Operator { reason: None })
        .await
        .expect("a `down` on an already-down node is not a disconnect and must not be refused");

    // ---------------------------------------------------------------------------------------
    // 4. The window itself: a permitted disconnect STAYS, and carries the administrator's bound.
    // ---------------------------------------------------------------------------------------
    // The unit tests pin the override flag and the timer over already-resolved inputs. What they
    // cannot see is this: that `ReconnectAfter` written into a policy FILE reaches the arming, and
    // that the flag really does hold the re-assert off at a reconcile point the operator did not ask
    // for. That second half is the bug the flag exists to fix — without it an unrelated `tnet set`
    // puts a node the policy had already agreed to release back on the tailnet.
    register_policy(
        "reconnect-after",
        r#"{"AlwaysOn.Enabled": true, "AlwaysOn.OverrideWithReason": true,
            "ReconnectAfter": "30m"}"#,
    );

    let bounded_dir = temp_dir("bounded");
    let mut bounded = connected_backend(&bounded_dir).await;
    assert!(
        bounded.watch_reconnect().borrow().is_none(),
        "a freshly loaded backend has no reconnect outstanding"
    );

    let before = tokio::time::Instant::now();
    bounded
        .down(Actor::Operator {
            reason: Some("laptop returned to IT"),
        })
        .await
        .expect("a reasoned disconnect must be permitted");
    assert!(
        !persisted_want_running(&bounded_dir).await,
        "the permitted disconnect must actually have brought the node down"
    );

    let armed =
        bounded.watch_reconnect().borrow().clone().expect(
            "a configured ReconnectAfter must arm the reconnect the administrator asked for",
        );
    let window = std::time::Duration::from_secs(30 * 60);
    assert!(
        armed.deadline() >= before + window,
        "the node must come back after the configured window, not before it"
    );
    assert!(
        armed.deadline() <= tokio::time::Instant::now() + window,
        "…and not later than one window from the disconnect either"
    );

    // The reconcile point that used to undo it: an unrelated `set`, which applies the effective
    // policy after the caller's own overrides. The node must stay down.
    bounded
        .set(tailscaled_rs::ipn::SetOptions {
            hostname: Some("documented-node".to_string()),
            ..Default::default()
        })
        .await
        .expect("an unrelated `set` on a down node just persists");
    assert!(
        !persisted_want_running(&bounded_dir).await,
        "a permitted disconnect must survive a reconcile point — otherwise the administrator's \
         window is 'until somebody runs an unrelated command', which is not a window at all"
    );
    assert!(
        bounded.watch_reconnect().borrow().is_some(),
        "and its deadline must still stand: a `set` is not a connect"
    );

    // Bringing the node up by hand spends the window: the exemption is over and the reconnect has
    // nothing left to do. Driven through `begin_up` — the prepare-and-persist phase, which is where
    // the connect edge lives — so this test never reaches for a control server it cannot have.
    bounded
        .begin_up(tailscaled_rs::ipn::UpOptions::default(), None)
        .await
        .expect("the connect path must prepare cleanly on a device-less backend");
    assert!(
        bounded.watch_reconnect().borrow().is_none(),
        "`up` must cancel an outstanding reconnect"
    );

    let _ = tokio::fs::remove_dir_all(&bounded_dir).await;
    let _ = tokio::fs::remove_dir_all(&dir).await;
}
