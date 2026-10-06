//! A policy-pinned exit node has to be REFUSED, not silently overwritten — and
//! `ExitNode.AllowOverride` has to mean something when an administrator sets it.
//!
//! Go's `checkEditPrefsAccessLocked` (`ipn/ipnlocal/local.go`) runs before any prefs edit is
//! applied: an edit that touches the exit node while the policy manages it is rejected with `exit
//! node cannot be changed: managed by policy`, unless `pkey.AllowExitNodeOverride` lets the user
//! pick a *different* node — and even then the edit may move the egress, never turn it off. Until
//! this change the fork had the *re-apply* (`ExitNodeIP` → the `exit_node` pref, after the caller's
//! own overrides) and no refusal, so `tnet set --exit-node=<peer>` under a pinning policy was
//! accepted, reported success, and persisted the administrator's node instead of the requested one.
//!
//! The unit tests next to [`exitnodepolicy`](../src/ipn/exitnodepolicy.rs) pin the decision itself
//! over an already-resolved policy. What they cannot see is the half that makes it real: that the
//! keys an administrator wrote into a *file* reach the gate, that the gate sits in front of the
//! write rather than after it, and that a permitted override then survives the reconcile that used
//! to undo it. That needs a registered policy source, which is process-global (Go's `rsop` store
//! list is too), so — like `tests/alwayson_disconnect.rs` — this binary holds exactly ONE test and
//! it owns the registry for the whole process.
//!
//! Upstream: `ipn/ipnlocal/local.go` (`checkEditPrefsAccessLocked`, `changeDisablesExitNodeLocked`,
//! `onEditPrefsLocked`, `applyExitNodeSysPolicyLocked`) @
//! `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8`.

use std::path::{Path, PathBuf};

use tailscaled_rs::ipn::{Backend, SetOptions, UpOptions, syspolicy};

/// The node the administrator pins with `ExitNodeIP`, and the one the operator keeps asking for.
/// Both in the tailnet's own CGNAT range, which is where a real exit node's address lives.
const ADMIN_EXIT_NODE: &str = "100.64.0.9";
const OPERATOR_EXIT_NODE: &str = "100.64.0.3";

/// A temp directory unique to this test binary's process, so a leftover from a previous run can
/// never be mistaken for this run's state.
fn temp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tailnetd-exitnode-{}-{tag}", std::process::id()))
}

/// Write a policy file and register it as a device-scope source, the way `tailnetd --syspolicy-file`
/// does at startup. Each call adds a source; the merge is last-writer-wins per key, which is how one
/// test process can observe two different policies in sequence.
fn register_policy(tag: &str, json: &str) {
    let path = std::env::temp_dir().join(format!(
        "tailnetd-exitnode-policy-{}-{tag}.json",
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

/// A backend on a freshly-created state dir — the daemon's own load path, so the profile-load
/// reconcile applies the registered policy exactly as it does at boot.
async fn fresh_backend(dir: &Path) -> Backend {
    let _ = tokio::fs::remove_dir_all(dir).await;
    tokio::fs::create_dir_all(dir)
        .await
        .expect("create the state dir");
    Backend::load(dir)
        .await
        .expect("a backend should load from the state dir")
}

/// The exit node in the PERSISTED prefs, read off disk rather than off the backend: an edit that
/// moved only memory would still be an edit that lied about what it stored. `None` when no prefs
/// file exists yet, which is what a refusal before the first write must leave behind.
async fn persisted_exit_node(dir: &Path) -> Option<String> {
    let raw = tokio::fs::read_to_string(dir.join("prefs.json"))
        .await
        .ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("prefs should be JSON");
    Some(
        parsed
            .get("exit_node")?
            .as_str()
            .expect("exit_node should be a string when set")
            .to_string(),
    )
}

/// Go's one message for every refusal this gate makes.
const MANAGED: &str = "exit node cannot be changed: managed by policy";

#[tokio::test(flavor = "current_thread")]
async fn a_policy_file_decides_who_may_change_the_exit_node() {
    // ---------------------------------------------------------------------------------------
    // 1. `ExitNodeIP` alone: the administrator's node is pinned, and every edit that names an
    //    exit node is refused — visibly, and before anything is written.
    // ---------------------------------------------------------------------------------------
    register_policy(
        "pinned",
        &format!(r#"{{"ExitNodeIP": "{ADMIN_EXIT_NODE}"}}"#),
    );

    let dir = temp_dir("pinned");
    let mut be = fresh_backend(&dir).await;

    let err = be
        .set(SetOptions {
            exit_node: Some(Some(OPERATOR_EXIT_NODE.to_string())),
            ..Default::default()
        })
        .await
        .expect_err("a pinned exit node is not the operator's to move");
    assert_eq!(
        format!("{err:#}"),
        MANAGED,
        "the operator must read Go's message, not a wrapped or reworded one"
    );
    assert_eq!(
        persisted_exit_node(&dir).await,
        None,
        "a refused edit must be refused BEFORE the write: nothing may have been persisted at all"
    );

    // Clearing it is refused for the same reason, with the same message.
    let err = be
        .set(SetOptions {
            exit_node: Some(None),
            ..Default::default()
        })
        .await
        .expect_err("`--exit-node=` is an exit-node edit too");
    assert_eq!(format!("{err:#}"), MANAGED);

    // And `up` is not the hole in the gate that `set` closed — Go guards every prefs edit, and both
    // roads reach the same check here.
    // (`PendingUp` is not `Debug`, so the refusal is matched rather than `expect_err`'d.)
    let Err(err) = be
        .begin_up(
            UpOptions {
                exit_node: Some(Some(OPERATOR_EXIT_NODE.to_string())),
                ..Default::default()
            },
            None,
        )
        .await
    else {
        panic!("`up --exit-node` under a pinning policy must be refused too");
    };
    assert_eq!(format!("{err:#}"), MANAGED);
    assert_eq!(
        persisted_exit_node(&dir).await,
        None,
        "a refused `up` must not have torn anything down or persisted anything either"
    );

    // An edit that names no exit node is not an exit-node edit: Go masks on the fields the request
    // actually sets, so a policy pinning the egress must not refuse `set --hostname`.
    be.set(SetOptions {
        hostname: Some("documented-node".to_string()),
        ..Default::default()
    })
    .await
    .expect("an unrelated `set` must still go through on a node with a pinned exit node");
    assert_eq!(
        persisted_exit_node(&dir).await.as_deref(),
        Some(ADMIN_EXIT_NODE),
        "and the write it performed carries the administrator's exit node, as the re-apply has \
         always done"
    );

    // ---------------------------------------------------------------------------------------
    // 2. Add `ExitNode.AllowOverride`: the user may now pick a DIFFERENT node — and the choice
    //    survives the reconcile that used to undo it.
    // ---------------------------------------------------------------------------------------
    // Registered as a second source, which wins per key — the merge `syspolicy` documents.
    register_policy(
        "override",
        &format!(r#"{{"ExitNodeIP": "{ADMIN_EXIT_NODE}", "ExitNode.AllowOverride": true}}"#),
    );

    let dir = temp_dir("override");
    let mut be = fresh_backend(&dir).await;
    be.set(SetOptions {
        exit_node: Some(Some(OPERATOR_EXIT_NODE.to_string())),
        ..Default::default()
    })
    .await
    .expect("ExitNode.AllowOverride exists precisely so a user may pick a different node");
    assert_eq!(
        persisted_exit_node(&dir).await.as_deref(),
        Some(OPERATOR_EXIT_NODE),
        "the permitted override must be what is persisted — the re-apply that runs a line later \
         must not overwrite the edit it just allowed"
    );

    // The reconcile point that would otherwise undo it: an unrelated `set`, which applies the
    // effective policy after the caller's own overrides.
    be.set(SetOptions {
        hostname: Some("documented-node".to_string()),
        ..Default::default()
    })
    .await
    .expect("an unrelated `set` just persists");
    assert_eq!(
        persisted_exit_node(&dir).await.as_deref(),
        Some(OPERATOR_EXIT_NODE),
        "a permitted override must survive a reconcile point — otherwise it lasts 'until somebody \
         runs an unrelated command', which is not an override at all"
    );

    // The bound on the opt-in (Go's `changeDisablesExitNodeLocked`): an override may move the
    // egress, never turn it off.
    let err = be
        .set(SetOptions {
            exit_node: Some(None),
            ..Default::default()
        })
        .await
        .expect_err("an override may not disable the administrator's exit node");
    assert_eq!(format!("{err:#}"), MANAGED);
    assert_eq!(
        persisted_exit_node(&dir).await.as_deref(),
        Some(OPERATOR_EXIT_NODE)
    );

    // Picking the administrator's own node again ends the override, so the policy applies alone
    // from here on — Go clears the flag when the user switches back to the state it requires.
    be.set(SetOptions {
        exit_node: Some(Some(ADMIN_EXIT_NODE.to_string())),
        ..Default::default()
    })
    .await
    .expect("returning to the policy's node is always permitted");
    assert_eq!(
        persisted_exit_node(&dir).await.as_deref(),
        Some(ADMIN_EXIT_NODE)
    );

    // ---------------------------------------------------------------------------------------
    // 3. The lifecycle edge: a connect ends any standing override, and then the connecting
    //    command's OWN exit-node choice applies — an `up --exit-node` the policy permits is still
    //    permitted, and is not undone by the connect it rode in on.
    // ---------------------------------------------------------------------------------------
    let dir = temp_dir("connect");
    let mut be = fresh_backend(&dir).await;
    be.set(SetOptions {
        exit_node: Some(Some(OPERATOR_EXIT_NODE.to_string())),
        ..Default::default()
    })
    .await
    .expect("the override is permitted");

    // A plain `up` names no exit node: the override it inherited is spent and the pinned node is
    // back in force. Driven through `begin_up` — the prepare-and-persist phase, which is where the
    // connect edge lives — so this test never reaches for a control server it cannot have.
    be.begin_up(UpOptions::default(), None)
        .await
        .expect("the connect path must prepare cleanly on a device-less backend");
    assert_eq!(
        persisted_exit_node(&dir).await.as_deref(),
        Some(ADMIN_EXIT_NODE),
        "connecting the node re-arms the policy, exactly as it re-arms always-on mode"
    );

    // …and an `up` that names one takes its own verdict with it.
    be.begin_up(
        UpOptions {
            exit_node: Some(Some(OPERATOR_EXIT_NODE.to_string())),
            ..Default::default()
        },
        None,
    )
    .await
    .expect("`up --exit-node <other>` is the same permitted override `set` makes");
    assert_eq!(
        persisted_exit_node(&dir).await.as_deref(),
        Some(OPERATOR_EXIT_NODE),
        "the connect clears what stood BEFORE the command; it must not throw away the command's \
         own permitted choice"
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
    let _ = tokio::fs::remove_dir_all(&temp_dir("pinned")).await;
    let _ = tokio::fs::remove_dir_all(&temp_dir("override")).await;
}
