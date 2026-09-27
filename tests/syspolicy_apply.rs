//! An administrator's policy file has to move the node's prefs — not merely be reported back.
//!
//! Go applies the effective policy in `applySysPolicyLocked` (`ipn/ipnlocal/local.go`) and
//! re-applies it from `reconcilePrefs` on every prefs write and on every profile load: `LoginURL`
//! overrides `ControlURL`, `Hostname` overrides the hostname (or, when the key is present but
//! empty, CLEARS it), and the `preferencePolicies` table maps a `PreferenceOption` key onto one
//! bool pref each. The failure this guards against is the one that looks exactly like success: a
//! daemon that resolves the file, types it, and prints it under `syspolicy list` with the right
//! origin, while the node itself stays as the operator left it. A report that renders the
//! administrator's intent is indistinguishable from enforcement of it until someone checks.
//!
//! The unit tests beside [`syspolicy`](../src/ipn/syspolicy.rs) pin the decision over an
//! already-merged setting list, and `tests/exit_node_policy.rs` / `tests/alwayson_disconnect.rs`
//! pin the two keys whose effect is a refusal. What none of them can see is this path: an
//! administrator's file on disk, read by the production loader, reaching the prefs a running
//! daemon persists — and outranking what the operator typed a moment earlier. That needs a
//! registered policy source, which is process-global (Go's `rsop` store list is too), so — like
//! those two binaries — this one holds exactly ONE test and owns the registry for the whole
//! process.
//!
//! Upstream: `ipn/ipnlocal/local.go` (`applySysPolicy`, `reconcilePrefs`, `preferencePolicies`) @
//! `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8`.

use std::path::{Path, PathBuf};

use tailscaled_rs::ipn::{Backend, SetOptions, syspolicy};

/// The control server the administrator pins with `LoginURL`. A documentation host, never resolved
/// by this test — nothing here reaches the network.
const POLICY_LOGIN_URL: &str = "https://control.example.com";
/// The hostname the administrator pins with `Hostname`…
const POLICY_HOSTNAME: &str = "policy-pinned";
/// …and the one the operator types instead, at every reconcile point below.
const OPERATOR_HOSTNAME: &str = "operator-typed";

/// A temp directory unique to this test binary's process, so a leftover from a previous run can
/// never be mistaken for this run's state.
fn temp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tailnetd-syspolicy-{}-{tag}", std::process::id()))
}

/// Write a policy file and register it as a device-scope source, the way `tailnetd
/// --syspolicy-file` does at startup. Each call adds a source; the merge is last-writer-wins per
/// key, which is how one test process can observe the administrator revising the file.
fn register_policy(tag: &str, json: &str) {
    let path = std::env::temp_dir().join(format!(
        "tailnetd-syspolicy-policy-{}-{tag}.json",
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

/// The PERSISTED prefs, read off disk rather than off the backend: a policy that moved only memory
/// would still be a policy the next daemon start forgets.
async fn persisted(dir: &Path) -> serde_json::Value {
    let raw = tokio::fs::read_to_string(dir.join("prefs.json"))
        .await
        .expect("a `set` must have written prefs.json");
    serde_json::from_str(&raw).expect("prefs should be JSON")
}

#[tokio::test(flavor = "current_thread")]
async fn a_policy_file_moves_the_prefs_and_outranks_what_the_operator_just_typed() {
    // -------------------------------------------------------------------------------------------
    // 1. The administrator's file, covering one key of each shape the apply path handles: a string
    //    pref (`LoginURL`), the tri-state string (`Hostname`), and three of the seven preference
    //    options — one that forces its pref ON, one that forces it OFF, and one that declines to
    //    have an opinion. `AllowIncomingConnections` is the inverted row (Go: "Allow Incoming (used
    //    by the UI) is the negation of ShieldsUp (used by the backend)"), so `never` must land as
    //    `shields_up: true`, not as the `false` a naive copy of the policy value would write.
    // -------------------------------------------------------------------------------------------
    register_policy(
        "pinned",
        &format!(
            r#"{{
                "LoginURL": "{POLICY_LOGIN_URL}",
                "Hostname": "{POLICY_HOSTNAME}",
                "AllowIncomingConnections": "never",
                "UseTailscaleSubnets": "always",
                "CheckUpdates": "never",
                "UseTailscaleDNSSettings": "user-decides"
            }}"#
        ),
    );

    let dir = temp_dir("pinned");
    let mut be = fresh_backend(&dir).await;

    // The operator now asks for the opposite of every key the administrator pinned, plus two the
    // policy says nothing about. The `set` itself is ACCEPTED — none of these keys has an edit gate
    // in front of it, and Go has none either; the policy wins by being re-applied over the
    // command's own overrides, just before the persist.
    be.set(SetOptions {
        hostname: Some(OPERATOR_HOSTNAME.to_string()),
        shields_up: Some(false),
        accept_routes: Some(false),
        update_check: Some(true),
        accept_dns: Some(false),
        exit_node_allow_lan_access: Some(true),
        ..Default::default()
    })
    .await
    .expect("a `set` under a policy is permitted; the policy answers it, it does not refuse it");

    let prefs = persisted(&dir).await;
    assert_eq!(
        prefs["hostname"], POLICY_HOSTNAME,
        "`Hostname` must overwrite the name the operator typed in the very same command"
    );
    assert_eq!(
        prefs["control_url"], POLICY_LOGIN_URL,
        "`LoginURL` must reach `control_url`, which no `set` flag can even name"
    );
    assert_eq!(
        prefs["shields_up"], true,
        "`AllowIncomingConnections: never` is the NEGATION of shields-up: it must land as \
         `shields_up: true`, over the operator's `false`"
    );
    assert_eq!(
        prefs["accept_routes"], true,
        "`UseTailscaleSubnets: always` must force the pref on over the operator's `false`"
    );
    assert_eq!(
        prefs["auto_update_check"], false,
        "`CheckUpdates: never` must force the pref off over the operator's `true`"
    );
    assert_eq!(
        prefs["accept_dns"], false,
        "`user-decides` is the policy declining to have an opinion: the operator's value stands"
    );
    assert_eq!(
        prefs["exit_node_allow_lan_access"], true,
        "a key the file never mentions must leave its pref entirely alone — the third state, and \
         the one that keeps a policy file from being a whole-prefs reset"
    );

    // -------------------------------------------------------------------------------------------
    // 2. The tri-state. Go needs a `"HostnameDefaultValue"` sentinel to tell "not configured" from
    //    "configured to empty", because those two have to mean opposite things: leave the pref
    //    alone, versus clear it back to the OS hostname. The administrator revises the file to the
    //    empty string; the operator types a name again; the name must not survive.
    // -------------------------------------------------------------------------------------------
    register_policy("cleared", r#"{"Hostname": ""}"#);

    let dir = temp_dir("cleared");
    let mut be = fresh_backend(&dir).await;
    be.set(SetOptions {
        hostname: Some(OPERATOR_HOSTNAME.to_string()),
        ..Default::default()
    })
    .await
    .expect("naming a hostname under a policy that clears it is still a permitted `set`");

    let prefs = persisted(&dir).await;
    assert_eq!(
        prefs["hostname"],
        serde_json::Value::Null,
        "a present-but-empty `Hostname` must CLEAR the pref, not leave the operator's name in place"
    );
    assert_eq!(
        prefs["shields_up"], true,
        "the revision names one key: the earlier source still supplies the rest of the policy"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir("pinned")).await;
    let _ = tokio::fs::remove_dir_all(&temp_dir("cleared")).await;
}
