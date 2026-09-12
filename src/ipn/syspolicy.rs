//! System-policy (MDM) resolution — the Rust analogue of Go's `util/syspolicy`.
//!
//! Go resolves an **effective policy** by merging zero or more registered policy *stores* into a
//! single `setting.Snapshot` (a map of policy-key → {value, origin, error}). The `tailscale
//! syspolicy list` / `reload` commands print that snapshot. On **Windows** Go registers the
//! registry-backed `Platform` store (HKLM for the device scope, HKCU for the user scope). On
//! **Linux/Unix** the registry store does not exist — but since v1.102.3 every platform can also
//! register a **JSON policy file** named by `tailscaled --syspolicy-file`, which is what gives an
//! admin on a non-Windows host something to write policy into at all.
//!
//! This module owns both halves of that: [`load_json_policy_file`] (Go
//! `syspolicy.LoadJSONPolicyFile`, called once at daemon startup from `tailnetd`) and the merge that
//! [`effective_policy`] / [`reload_effective_policy`] report over. Go's other in-tree store, the
//! env-var-sourced `EnvPolicyStore`, is **never registered by default**, so — as before — we read no
//! environment source either.
//!
//! ## Precedence
//!
//! Go's `rsop` merges same-scope sources in registration order, so a **later-registered source wins
//! per key**, with earlier sources still supplying the keys it does not set. That is why the JSON
//! file beats the Windows registry there: `cmd/tailscaled` registers it after the platform store.
//! This daemon consults **exactly one** source — the JSON file — because it has no registry store
//! and registers no env store, so on every platform it supports the merge is the file itself. The
//! ordering rule is still implemented ([`merge`], last writer wins) rather than assumed away, so
//! adding a second source later is a registration call and not a redesign.
//!
//! ## Applying the snapshot to prefs
//!
//! Resolving is half the job; [`apply_to_prefs`] is the other half — the port of Go's
//! `ipnlocal.applySysPolicy` (+ `applyExitNodeSysPolicyLocked`), which overwrites the node's
//! [`Prefs`] with what the administrator configured. Go runs it from `reconcilePrefs`, which sits on
//! every prefs write and on every profile load; this daemon calls it from the same places it has:
//! profile load (daemon start and `tnet switch`), `up`, `set` and the `--config` merge, always
//! **after** the caller's own overrides, so **policy outranks whatever the operator just typed**.
//! That is the entire point of policy: a `tnet set --hostname laptop` against a policy file pinning
//! `"Hostname"` persists the pinned name, not the typed one.
//!
//! What it applies, and the rulings this fork had to make that Go did not:
//!
//! - `LoginURL` → `control_url`, `Hostname` → `hostname`. `Hostname` is a **tri-state**: absent
//!   leaves the pref alone, a non-empty value pins it, and a present-but-empty value CLEARS it (back
//!   to the OS hostname). Go needs a `"HostnameDefaultValue"` sentinel to express that, because its
//!   pref is a bare string; here the pref is already an `Option<String>` and the store already knows
//!   whether a key is configured, so the tri-state falls out with no sentinel.
//! - `AlwaysOn.Enabled` forces `want_running` back to true. That is only half of always-on mode: the
//!   other half is the **disconnect gate** ([`alwayson`](super::alwayson)), which reads
//!   [`PKEY_ALWAYS_ON`] and [`PKEY_ALWAYS_ON_OVERRIDE_WITH_REASON`] by name and refuses a
//!   `down`/`logout` outright unless the override key is set and the operator gave a reason. Go
//!   splits it the same way (`applySysPolicy` re-asserts the intent, `ipnauth.CheckDisconnectPolicy`
//!   refuses the disconnect), so both keys are enforced here and neither is reported as unenforced.
//!   What is **not** ported is the window between the two: Go's `overrideAlwaysOn` flag and
//!   `ReconnectAfter` timer, which suppress the re-assert for as long as a permitted override
//!   stands. Without them a disconnect the gate allowed holds until the next reconcile point
//!   (daemon start, `up`, `set`, `--config` reload) and is undone there — see the note on
//!   [`apply_settings_to_prefs`].
//! - Seven of Go's eight `preferencePolicies` map onto one bool pref each. The eighth,
//!   `UnattendedMode` (Go `ForceDaemon`), asks a GUI client to keep the daemon connected while no
//!   user is logged in; a system daemon with no user session is unattended by construction, which is
//!   why there is no pref for it — so it is reported as unenforced.
//! - `ExitNodeID` is **not applied**. Go pins a `tailcfg.StableNodeID`, and parks the pref on a
//!   deliberately invalid id while an `auto:` expression is unresolved so that traffic blackholes
//!   instead of leaking past the policy. This fork's exit node is one selector resolved by tailnet IP
//!   or MagicDNS name (`resolve_exit_node_arg`), with no stable-node-id form and no auto-selection —
//!   so storing the id would match no peer, and a selector that matches no peer egresses DIRECTLY.
//!   That is the leak the blackhole exists to prevent, so the honest answer is to refuse the key
//!   loudly instead of appearing to honour it. Go's mutual exclusion is kept: a configured
//!   `ExitNodeID` suppresses `ExitNodeIP` here too, so the refusal is one message rather than a
//!   silent downgrade to the key the admin de-prioritised. `ExitNodeIP` alone is applied.
//!
//! Refusals are returned, not swallowed: [`PolicyApplication::refused`] names every configured key
//! this build cannot enforce, and the daemon logs it at WARN every time the policy is reconciled. A
//! report that renders an administrator's intent while changing nothing is worse than no policy
//! support at all, so an unenforceable key has to say so.
//!
//! Two more keys act without ever touching prefs, because their effect is a refusal rather than a
//! rewritten pref: `tailnetd` reads [`PKEY_ENCRYPT_STATE`] and [`PKEY_HARDWARE_ATTESTATION`] by name
//! for two startup refusals.
//!
//! Two consequences worth stating. The applied values are **persisted** into `prefs.json` by
//! whichever write follows (a profile load applies in memory only and writes nothing, so merely
//! having a policy file never creates prefs for a never-configured node), which means removing a
//! policy file later leaves its last values behind as ordinary prefs — Go behaves the same way. And
//! `tnet syspolicy reload` deliberately does **not** re-apply: Go's JSON store captures the file at
//! construction and never re-reads it, so a reload cannot produce a different snapshot than the one
//! already applied, and re-applying would turn a read-only LocalAPI verb into a prefs write for no
//! observable gain (see the invariant on [`registered_store_settings`]).
//!
//! Scope: Go's CLI always resolves `setting.DefaultScope()`, which is the **device scope** on every
//! non-Windows platform, and `LoadJSONPolicyFile` registers at `setting.DeviceScope`. We record that
//! as the report's scope and do not parameterize it (the CLI never varies it); profile/user scoping
//! can be added if a real caller ever needs it.
//!
//! Upstream: `cmd/tailscaled/syspolicy.go`, `util/syspolicy/load.go`,
//! `util/syspolicy/source/json_policy_store.go`, `util/syspolicy/source/policy_reader.go` and
//! `util/syspolicy/policy_keys.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`; the apply half is
//! `ipn/ipnlocal/local.go` (`applySysPolicy`, `applyExitNodeSysPolicyLocked`,
//! `preferencePolicies`) @ `bbcd7d1fc2054b9189ebc1531acf74bd880ca0c8`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::RwLock;

use serde_json::{Map, Value};

use crate::goduration::{format_go_duration, parse_go_duration};
use crate::localapi::{PolicyReport, PolicySetting};
use crate::prefs::Prefs;

/// Go `pkey.EncryptState` — the policy key that asks a daemon to encrypt its state file at rest.
/// Named because `tailnetd` reads it by name (Go's `handleTPMFlags` does the same via
/// `policyclient.Get().GetBoolean(pkey.EncryptState, false)`), so the spelling has exactly one
/// definition shared with [`DEFINITIONS`].
pub const PKEY_ENCRYPT_STATE: &str = "EncryptState";

/// Go `pkey.HardwareAttestation` — the policy key that asks a daemon to bind the node identity to a
/// hardware-backed key. Read by name for the same reason as [`PKEY_ENCRYPT_STATE`].
pub const PKEY_HARDWARE_ATTESTATION: &str = "HardwareAttestation";

/// Go `pkey.AlwaysOn` — the policy key that forbids disconnecting the node. Read by name by the
/// disconnect gate ([`alwayson`](super::alwayson)), so — like [`PKEY_ENCRYPT_STATE`] — the spelling
/// has exactly one definition, shared with [`DEFINITIONS`].
pub const PKEY_ALWAYS_ON: &str = "AlwaysOn.Enabled";

/// Go `pkey.AlwaysOnOverrideWithReason` — the policy key that lets an operator disconnect an
/// always-on node by saying why. Read by name for the same reason as [`PKEY_ALWAYS_ON`].
pub const PKEY_ALWAYS_ON_OVERRIDE_WITH_REASON: &str = "AlwaysOn.OverrideWithReason";

/// The scope name the CLI resolves, matching Go `setting.DefaultScope().String()` on non-Windows
/// hosts (`"Device"`). Centralized so the report and any future scope plumbing agree on the spelling.
const DEVICE_SCOPE: &str = "Device";

/// The source name `tailnetd` registers the `--syspolicy-file` store under, matching the literal
/// `cmd/tailscaled` passes to `syspolicy.LoadJSONPolicyFile`. It is user-visible: the Origin column
/// of `tnet syspolicy list` shows `JSONFile (Device)` for every setting the file supplies.
pub const JSON_FILE_SOURCE_NAME: &str = "JSONFile";

/// A registered policy store's contribution to the effective policy: the settings it resolved,
/// already rendered into the wire shape the report carries.
///
/// The source's *name* is not a field: it is already baked into every setting's `origin` string
/// (`JSONFile (Device)`), which is where both the CLI's Origin column and any future diagnostic read
/// it from, so carrying a second copy here would be a value nothing may consult.
///
/// Go keeps a live `source.Reader` per store and re-reads it lazily. A [`JSONPolicyStore`-equivalent]
/// has nothing to re-read — Go's own JSON store "is a read-only snapshot; the underlying map is
/// captured at construction time and never re-read" — so we capture the resolved settings once, at
/// registration, and hold those. This also keeps the read path side-effect-free (see the invariant
/// on [`registered_store_settings`]): answering `syspolicy list` touches no file and no syscall.
///
/// [`JSONPolicyStore`-equivalent]: load_json_policy_file
#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicySource {
    /// The settings this source resolved, one per configured policy key.
    settings: Vec<PolicySetting>,
}

/// Every registered device-scope policy source, in registration order (Go's `rsop` store list).
///
/// Process-global because Go's is: `LoadJSONPolicyFile` is called once from `main` before anything
/// reads a policy setting, and the LocalAPI handlers ([`Backend::syspolicy_list`]) are static — they
/// take neither the backend lock nor a receiver, exactly like Go's `rsop.PolicyFor(scope)`.
///
/// [`Backend::syspolicy_list`]: crate::ipn::Backend::syspolicy_list
static REGISTERED: RwLock<Vec<PolicySource>> = RwLock::new(Vec::new());

/// What [`load_json_policy_file`] did, so the caller can log it honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadOutcome {
    /// The file does not exist. Nothing was registered and this is **not** an error: Go returns nil
    /// for `fs.ErrNotExist`, so the stock default path being absent is the silent, normal case.
    NoFile,
    /// The file parsed and validated, and its settings are now registered as a device-scope source.
    Registered {
        /// How many policy settings the file supplied (the row count `syspolicy list` will show).
        settings: usize,
    },
}

/// Load the JSON policy file at `path` and register its settings as a device-scope policy source
/// under `source_name` — Go `syspolicy.LoadJSONPolicyFile` (`util/syspolicy/load.go`), the body of
/// `tailscaled --syspolicy-file`.
///
/// Faithful to Go's three outcomes:
/// - **absent file** → [`LoadOutcome::NoFile`], no source registered, no error. The default path
///   ships empty on most hosts, so this is the common case and must stay quiet.
/// - **readable, well-formed, valid** → the settings are read once and registered.
/// - **anything else** → an error describing the whole problem. Malformed JSON, a non-object
///   document, an unknown policy key, or a value that cannot be decoded as its key's registered type
///   all surface *here*, at startup, rather than at first use — and **nothing is registered**, so a
///   half-valid file never applies half its settings. The caller (`tailnetd`) logs the error and
///   keeps running: a bad policy file must not stop the daemon from coming up.
///
/// The error strings are Go's shapes, including its doubled prefix on a parse failure
/// (`syspolicy: loading <path>: syspolicy: parsing JSON: …`) — Go wraps the store constructor's
/// already-prefixed error, and reproducing that is the point of a port. The one unavoidable
/// divergence is the text of an OS-level read failure, which comes from Rust's `io::Error`
/// (`Permission denied (os error 13)`) rather than Go's (`open …: permission denied`).
pub fn load_json_policy_file(source_name: &str, path: &Path) -> Result<LoadOutcome, String> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        // Go: `if errors.Is(err, fs.ErrNotExist) { return nil }` — an absent file disables the
        // source without complaint, which is what makes a default path safe to ship.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(LoadOutcome::NoFile),
        Err(e) => return Err(format!("syspolicy: loading {}: {e}", path.display())),
    };
    let store = parse_json_store(&data)
        .map_err(|e| format!("syspolicy: loading {}: {e}", path.display()))?;
    if let Err(problems) = validate(&store) {
        return Err(format!(
            "syspolicy: invalid {}:\n{problems}",
            path.display()
        ));
    }

    // Validation passed, so every key is known and every value decodes; read the snapshot once and
    // register it. (Go's `rsop.RegisterStore` can fail; ours cannot — there is no reader to
    // construct and no store to lock — so there is no third error shape to port here.)
    let settings = read_settings(&store, source_name);
    let count = settings.len();
    REGISTERED
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(PolicySource { settings });
    Ok(LoadOutcome::Registered { settings: count })
}

/// Resolve the effective system policy (the `tnet syspolicy list` path; Go
/// `LocalClient.GetEffectivePolicy(DefaultScope())` → `rsop.PolicyFor(scope).Get()`).
///
/// Returns the merge of all registered policy stores for the device scope: empty (and the CLI prints
/// "No policy settings") on a daemon started with no `--syspolicy-file`, or with one naming a file
/// that does not exist or failed to load. Never errors.
pub(super) fn effective_policy() -> PolicyReport {
    PolicyReport {
        scope: DEVICE_SCOPE.to_string(),
        settings: registered_store_settings(),
    }
}

/// Force a re-read of the effective system policy (the `tnet syspolicy reload` path; Go
/// `LocalClient.ReloadEffectivePolicy(DefaultScope())` → `rsop.PolicyFor(scope).Reload()`).
///
/// Go's `reload` forces a full re-read + re-merge of every registered source even when nothing
/// changed. For the JSON file source that is observationally identical to [`effective_policy`], and
/// deliberately so: Go's `JSONPolicyStore` captures the file's contents at construction and never
/// re-reads them, so `tailscale syspolicy reload` does **not** pick up an edit made to
/// `syspolicy.json` after the daemon started — only a restart does. Kept a distinct verb (faithful
/// to Go, and the place a genuinely re-readable source would be re-read). Never errors.
pub(super) fn reload_effective_policy() -> PolicyReport {
    // The forced re-read re-merges the registered sources; none of them can have changed underneath
    // us, because each captured its settings at registration (see `PolicySource`).
    PolicyReport {
        scope: DEVICE_SCOPE.to_string(),
        settings: registered_store_settings(),
    }
}

/// The merged settings from every registered policy store, for the device scope.
///
/// INVARIANT for any future store wired in here: reading/reloading it MUST be side-effect-free. The
/// `syspolicy list`/`reload` LocalAPI is classified read-only (`auth::requires_write` → false,
/// gated on `PermitRead`, matching Go's `policy/` handler). If a registered store's read ever
/// performs an observable action (writes a cache as the daemon's uid, fetches over the network,
/// spawns a helper), that classification becomes too weak — a non-owner read-only caller could drive
/// the side effect. In that case, reclassify `Request::SyspolicyReload` (at least) as a write in
/// `auth.rs` before wiring the store. The JSON file source satisfies the invariant by construction:
/// the file is read exactly once, at startup, on the daemon's own initiative.
fn registered_store_settings() -> Vec<PolicySetting> {
    merge(
        &REGISTERED
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    )
}

/// Merge registered sources into one device-scope setting list, **last registration wins per key**
/// (Go's `rsop` layering — see the Precedence section in the module docs), with the result sorted by
/// key so the report is stable regardless of registration or definition order.
fn merge(sources: &[PolicySource]) -> Vec<PolicySetting> {
    let mut by_key: BTreeMap<&str, &PolicySetting> = BTreeMap::new();
    for source in sources {
        for setting in &source.settings {
            by_key.insert(setting.key.as_str(), setting);
        }
    }
    by_key.into_values().cloned().collect()
}

// ---------------------------------------------------------------------------------------------
// The JSON policy store (Go `util/syspolicy/source/json_policy_store.go`).
// ---------------------------------------------------------------------------------------------

/// The type a policy key's value must decode as — Go's `setting.Type` restricted to the variants
/// this fork's definition table actually uses.
///
/// Go additionally has `IntegerValue` (read via `Store.ReadUInt64`). No key in
/// `implicitDefinitions` is declared with it at the pinned ref, so a variant here would be
/// permanently unconstructible; it is omitted rather than carried as dead code, and adding it is a
/// one-line change the day upstream declares an integer policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueType {
    /// JSON `true`/`false` (Go `setting.BooleanValue`).
    Boolean,
    /// A JSON string (Go `setting.StringValue`).
    String,
    /// A JSON array of strings (Go `setting.StringListValue`).
    StringList,
    /// A JSON string, one of `always` / `never` / `user-decides` (Go
    /// `setting.PreferenceOptionValue`).
    PreferenceOption,
    /// A JSON string, one of `show` / `hide` (Go `setting.VisibilityValue`).
    Visibility,
    /// A JSON string in Go's `time.ParseDuration` grammar, e.g. `24h` (Go
    /// `setting.DurationValue`).
    Duration,
}

impl ValueType {
    /// The JSON type name Go's `%T` prints for a value of this setting type, used in the
    /// `want <type>` half of a type-mismatch message. Every one of these is read out of the document
    /// as a JSON string except a boolean and a list.
    fn wanted_json_type(self) -> &'static str {
        match self {
            ValueType::Boolean => "bool",
            ValueType::StringList => "array",
            _ => "string",
        }
    }
}

/// One registered policy setting definition — Go's `setting.Definition`, reduced to the two fields
/// that matter here.
///
/// Go's third field, the setting's scope (`DeviceSetting` / `UserSetting`), is deliberately not
/// modelled: `source.Reader` skips a definition only when `origin.Scope().IsConfigurableSetting` is
/// false, and that test is `setting.Scope() >= scope.Kind()`, which is true for **every** definition
/// at the device scope. Since this daemon only ever resolves the device scope, carrying the field
/// would add a value that nothing may branch on.
#[derive(Debug, Clone, Copy)]
struct Definition {
    /// The policy key as it is spelled in the file and in the report's Name column (Go `pkey.Key` —
    /// note these are frequently *not* the Go constant's name: `ControlURL` is `"LoginURL"`).
    key: &'static str,
    /// The type its value must decode as.
    ty: ValueType,
}

/// Shorthand for one row of [`DEFINITIONS`].
const fn def(key: &'static str, ty: ValueType) -> Definition {
    Definition { key, ty }
}

/// Every policy key this daemon recognises — a direct port of Go's `implicitDefinitions`
/// (`util/syspolicy/policy_keys.go`), with the key strings from `util/syspolicy/pkey/pkey.go`.
///
/// This table is what makes an unknown key an error instead of a silent typo: Go's `Validate`
/// rejects any key not in it, so `{"Hostnmae": "x"}` refuses the whole file at startup rather than
/// leaving the admin to wonder why the policy has no effect. The order is Go's (device settings
/// first, then user settings); the report is sorted by key at merge time, so it does not matter to
/// output.
const DEFINITIONS: &[Definition] = &[
    // Device policy settings (configurable only on a per-device basis in Go).
    def("AllowedSuggestedExitNodes", ValueType::StringList),
    def("ExitNode.AllowOverride", ValueType::Boolean),
    def("AllowTailscaledRestart", ValueType::Boolean),
    def(PKEY_ALWAYS_ON, ValueType::Boolean),
    def(PKEY_ALWAYS_ON_OVERRIDE_WITH_REASON, ValueType::Boolean),
    def("InstallUpdates", ValueType::PreferenceOption),
    def("AuthKey", ValueType::String),
    def("CheckUpdates", ValueType::PreferenceOption),
    def("LoginURL", ValueType::String),
    def("DeviceSerialNumber", ValueType::String),
    def("EnableDNSRegistration", ValueType::PreferenceOption),
    def("AllowIncomingConnections", ValueType::PreferenceOption),
    def("AdvertiseExitNode", ValueType::PreferenceOption),
    def("UnattendedMode", ValueType::PreferenceOption),
    def("UseTailscaleDNSSettings", ValueType::PreferenceOption),
    def("UseTailscaleSubnets", ValueType::PreferenceOption),
    def("ExitNodeAllowLANAccess", ValueType::PreferenceOption),
    def("ExitNodeID", ValueType::String),
    def("ExitNodeIP", ValueType::String),
    def("FlushDNSOnSessionUnlock", ValueType::Boolean),
    def(PKEY_ENCRYPT_STATE, ValueType::Boolean),
    def("Hostname", ValueType::String),
    def("LogSCMInteractions", ValueType::Boolean),
    def("LogTarget", ValueType::String),
    def("MachineCertificateSubject", ValueType::String),
    def("PostureChecking", ValueType::PreferenceOption),
    def("ReconnectAfter", ValueType::Duration),
    def("Tailnet", ValueType::String),
    def(PKEY_HARDWARE_ATTESTATION, ValueType::Boolean),
    // User policy settings (configurable on a user- or device-basis; all of them are configurable
    // at the device scope, which is the only scope this daemon resolves).
    def("AdminConsole", ValueType::Visibility),
    def("ApplyUpdates", ValueType::Visibility),
    def("ExitNodesPicker", ValueType::Visibility),
    def("KeyExpirationNotice", ValueType::Duration),
    def("ManagedByCaption", ValueType::String),
    def("ManagedByOrganizationName", ValueType::String),
    def("ManagedByURL", ValueType::String),
    def("NetworkDevices", ValueType::Visibility),
    def("PreferencesMenu", ValueType::Visibility),
    def("ResetToDefaults", ValueType::Visibility),
    def("RunExitNode", ValueType::Visibility),
    def("SuggestedExitNode", ValueType::Visibility),
    def("TestMenu", ValueType::Visibility),
    def("UpdateMenu", ValueType::Visibility),
    def("OnboardingFlow", ValueType::Visibility),
];

/// The definition registered for `key`, or `None` if the key is not a known policy setting — Go's
/// `setting.DefinitionOf` lookup inside `Validate`.
fn definition_of(key: &str) -> Option<&'static Definition> {
    DEFINITIONS.iter().find(|d| d.key == key)
}

/// Read a boolean policy setting from the effective device-scope policy — Go
/// `syspolicy.GetBoolean(key, defaultValue)`, which `cmd/tailscaled` calls as
/// `policyclient.Get().GetBoolean(pkey.EncryptState, false)`.
///
/// `default` is returned whenever Go would return its own default: the key is not configured by any
/// registered source (Go's not-configured branch), the key is not a registered *boolean* definition
/// (Go's `ErrTypeMismatch`), or the setting resolved to an error instead of a value. Go's signature
/// is `(bool, error)` and every `cmd/tailscaled` caller discards the error and keeps the default, so
/// the error is folded into the default here rather than handed to a caller that would drop it.
///
/// Side-effect-free, like every other read of the registered stores — see the invariant on
/// [`registered_store_settings`].
pub fn get_boolean(key: &str, default: bool) -> bool {
    boolean_setting(&registered_store_settings(), key, default)
}

/// The decision behind [`get_boolean`], over an already-merged setting list so it is testable
/// without touching the process-global registry.
///
/// The definition-table check is not redundant with the lookup: it is Go's `ErrTypeMismatch` guard,
/// and it is what stops a caller asking for `GetBoolean("Hostname", …)` from getting a value parsed
/// out of a string setting's rendered form.
fn boolean_setting(settings: &[PolicySetting], key: &str, default: bool) -> bool {
    // A row carrying an error has no value; Go reports the error and the caller keeps the default,
    // which is what folding `None` into `default` does here.
    configured_boolean(settings, key).unwrap_or(default)
}

/// The value of boolean policy `key`, or `None` when it is **not configured** by any registered
/// source (Go's `ErrNotConfigured`), is not a registered *boolean* definition (Go's
/// `ErrTypeMismatch`), or resolved to an error instead of a value.
///
/// Distinguishing "not configured" from a configured `false` is what [`apply_settings_to_prefs`]
/// needs and [`boolean_setting`] does not — Go's `GetBoolean` collapses the two into its caller's
/// default, which is the right answer for `EncryptState` and the wrong one for `AlwaysOn.Enabled`.
fn configured_boolean(settings: &[PolicySetting], key: &str) -> Option<bool> {
    if !matches!(definition_of(key), Some(d) if d.ty == ValueType::Boolean) {
        return None;
    }
    settings
        .iter()
        .find(|s| s.key == key)?
        .value
        .as_deref()?
        .parse::<bool>()
        .ok()
}

/// The value of string policy `key`, or `None` when it is not configured, is not a registered
/// *string* definition, or resolved to an error — Go `syspolicy.GetString`'s configured branch.
///
/// A configured **empty** string is `Some("")`, not `None`: the two mean opposite things for
/// `Hostname` (see the tri-state note in the module docs), so the distinction cannot be collapsed.
fn configured_string<'a>(settings: &'a [PolicySetting], key: &str) -> Option<&'a str> {
    if !matches!(definition_of(key), Some(d) if d.ty == ValueType::String) {
        return None;
    }
    settings.iter().find(|s| s.key == key)?.value.as_deref()
}

/// The value of preference-option policy `key`, or `None` when it is not configured, is not a
/// registered *`PreferenceOption`* definition, or resolved to an error — Go
/// `syspolicy.GetPreferenceOption`'s configured branch.
fn configured_preference(settings: &[PolicySetting], key: &str) -> Option<PreferenceOption> {
    if !matches!(definition_of(key), Some(d) if d.ty == ValueType::PreferenceOption) {
        return None;
    }
    Some(PreferenceOption::parse(
        settings.iter().find(|s| s.key == key)?.value.as_deref()?,
    ))
}

/// Parse the policy file's bytes into its top-level object — Go
/// `source.NewJSONPolicyStoreFromBytes`.
///
/// **Standard JSON only.** Go accepts HuJSON (comments, trailing commas) when that feature is linked
/// into the build; this fork omits HuJSON for the declarative `--config` file too (see
/// `conffile::load`), and staying consistent beats supporting one dialect in one file type. A
/// comment in the policy file is therefore a load error, not a silently ignored line.
///
/// A JSON `null` document decodes to an empty store rather than an error, matching Go: `null`
/// unmarshals into a nil map, which reads as "no keys configured".
fn parse_json_store(data: &[u8]) -> Result<Map<String, Value>, String> {
    let parsed: Value =
        serde_json::from_slice(data).map_err(|e| format!("syspolicy: parsing JSON: {e}"))?;
    match parsed {
        Value::Object(map) => Ok(map),
        Value::Null => Ok(Map::new()),
        other => Err(format!(
            "syspolicy: parsing JSON: cannot unmarshal {} into a policy object",
            go_type_name(&other)
        )),
    }
}

/// The name Go's `%T` prints for a value decoded out of a JSON document by `encoding/json` with
/// `UseNumber` — used verbatim in the type-mismatch messages, so a mistyped policy value reads the
/// same here as it does from `tailscaled`.
fn go_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "<nil>",
        Value::Bool(_) => "bool",
        Value::Number(_) => "json.Number",
        Value::String(_) => "string",
        Value::Array(_) => "[]interface {}",
        Value::Object(_) => "map[string]interface {}",
    }
}

/// Go's `%q` on a string: double-quoted with escapes. Rust's `{:?}` agrees with Go for the
/// characters a policy key or value realistically contains.
///
/// `pub(super)` because the always-on audit record renders Go's `%q` over a profile name and a
/// username too ([`alwayson`](super::alwayson)), and two spellings of "Go's %q" would be one
/// spelling too many.
pub(super) fn quoted(s: &str) -> String {
    format!("{s:?}")
}

/// Check that every key in the parsed document is a known policy setting and that its value decodes
/// as that setting's type — Go `JSONPolicyStore.Validate`.
///
/// Every problem is reported, not just the first: Go joins them with `errors.Join` (one per line) so
/// an admin fixes the whole file in one pass instead of one startup per mistake. Keys are visited in
/// sorted order — Go sorts explicitly, and `serde_json::Map` is a `BTreeMap`, so iteration already
/// is — which makes the message deterministic.
///
/// Stricter than a plain read for the two enum-like types, exactly as Go is: `PreferenceOption` and
/// `Visibility` coerce an unrecognised string to a default when *read*, which would silently turn a
/// misspelled `"alwyas"` into `user-decides`, so validation checks the raw string instead.
fn validate(store: &Map<String, Value>) -> Result<(), String> {
    let mut problems: Vec<String> = Vec::new();
    for (key, value) in store {
        let Some(def) = definition_of(key) else {
            problems.push(format!("unknown policy setting {}", quoted(key)));
            continue;
        };
        let outcome = match def.ty {
            ValueType::PreferenceOption => validate_enum(
                value,
                key,
                &["always", "never", "user-decides"],
                "PreferenceOption",
                r#"("always", "never", or "user-decides")"#,
            ),
            ValueType::Visibility => validate_enum(
                value,
                key,
                &["show", "hide"],
                "Visibility",
                r#"("show" or "hide")"#,
            ),
            _ => read_value(value, key, def.ty).map(|_| ()),
        };
        if let Err(problem) = outcome {
            problems.push(format!("{}: {problem}", quoted(key)));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

/// The strict half of [`validate`] for Go's two enum-like setting types: the value must be a string
/// **and** one of the listed spellings, because their `UnmarshalText` never fails and would
/// otherwise turn a typo into a default at read time.
fn validate_enum(
    value: &Value,
    key: &str,
    allowed: &[&str],
    type_name: &str,
    allowed_text: &str,
) -> Result<(), String> {
    let s = as_string(value, key)?;
    if allowed.contains(&s.as_str()) {
        return Ok(());
    }
    Err(format!(
        "type mismatch: {} is not a valid {type_name} {allowed_text}",
        quoted(&s)
    ))
}

/// Read `value` as the type `ty` requires and render it the way Go's `%v` would print the decoded
/// value — the Value column of `syspolicy list`.
///
/// Go splits this across `Store.Read*` (which decodes) and `printPolicySettings` (which prints with
/// `%v`); the two are joined here because the report's wire type carries the value as a string.
/// The renderings are Go's: a `[]string` prints as `[a b c]`, a `time.Duration` as
/// `Duration.String()` (`24h` in the file becomes `24h0m0s`), and the enum-like types as their
/// `String()` spelling.
fn read_value(value: &Value, key: &str, ty: ValueType) -> Result<String, String> {
    match ty {
        ValueType::Boolean => match value.as_bool() {
            Some(b) => Ok(b.to_string()),
            None => Err(type_mismatch(key, value, ty)),
        },
        ValueType::String => as_string(value, key),
        ValueType::StringList => {
            let Some(items) = value.as_array() else {
                return Err(type_mismatch(key, value, ty));
            };
            let mut out: Vec<&str> = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                match item.as_str() {
                    Some(s) => out.push(s),
                    // Go names the offending index: `"K"[1] is bool, want string`.
                    None => {
                        return Err(format!(
                            "type mismatch: {}[{i}] is {}, want string",
                            quoted(key),
                            go_type_name(item)
                        ));
                    }
                }
            }
            // Go's `%v` of a `[]string`: elements space-separated inside square brackets.
            Ok(format!("[{}]", out.join(" ")))
        }
        // Go's `UnmarshalText` for these two never fails; an unrecognised spelling becomes the
        // default. Validation has already refused any such spelling, so the coercion is unreachable
        // through the load path — it is kept because it is what Go does at read time.
        ValueType::PreferenceOption => Ok(match as_string(value, key)?.as_str() {
            "always" => "always",
            "never" => "never",
            _ => "user-decides",
        }
        .to_string()),
        ValueType::Visibility => Ok(match as_string(value, key)?.as_str() {
            "hide" => "hide",
            _ => "show",
        }
        .to_string()),
        ValueType::Duration => {
            let s = as_string(value, key)?;
            // Go hands the raw string to `time.ParseDuration` and reports its error verbatim, so a
            // bad duration reads `time: unknown unit "d" in duration "7d"`.
            Ok(format_go_duration(parse_go_duration(&s)?))
        }
    }
}

/// Read `value` as a JSON string or produce Go's `want string` mismatch — the shared front half of
/// every string-shaped setting type.
fn as_string(value: &Value, key: &str) -> Result<String, String> {
    match value.as_str() {
        Some(s) => Ok(s.to_string()),
        None => Err(type_mismatch(key, value, ValueType::String)),
    }
}

/// Go's type-mismatch text: `type mismatch: "Hostname" is bool, want string`, where `type mismatch`
/// is `setting.ErrTypeMismatch`'s message, the key is `%q`-quoted and the actual type is `%T`.
fn type_mismatch(key: &str, value: &Value, ty: ValueType) -> String {
    format!(
        "type mismatch: {} is {}, want {}",
        quoted(key),
        go_type_name(value),
        ty.wanted_json_type()
    )
}

/// Resolve the whole definition table against a validated store — Go `source.Reader.reload`.
///
/// One entry per *configured* key: a definition the document does not mention is skipped (Go's
/// `ErrNotConfigured` branch), which is what keeps `syspolicy list` showing the admin's file rather
/// than 44 rows of defaults. A per-key read error would be carried in the row's Error column rather
/// than dropping the row — Go's behaviour — though the load path cannot produce one, because
/// [`validate`] already refused every value this could fail on.
fn read_settings(store: &Map<String, Value>, source_name: &str) -> Vec<PolicySetting> {
    // Go `setting.Origin.String()`: `<name> (<scope>)`, e.g. `JSONFile (Device)`.
    let origin = format!("{source_name} ({DEVICE_SCOPE})");
    let mut out = Vec::new();
    for def in DEFINITIONS {
        let Some(value) = store.get(def.key) else {
            continue;
        };
        let (value, error) = match read_value(value, def.key, def.ty) {
            Ok(rendered) => (Some(rendered), None),
            Err(text) => (None, Some(text)),
        };
        out.push(PolicySetting {
            key: def.key.to_string(),
            origin: origin.clone(),
            value,
            error,
        });
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Applying the effective policy to prefs (Go `ipnlocal.applySysPolicy`).
// ---------------------------------------------------------------------------------------------

/// Go `setting.PreferenceOption`: an administrator's three-state answer about one boolean
/// preference — force it on, force it off, or leave it to whoever owns the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreferenceOption {
    /// `always` — the preference is on and the operator cannot turn it off.
    Always,
    /// `never` — the preference is off and the operator cannot turn it on.
    Never,
    /// `user-decides` — the policy expresses no opinion; the current value stands.
    UserDecides,
}

impl PreferenceOption {
    /// Go `PreferenceOption.ShouldEnable(def)`: `always`/`never` answer outright, `user-decides`
    /// keeps whatever the node already has.
    fn should_enable(self, current: bool) -> bool {
        match self {
            PreferenceOption::Always => true,
            PreferenceOption::Never => false,
            PreferenceOption::UserDecides => current,
        }
    }

    /// Decode the rendered Value column back into the option — the inverse of the
    /// `ValueType::PreferenceOption` arm of [`read_value`].
    ///
    /// Total, like Go's `UnmarshalText`, which never fails and falls back to `user-decides`. That
    /// fallback is unreachable through the load path ([`validate`] refuses any other spelling
    /// outright, precisely so a misspelled `"alwyas"` cannot silently become "leave it alone").
    fn parse(rendered: &str) -> Self {
        match rendered {
            "always" => PreferenceOption::Always,
            "never" => PreferenceOption::Never,
            _ => PreferenceOption::UserDecides,
        }
    }
}

/// One of Go's `preferencePolicies` rows: a `PreferenceOption` policy key wired to the single bool
/// pref it governs.
///
/// `set` writes the pref **and returns the pref's new value rendered for the log**, rather than the
/// caller re-deriving it: for `AllowIncomingConnections` the policy's bool and the pref's bool are
/// opposites (Go's comment: "Allow Incoming (used by the UI) is the negation of ShieldsUp (used by
/// the backend)"), so a log line built from the policy value would report the wrong pref state on
/// the one row where it matters most.
struct PreferencePolicy {
    /// The policy key, as spelled in the file and in [`DEFINITIONS`].
    key: &'static str,
    /// The pref it governs, spelled as [`crate::ipn::revert_guard`] spells it — these names are
    /// matched against that guard's keys (see [`pinned_prefs_in`]), so the two must agree.
    pref: &'static str,
    /// The pref's current value, in the policy's polarity.
    get: fn(&Prefs) -> bool,
    /// Write the policy's answer; returns the resulting PREF value, rendered.
    set: fn(&mut Prefs, bool) -> String,
}

/// Go's `preferencePolicies` (`ipn/ipnlocal/local.go`), less the one row this daemon has no pref
/// for.
///
/// The absentee is `UnattendedMode` (Go's `ForceDaemon`), which asks a GUI client to keep the
/// daemon connected while no user is signed in. A system daemon has no user session to be tied to —
/// it is unattended by construction — which is why [`crate::prefs::Prefs`] has no field for it and
/// why [`apply_settings_to_prefs`] reports the key as unenforced instead of quietly dropping it.
const PREFERENCE_POLICIES: &[PreferencePolicy] = &[
    PreferencePolicy {
        // Go's own note: this key is the UI's polarity, `ShieldsUp` is the backend's, so the row has
        // to invert in both directions.
        key: "AllowIncomingConnections",
        pref: "shields_up",
        get: |p| !p.shields_up,
        set: |p, v| {
            p.shields_up = !v;
            p.shields_up.to_string()
        },
    },
    PreferencePolicy {
        key: "ExitNodeAllowLANAccess",
        pref: "exit_node_allow_lan_access",
        get: |p| p.exit_node_allow_lan_access,
        set: |p, v| {
            p.exit_node_allow_lan_access = v;
            v.to_string()
        },
    },
    PreferencePolicy {
        // Go `EnableTailscaleDNS` → `Prefs.CorpDNS`.
        key: "UseTailscaleDNSSettings",
        pref: "accept_dns",
        get: |p| p.accept_dns,
        set: |p, v| {
            p.accept_dns = v;
            v.to_string()
        },
    },
    PreferencePolicy {
        // Go `EnableTailscaleSubnets` → `Prefs.RouteAll`.
        key: "UseTailscaleSubnets",
        pref: "accept_routes",
        get: |p| p.accept_routes,
        set: |p, v| {
            p.accept_routes = v;
            v.to_string()
        },
    },
    PreferencePolicy {
        key: "CheckUpdates",
        pref: "auto_update_check",
        get: |p| p.auto_update_check,
        set: |p, v| {
            p.auto_update_check = v;
            v.to_string()
        },
    },
    PreferencePolicy {
        // Go `ApplyUpdates` → `Prefs.AutoUpdate.Apply`, an `opt.Bool`. Go reads it as
        // `v, _ := Apply.Get()`, i.e. UNSET reads as false — so `never` and `user-decides` leave an
        // unset pref unset (no change), and only `always` ever writes one. Mirrored exactly by the
        // `unwrap_or(false)` here.
        //
        // This deliberately bypasses the fork's own `selfupdate::check_auto_update_pref` refusal,
        // which guards the OPERATOR's `tnet set --auto-update` on a host that cannot replace its own
        // binary. That refusal protects a person from promising something they cannot keep; it is not
        // a rule the administrator's policy is subject to, and Go applies this key unconditionally.
        // The pref only advertises `Hostinfo.AllowsUpdate`, so the worst case is a node telling the
        // tailnet it accepts update triggers that an operator will then have to apply by hand.
        key: "InstallUpdates",
        pref: "auto_update_apply",
        get: |p| p.auto_update_apply.unwrap_or(false),
        set: |p, v| {
            p.auto_update_apply = Some(v);
            v.to_string()
        },
    },
    PreferencePolicy {
        key: "AdvertiseExitNode",
        pref: "advertise_exit_node",
        get: |p| p.advertise_exit_node,
        set: |p, v| {
            p.advertise_exit_node = v;
            v.to_string()
        },
    },
];

/// One pref a policy setting actually changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyChange {
    /// The policy key that caused it.
    pub key: &'static str,
    /// The pref it landed on.
    pub pref: &'static str,
    /// The pref's new value, rendered. An [`Option`] pref that was CLEARED renders as the empty
    /// string, which is what "no value" looks like in the file that asked for it.
    pub value: String,
}

/// One configured policy key this build cannot enforce, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRefusal {
    /// The policy key the administrator configured.
    pub key: &'static str,
    /// Why nothing happened, in words an administrator can act on.
    pub reason: String,
}

/// What [`apply_to_prefs`] did — the honest answer to "did my policy file take effect?".
///
/// Both halves matter. `changed` is the enforcement; `refused` is the part that keeps this from
/// being the reporting-only surface it replaced, where an administrator could watch their intent
/// echoed back and find the node unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyApplication {
    /// Every pref a policy setting moved, in the order the policy was evaluated.
    pub changed: Vec<PolicyChange>,
    /// Every configured key this build cannot enforce.
    pub refused: Vec<PolicyRefusal>,
}

impl PolicyApplication {
    /// Whether the policy neither changed nor refused anything — the usual case, and the one the
    /// caller stays quiet about.
    pub fn is_quiet(&self) -> bool {
        self.changed.is_empty() && self.refused.is_empty()
    }
}

/// Apply the effective device-scope policy to `prefs` — Go `ipnlocal.applySysPolicy`, called from
/// the daemon wherever Go's `reconcilePrefs` runs (profile load, `up`, `set`, `--config`).
///
/// Side-effect-free apart from `prefs`: it reads the registered stores exactly as
/// [`effective_policy`] does (see the invariant on [`registered_store_settings`]) and touches no
/// file. Persisting the result is the caller's job.
pub(super) fn apply_to_prefs(prefs: &mut Prefs) -> PolicyApplication {
    apply_settings_to_prefs(&registered_store_settings(), prefs)
}

/// The decision behind [`apply_to_prefs`], over an already-merged setting list so the whole of Go's
/// `applySysPolicy` is testable without the process-global registry.
///
/// Go's order, which this keeps: `LoginURL`, `Hostname`, the exit node, `AlwaysOn`, then the
/// `preferencePolicies` table. No row reads a pref another row writes, so the order is documentary
/// rather than load-bearing.
///
/// **`down` and `logout` are deliberately not reconcile points.** `AlwaysOn.Enabled` re-asserts
/// `want_running` wherever this runs, which means a node under an always-on policy comes back up at
/// the next daemon start, `up`, `set` or config reload — but a disconnect the gate has just let
/// through still stops the node now, and stays stopped until one of those points comes round.
/// Re-asserting inside `down` itself would make the permitted disconnect a lie: the gate
/// ([`alwayson`](super::alwayson)) is where the policy decides whether the operator may stop the
/// node, and a `down` that is allowed and then immediately undone is worse than one that is refused,
/// because nothing tells the operator which happened. Go bridges the same gap with the
/// `overrideAlwaysOn` flag and its `ReconnectAfter` timer — a permitted override suppresses the
/// re-assert for a bounded window, then the node reconnects. Neither is ported yet, so the window
/// here is "until the next reconcile point" rather than a duration the administrator sets.
fn apply_settings_to_prefs(settings: &[PolicySetting], prefs: &mut Prefs) -> PolicyApplication {
    let mut out = PolicyApplication::default();

    // `LoginURL` → the control server. Go compares against the current value and writes on
    // difference; an EMPTY configured value means "no override" in Go's bare-string pref, which is
    // this fork's `None` (fall back to the engine/`TS_CONTROL_URL` default).
    if let Some(url) = configured_string(settings, "LoginURL") {
        let want = (!url.is_empty()).then(|| url.to_string());
        if prefs.control_url != want {
            prefs.control_url = want;
            out.changed.push(PolicyChange {
                key: "LoginURL",
                pref: "control_url",
                value: prefs.control_url.clone().unwrap_or_default(),
            });
        }
    }

    // `Hostname` → the requested hostname, tri-state (see the module docs): configured-and-empty
    // CLEARS the pref rather than leaving it alone, which is the distinction Go's
    // `HostnameDefaultValue` sentinel exists to draw.
    if let Some(hostname) = configured_string(settings, "Hostname") {
        let want = (!hostname.is_empty()).then(|| hostname.to_string());
        if prefs.hostname != want {
            prefs.hostname = want;
            out.changed.push(PolicyChange {
                key: "Hostname",
                pref: "hostname",
                value: prefs.hostname.clone().unwrap_or_default(),
            });
        }
    }

    apply_exit_node_policy(settings, prefs, &mut out);

    // `AlwaysOn.Enabled` → force the node back to "should be connected". One-way: the policy can
    // only turn want-running ON (Go's `alwaysOn && !prefs.WantRunning`), never off.
    //
    // `AlwaysOn.OverrideWithReason` has no pref to move and is therefore absent here, but it is NOT
    // unenforced: the disconnect gate reads it by name to decide whether `down`/`logout` may proceed
    // at all (see the module docs), which is the whole of its effect in Go too.
    if configured_boolean(settings, PKEY_ALWAYS_ON) == Some(true) && !prefs.want_running {
        prefs.want_running = true;
        out.changed.push(PolicyChange {
            key: PKEY_ALWAYS_ON,
            pref: "want_running",
            value: "true".to_string(),
        });
    }

    // The `preferencePolicies` table: one `PreferenceOption` key per bool pref. `user-decides`
    // resolves to the pref's current value, so it never counts as a change — matching Go, which only
    // writes when `curVal != newVal`.
    for policy in PREFERENCE_POLICIES {
        let Some(option) = configured_preference(settings, policy.key) else {
            continue;
        };
        let current = (policy.get)(prefs);
        let wanted = option.should_enable(current);
        if wanted != current {
            let value = (policy.set)(prefs, wanted);
            out.changed.push(PolicyChange {
                key: policy.key,
                pref: policy.pref,
                value,
            });
        }
    }
    if configured_preference(settings, "UnattendedMode").is_some() {
        out.refused.push(PolicyRefusal {
            key: "UnattendedMode",
            reason: "this is a system daemon with no user session to be tied to, so it is already \
                     unattended; there is no preference for the policy to move"
                .to_string(),
        });
    }

    out
}

/// The exit-node half — Go `applyExitNodeSysPolicyLocked` — with this fork's ruling on `ExitNodeID`.
///
/// Go's mutual exclusion is preserved: a configured, non-empty `ExitNodeID` wins outright and
/// `ExitNodeIP` is never consulted. Since the id cannot be honoured here (see the module docs), that
/// means a file naming both pins neither, and says so once — rather than silently falling through to
/// the key the administrator ranked second.
fn apply_exit_node_policy(
    settings: &[PolicySetting],
    prefs: &mut Prefs,
    out: &mut PolicyApplication,
) {
    if let Some(id) = configured_string(settings, "ExitNodeID").filter(|id| !id.is_empty()) {
        // Go turns an `auto:`-prefixed id into an `ExitNodeExpression` and parks `ExitNodeID` on a
        // deliberately invalid id until the pick resolves, so traffic blackholes rather than leaking
        // outside the policy. Both halves need machinery this build does not have — it refuses
        // `--exit-node auto:…` by name for the same reason — so the two cases are named separately
        // and neither is applied.
        let reason = if id.starts_with("auto:") {
            format!(
                "{id:?}: automatic exit-node selection (`auto:`…) is not supported by this build, \
                 which has no expression to resolve and no blackhole state to park on while it is \
                 unresolved; pin a concrete node with ExitNodeIP"
            )
        } else {
            format!(
                "{id:?}: this build selects an exit node by tailnet IP or MagicDNS name, not by \
                 stable node id, and a selector that matches no peer egresses DIRECTLY rather than \
                 blackholing — which is the leak this key exists to prevent; pin the node with \
                 ExitNodeIP"
            )
        };
        out.refused.push(PolicyRefusal {
            key: "ExitNodeID",
            reason,
        });
        return;
    }

    let Some(raw) = configured_string(settings, "ExitNodeIP").filter(|ip| !ip.is_empty()) else {
        return;
    };
    // Go ignores a value `netip.ParseAddr` rejects (its `err == nil` guard). Ignoring it is right —
    // an unparseable address must not become a peer NAME to match against — but doing it silently is
    // not, so the refusal is reported.
    let Ok(addr) = raw.parse::<std::net::IpAddr>() else {
        out.refused.push(PolicyRefusal {
            key: "ExitNodeIP",
            reason: format!("{raw:?} is not an IP address"),
        });
        return;
    };
    // Stored in the address's canonical form, which is what `resolve_exit_node_arg` and the engine's
    // selector both parse back.
    let want = addr.to_string();
    if prefs.exit_node.as_deref() != Some(want.as_str()) {
        prefs.exit_node = Some(want.clone());
        out.changed.push(PolicyChange {
            key: "ExitNodeIP",
            pref: "exit_node",
            value: want,
        });
    }
}

/// The prefs the effective policy **pins** — the ones an operator cannot move, whether or not they
/// currently differ from what the policy says.
///
/// Read by [`Backend::up_revert_guard`], which must not refuse an `up` for "silently reverting" a
/// pref that the very same `up` re-applies from policy a moment later. See
/// [`revert_guard::drop_policy_pinned`].
///
/// [`Backend::up_revert_guard`]: crate::ipn::Backend::up_revert_guard
/// [`revert_guard::drop_policy_pinned`]: super::revert_guard::drop_policy_pinned
pub(super) fn pinned_prefs() -> Vec<&'static str> {
    pinned_prefs_in(&registered_store_settings())
}

/// The decision behind [`pinned_prefs`], over an already-merged setting list.
///
/// Every name here is a name [`apply_settings_to_prefs`] can write (asserted by a test, so the two
/// cannot drift), spelled the way [`crate::ipn::revert_guard`] spells its keys. `want_running` is
/// absent on purpose: `AlwaysOn` does pin it, but it is lifecycle rather than an up-managed setting,
/// so the guard has no arm for it to suppress.
fn pinned_prefs_in(settings: &[PolicySetting]) -> Vec<&'static str> {
    let mut pinned = Vec::new();
    if configured_string(settings, "LoginURL").is_some() {
        pinned.push("control_url");
    }
    if configured_string(settings, "Hostname").is_some() {
        pinned.push("hostname");
    }
    // Only a value that is actually applied pins the pref: a refused `ExitNodeID` changes nothing,
    // so the operator's own exit node is still theirs to lose and still worth guarding.
    if configured_string(settings, "ExitNodeID")
        .filter(|id| !id.is_empty())
        .is_none()
        && configured_string(settings, "ExitNodeIP")
            .filter(|ip| !ip.is_empty())
            .is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok())
    {
        pinned.push("exit_node");
    }
    for policy in PREFERENCE_POLICIES {
        // `user-decides` is the policy declining to have an opinion, so it pins nothing.
        if matches!(configured_preference(settings, policy.key),
            Some(option) if option != PreferenceOption::UserDecides)
        {
            pinned.push(policy.pref);
        }
    }
    pinned
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse + validate + resolve a document the way [`load_json_policy_file`] does, without
    /// touching the process-global registry — so these tests stay independent of each other and of
    /// whatever a daemon would have registered.
    fn resolve(json: &str) -> Result<Vec<PolicySetting>, String> {
        let store = parse_json_store(json.as_bytes())?;
        validate(&store)?;
        Ok(read_settings(&store, JSON_FILE_SOURCE_NAME))
    }

    #[test]
    fn list_is_empty_device_scoped_with_no_registered_source() {
        // A daemon that registered no policy file resolves an empty-but-valid snapshot: device
        // scope, no settings, no error. `syspolicy list` prints "No policy settings".
        let r = effective_policy();
        assert_eq!(r.scope, "Device");
        assert!(
            r.settings.is_empty(),
            "no policy source is registered in this test process; the effective policy must be empty"
        );
    }

    #[test]
    fn reload_matches_list_with_no_sources() {
        // With zero sources the forced re-read yields the same empty snapshot as `list`.
        assert_eq!(reload_effective_policy(), effective_policy());
    }

    #[test]
    fn reload_is_device_scoped_and_empty() {
        let r = reload_effective_policy();
        assert_eq!(r.scope, "Device");
        assert!(r.settings.is_empty());
    }

    #[test]
    fn a_configured_file_resolves_to_device_scoped_rows_with_the_file_as_origin() {
        let settings = resolve(
            r#"{"Hostname": "documented-node", "AlwaysOn.Enabled": true,
                "CheckUpdates": "always", "AdminConsole": "hide",
                "ReconnectAfter": "60m",
                "AllowedSuggestedExitNodes": ["nodeA", "nodeB"]}"#,
        )
        .expect("a well-formed policy file should load");

        let rendered: Vec<(String, Option<String>)> = settings
            .iter()
            .map(|s| (s.key.clone(), s.value.clone()))
            .collect();
        // Every row carries the file as its origin and no error.
        for s in &settings {
            assert_eq!(s.origin, "JSONFile (Device)", "row {:?}", s.key);
            assert_eq!(s.error, None, "row {:?} should resolve cleanly", s.key);
        }
        // The values are Go's `%v` renderings, not the raw JSON: a duration is canonicalised by
        // `Duration.String()` and a list is Go's `[a b c]`.
        assert!(rendered.contains(&("Hostname".to_string(), Some("documented-node".to_string()))));
        assert!(rendered.contains(&("AlwaysOn.Enabled".to_string(), Some("true".to_string()))));
        assert!(rendered.contains(&("CheckUpdates".to_string(), Some("always".to_string()))));
        assert!(rendered.contains(&("AdminConsole".to_string(), Some("hide".to_string()))));
        assert!(rendered.contains(&("ReconnectAfter".to_string(), Some("1h0m0s".to_string()))));
        assert!(rendered.contains(&(
            "AllowedSuggestedExitNodes".to_string(),
            Some("[nodeA nodeB]".to_string())
        )));
        assert_eq!(settings.len(), 6, "only configured keys become rows");
    }

    #[test]
    fn only_configured_keys_appear() {
        // The definition table has dozens of keys; a one-key file must produce exactly one row, not
        // a row per known policy (Go skips `ErrNotConfigured`).
        let settings = resolve(r#"{"Tailnet": "example.com"}"#).expect("one key should load");
        assert_eq!(settings.len(), 1);
        assert_eq!(settings[0].key, "Tailnet");
        assert_eq!(settings[0].value.as_deref(), Some("example.com"));
    }

    #[test]
    fn an_empty_object_is_valid_and_configures_nothing() {
        assert_eq!(resolve("{}"), Ok(Vec::new()));
        // Go decodes a `null` document into a nil map, which is "no keys configured", not an error.
        assert_eq!(resolve("null"), Ok(Vec::new()));
    }

    #[test]
    fn an_unknown_key_refuses_the_whole_file() {
        let err = resolve(r#"{"Hostnmae": "typo"}"#).expect_err("an unknown key must refuse");
        assert_eq!(err, r#"unknown policy setting "Hostnmae""#);
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        // Go joins the validation errors so one startup surfaces the whole broken file. Keys are
        // visited in sorted order, so the message is deterministic.
        let err = resolve(r#"{"Hostname": 7, "Nope": 1, "CheckUpdates": "sometimes"}"#)
            .expect_err("three problems must refuse");
        assert_eq!(
            err,
            concat!(
                "\"CheckUpdates\": type mismatch: \"sometimes\" is not a valid PreferenceOption ",
                "(\"always\", \"never\", or \"user-decides\")\n",
                "\"Hostname\": type mismatch: \"Hostname\" is json.Number, want string\n",
                "unknown policy setting \"Nope\""
            )
        );
    }

    #[test]
    fn each_setting_type_refuses_the_wrong_json_type() {
        for (json, want) in [
            (
                r#"{"AlwaysOn.Enabled": "yes"}"#,
                "\"AlwaysOn.Enabled\": type mismatch: \"AlwaysOn.Enabled\" is string, want bool",
            ),
            (
                r#"{"Hostname": ["a"]}"#,
                "\"Hostname\": type mismatch: \"Hostname\" is []interface {}, want string",
            ),
            (
                r#"{"AllowedSuggestedExitNodes": "nodeA"}"#,
                "\"AllowedSuggestedExitNodes\": type mismatch: \"AllowedSuggestedExitNodes\" is \
                 string, want array",
            ),
            (
                r#"{"AllowedSuggestedExitNodes": ["nodeA", 2]}"#,
                "\"AllowedSuggestedExitNodes\": type mismatch: \"AllowedSuggestedExitNodes\"[1] is \
                 json.Number, want string",
            ),
            (
                r#"{"AdminConsole": "maybe"}"#,
                "\"AdminConsole\": type mismatch: \"maybe\" is not a valid Visibility (\"show\" or \
                 \"hide\")",
            ),
            (
                r#"{"ReconnectAfter": "7d"}"#,
                "\"ReconnectAfter\": time: unknown unit \"d\" in duration \"7d\"",
            ),
            (
                r#"{"ReconnectAfter": null}"#,
                "\"ReconnectAfter\": type mismatch: \"ReconnectAfter\" is <nil>, want string",
            ),
        ] {
            assert_eq!(
                resolve(json).expect_err("the case should refuse"),
                want,
                "for {json}"
            );
        }
    }

    #[test]
    fn malformed_json_refuses_with_gos_prefix() {
        let err = parse_json_store(b"{\"Hostname\": }").expect_err("malformed JSON must refuse");
        assert!(
            err.starts_with("syspolicy: parsing JSON: "),
            "unexpected message: {err}"
        );
        // A comment is malformed too: this fork parses standard JSON only (no HuJSON), matching how
        // it reads the `--config` file.
        assert!(
            parse_json_store(b"{\n// a comment\n}").is_err(),
            "HuJSON comments are not accepted"
        );
    }

    #[test]
    fn a_non_object_document_refuses() {
        assert_eq!(
            parse_json_store(b"[1, 2]").expect_err("a JSON array is not a policy document"),
            "syspolicy: parsing JSON: cannot unmarshal []interface {} into a policy object"
        );
    }

    #[test]
    fn an_absent_file_registers_nothing_and_is_not_an_error() {
        // Go returns nil for `fs.ErrNotExist`: the stock default path is absent on most hosts, so
        // this is the normal case and must not log or refuse.
        let missing = std::env::temp_dir().join(format!(
            "tailnetd-syspolicy-absent-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&missing);
        assert_eq!(
            load_json_policy_file(JSON_FILE_SOURCE_NAME, &missing),
            Ok(LoadOutcome::NoFile)
        );
        // Nothing was registered, so the effective policy is still empty.
        assert!(effective_policy().settings.is_empty());
    }

    #[test]
    fn a_bad_file_names_the_path_and_registers_nothing() {
        let path = std::env::temp_dir().join(format!(
            "tailnetd-syspolicy-bad-{}-{}.json",
            std::process::id(),
            line!()
        ));
        std::fs::write(&path, br#"{"Nope": 1}"#).expect("the temp file should be writable");
        let err = load_json_policy_file(JSON_FILE_SOURCE_NAME, &path)
            .expect_err("an invalid file must refuse");
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            err,
            format!(
                "syspolicy: invalid {}:\nunknown policy setting \"Nope\"",
                path.display()
            )
        );
        // Refused wholesale: a file with one bad key contributes none of its keys.
        assert!(effective_policy().settings.is_empty());
    }

    #[test]
    fn a_malformed_file_carries_gos_doubled_prefix() {
        let path = std::env::temp_dir().join(format!(
            "tailnetd-syspolicy-malformed-{}-{}.json",
            std::process::id(),
            line!()
        ));
        std::fs::write(&path, b"not json").expect("the temp file should be writable");
        let err = load_json_policy_file(JSON_FILE_SOURCE_NAME, &path)
            .expect_err("a malformed file must refuse");
        let _ = std::fs::remove_file(&path);
        // Go wraps the store constructor's already-prefixed error, so both prefixes appear.
        assert!(
            err.starts_with(&format!(
                "syspolicy: loading {}: syspolicy: parsing JSON: ",
                path.display()
            )),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn a_later_source_wins_per_key_and_earlier_ones_fill_the_rest() {
        // Go's `rsop` layers same-scope sources in registration order. This daemon registers one
        // source today, but the rule is the ported one — and it is what would make a JSON file beat
        // a registry store on Windows.
        let earlier = PolicySource {
            settings: vec![
                PolicySetting {
                    key: "Hostname".to_string(),
                    origin: "Platform (Device)".to_string(),
                    value: Some("from-registry".to_string()),
                    error: None,
                },
                PolicySetting {
                    key: "Tailnet".to_string(),
                    origin: "Platform (Device)".to_string(),
                    value: Some("example.com".to_string()),
                    error: None,
                },
            ],
        };
        let later = PolicySource {
            settings: vec![PolicySetting {
                key: "Hostname".to_string(),
                origin: "JSONFile (Device)".to_string(),
                value: Some("from-file".to_string()),
                error: None,
            }],
        };

        let merged = merge(&[earlier, later]);
        // Sorted by key, the later source's Hostname wins, and the key it does not set survives.
        assert_eq!(
            merged
                .iter()
                .map(|s| (s.key.as_str(), s.value.as_deref(), s.origin.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("Hostname", Some("from-file"), "JSONFile (Device)"),
                ("Tailnet", Some("example.com"), "Platform (Device)"),
            ]
        );
    }

    #[test]
    fn the_definition_table_has_no_duplicate_keys() {
        // Two Go constants map to confusingly similar key strings (`ApplyUpdates` is the key of
        // `AutoUpdateVisibility`, while the `ApplyUpdates` constant's key is `InstallUpdates`), so a
        // transcription slip here would shadow a real policy key. `definition_of` takes the first
        // match, which would silently be the wrong type.
        let mut seen = std::collections::BTreeSet::new();
        for d in DEFINITIONS {
            assert!(seen.insert(d.key), "duplicate policy key {:?}", d.key);
        }
        assert_eq!(seen.len(), DEFINITIONS.len());
    }

    // --- `get_boolean` (Go `syspolicy.GetBoolean`) ---------------------------------------------
    //
    // The two TPM policy keys `tailnetd` reads at startup are booleans, so this is the read path
    // behind `handleTPMFlags`'s `policyclient.Get().GetBoolean(pkey.EncryptState, false)`.

    #[test]
    fn a_configured_boolean_policy_key_reads_as_its_value() {
        let settings = resolve(r#"{"EncryptState": true, "HardwareAttestation": false}"#)
            .expect("both keys are registered booleans");
        // The default is deliberately the opposite of each configured value, so a `get_boolean`
        // that ignored the file would fail rather than coincidentally agree with it.
        assert!(boolean_setting(&settings, PKEY_ENCRYPT_STATE, false));
        assert!(!boolean_setting(&settings, PKEY_HARDWARE_ATTESTATION, true));
    }

    #[test]
    fn an_unconfigured_boolean_policy_key_reads_as_the_default() {
        // Go's not-configured branch: the file sets one key, so the other must fall back.
        let settings = resolve(r#"{"EncryptState": true}"#).expect("a registered boolean");
        assert!(!boolean_setting(
            &settings,
            PKEY_HARDWARE_ATTESTATION,
            false
        ));
        assert!(boolean_setting(&settings, PKEY_HARDWARE_ATTESTATION, true));
    }

    #[test]
    fn a_non_boolean_or_unknown_key_reads_as_the_default() {
        // Go's `ErrTypeMismatch`: `Hostname` is a string setting, so asking for it as a boolean
        // yields the default rather than something parsed out of its rendered value. An unknown key
        // has no definition at all and behaves the same way.
        let settings = resolve(r#"{"Hostname": "true"}"#).expect("a registered string setting");
        assert!(!boolean_setting(&settings, "Hostname", false));
        assert!(boolean_setting(&settings, "Hostname", true));
        assert!(!boolean_setting(&settings, "Hostnmae", false));
    }

    #[test]
    fn get_boolean_returns_the_default_with_no_registered_source() {
        // The public entry point over the process-global registry, which no unit test registers
        // into (see `resolve`): a daemon started without `--syspolicy-file` must see the caller's
        // default for both TPM keys, which is what keeps `handleTPMFlags` quiet by default.
        assert!(!get_boolean(PKEY_ENCRYPT_STATE, false));
        assert!(!get_boolean(PKEY_HARDWARE_ATTESTATION, false));
        assert!(get_boolean(PKEY_ENCRYPT_STATE, true));
    }

    // -------------------------------------------------------------------------------------------
    // Applying the snapshot to prefs (Go `applySysPolicy`).
    // -------------------------------------------------------------------------------------------

    /// Resolve a policy document and apply it to `prefs`, exactly as the daemon's reconcile does —
    /// via the production [`apply_settings_to_prefs`], not a re-derivation — while staying off the
    /// process-global registry (see [`resolve`]).
    fn apply(json: &str, prefs: &mut Prefs) -> PolicyApplication {
        let settings = resolve(json).expect("the policy document should load");
        apply_settings_to_prefs(&settings, prefs)
    }

    /// The keys the apply path spells as literals must all be registered definitions of the type it
    /// reads them as. A typo would otherwise be invisible: `configured_*` returns `None` for an
    /// unknown key, so the setting would simply never apply and nothing would say why.
    #[test]
    fn every_key_the_apply_path_names_is_a_registered_definition_of_the_right_type() {
        for key in ["LoginURL", "Hostname", "ExitNodeID", "ExitNodeIP"] {
            let def = definition_of(key).unwrap_or_else(|| panic!("{key} must be defined"));
            assert_eq!(def.ty, ValueType::String, "{key}");
        }
        // `PKEY_ALWAYS_ON` is named by the apply path; `PKEY_ALWAYS_ON_OVERRIDE_WITH_REASON` is
        // named by the disconnect gate, which reads it through the same store and so needs the same
        // definition to exist with the same type.
        for key in [PKEY_ALWAYS_ON, PKEY_ALWAYS_ON_OVERRIDE_WITH_REASON] {
            let def = definition_of(key).unwrap_or_else(|| panic!("{key} must be defined"));
            assert_eq!(def.ty, ValueType::Boolean, "{key}");
        }
        for key in PREFERENCE_POLICIES
            .iter()
            .map(|p| p.key)
            .chain(["UnattendedMode"])
        {
            let def = definition_of(key).unwrap_or_else(|| panic!("{key} must be defined"));
            assert_eq!(def.ty, ValueType::PreferenceOption, "{key}");
        }
    }

    #[test]
    fn an_empty_policy_leaves_every_pref_alone() {
        let mut prefs = Prefs {
            hostname: Some("operator-chose-this".into()),
            ..Prefs::default()
        };
        let applied = apply("{}", &mut prefs);
        assert!(applied.is_quiet(), "{applied:?}");
        assert_eq!(prefs.hostname.as_deref(), Some("operator-chose-this"));
    }

    #[test]
    fn login_url_and_hostname_override_what_the_operator_set() {
        // The whole point of policy: the pref the operator chose loses to the pref the admin pinned.
        let mut prefs = Prefs {
            control_url: Some("https://operator.example.com".into()),
            hostname: Some("laptop".into()),
            ..Prefs::default()
        };
        let applied = apply(
            r#"{"LoginURL": "https://headscale.example.com", "Hostname": "kiosk-3"}"#,
            &mut prefs,
        );
        assert_eq!(
            prefs.control_url.as_deref(),
            Some("https://headscale.example.com")
        );
        assert_eq!(prefs.hostname.as_deref(), Some("kiosk-3"));
        assert_eq!(
            applied
                .changed
                .iter()
                .map(|c| (c.key, c.pref, c.value.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("LoginURL", "control_url", "https://headscale.example.com"),
                ("Hostname", "hostname", "kiosk-3"),
            ]
        );
        assert!(applied.refused.is_empty(), "{applied:?}");
    }

    #[test]
    fn a_configured_empty_hostname_clears_it_but_an_absent_key_does_not() {
        // Go needs a `HostnameDefaultValue` sentinel to tell these two apart; here the store already
        // knows whether the key is configured. Both halves of the tri-state, on the same prefs.
        let mut prefs = Prefs {
            hostname: Some("laptop".into()),
            ..Prefs::default()
        };
        let untouched = apply(r#"{"CheckUpdates": "user-decides"}"#, &mut prefs);
        assert!(untouched.is_quiet(), "{untouched:?}");
        assert_eq!(
            prefs.hostname.as_deref(),
            Some("laptop"),
            "a policy that does not mention Hostname must leave it alone"
        );

        let cleared = apply(r#"{"Hostname": ""}"#, &mut prefs);
        assert_eq!(
            prefs.hostname, None,
            "a configured-but-empty Hostname CLEARS the pref (back to the OS hostname)"
        );
        assert_eq!(cleared.changed.len(), 1);
        assert_eq!(cleared.changed[0].pref, "hostname");
        assert_eq!(cleared.changed[0].value, "");
    }

    #[test]
    fn an_empty_login_url_falls_back_to_the_engine_default() {
        let mut prefs = Prefs {
            control_url: Some("https://operator.example.com".into()),
            ..Prefs::default()
        };
        apply(r#"{"LoginURL": ""}"#, &mut prefs);
        assert_eq!(prefs.control_url, None);
    }

    #[test]
    fn always_on_forces_want_running_back_up_and_never_turns_it_off() {
        let mut prefs = Prefs::default();
        assert!(!prefs.want_running);
        let applied = apply(r#"{"AlwaysOn.Enabled": true}"#, &mut prefs);
        assert!(prefs.want_running);
        assert_eq!(applied.changed.len(), 1);
        assert_eq!(applied.changed[0].pref, "want_running");

        // One-way, like Go's `alwaysOn && !prefs.WantRunning`: a false value is not a `down`.
        let mut running = Prefs {
            want_running: true,
            ..Prefs::default()
        };
        let off = apply(r#"{"AlwaysOn.Enabled": false}"#, &mut running);
        assert!(running.want_running, "AlwaysOn: false must not stop a node");
        assert!(off.is_quiet(), "{off:?}");
    }

    #[test]
    fn the_preference_options_force_their_prefs_on_and_off() {
        // `always` on every row, against prefs where each governed pref is at the opposite value.
        let mut prefs = Prefs {
            shields_up: true,
            exit_node_allow_lan_access: false,
            accept_dns: false,
            accept_routes: false,
            auto_update_check: false,
            auto_update_apply: None,
            advertise_exit_node: false,
            ..Prefs::default()
        };
        let applied = apply(
            r#"{"AllowIncomingConnections": "always", "ExitNodeAllowLANAccess": "always",
                "UseTailscaleDNSSettings": "always", "UseTailscaleSubnets": "always",
                "CheckUpdates": "always", "InstallUpdates": "always",
                "AdvertiseExitNode": "always"}"#,
            &mut prefs,
        );
        assert!(
            !prefs.shields_up,
            "AllowIncomingConnections is the NEGATION of shields-up"
        );
        assert!(prefs.exit_node_allow_lan_access);
        assert!(prefs.accept_dns);
        assert!(prefs.accept_routes);
        assert!(prefs.auto_update_check);
        assert_eq!(prefs.auto_update_apply, Some(true));
        assert!(prefs.advertise_exit_node);
        assert_eq!(
            applied.changed.len(),
            PREFERENCE_POLICIES.len(),
            "every row should have moved: {applied:?}"
        );

        // And `never` on the same rows, from the values `always` just produced.
        let applied = apply(
            r#"{"AllowIncomingConnections": "never", "ExitNodeAllowLANAccess": "never",
                "UseTailscaleDNSSettings": "never", "UseTailscaleSubnets": "never",
                "CheckUpdates": "never", "InstallUpdates": "never",
                "AdvertiseExitNode": "never"}"#,
            &mut prefs,
        );
        assert!(prefs.shields_up, "never = incoming blocked = shields up");
        assert!(!prefs.exit_node_allow_lan_access);
        assert!(!prefs.accept_dns);
        assert!(!prefs.accept_routes);
        assert!(!prefs.auto_update_check);
        assert_eq!(prefs.auto_update_apply, Some(false));
        assert!(!prefs.advertise_exit_node);
        assert_eq!(applied.changed.len(), PREFERENCE_POLICIES.len());
    }

    #[test]
    fn user_decides_leaves_the_pref_exactly_as_it_was() {
        // Go writes only when `curVal != newVal`, and `user-decides` resolves to `curVal` — so it is
        // not a change, on either polarity of the shields-up row.
        for shields_up in [false, true] {
            let mut prefs = Prefs {
                shields_up,
                accept_routes: true,
                ..Prefs::default()
            };
            let applied = apply(
                r#"{"AllowIncomingConnections": "user-decides", "UseTailscaleSubnets": "user-decides"}"#,
                &mut prefs,
            );
            assert_eq!(prefs.shields_up, shields_up);
            assert!(prefs.accept_routes);
            assert!(applied.is_quiet(), "{applied:?}");
        }
    }

    #[test]
    fn install_updates_leaves_an_unstated_opt_in_unstated_unless_it_is_always() {
        // Go reads `AutoUpdate.Apply` as `v, _ := Get()`, so UNSET reads false: `never` agrees with
        // it and writes nothing, keeping Go's tri-state `unset` distinct from an explicit `false`.
        let mut prefs = Prefs::default();
        assert_eq!(prefs.auto_update_apply, None);
        let applied = apply(r#"{"InstallUpdates": "never"}"#, &mut prefs);
        assert_eq!(
            prefs.auto_update_apply, None,
            "`never` must not turn an unstated opt-in into an explicit false"
        );
        assert!(applied.is_quiet(), "{applied:?}");

        apply(r#"{"InstallUpdates": "always"}"#, &mut prefs);
        assert_eq!(prefs.auto_update_apply, Some(true));
    }

    #[test]
    fn exit_node_ip_pins_the_selector_over_the_operators_choice() {
        let mut prefs = Prefs {
            exit_node: Some("someone-elses-node".into()),
            ..Prefs::default()
        };
        let applied = apply(r#"{"ExitNodeIP": "100.64.0.9"}"#, &mut prefs);
        assert_eq!(prefs.exit_node.as_deref(), Some("100.64.0.9"));
        assert_eq!(applied.changed.len(), 1);
        assert_eq!(applied.changed[0].key, "ExitNodeIP");
        assert_eq!(applied.changed[0].pref, "exit_node");
        assert!(applied.refused.is_empty(), "{applied:?}");
    }

    #[test]
    fn an_unparseable_exit_node_ip_is_refused_rather_than_stored_as_a_peer_name() {
        // Go's `err == nil` guard drops the value; storing it would turn a typo'd address into a
        // NAME selector that matches no peer, which egresses directly.
        let mut prefs = Prefs::default();
        let applied = apply(r#"{"ExitNodeIP": "192.0.2.999"}"#, &mut prefs);
        assert_eq!(prefs.exit_node, None);
        assert!(applied.changed.is_empty());
        assert_eq!(applied.refused.len(), 1);
        assert_eq!(applied.refused[0].key, "ExitNodeIP");
        assert!(
            applied.refused[0].reason.contains("not an IP address"),
            "{:?}",
            applied.refused[0]
        );
    }

    #[test]
    fn a_stable_exit_node_id_is_refused_and_suppresses_exit_node_ip() {
        // Go's mutual exclusion (ID wins, IP is never consulted) is kept even though the ID cannot
        // be honoured — so a file naming both pins NEITHER, and says so once.
        let mut prefs = Prefs::default();
        let applied = apply(
            r#"{"ExitNodeID": "nABC123CNTRL", "ExitNodeIP": "100.64.0.9"}"#,
            &mut prefs,
        );
        assert_eq!(
            prefs.exit_node, None,
            "a refused ExitNodeID must not fall through to the key the admin ranked second"
        );
        assert!(applied.changed.is_empty(), "{applied:?}");
        assert_eq!(applied.refused.len(), 1);
        assert_eq!(applied.refused[0].key, "ExitNodeID");
        assert!(
            applied.refused[0].reason.contains("stable node id"),
            "{:?}",
            applied.refused[0]
        );
    }

    #[test]
    fn an_auto_exit_node_expression_is_refused_by_name() {
        // The `auto:` form needs both an expression resolver and a blackhole state to park on; this
        // build has neither, and refuses `--exit-node auto:…` on the operator path for the same
        // reason. The refusal must name the feature, not the node.
        let mut prefs = Prefs::default();
        let applied = apply(r#"{"ExitNodeID": "auto:any"}"#, &mut prefs);
        assert_eq!(prefs.exit_node, None);
        assert_eq!(applied.refused.len(), 1);
        assert_eq!(applied.refused[0].key, "ExitNodeID");
        assert!(
            applied.refused[0].reason.contains("auto:"),
            "{:?}",
            applied.refused[0]
        );
    }

    #[test]
    fn the_key_with_no_pref_to_move_is_reported_unenforced() {
        // `UnattendedMode` has no counterpart in this daemon; reporting it is what keeps the policy
        // file from looking enforced when it is not.
        let mut prefs = Prefs::default();
        let applied = apply(r#"{"UnattendedMode": "always"}"#, &mut prefs);
        assert!(applied.changed.is_empty(), "{applied:?}");
        let refused: Vec<&str> = applied.refused.iter().map(|r| r.key).collect();
        assert!(refused.contains(&"UnattendedMode"), "{refused:?}");
    }

    #[test]
    fn the_always_on_override_key_is_not_reported_unenforced() {
        // It moves no pref, so the apply path is silent about it — but it IS enforced, by the
        // disconnect gate that reads it by name. Reporting it as unenforced would tell an
        // administrator their `--reason` exemption does nothing, which is the opposite of true.
        let mut prefs = Prefs::default();
        let applied = apply(
            r#"{"AlwaysOn.Enabled": true, "AlwaysOn.OverrideWithReason": true}"#,
            &mut prefs,
        );
        assert!(
            prefs.want_running,
            "AlwaysOn.Enabled still re-asserts intent"
        );
        let refused: Vec<&str> = applied.refused.iter().map(|r| r.key).collect();
        assert!(refused.is_empty(), "{refused:?}");
        // The gate's own decision is pinned by the unit tests in `alwayson` (over resolved booleans)
        // and end-to-end by `tests/alwayson_disconnect.rs` (over a registered policy file); this
        // test owns only the half that lives here — that the apply path stays quiet about the key
        // instead of contradicting them.
    }

    #[test]
    fn re_applying_the_same_policy_reports_no_further_change() {
        // The reconcile runs on every prefs write, so a policy that is already in force must be
        // silent — otherwise every `tnet set` would log a change that did not happen.
        let doc = r#"{"Hostname": "kiosk-3", "LoginURL": "https://headscale.example.com",
                      "ExitNodeIP": "100.64.0.9", "AlwaysOn.Enabled": true,
                      "AllowIncomingConnections": "never", "CheckUpdates": "always"}"#;
        let mut prefs = Prefs::default();
        let first = apply(doc, &mut prefs);
        assert!(!first.changed.is_empty());
        let second = apply(doc, &mut prefs);
        assert!(
            second.is_quiet(),
            "the second application must be a no-op: {second:?}"
        );
    }

    #[test]
    fn pinned_prefs_names_exactly_what_the_apply_path_can_write() {
        // Drift tripwire: `pinned_prefs_in` suppresses accidental-revert warnings, so a name it
        // misses re-arms a warning policy makes wrong, and a name it invents silences a real one.
        let doc = r#"{"LoginURL": "https://headscale.example.com", "Hostname": "kiosk-3",
                      "ExitNodeIP": "100.64.0.9", "AllowIncomingConnections": "never",
                      "ExitNodeAllowLANAccess": "always", "UseTailscaleDNSSettings": "never",
                      "UseTailscaleSubnets": "always", "CheckUpdates": "never",
                      "InstallUpdates": "always", "AdvertiseExitNode": "always"}"#;
        let settings = resolve(doc).expect("load");
        let pinned = pinned_prefs_in(&settings);
        // Applied against defaults, every one of those keys moves its pref.
        let mut prefs = Prefs::default();
        let applied = apply_settings_to_prefs(&settings, &mut prefs);
        let mut changed: Vec<&str> = applied.changed.iter().map(|c| c.pref).collect();
        changed.sort_unstable();
        let mut pinned_sorted = pinned.clone();
        pinned_sorted.sort_unstable();
        assert_eq!(changed, pinned_sorted, "pinned {pinned:?}");
    }

    #[test]
    fn pinned_prefs_ignores_user_decides_and_a_refused_exit_node_id() {
        // `user-decides` is the policy declining to have an opinion, and a refused ExitNodeID
        // applies nothing — in both cases the operator's own value is still theirs to lose, so the
        // revert guard must keep warning about it.
        let settings = resolve(
            r#"{"AllowIncomingConnections": "user-decides", "ExitNodeID": "nABC123CNTRL",
                "ExitNodeIP": "100.64.0.9"}"#,
        )
        .expect("load");
        assert!(pinned_prefs_in(&settings).is_empty());
    }

    #[test]
    fn pinned_prefs_is_empty_with_no_registered_source() {
        // The entry point over the process-global registry, which no unit test registers into.
        assert!(pinned_prefs().is_empty());
    }
}
