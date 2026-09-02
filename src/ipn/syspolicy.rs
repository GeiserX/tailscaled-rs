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
//! ## Reporting only
//!
//! The snapshot is *reported* (`tnet syspolicy list`/`reload`); it is not yet *applied* to prefs.
//! Go enforces policy in `ipnlocal.applySysPolicy` — a separate surface this fork does not have, so
//! writing `"Hostname"` into the policy file makes it visible to `syspolicy list` without changing
//! the node's hostname. Keeping the source and the enforcement separate is deliberate: an operator
//! can see exactly what the daemon parsed before any of it has an effect.
//!
//! Scope: Go's CLI always resolves `setting.DefaultScope()`, which is the **device scope** on every
//! non-Windows platform, and `LoadJSONPolicyFile` registers at `setting.DeviceScope`. We record that
//! as the report's scope and do not parameterize it (the CLI never varies it); profile/user scoping
//! can be added if a real caller ever needs it.
//!
//! Upstream: `cmd/tailscaled/syspolicy.go`, `util/syspolicy/load.go`,
//! `util/syspolicy/source/json_policy_store.go`, `util/syspolicy/source/policy_reader.go` and
//! `util/syspolicy/policy_keys.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::RwLock;

use serde_json::{Map, Value};

use crate::goduration::{format_go_duration, parse_go_duration};
use crate::localapi::{PolicyReport, PolicySetting};

/// Go `pkey.EncryptState` — the policy key that asks a daemon to encrypt its state file at rest.
/// Named because `tailnetd` reads it by name (Go's `handleTPMFlags` does the same via
/// `policyclient.Get().GetBoolean(pkey.EncryptState, false)`), so the spelling has exactly one
/// definition shared with [`DEFINITIONS`].
pub const PKEY_ENCRYPT_STATE: &str = "EncryptState";

/// Go `pkey.HardwareAttestation` — the policy key that asks a daemon to bind the node identity to a
/// hardware-backed key. Read by name for the same reason as [`PKEY_ENCRYPT_STATE`].
pub const PKEY_HARDWARE_ATTESTATION: &str = "HardwareAttestation";

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
    def("AlwaysOn.Enabled", ValueType::Boolean),
    def("AlwaysOn.OverrideWithReason", ValueType::Boolean),
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
    if !matches!(definition_of(key), Some(d) if d.ty == ValueType::Boolean) {
        return default;
    }
    settings
        .iter()
        .find(|s| s.key == key)
        // A row carrying an error has no value; Go reports the error and the caller keeps the
        // default, which is what falling through to `unwrap_or` does here.
        .and_then(|s| s.value.as_deref())
        .and_then(|v| v.parse::<bool>().ok())
        .unwrap_or(default)
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
fn quoted(s: &str) -> String {
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
}
