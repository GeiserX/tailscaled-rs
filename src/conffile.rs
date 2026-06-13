//! Declarative daemon config file — the Rust analogue of Go's `ipn.ConfigVAlpha` + `ipn/conffile`.
//!
//! `tailnetd --config <file>` loads a JSON document describing the node's intended prefs up front,
//! the path headless / k8s / automated installs rely on (declarative prefs without an interactive
//! `tnet up`). This module owns: the [`ConfigVAlpha`] DTO (Go-faithful field names), [`load`] (read +
//! version-gate + strict-parse, mirroring `conffile.Load`), and [`Config::apply_to_prefs`] (merge the
//! honored subset into [`Prefs`]).
//!
//! ## Honest omission
//!
//! Go's `ConfigVAlpha` carries fields this fork has no home for yet (operator user, SNAT/netfilter,
//! app-connector, posture, web-client, auto-update, …). We still **parse** them — a valid Go config
//! must not error here — but we only **honor** the subset that maps to a real [`Prefs`] field, and we
//! **warn** (never silently drop) when an unmapped field is set to a non-default value, so a headless
//! operator sees exactly what is and isn't applied. The mapped set today: `Enabled` → `want_running`,
//! `ServerURL` → `control_url`, `Hostname`, `AcceptDNS`, `AcceptRoutes`, `ExitNode`, `AdvertiseRoutes`,
//! `AdvertiseTags`, `ShieldsUp`, `RunSSHServer` → `ssh_enabled`. `AuthKey` is returned separately (it
//! is a registration credential, not a persisted pref).

use anyhow::{Context, Result, anyhow, bail};
use secrecy::SecretString;
use serde::Deserialize;

use crate::prefs::Prefs;

/// A parsed `--config` document: the raw [`ConfigVAlpha`] plus the version string it declared.
///
/// Deliberately does NOT derive `Debug` (nor does [`ConfigVAlpha`]): the config carries an `AuthKey`,
/// and withholding `Debug` keeps the whole document off any accidental `{:?}` / debug-log path — the
/// same secret-hygiene discipline `tnet`'s `Cli`/`Command` use (see `src/bin/tnet.rs`).
#[derive(Clone)]
pub struct Config {
    /// The declared `version` (only `"alpha0"` is accepted today).
    pub version: String,
    /// The parsed config body.
    pub parsed: ConfigVAlpha,
}

/// The declarative config schema — a serde mirror of Go's `ipn.ConfigVAlpha` (`ipn/conf.go`).
///
/// Field names match Go's JSON exactly (Go uses the Go field name for the un-tagged fields and an
/// explicit `json:"…"` tag for the camelCase ones; both are reproduced via `#[serde(rename)]`). Every
/// field is optional (`#[serde(default)]` at the container) so a minimal config (`{"version":"alpha0"}`)
/// parses. Tri-state Go `opt.Bool` (`""` / `"true"` / `"false"`) is modelled as `Option<bool>`: absent
/// / JSON `null` → `None` (leave the pref at its default); `true`/`false` → `Some(_)`.
///
/// Unknown fields are NOT rejected here (unlike Go's `DisallowUnknownFields`): forward-compatibility
/// (a newer Go config with a field this build predates) is preferred over a hard parse error, and the
/// honest-omission warnings below already surface anything set-but-unmapped. The `version` gate in
/// [`load`] is the real compatibility guard.
#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct ConfigVAlpha {
    /// Schema version; `"alpha0"` today. Gated in [`load`] before this struct is decoded.
    pub version: String,
    /// `wantRunning`: whether the node should connect. Go default (unset) is `true`.
    pub enabled: Option<bool>,
    /// Control server URL; `None` → the engine/`TS_CONTROL_URL` default.
    #[serde(rename = "ServerURL")]
    pub server_url: Option<String>,
    /// Auth key for registration when `NeedsLogin` (or `file:<path>` to read it from a file). Not a
    /// persisted pref — [`Config::apply_to_prefs`] returns it as a [`SecretString`] and it is never
    /// written into `prefs`. Kept as `String` here only because it must deserialize from the JSON
    /// (`secrecy 0.10`'s `SecretString` needs an opt-in serde feature); the leak risk that a `String`
    /// field would otherwise pose via `{:?}` is closed by **withholding `Debug`** on this struct
    /// (see the type's derive list — the deliberate omission matches `tnet`'s `Cli`).
    pub auth_key: Option<String>,
    /// Requested hostname; `None` → the OS hostname.
    pub hostname: Option<String>,
    /// `--accept-dns` (Go `CorpDNS`). Go default `true`.
    #[serde(rename = "acceptDNS")]
    pub accept_dns: Option<bool>,
    /// `--accept-routes`. Go default `true`.
    #[serde(rename = "acceptRoutes")]
    pub accept_routes: Option<bool>,
    /// Exit node selector: IP, StableID, or MagicDNS base name.
    #[serde(rename = "exitNode")]
    pub exit_node: Option<String>,
    /// Allow LAN access while using an exit node. **Not yet mapped** (no such pref in this fork).
    #[serde(rename = "allowLANWhileUsingExitNode")]
    pub allow_lan_while_using_exit_node: Option<bool>,
    /// Subnet routes (CIDRs) to advertise.
    pub advertise_routes: Vec<String>,
    /// ACL tags to request at registration (`tag:<name>`).
    pub advertise_tags: Vec<String>,
    /// Shields-up: block inbound connections from peers.
    pub shields_up: Option<bool>,
    /// Run the Tailscale SSH server (Go `RunSSHServer`). Requires the `ssh` build + root at runtime.
    #[serde(rename = "RunSSHServer")]
    pub run_ssh_server: Option<bool>,

    // ---- Parsed-but-not-yet-honored (engine-gated / non-goal in this fork). Kept so a valid Go
    // config parses; `apply_to_prefs` warns when any is set to a non-default. ----
    /// Go `OperatorUser` — local user allowed to operate the daemon without root. No daemon authz tier yet.
    pub operator_user: Option<String>,
    /// Go `DisableSNAT`. Engine routing concern, not a daemon pref. Explicit rename: `rename_all =
    /// "PascalCase"` would mangle this to `DisableSnat`, but Go's field is `DisableSNAT` (all-caps
    /// acronym) — without the rename a real Go config's `DisableSNAT` would be silently ignored and the
    /// honest-omission `warn_unmapped` would never fire for it.
    #[serde(rename = "DisableSNAT")]
    pub disable_snat: Option<bool>,
    /// Go `NetfilterMode` ("on"/"off"/"nodivert"). Engine routing concern.
    pub netfilter_mode: Option<String>,
    /// Go `NoStatefulFiltering`. Engine routing concern.
    pub no_stateful_filtering: Option<bool>,
    /// Go `PostureChecking`. Not implemented in this fork.
    pub posture_checking: Option<bool>,
    /// Go `RunWebClient`. The web client is a documented non-goal of this fork.
    pub run_web_client: Option<bool>,
}

/// Load and parse a `--config` file (Go `conffile.Load`).
///
/// Reads `path`, parses it as **standard JSON** (this fork omits HuJSON — the comment-stripping
/// preprocessor Go gates behind a build feature; a config must be valid JSON here), gates the
/// `version` (only `"alpha0"` is accepted — an empty or unrecognized version is a clear error, like
/// Go), then decodes the full [`ConfigVAlpha`]. Fails loudly with context on any step (a misconfigured
/// headless deploy must fail fast, not start half-configured).
pub fn load(path: &std::path::Path) -> Result<Config> {
    let raw =
        std::fs::read(path).with_context(|| format!("reading config file {}", path.display()))?;

    // Gate the version BEFORE decoding the whole body (Go decodes a {version} probe first), so an
    // unsupported version yields a precise message rather than a confusing field error.
    #[derive(Deserialize)]
    struct VersionProbe {
        #[serde(default)]
        version: String,
    }
    let probe: VersionProbe = serde_json::from_slice(&raw).with_context(|| {
        format!(
            "parsing config file {} (must be valid JSON)",
            path.display()
        )
    })?;
    match probe.version.as_str() {
        "" => bail!(
            "config file {}: no \"version\" field defined (want \"alpha0\")",
            path.display()
        ),
        "alpha0" => {}
        other => bail!(
            "config file {}: unsupported \"version\" value {other:?}; want \"alpha0\" for now",
            path.display()
        ),
    }

    let parsed: ConfigVAlpha = serde_json::from_slice(&raw)
        .with_context(|| format!("parsing config file {}", path.display()))?;
    Ok(Config {
        version: probe.version,
        parsed,
    })
}

impl Config {
    /// Merge the honored subset of this config into `prefs`, returning the registration auth key (if
    /// the config supplied one) for the caller to use at bring-up — it is a credential, not a
    /// persisted pref, so it is never written into `prefs`.
    ///
    /// A field left unset in the config (`None` / empty vec) does NOT touch the corresponding pref, so
    /// the config layers on top of the daemon's defaults rather than resetting them. Each engine-gated
    /// / non-goal field that is *set to a non-default value* is logged at `warn` so a headless operator
    /// can see it was parsed but not applied (honest omission — never a silent drop).
    ///
    /// `AuthKey` resolution: a bare value is returned as-is; a `file:<path>` value is read from that
    /// file (trimmed) — Go's convention for keeping the secret out of the (often world-readable)
    /// config file itself.
    pub fn apply_to_prefs(&self, prefs: &mut Prefs) -> Result<Option<SecretString>> {
        let c = &self.parsed;

        // `Enabled` is special: Go ALWAYS masks `WantRunning` in from a config (`mp.WantRunning =
        // !c.Enabled.EqualBool(false)`; `mp.WantRunningSet = mp.WantRunning || c.Enabled != ""`), so an
        // UNSET `Enabled` means the node should come UP (`!EqualBool(false)` → true). This is the
        // headless contract — deploy a `--config` and the node runs unless you write `"Enabled": false`.
        // So, unlike the other (apply-only-when-set) fields below, we default it to `true` rather than
        // leaving the pref untouched. (The other fields match Go's conditional masking — Go only sets
        // e.g. `RouteAllSet`/`CorpDNSSet`/`HostnameSet` when the field is explicitly present, so an
        // unset field there correctly leaves the existing pref.)
        prefs.want_running = c.enabled.unwrap_or(true);
        if let Some(url) = &c.server_url {
            prefs.control_url = Some(url.clone());
        }
        if let Some(hostname) = &c.hostname {
            prefs.hostname = Some(hostname.clone());
        }
        if let Some(v) = c.accept_dns {
            prefs.accept_dns = v;
        }
        if let Some(v) = c.accept_routes {
            prefs.accept_routes = v;
        }
        if let Some(exit) = &c.exit_node {
            prefs.exit_node = Some(exit.clone());
        }
        if !c.advertise_routes.is_empty() {
            prefs.advertise_routes = c.advertise_routes.clone();
        }
        if !c.advertise_tags.is_empty() {
            prefs.advertise_tags = c.advertise_tags.clone();
        }
        if let Some(v) = c.shields_up {
            prefs.shields_up = v;
        }
        if let Some(v) = c.run_ssh_server {
            prefs.ssh_enabled = v;
        }

        warn_unmapped(c);

        // Resolve the auth key (bare value or `file:<path>`). Returned as a `SecretString`, never
        // persisted. An empty key is treated as absent (matching the CLI's guard).
        match &c.auth_key {
            None => Ok(None),
            Some(k) if k.is_empty() => Ok(None),
            Some(k) => Ok(Some(resolve_auth_key(k)?)),
        }
    }
}

/// Resolve a config `AuthKey` value: a `file:<path>` form reads + trims the key from that file (Go's
/// convention, keeping the secret out of the config), anything else is the literal key. Returns a
/// [`SecretString`] so the resolved key does not outlive this call as a plain `String`.
fn resolve_auth_key(value: &str) -> Result<SecretString> {
    match value.strip_prefix("file:") {
        Some(path) => {
            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("reading auth key file {path}"))?;
            let key = contents.trim();
            if key.is_empty() {
                return Err(anyhow!("auth key file {path} is empty"));
            }
            Ok(SecretString::from(key.to_string()))
        }
        // Not a `file:` form → the literal config value is the key.
        None => Ok(SecretString::from(value.to_string())),
    }
}

/// Log a `warn` for each engine-gated / non-goal field that is set to a non-default value, so an
/// operator sees the config carried something this build does not honor (honest omission). Pure-ish
/// (only logs); no pref mutation.
fn warn_unmapped(c: &ConfigVAlpha) {
    let mut unmapped: Vec<&str> = Vec::new();
    if c.allow_lan_while_using_exit_node.is_some() {
        unmapped.push("AllowLANWhileUsingExitNode");
    }
    if c.operator_user.is_some() {
        unmapped.push("OperatorUser");
    }
    if c.disable_snat.is_some() {
        unmapped.push("DisableSNAT");
    }
    if c.netfilter_mode.is_some() {
        unmapped.push("NetfilterMode");
    }
    if c.no_stateful_filtering.is_some() {
        unmapped.push("NoStatefulFiltering");
    }
    if c.posture_checking.is_some() {
        unmapped.push("PostureChecking");
    }
    if c.run_web_client.is_some() {
        unmapped.push("RunWebClient");
    }
    if !unmapped.is_empty() {
        tracing::warn!(
            fields = ?unmapped,
            "config: these fields were parsed but are NOT honored by this build (engine-gated or \
             non-goal); they have no effect"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    /// Load a config from an inline JSON string via a temp file. `Config` deliberately has no `Debug`
    /// (secret hygiene), so we cannot use `.expect()`/`.unwrap()` (they need `Debug` on the Err/Ok);
    /// match the `Result` by hand instead.
    fn cfg(json: &str) -> Config {
        let dir = std::env::temp_dir().join(format!("tailnetd-conf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Filename must be UNIQUE PER CALL: cargo runs these `#[test]`s as parallel threads in one
        // process, and `SystemTime::now().as_nanos()` is NOT collision-free at that resolution on
        // macOS — two concurrent `cfg()` calls could land on the same path, so one test's `write`/
        // `load` races another's `remove_file` (intermittent failure under the full parallel suite).
        // An atomic counter makes the name truly unique (mirrors `tests/localapi_loop.rs`'s `UNIQUE`).
        use std::sync::atomic::{AtomicU64, Ordering};
        static CFG_SEQ: AtomicU64 = AtomicU64::new(0);
        let path = dir.join(format!(
            "c-{}.json",
            CFG_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, json).unwrap();
        let loaded = load(&path);
        let _ = std::fs::remove_file(&path);
        match loaded {
            Ok(c) => c,
            Err(e) => panic!("load config failed: {e}"),
        }
    }

    /// The auth key a config yields, as a plain `String` for assertions (the production type is a
    /// `SecretString`). Test-only — exposing the secret in a test is fine.
    fn key_str(k: Option<SecretString>) -> Option<String> {
        k.map(|s| s.expose_secret().to_string())
    }

    #[test]
    fn minimal_config_parses() {
        let c = cfg(r#"{"version":"alpha0"}"#);
        assert_eq!(c.version, "alpha0");
        let mut p = Prefs::default();
        let before = p.clone();
        let key = c.apply_to_prefs(&mut p).unwrap();
        assert!(key.is_none());
        // `Enabled` is special (Go-faithful): unset → the node should come UP, so a minimal config
        // sets want_running=true even though `Prefs::default()` is false.
        assert!(
            p.want_running,
            "unset Enabled defaults the node to up (Go !EqualBool(false))"
        );
        // Every other unset field is left untouched (here accept_dns keeps its default).
        assert_eq!(p.accept_dns, before.accept_dns);
    }

    #[test]
    fn version_gate_rejects_missing_and_unknown() {
        // Missing version.
        let dir = std::env::temp_dir().join(format!("tailnetd-conf-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nover.json");
        // `Config` has no `Debug`, so `unwrap_err()` won't compile — assert via the Err arm directly.
        let err_str = |path: &std::path::Path| match load(path) {
            Ok(_) => panic!("expected an error"),
            Err(e) => e.to_string(),
        };
        std::fs::write(&path, r#"{"Hostname":"x"}"#).unwrap();
        let err = err_str(&path);
        assert!(err.contains("no \"version\""), "{err}");
        // Unknown version.
        std::fs::write(&path, r#"{"version":"beta9"}"#).unwrap();
        let err = err_str(&path);
        assert!(
            err.contains("unsupported") && err.contains("beta9"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mapped_fields_apply_to_prefs() {
        let c = cfg(r#"{
                "version":"alpha0",
                "Enabled":true,
                "ServerURL":"https://hs.example.com",
                "Hostname":"node-a",
                "acceptDNS":false,
                "acceptRoutes":true,
                "exitNode":"100.64.0.9",
                "AdvertiseRoutes":["10.0.0.0/24"],
                "AdvertiseTags":["tag:server"],
                "ShieldsUp":true,
                "RunSSHServer":true
            }"#);
        let mut p = Prefs::default();
        let key = c.apply_to_prefs(&mut p).unwrap();
        assert!(key.is_none());
        assert!(p.want_running);
        assert_eq!(p.control_url.as_deref(), Some("https://hs.example.com"));
        assert_eq!(p.hostname.as_deref(), Some("node-a"));
        assert!(!p.accept_dns, "acceptDNS:false must apply");
        assert!(p.accept_routes);
        assert_eq!(p.exit_node.as_deref(), Some("100.64.0.9"));
        assert_eq!(p.advertise_routes, vec!["10.0.0.0/24".to_string()]);
        assert_eq!(p.advertise_tags, vec!["tag:server".to_string()]);
        assert!(p.shields_up);
        assert!(p.ssh_enabled);
    }

    #[test]
    fn unset_fields_leave_prefs_untouched() {
        // A config that sets only Hostname must not reset the conditionally-masked fields
        // (accept_routes / accept_dns / exit_node / …) — only `Enabled` is unconditionally applied
        // (see minimal_config_parses), so test the conditional ones here.
        let c = cfg(r#"{"version":"alpha0","Hostname":"only-host"}"#);
        let mut p = Prefs {
            accept_routes: true,
            ..Prefs::default()
        };
        c.apply_to_prefs(&mut p).unwrap();
        assert_eq!(p.hostname.as_deref(), Some("only-host"));
        assert!(
            p.accept_routes,
            "unset acceptRoutes must not clobber an existing pref"
        );
        assert!(p.accept_dns, "unset acceptDNS keeps the default (true)");
        assert!(!p.shields_up, "unset ShieldsUp keeps the default (false)");
    }

    #[test]
    fn bare_auth_key_is_returned_not_persisted() {
        let c = cfg(r#"{"version":"alpha0","AuthKey":"tskey-abc123"}"#);
        let mut p = Prefs::default();
        let key = c.apply_to_prefs(&mut p).unwrap();
        assert_eq!(key_str(key).as_deref(), Some("tskey-abc123"));
        // The key is a credential — it must NOT have been written into any pref field.
        assert!(p.control_url.is_none());
    }

    #[test]
    fn file_prefixed_auth_key_is_read_from_file() {
        let dir = std::env::temp_dir().join(format!("tailnetd-conf-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let keypath = dir.join("authkey");
        std::fs::write(&keypath, "tskey-from-file\n").unwrap();
        let c = cfg(&format!(
            r#"{{"version":"alpha0","AuthKey":"file:{}"}}"#,
            keypath.display()
        ));
        let mut p = Prefs::default();
        let key = c.apply_to_prefs(&mut p).unwrap();
        assert_eq!(
            key_str(key).as_deref(),
            Some("tskey-from-file"),
            "file: key must be read + trimmed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_fields_are_tolerated_not_rejected() {
        // Forward-compat: a newer Go config field this build predates must parse, not error.
        let c = cfg(r#"{"version":"alpha0","SomeFutureField":42,"Hostname":"h"}"#);
        let mut p = Prefs::default();
        c.apply_to_prefs(&mut p).unwrap();
        assert_eq!(p.hostname.as_deref(), Some("h"));
    }
}
