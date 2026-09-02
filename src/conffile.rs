//! Declarative daemon config file — the Rust analogue of Go's `ipn.ConfigVAlpha` + `ipn/conffile`.
//!
//! `tailnetd --config <source>` loads a JSON document describing the node's intended prefs up front,
//! the path headless / k8s / automated installs rely on (declarative prefs without an interactive
//! `tnet up`). This module owns: the [`ConfigVAlpha`] DTO (Go-faithful field names), [`load`] (read +
//! version-gate + strict-parse, mirroring `conffile.Load`), and [`Config::apply_to_prefs`] (merge the
//! honored subset into [`Prefs`]).
//!
//! ## The flag takes a SOURCE, not just a path
//!
//! Go's `--config` value is a config *source* ([`ConfigFlag`] parses it):
//!
//! * a file path — the common case;
//! * [`VM_USER_DATA_PATH`] (`vm:user-data`), the VM's user-data from the cloud instance metadata
//!   service (EC2) — recognized here, but see [`load`]: this build cannot read it;
//! * either of those behind an [`OPTIONAL_PREFIX`] (`optional:`) marker, meaning an **absent** source
//!   is not fatal — the node boots unconfigured and can be enrolled interactively instead of failing
//!   to start, while a source that is present but **invalid** still fails.
//!
//! That last distinction is why the read phase of [`load`] reports [`NoConfig`] (Go's
//! `conffile.ErrNoConfig`) rather than one opaque failure: `optional:` must be able to tell "no config
//! present" from "config present and malformed".
//!
//! ## Honest omission
//!
//! Go's `ConfigVAlpha` carries fields this fork has no home for (SNAT/netfilter, services, serve,
//! relay-server, …). We still **parse** them — a valid Go config must not error here — but we only
//! **honor** the subset that maps to a real [`Prefs`] field, and we **warn** (never silently drop)
//! when an unmapped field is set to a non-default value, so a headless operator sees exactly what is
//! and isn't applied. Both lists are re-derived field-by-field against `ipn/conf.go` @
//! `53a0d659afa51835dd7a9283873cca44261454f8` (upstream v1.102.3), and [`ConfigVAlpha`] declares its
//! fields in Go's own declaration order so the next re-derivation is a straight read-down.
//!
//! **Honored** (17 of Go's 27 settable keys): `Enabled` → `want_running`, `ServerURL` →
//! `control_url`, `OperatorUser` → `operator_user`, `Hostname`, `acceptDNS` → `accept_dns`,
//! `acceptRoutes` → `accept_routes`, `exitNode` → `exit_node`, `allowLANWhileUsingExitNode` →
//! `exit_node_allow_lan_access`, `AdvertiseRoutes`, `AdvertiseExitNode` → `advertise_exit_node`,
//! `AppConnector.Advertise` → `advertise_app_connector`, `PostureChecking` → `posture_checking`,
//! `RunSSHServer` → `ssh_enabled`, `RunWebClient` → `run_web_client`, `ShieldsUp` → `shields_up`,
//! `AutoUpdate.Check`/`.Apply` → `auto_update_check`/`auto_update_apply`. `AuthKey` is returned
//! separately (it is a registration credential, not a persisted pref).
//!
//! **Parsed but not honored** (warned by `unmapped_fields`): `Locked`, `DisableSNAT`,
//! `AdvertiseServices`, `NetfilterMode`, `NoStatefulFiltering`, `RemoteConfig`, `ServeConfigTemp`,
//! `StaticEndpoints`, `RelayServerPort`, `RelayServerStaticEndpoints`.
//!
//! The drift runs both ways, so the two lists together must cover **every** Go field: a Go field in
//! neither is a silent drop (what `AdvertiseExitNode`, `RemoteConfig`, `RelayServerPort` and
//! `RelayServerStaticEndpoints` were), and a field left in the warning list after its pref shipped is
//! a lie in the log (what `AllowLANWhileUsingExitNode`, `OperatorUser`, `PostureChecking` and
//! `RunWebClient` were). `every_go_field_is_either_honored_or_warned` pins that.
//!
//! NOTE: Go's `ConfigVAlpha` has **no** tags field — ACL tags are carried by the auth key at
//! registration, never by the config file (re-verified at the pinned ref). So there is no
//! `AdvertiseTags` config mapping (tags are still settable via `tnet up --advertise-tags`). Same for
//! this fork's `node_nickname`, `ephemeral`, `tun_*` and `taildrop_dir` prefs: Go's config has no key
//! for them, so there is nothing to map and nothing to warn about.

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
    // Fields below are in Go's own declaration order (`ipn/conf.go`), each tagged HONORED (mapped
    // onto a real `Prefs` field by `apply_to_prefs`) or WARNED (parsed for forward-compat, reported
    // by `unmapped_fields`). Keeping the order means re-deriving against a newer upstream is a
    // straight read-down of two files side by side — which is how the four dropped fields
    // (`AdvertiseExitNode`, `RemoteConfig`, `RelayServerPort`, `RelayServerStaticEndpoints`) were
    // found in the first place.
    /// Schema version; `"alpha0"` today. Gated in [`load`] before this struct is decoded.
    pub version: String,
    /// WARNED. Go `Locked`: whether the config is locked from out-of-band `tnet set` mutations. NOT
    /// enforced by this fork (`tnet set` remains free to mutate prefs), so it is surfaced by
    /// `unmapped_fields` rather than silently dropped — an operator who set `"Locked": true`
    /// (expecting `set` to be refused) must see that it is not honored. Parsing it explicitly (vs
    /// relying on the unknown-key catch-all) keeps that honest-omission contract intact.
    pub locked: Option<bool>,
    /// HONORED → [`Prefs::control_url`]. Control server URL; `None` → the engine/`TS_CONTROL_URL`
    /// default.
    #[serde(rename = "ServerURL")]
    pub server_url: Option<String>,
    /// HONORED (returned, never persisted). Auth key for registration when `NeedsLogin` (or
    /// `file:<path>` to read it from a file). Not a persisted pref — [`Config::apply_to_prefs`]
    /// returns it as a [`SecretString`] and it is never written into `prefs`. Kept as `String` here
    /// only because it must deserialize from the JSON (`secrecy 0.10`'s `SecretString` needs an
    /// opt-in serde feature); the leak risk that a `String` field would otherwise pose via `{:?}` is
    /// closed by **withholding `Debug`** on this struct (see the type's derive list — the deliberate
    /// omission matches `tnet`'s `Cli`).
    pub auth_key: Option<String>,
    /// HONORED → [`Prefs::want_running`]. `wantRunning`: whether the node should connect. Go default
    /// (unset) is `true` — see [`Config::apply_to_prefs`], where this is the one unconditionally
    /// applied field.
    pub enabled: Option<bool>,
    /// HONORED → [`Prefs::operator_user`]. Go `OperatorUser` — the local user allowed to operate the
    /// daemon without root. Recorded like `tnet set --operator`; as that pref's docs say, this fork's
    /// LocalAPI write policy is still the root-or-owner-UID check, so setting it records intent.
    pub operator_user: Option<String>,
    /// HONORED → [`Prefs::hostname`]. Requested hostname; `None` → the OS hostname.
    pub hostname: Option<String>,
    /// HONORED → [`Prefs::accept_dns`]. `--accept-dns` (Go `CorpDNS`). Go default `true`.
    #[serde(rename = "acceptDNS")]
    pub accept_dns: Option<bool>,
    /// HONORED → [`Prefs::accept_routes`]. `--accept-routes`.
    #[serde(rename = "acceptRoutes")]
    pub accept_routes: Option<bool>,
    /// HONORED → [`Prefs::exit_node`]. Exit node selector: IP, StableID, or MagicDNS base name.
    #[serde(rename = "exitNode")]
    pub exit_node: Option<String>,
    /// HONORED → [`Prefs::exit_node_allow_lan_access`]. Allow LAN access while using an exit node
    /// (Go `--exit-node-allow-lan-access`).
    #[serde(rename = "allowLANWhileUsingExitNode")]
    pub allow_lan_while_using_exit_node: Option<bool>,
    /// HONORED → [`Prefs::advertise_routes`]. Subnet routes (CIDRs) to advertise.
    pub advertise_routes: Vec<String>,
    /// HONORED → [`Prefs::advertise_exit_node`]. Go `AdvertiseExitNode` — advertise this node as an
    /// exit node. It **composes** with [`advertise_routes`](ConfigVAlpha::advertise_routes) rather
    /// than replacing it: Go stores the exit-node advertisement *inside* `AdvertiseRoutes` (as the two
    /// v4/v6 default routes) and appends those two to whatever the config listed
    /// (`ToPrefs`: `mp.AdvertiseRoutes = append(mp.AdvertiseRoutes, tsaddr.AllIPv4(), …)`). This fork
    /// keeps the two as separate prefs that the engine composes, so the same "routes AND exit" outcome
    /// falls out of setting both — see [`Config::apply_to_prefs`].
    pub advertise_exit_node: Option<bool>,
    /// WARNED. Go `DisableSNAT`. Engine routing concern, not a daemon pref. Explicit rename:
    /// `rename_all = "PascalCase"` would mangle this to `DisableSnat`, but Go's field is `DisableSNAT`
    /// (all-caps acronym) — without the rename a real Go config's `DisableSNAT` would be silently
    /// ignored and the honest-omission warning would never fire for it.
    #[serde(rename = "DisableSNAT")]
    pub disable_snat: Option<bool>,
    /// WARNED. Go `AdvertiseServices` — Tailscale Services this node advertises. No
    /// service-advertisement pref in this fork; parsed + warned so a real Go config that sets it is
    /// not silently dropped.
    pub advertise_services: Vec<String>,
    /// HONORED → [`Prefs::advertise_app_connector`]. Go `AppConnector` (`ipn.AppConnectorPrefs`) —
    /// advertise this node as an app connector.
    pub app_connector: Option<AppConnectorPrefs>,
    /// WARNED. Go `NetfilterMode` ("on"/"off"/"nodivert"). Engine routing concern.
    pub netfilter_mode: Option<String>,
    /// WARNED. Go `NoStatefulFiltering`. Engine routing concern.
    pub no_stateful_filtering: Option<bool>,
    /// HONORED → [`Prefs::posture_checking`]. Go `PostureChecking` (`--report-posture`).
    pub posture_checking: Option<bool>,
    /// HONORED → [`Prefs::ssh_enabled`]. Run the Tailscale SSH server (Go `RunSSHServer`). Requires
    /// the `ssh` build + root at runtime.
    #[serde(rename = "RunSSHServer")]
    pub run_ssh_server: Option<bool>,
    /// HONORED → [`Prefs::run_web_client`]. Go `RunWebClient` (`--webclient`). A carried pref: no web
    /// server is started (see the pref's docs), but the declared intent is recorded rather than lost.
    pub run_web_client: Option<bool>,
    /// HONORED → [`Prefs::shields_up`]. Shields-up: block inbound connections from peers.
    pub shields_up: Option<bool>,
    /// WARNED, and permanently so. Go `RemoteConfig` — delegate full remote control of this node's
    /// prefs *and its LocalAPI* to the tailnet admin, bypassing the per-feature double opt-in. This
    /// fork **declines the behaviour** rather than deferring it (THREAT_MODEL §4.1: authorization is
    /// local, and control is a peer whose input is validated, never a principal that may rewrite
    /// prefs) — `tnet set --remote-config` is refused by name for exactly that reason, see
    /// `docs/ENGINE_ASKS.md` §34. Warned rather than silently dropped because an operator who
    /// declared it would otherwise believe the tailnet admin owns this node's settings when nothing
    /// does.
    pub remote_config: Option<bool>,
    /// HONORED → [`Prefs::auto_update_check`] + [`Prefs::auto_update_apply`]. Go `AutoUpdate`
    /// (`ipn.AutoUpdatePrefs`) — self-update policy. Go applies the **whole struct** when the key is
    /// present (`AutoUpdateSet{ApplySet: true, CheckSet: true}`), so a missing inner key means that
    /// inner field's Go zero value, not the pref default — see [`AutoUpdatePrefs`].
    pub auto_update: Option<AutoUpdatePrefs>,
    /// WARNED. Go `ServeConfigTemp` — an embedded serve config. Set via `tnet serve` in this fork, not
    /// the declarative config; parsed as opaque (`serde_json::Value`) because we never inspect it.
    pub serve_config_temp: Option<serde_json::Value>,
    /// WARNED. Go `StaticEndpoints` — operator-pinned WireGuard endpoints. Engine-gated (no `Config`
    /// knob). Kept as raw strings rather than parsed `SocketAddr`s: nothing here consumes them, and a
    /// forward-compat parse is not worth a new way for a valid Go config to fail.
    pub static_endpoints: Vec<String>,
    /// WARNED. Go `RelayServerPort` — the UDP port for the peer-relay server to bind (`0` picks a
    /// random port, an absent value disables the relay server). Engine-gated: the pinned engine has no
    /// relay listener to bind and cannot advertise the role (`docs/ENGINE_ASKS.md` §34), which is why
    /// `tnet set --relay-server-port` honours only the disable form and refuses a port by name.
    pub relay_server_port: Option<u16>,
    /// WARNED. Go `RelayServerStaticEndpoints` — static `IP:port` endpoints to advertise as relay
    /// candidates. Only meaningful alongside `RelayServerPort`, which is engine-gated too. Raw
    /// strings, for the same reason as [`static_endpoints`](ConfigVAlpha::static_endpoints).
    pub relay_server_static_endpoints: Vec<String>,
}

/// Go `ipn.AppConnectorPrefs` (`ipn/prefs.go`) — the object Go's `AppConnector` config key decodes to.
///
/// Typed rather than opaque so `Advertise` can actually reach [`Prefs::advertise_app_connector`].
/// `Debug` is safe to derive here (unlike on [`ConfigVAlpha`], which carries the auth key): this
/// struct holds one bool and no secret, and the parent still has no `Debug` to print it through.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "PascalCase")]
pub struct AppConnectorPrefs {
    /// Advertise this node as an app connector (Go `AppConnectorPrefs.Advertise`).
    pub advertise: bool,
}

/// Go `ipn.AutoUpdatePrefs` (`ipn/prefs.go`) — the object Go's `AutoUpdate` config key decodes to.
///
/// The inner defaults are **Go's zero values, not this fork's pref defaults**, and that is
/// deliberate: `ToPrefs` assigns the decoded struct wholesale and sets BOTH mask bits
/// (`AutoUpdateSet{ApplySet: true, CheckSet: true}`), so in Go `"AutoUpdate": {"Apply": true}` also
/// writes `Check: false` — the Go zero value for the key the JSON omitted — over whatever `Check` was.
/// Defaulting `check` to `false` here reproduces that exactly; defaulting it to [`Prefs`]'s `true`
/// would quietly make this fork's config mean something Go's does not.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "PascalCase")]
pub struct AutoUpdatePrefs {
    /// Whether a background updater should check for updates (Go `AutoUpdatePrefs.Check`).
    pub check: bool,
    /// Whether updates are applied automatically (Go `AutoUpdatePrefs.Apply`, an `opt.Bool`:
    /// absent/`null` → `None`, the never-stated state).
    pub apply: Option<bool>,
}

/// The sentinel `--config` value meaning "read the config from the VM's user-data, via the cloud
/// instance metadata service" instead of from a file on disk (Go `conffile.VMUserDataPath`).
pub const VM_USER_DATA_PATH: &str = "vm:user-data";

/// The prefix that marks a `--config` source as optional (Go `cmd/tailscaled`'s `optional:`): an
/// absent source is not a startup failure. See [`ConfigFlag`].
pub const OPTIONAL_PREFIX: &str = "optional:";

/// "No config was provided" — the Rust analogue of Go's `conffile.ErrNoConfig`, and the error
/// [`load`] reports for every **read-phase** failure: a missing or unreadable file, or a
/// `vm:user-data` source this build cannot read.
///
/// It is deliberately distinguishable from the errors [`load`] returns once the bytes ARE in hand (a
/// JSON syntax error, an absent/unsupported `version`), because that is the entire contract of the
/// `optional:` prefix: **absent** → boot unconfigured; **present but malformed** → still fail. Callers
/// classify with [`is_no_config`] (Go `errors.Is(err, conffile.ErrNoConfig)`) rather than by matching
/// on message text.
#[derive(Debug)]
pub struct NoConfig {
    /// The source as the operator named it (`/etc/tailnetd/config.json`, `vm:user-data`, …).
    pub source: String,
    /// Why nothing could be read from it (the underlying I/O error, or why the source is unreadable
    /// by this build). Carried as a string because it is only ever reported, never re-inspected —
    /// Go likewise flattens it in with `fmt.Errorf("%w: %v", ErrNoConfig, err)`.
    pub reason: String,
}

impl std::fmt::Display for NoConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no config present at {}: {}", self.source, self.reason)
    }
}

impl std::error::Error for NoConfig {}

/// Does this error mean "the config source is absent" (as opposed to "present but invalid")? The Go
/// `errors.Is(err, conffile.ErrNoConfig)` of this port.
///
/// Walks the whole [`anyhow`] chain, so a caller's own `.with_context(…)` wrapper — which every
/// `--config` call site adds — cannot hide the classification.
pub fn is_no_config(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| cause.is::<NoConfig>())
}

/// Where a `--config` document comes from.
///
/// Go passes the raw flag string to `conffile.Load`, where `vm:user-data` is a *sentinel* rather than
/// a filename. Typing it here is the fix for this fork's original `PathBuf` flag, which had no way to
/// express "not a path" and so tried to `open("vm:user-data")` and died at startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigSource {
    /// A JSON config document at this path on disk.
    File(std::path::PathBuf),
    /// The VM's user-data, from the cloud instance metadata service (Go `VMUserDataPath`, EC2 today).
    /// Recognized by this build but not readable by it — see [`load`].
    VmUserData,
}

impl ConfigSource {
    /// Classify a `--config` value whose `optional:` prefix (if any) has already been stripped — Go's
    /// `switch path { case VMUserDataPath: readVMUserData() default: os.ReadFile(path) }`.
    pub fn parse(value: &str) -> Self {
        if value == VM_USER_DATA_PATH {
            Self::VmUserData
        } else {
            Self::File(std::path::PathBuf::from(value))
        }
    }
}

impl std::fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(path) => write!(f, "{}", path.display()),
            Self::VmUserData => f.write_str(VM_USER_DATA_PATH),
        }
    }
}

/// A parsed `tailnetd --config` flag value: the [`ConfigSource`] plus whether the operator marked it
/// `optional:` (Go strips that prefix in `cmd/tailscaled/tailscaled.go`, not in `conffile`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigFlag {
    /// `optional:` was given: an **absent** source is not fatal — boot unconfigured and let the node
    /// be enrolled interactively. A source that is present but invalid still fails.
    pub optional: bool,
    /// The source, with any `optional:` prefix stripped.
    pub source: ConfigSource,
}

impl ConfigFlag {
    /// Parse a raw `--config` value.
    ///
    /// `None` for an empty value: Go gates its whole config block on `args.confFile != ""`, so
    /// `--config ""` means "no config given", not "read the file named ``". Note that
    /// `--config optional:` (an empty source *behind* the marker) is NOT that case — it is an
    /// optional source that is absent, which [`load`] duly reports as [`NoConfig`] and
    /// [`ConfigFlag::load`] duly tolerates, exactly as Go's `os.ReadFile("")` does.
    pub fn parse(value: &str) -> Option<Self> {
        if value.is_empty() {
            return None;
        }
        // Go: `if p, ok := strings.CutPrefix(path, "optional:"); ok { optional, path = true, p }` —
        // ONE prefix is stripped, so `optional:optional:x` is an optional source literally named
        // `optional:x`.
        Some(match value.strip_prefix(OPTIONAL_PREFIX) {
            Some(rest) => Self {
                optional: true,
                source: ConfigSource::parse(rest),
            },
            None => Self {
                optional: false,
                source: ConfigSource::parse(value),
            },
        })
    }

    /// [`load`] this flag's source, applying the `optional:` contract: `Ok(None)` means "no config
    /// present, and that is allowed — carry on unconfigured" (Go's
    /// `case optional && errors.Is(err, conffile.ErrNoConfig)`). Every other failure — including any
    /// failure at all when `optional` is false, and a malformed-but-present config even when it is
    /// true — is returned as an error, because a config the operator declared and that exists must
    /// never be silently ignored.
    pub fn load(&self) -> Result<Option<Config>> {
        match load(&self.source) {
            Ok(config) => Ok(Some(config)),
            Err(e) if self.optional && is_no_config(&e) => {
                tracing::info!(
                    source = %self.source,
                    reason = %e,
                    "config: none present; continuing unconfigured (--config optional:)"
                );
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

/// Load and parse a `--config` source (Go `conffile.Load`).
///
/// Reads `source`, parses it as **standard JSON** (this fork omits HuJSON — the comment-stripping
/// preprocessor Go gates behind a build feature; a config must be valid JSON here), gates the
/// `version` (only `"alpha0"` is accepted — an empty or unrecognized version is a clear error, like
/// Go), then decodes the full [`ConfigVAlpha`]. Fails loudly with context on any step (a misconfigured
/// headless deploy must fail fast, not start half-configured).
///
/// ## Two kinds of failure
///
/// A **read-phase** failure — the source is absent or unreadable — is reported as [`NoConfig`], which
/// [`is_no_config`] recognizes anywhere in the error chain. Everything after the bytes are in hand
/// (bad JSON, missing or unsupported `version`) is a plain error. Only the first kind is survivable,
/// and only behind `optional:` — see [`ConfigFlag::load`].
///
/// ## `vm:user-data` is recognized but not readable here
///
/// Go reads [`VM_USER_DATA_PATH`] from the EC2 instance metadata service, behind its `HasAWS` build
/// feature; a Go build *without* that feature returns `feature.ErrUnavailable`, which `conffile.Load`
/// wraps in `ErrNoConfig` exactly like a missing file. This fork has no cloud-metadata client, so it
/// takes that same branch. The point is the error path, and it is now the right one: the sentinel is
/// recognized rather than mistaken for a filename, `--config optional:vm:user-data` (the cloud-init
/// form) boots unconfigured instead of dying at startup, and a bare `--config vm:user-data` still
/// fails loudly — naming what is missing — rather than silently ignoring a declared config source.
pub fn load(source: &ConfigSource) -> Result<Config> {
    let raw = match source {
        ConfigSource::File(path) => std::fs::read(path).map_err(|e| {
            anyhow!(NoConfig {
                source: source.to_string(),
                reason: e.to_string(),
            })
        })?,
        ConfigSource::VmUserData => {
            return Err(anyhow!(NoConfig {
                source: VM_USER_DATA_PATH.to_string(),
                reason: "reading a VM's user-data (cloud instance metadata) is not supported by \
                         this build"
                    .to_string(),
            }));
        }
    };

    // Gate the version BEFORE decoding the whole body (Go decodes a {version} probe first), so an
    // unsupported version yields a precise message rather than a confusing field error.
    #[derive(Deserialize)]
    struct VersionProbe {
        #[serde(default)]
        version: String,
    }
    let probe: VersionProbe = serde_json::from_slice(&raw)
        .with_context(|| format!("parsing config file {source} (must be valid JSON)"))?;
    match probe.version.as_str() {
        "" => bail!("config file {source}: no \"version\" field defined (want \"alpha0\")"),
        "alpha0" => {}
        other => bail!(
            "config file {source}: unsupported \"version\" value {other:?}; want \"alpha0\" for now"
        ),
    }

    let parsed: ConfigVAlpha =
        serde_json::from_slice(&raw).with_context(|| format!("parsing config file {source}"))?;
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

        // VALIDATE every field-level value BEFORE mutating `prefs` (all-or-nothing). The daemon's
        // contract is "fail fast — never start half-configured"; a config that PARSES but carries a
        // bad CIDR / control-url scheme / exit-node would otherwise be persisted and only caught
        // (non-fatally) deep in the auto-start `build_config`, leaving an unbringable value on disk.
        // Catching it here makes `--config` reject the file hard (like a bad version) and keeps the
        // merge atomic — we bail before touching `prefs`. Re-uses the same parsers `build_config` uses
        // so the two layers agree.
        if let Some(url) = &c.server_url {
            let parsed = url::Url::parse(url)
                .with_context(|| format!("config: invalid ServerURL {url:?}"))?;
            match parsed.scheme() {
                "http" | "https" => {}
                other => bail!("config: ServerURL {url:?} scheme {other:?} is not http or https"),
            }
        }
        for s in &c.advertise_routes {
            s.parse::<ipnet::IpNet>()
                .with_context(|| format!("config: invalid advertise route {s:?}"))?;
        }
        if let Some(exit) = &c.exit_node {
            // The engine's `ExitNodeSelector::FromStr` is infallible (a non-IP string → a Name that
            // simply matches no peer), so a typo'd exit node would SILENTLY route nowhere. Reject the
            // obvious-garbage forms here: empty/whitespace, and the `auto:` family (which the up/set
            // path's `validate_exit_node_selector` also rejects — auto-exit-node selection is not
            // wired). A bare IP or a plausible MagicDNS name is accepted (resolved against the netmap
            // at bring-up, like Go).
            let e = exit.trim();
            if e.is_empty() {
                bail!("config: exitNode must not be empty (omit the field to use no exit node)");
            }
            if e.starts_with("auto:") {
                bail!(
                    "config: exitNode {exit:?} uses the auto: form, which this build does not support"
                );
            }
        }

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
        if let Some(v) = c.shields_up {
            prefs.shields_up = v;
        }
        if let Some(v) = c.run_ssh_server {
            prefs.ssh_enabled = v;
        }
        // `AdvertiseExitNode` — deliberately applied AFTER `advertise_routes`, because in Go the two
        // are the SAME field and the order is what makes them compose: `ToPrefs` sets
        // `mp.AdvertiseRoutes` from the config's list first, then, if `AdvertiseExitNode` is true,
        // *appends* the v4/v6 default routes to it (falling back to just those two when the config
        // listed no routes). Advertising as an exit node therefore never drops the subnet routes the
        // same config asked for. This fork splits the intent into two prefs that the engine composes
        // (`Config::advertise_exit_node` + `Config::advertise_routes`, see `ipn::config`), so writing
        // the bool here after the routes yields exactly Go's outcome for all four combinations.
        //
        // One deliberate difference: Go acts only on `EqualBool(true)` — an explicit
        // `"AdvertiseExitNode": false` leaves its derived routes alone, because in Go the *absence*
        // of the default routes is what "not an exit node" means and an unset `AdvertiseRoutes` must
        // not clobber the existing set. Here the bool is the ONLY carrier of the intent, so an
        // explicitly declared `false` is applied as `false`. Ignoring it would be precisely the
        // silent-drop this module forbids, and it matches `tnet up --advertise-exit-node=false`.
        if let Some(v) = c.advertise_exit_node {
            prefs.advertise_exit_node = v;
        }
        if let Some(op) = &c.operator_user {
            // Go: `mp.OperatorUser = *c.OperatorUser` — an explicit empty string means "no operator",
            // which this fork spells `None` (the same clearing `tnet set --operator=` performs).
            prefs.operator_user = if op.is_empty() {
                None
            } else {
                Some(op.clone())
            };
        }
        if let Some(v) = c.allow_lan_while_using_exit_node {
            prefs.exit_node_allow_lan_access = v;
        }
        if let Some(v) = c.posture_checking {
            prefs.posture_checking = v;
        }
        if let Some(v) = c.run_web_client {
            prefs.run_web_client = v;
        }
        if let Some(app) = c.app_connector {
            prefs.advertise_app_connector = app.advertise;
        }
        // Go assigns the whole `AutoUpdatePrefs` struct and sets BOTH mask bits, so a present
        // `AutoUpdate` object writes both prefs — including from an inner key the JSON omitted, whose
        // value is then Go's zero (`Check: false`). See `AutoUpdatePrefs` for why that is reproduced
        // rather than smoothed over.
        if let Some(au) = c.auto_update {
            prefs.auto_update_check = au.check;
            prefs.auto_update_apply = au.apply;
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

/// The Go config fields this build parses but does NOT honor, for each one that is set to a
/// non-default value — the honest-omission list, in Go's declaration order.
///
/// Split out from [`warn_unmapped`] (which only logs it) so a test can assert the exact list the
/// production code produces for a given config. That matters more than it looks: the list drifts in
/// *both* directions — a Go field missing from it AND from [`ConfigVAlpha`] is a silent drop, while a
/// field left in it after this fork grew the pref behind it is a warning that lies. Four entries were
/// each kind before this list was re-derived against `ipn/conf.go` @
/// `53a0d659afa51835dd7a9283873cca44261454f8`.
///
/// Only non-default values are reported: warning about a field the operator left at its default (or
/// spelled out at its default) would be noise, and Go's `ToPrefs` likewise no-ops on an unset
/// `opt.Bool`.
fn unmapped_fields(c: &ConfigVAlpha) -> Vec<&'static str> {
    let mut unmapped: Vec<&'static str> = Vec::new();
    // `Locked: true` is an operator intent (refuse out-of-band `tnet set`) this fork does not enforce;
    // warn so it is never silently ignored. `Locked: false`/absent is the default (no lock), so only
    // a true value is worth surfacing.
    if c.locked == Some(true) {
        unmapped.push("Locked");
    }
    if c.disable_snat.is_some() {
        unmapped.push("DisableSNAT");
    }
    if !c.advertise_services.is_empty() {
        unmapped.push("AdvertiseServices");
    }
    if c.netfilter_mode.is_some() {
        unmapped.push("NetfilterMode");
    }
    if c.no_stateful_filtering.is_some() {
        unmapped.push("NoStatefulFiltering");
    }
    if c.remote_config.is_some() {
        unmapped.push("RemoteConfig");
    }
    if c.serve_config_temp.is_some() {
        unmapped.push("ServeConfigTemp");
    }
    if !c.static_endpoints.is_empty() {
        unmapped.push("StaticEndpoints");
    }
    // Go's `RelayServerPort` is a pointer whose *absence* disables the relay server, so any present
    // value — `0` included, which asks Go to pick a random port — is a real request this build drops.
    if c.relay_server_port.is_some() {
        unmapped.push("RelayServerPort");
    }
    if !c.relay_server_static_endpoints.is_empty() {
        unmapped.push("RelayServerStaticEndpoints");
    }
    unmapped
}

/// Log a `warn` naming every `unmapped_fields` entry, so an operator sees the config carried
/// something this build does not honor (honest omission). Pure-ish (only logs); no pref mutation.
fn warn_unmapped(c: &ConfigVAlpha) {
    let unmapped = unmapped_fields(c);
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
        let loaded = load(&ConfigSource::File(path.clone()));
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
    fn apply_validates_fields_before_mutating_and_fails_hard() {
        // A config that PARSES but carries a field-level invalid must fail `apply_to_prefs` HARD
        // (the daemon's fail-fast / never-start-half-configured contract) AND leave prefs untouched
        // (all-or-nothing — the validation runs before any mutation). `apply_to_prefs` returns a
        // `Result` whose Ok carries a `SecretString` (no Debug), so match by hand.
        let err = |json: &str| {
            let c = cfg(json);
            let mut p = Prefs::default();
            let before = p.clone();
            match c.apply_to_prefs(&mut p) {
                Ok(_) => panic!("expected apply_to_prefs to reject {json}"),
                Err(e) => {
                    // All-or-nothing: a rejected config must not have mutated prefs.
                    assert_eq!(
                        p.want_running, before.want_running,
                        "prefs must be untouched on a rejected config"
                    );
                    assert_eq!(p.control_url, before.control_url);
                    assert_eq!(p.advertise_routes, before.advertise_routes);
                    e.to_string()
                }
            }
        };
        // Bad control-url scheme.
        let e = err(r#"{"version":"alpha0","ServerURL":"ftp://nope"}"#);
        assert!(e.contains("ServerURL") && e.contains("scheme"), "{e}");
        // Malformed ServerURL.
        let e = err(r#"{"version":"alpha0","ServerURL":"not a url"}"#);
        assert!(e.to_lowercase().contains("serverurl"), "{e}");
        // Bad advertise route CIDR.
        let e = err(r#"{"version":"alpha0","AdvertiseRoutes":["10.0.0.0/8","garbage"]}"#);
        assert!(
            e.contains("advertise route") && e.contains("garbage"),
            "{e}"
        );
        // Empty exit node.
        let e = err(r#"{"version":"alpha0","exitNode":"  "}"#);
        assert!(e.contains("exitNode") && e.contains("empty"), "{e}");
        // auto: exit node (not supported by this build).
        let e = err(r#"{"version":"alpha0","exitNode":"auto:any"}"#);
        assert!(e.contains("auto:"), "{e}");
    }

    #[test]
    fn apply_accepts_valid_fields() {
        // The valid forms of the above must apply cleanly (proves the guards aren't over-eager).
        let c = cfg(r#"{"version":"alpha0","ServerURL":"https://hs.example.com",
                "AdvertiseRoutes":["10.0.0.0/8","192.168.1.0/24"],"exitNode":"100.64.0.9"}"#);
        let mut p = Prefs::default();
        let key = c.apply_to_prefs(&mut p).unwrap();
        assert!(key.is_none());
        assert_eq!(p.control_url.as_deref(), Some("https://hs.example.com"));
        assert_eq!(p.advertise_routes, vec!["10.0.0.0/8", "192.168.1.0/24"]);
        assert_eq!(p.exit_node.as_deref(), Some("100.64.0.9"));
        // A plausible MagicDNS name (non-IP, non-auto) is accepted too.
        let c2 = cfg(r#"{"version":"alpha0","exitNode":"exit-node.tailnet.ts.net"}"#);
        let mut p2 = Prefs::default();
        assert!(c2.apply_to_prefs(&mut p2).is_ok());
        assert_eq!(p2.exit_node.as_deref(), Some("exit-node.tailnet.ts.net"));
    }

    #[test]
    fn version_gate_rejects_missing_and_unknown() {
        // Missing version.
        let dir = std::env::temp_dir().join(format!("tailnetd-conf-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nover.json");
        // `Config` has no `Debug`, so `unwrap_err()` won't compile — assert via the Err arm directly.
        let err_str = |path: &std::path::Path| match load(&ConfigSource::File(path.to_path_buf())) {
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
        assert!(p.shields_up);
        assert!(p.ssh_enabled);
    }

    #[test]
    fn go_config_fields_without_a_pref_parse_and_are_not_applied() {
        // Go's ConfigVAlpha carries fields this fork has no pref for — AdvertiseServices,
        // ServeConfigTemp, StaticEndpoints, RemoteConfig, RelayServerPort,
        // RelayServerStaticEndpoints, DisableSNAT, NetfilterMode, NoStatefulFiltering, Locked. A real
        // Go config that sets them MUST parse (no error) and MUST NOT mutate prefs — they are
        // surfaced by `unmapped_fields` (honest omission), never silently applied. Critically, Go has
        // NO tags field in the config (tags ride the auth key), so there is no AdvertiseTags mapping
        // to leave a pref set.
        let c = cfg(r#"{
                "version":"alpha0",
                "Hostname":"only-host",
                "AdvertiseServices":["svc:web"],
                "RemoteConfig":true,
                "RelayServerPort":41641,
                "RelayServerStaticEndpoints":["192.0.2.10:41641"],
                "StaticEndpoints":["1.2.3.4:41641"]
            }"#);
        let mut p = Prefs::default();
        let key = c.apply_to_prefs(&mut p).unwrap();
        assert!(key.is_none());
        // Only the mapped field applied; the engine-gated/non-goal Go fields left prefs at default.
        assert_eq!(p.hostname.as_deref(), Some("only-host"));
        assert!(
            p.advertise_routes.is_empty(),
            "no AdvertiseRoutes in the config → pref untouched"
        );
        assert!(
            p.advertise_tags.is_empty(),
            "the config has no tags field at all (Go carries tags on the auth key) → pref untouched"
        );
        // …and each one is REPORTED, not dropped. `RelayServerPort` in particular: Go treats the
        // pointer's presence as "run a relay server", so even a non-zero port here is a request this
        // build silently ignored before it was in this list at all.
        assert_eq!(
            unmapped_fields(&c.parsed),
            vec![
                "AdvertiseServices",
                "RemoteConfig",
                "StaticEndpoints",
                "RelayServerPort",
                "RelayServerStaticEndpoints",
            ]
        );
    }

    /// `AdvertiseExitNode` is the field whose absence was actually damaging: it is not engine-gated —
    /// this fork has `Prefs::advertise_exit_node` and `tnet up --advertise-exit-node` — so a Go config
    /// declaring it booted a node that quietly was not an exit node and said nothing about it.
    ///
    /// Go `ipn/conf.go` `ToPrefs` also *composes* it with `AdvertiseRoutes` (appending the two default
    /// routes rather than replacing the set), so the subnet routes the same config asked for must
    /// survive. This fork splits the intent across two prefs the engine composes; the composition is
    /// visible here as "both prefs set from one config".
    #[test]
    fn advertise_exit_node_applies_and_composes_with_advertise_routes() {
        let c = cfg(r#"{
                "version":"alpha0",
                "AdvertiseRoutes":["192.0.2.0/24"],
                "AdvertiseExitNode":true
            }"#);
        let mut p = Prefs::default();
        c.apply_to_prefs(&mut p).unwrap();
        assert!(
            p.advertise_exit_node,
            "a config declaring AdvertiseExitNode must actually advertise as an exit node"
        );
        assert_eq!(
            p.advertise_routes,
            vec!["192.0.2.0/24".to_string()],
            "advertising as an exit node must COMPOSE with the config's subnet routes (Go appends \
             the default routes), never replace them"
        );

        // Exit node alone, no routes: Go's `else` branch (AdvertiseRoutes was never set).
        let c = cfg(r#"{"version":"alpha0","AdvertiseExitNode":true}"#);
        let mut p = Prefs::default();
        c.apply_to_prefs(&mut p).unwrap();
        assert!(p.advertise_exit_node);
        assert!(p.advertise_routes.is_empty());

        // An explicitly declared `false` is applied as false — in this fork the bool is the only
        // carrier of the intent, so ignoring it (as Go's EqualBool(true) guard does, where the
        // intent lives inside AdvertiseRoutes instead) would be the silent drop this module forbids.
        let c = cfg(r#"{"version":"alpha0","AdvertiseExitNode":false}"#);
        let mut p = Prefs {
            advertise_exit_node: true,
            ..Prefs::default()
        };
        c.apply_to_prefs(&mut p).unwrap();
        assert!(!p.advertise_exit_node);

        // Omitting it entirely leaves the pref alone (the module's layering contract).
        let c = cfg(r#"{"version":"alpha0","Hostname":"h"}"#);
        let mut p = Prefs {
            advertise_exit_node: true,
            ..Prefs::default()
        };
        c.apply_to_prefs(&mut p).unwrap();
        assert!(
            p.advertise_exit_node,
            "an unmentioned AdvertiseExitNode must not clobber the existing pref"
        );
        // …and it is not reported as unmapped either, in any of those cases.
        assert!(!unmapped_fields(&c.parsed).contains(&"AdvertiseExitNode"));
    }

    /// The drift ran the other way too: the warning list kept naming fields whose prefs had since
    /// shipped, and `apply_to_prefs` mapped none of them — so the declarative path was strictly weaker
    /// than the flag path for prefs the daemon already had. Each of these has a `tnet up`/`set` flag.
    #[test]
    fn prefs_that_shipped_after_the_first_port_are_honored_not_warned() {
        let c = cfg(r#"{
                "version":"alpha0",
                "OperatorUser":"alice",
                "allowLANWhileUsingExitNode":true,
                "PostureChecking":true,
                "RunWebClient":true,
                "AppConnector":{"Advertise":true},
                "AutoUpdate":{"Check":true,"Apply":true}
            }"#);
        let mut p = Prefs::default();
        c.apply_to_prefs(&mut p).unwrap();
        assert_eq!(p.operator_user.as_deref(), Some("alice"), "--operator");
        assert!(p.exit_node_allow_lan_access, "--exit-node-allow-lan-access");
        assert!(p.posture_checking, "--report-posture");
        assert!(p.run_web_client, "--webclient");
        assert!(p.advertise_app_connector, "--advertise-connector");
        assert!(p.auto_update_check, "--update-check");
        assert_eq!(p.auto_update_apply, Some(true), "--auto-update");
        // None of them may still be claimed as "parsed but not honored" — a warning that lies is as
        // bad as a silent drop.
        assert!(
            unmapped_fields(&c.parsed).is_empty(),
            "{:?}",
            unmapped_fields(&c.parsed)
        );

        // The false/clearing forms apply too (Go assigns the value, it does not only turn things on).
        let c = cfg(r#"{
                "version":"alpha0",
                "OperatorUser":"",
                "allowLANWhileUsingExitNode":false,
                "PostureChecking":false,
                "RunWebClient":false,
                "AppConnector":{"Advertise":false}
            }"#);
        let mut p = Prefs {
            operator_user: Some("bob".to_string()),
            exit_node_allow_lan_access: true,
            posture_checking: true,
            run_web_client: true,
            advertise_app_connector: true,
            ..Prefs::default()
        };
        c.apply_to_prefs(&mut p).unwrap();
        assert_eq!(
            p.operator_user, None,
            "Go's empty OperatorUser means no operator (`tnet set --operator=`)"
        );
        assert!(!p.exit_node_allow_lan_access);
        assert!(!p.posture_checking);
        assert!(!p.run_web_client);
        assert!(!p.advertise_app_connector);
    }

    /// Go's `ToPrefs` assigns the whole `AutoUpdatePrefs` struct and sets BOTH mask bits, so a
    /// present `AutoUpdate` object writes `Check` from the object even when the JSON omitted that
    /// inner key — with Go's zero value, `false`, not this fork's `true` pref default. Reproduced
    /// rather than smoothed over: the alternative is a config file that means one thing under
    /// `tailscaled` and another here.
    #[test]
    fn auto_update_object_writes_both_inner_fields_like_go() {
        let c = cfg(r#"{"version":"alpha0","AutoUpdate":{"Apply":true}}"#);
        let mut p = Prefs::default();
        assert!(p.auto_update_check, "the pref's own default is true");
        c.apply_to_prefs(&mut p).unwrap();
        assert_eq!(p.auto_update_apply, Some(true));
        assert!(
            !p.auto_update_check,
            "an AutoUpdate object omitting Check writes Go's zero value (false), because Go assigns \
             the whole struct with CheckSet+ApplySet"
        );

        // Apply is an opt.Bool: an object that omits it leaves the pref at the never-stated state.
        let c = cfg(r#"{"version":"alpha0","AutoUpdate":{"Check":true}}"#);
        let mut p = Prefs {
            auto_update_apply: Some(true),
            ..Prefs::default()
        };
        c.apply_to_prefs(&mut p).unwrap();
        assert!(p.auto_update_check);
        assert_eq!(p.auto_update_apply, None);

        // No AutoUpdate key at all → neither pref is touched.
        let c = cfg(r#"{"version":"alpha0","Hostname":"h"}"#);
        let mut p = Prefs {
            auto_update_apply: Some(false),
            auto_update_check: false,
            ..Prefs::default()
        };
        c.apply_to_prefs(&mut p).unwrap();
        assert_eq!(p.auto_update_apply, Some(false));
        assert!(!p.auto_update_check);
    }

    /// The contract this module lives by, pinned as one test: EVERY field of Go's `ConfigVAlpha`
    /// (`ipn/conf.go` @ 53a0d659afa51835dd7a9283873cca44261454f8) is either honored — it moves a
    /// `Prefs` field — or reported by `unmapped_fields`. A field in neither is a silent drop, which is
    /// what `AdvertiseExitNode`, `RemoteConfig`, `RelayServerPort` and `RelayServerStaticEndpoints`
    /// were.
    ///
    /// Every key Go declares is set here to a non-default value, so a field that stops being parsed
    /// (a rename, a dropped `#[serde(rename)]`) shows up as a pref that did not move or a warning
    /// that did not fire.
    #[test]
    fn every_go_field_is_either_honored_or_warned() {
        let c = cfg(r#"{
                "version":"alpha0",
                "Locked":true,
                "ServerURL":"https://hs.example.com",
                "AuthKey":"tskey-abc123",
                "Enabled":true,
                "OperatorUser":"alice",
                "Hostname":"node-a",
                "acceptDNS":false,
                "acceptRoutes":true,
                "exitNode":"100.64.0.9",
                "allowLANWhileUsingExitNode":true,
                "AdvertiseRoutes":["192.0.2.0/24"],
                "AdvertiseExitNode":true,
                "DisableSNAT":true,
                "AdvertiseServices":["svc:web"],
                "AppConnector":{"Advertise":true},
                "NetfilterMode":"nodivert",
                "NoStatefulFiltering":true,
                "PostureChecking":true,
                "RunSSHServer":true,
                "RunWebClient":true,
                "ShieldsUp":true,
                "RemoteConfig":true,
                "AutoUpdate":{"Check":true,"Apply":true},
                "ServeConfigTemp":{"TCP":{}},
                "StaticEndpoints":["192.0.2.10:41641"],
                "RelayServerPort":0,
                "RelayServerStaticEndpoints":["192.0.2.11:41641"]
            }"#);
        let mut p = Prefs::default();
        let key = c.apply_to_prefs(&mut p).unwrap();

        // HONORED — 16 keys onto prefs, plus AuthKey returned as a credential.
        assert_eq!(key_str(key).as_deref(), Some("tskey-abc123"));
        assert!(p.want_running);
        assert_eq!(p.control_url.as_deref(), Some("https://hs.example.com"));
        assert_eq!(p.operator_user.as_deref(), Some("alice"));
        assert_eq!(p.hostname.as_deref(), Some("node-a"));
        assert!(!p.accept_dns);
        assert!(p.accept_routes);
        assert_eq!(p.exit_node.as_deref(), Some("100.64.0.9"));
        assert!(p.exit_node_allow_lan_access);
        assert_eq!(p.advertise_routes, vec!["192.0.2.0/24".to_string()]);
        assert!(p.advertise_exit_node);
        assert!(p.advertise_app_connector);
        assert!(p.posture_checking);
        assert!(p.ssh_enabled);
        assert!(p.run_web_client);
        assert!(p.shields_up);
        assert!(p.auto_update_check);
        assert_eq!(p.auto_update_apply, Some(true));

        // WARNED — the remaining 10, in Go's declaration order. An exact match (not `contains`) is
        // the point: it fails both when a Go field goes unreported AND when a field lingers here
        // after its pref shipped.
        assert_eq!(
            unmapped_fields(&c.parsed),
            vec![
                "Locked",
                "DisableSNAT",
                "AdvertiseServices",
                "NetfilterMode",
                "NoStatefulFiltering",
                "RemoteConfig",
                "ServeConfigTemp",
                "StaticEndpoints",
                "RelayServerPort",
                "RelayServerStaticEndpoints",
            ]
        );
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

    /// A `--config` value is a SOURCE, not just a path: `optional:` is stripped (once), and
    /// `vm:user-data` is a sentinel rather than a filename. Go:
    /// `strings.CutPrefix(path, "optional:")` in `cmd/tailscaled` + `case VMUserDataPath` in
    /// `conffile.Load`.
    #[test]
    fn config_flag_parses_optional_prefix_and_vm_user_data_sentinel() {
        let flag = |v: &str| ConfigFlag::parse(v);

        // Plain path: not optional, a file source.
        assert_eq!(
            flag("/etc/tailnetd/config.json"),
            Some(ConfigFlag {
                optional: false,
                source: ConfigSource::File(std::path::PathBuf::from("/etc/tailnetd/config.json")),
            })
        );
        // The sentinel, bare and behind the marker.
        assert_eq!(
            flag("vm:user-data"),
            Some(ConfigFlag {
                optional: false,
                source: ConfigSource::VmUserData,
            })
        );
        assert_eq!(
            flag("optional:vm:user-data"),
            Some(ConfigFlag {
                optional: true,
                source: ConfigSource::VmUserData,
            }),
            "the cloud-init form: optional marker + user-data sentinel"
        );
        // Optional file path.
        assert_eq!(
            flag("optional:/etc/tailnetd/config.json"),
            Some(ConfigFlag {
                optional: true,
                source: ConfigSource::File(std::path::PathBuf::from("/etc/tailnetd/config.json")),
            })
        );
        // Exactly ONE prefix is stripped (Go's CutPrefix), so the rest is a literal source name.
        assert_eq!(
            flag("optional:optional:x"),
            Some(ConfigFlag {
                optional: true,
                source: ConfigSource::File(std::path::PathBuf::from("optional:x")),
            })
        );
        // Empty value = "no --config given" (Go gates on `args.confFile != ""`).
        assert_eq!(flag(""), None);
        // But `optional:` with an empty source IS a flag — an optional source that is simply absent.
        assert_eq!(
            flag("optional:"),
            Some(ConfigFlag {
                optional: true,
                source: ConfigSource::File(std::path::PathBuf::new()),
            })
        );
        // Display round-trips the source as the operator wrote it (used in every error message).
        assert_eq!(ConfigSource::VmUserData.to_string(), "vm:user-data");
        assert_eq!(
            ConfigSource::File(std::path::PathBuf::from("/tmp/c.json")).to_string(),
            "/tmp/c.json"
        );
    }

    /// The load error must distinguish "no config present" from "config present and malformed" —
    /// Go's `conffile.ErrNoConfig` vs. a plain parse error. This is what makes `optional:` possible.
    #[test]
    fn absent_source_is_no_config_but_malformed_one_is_not() {
        let dir = std::env::temp_dir().join(format!("tailnetd-conf-noconf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Missing file → NoConfig.
        let missing = dir.join("definitely-absent.json");
        let err = match load(&ConfigSource::File(missing.clone())) {
            Ok(_) => panic!("a missing config file must not load"),
            Err(e) => e,
        };
        assert!(
            is_no_config(&err),
            "a missing file is 'no config present': {err}"
        );
        assert!(err.to_string().contains("no config present"), "{err}");

        // The classification survives a caller's context wrapper (every call site adds one).
        let wrapped = err.context("loading --config");
        assert!(
            is_no_config(&wrapped),
            "context must not hide the classification: {wrapped}"
        );

        // Present but malformed JSON → NOT NoConfig (it must still fail, even with `optional:`).
        let broken = dir.join("broken.json");
        std::fs::write(&broken, "{ this is not json").unwrap();
        let err = match load(&ConfigSource::File(broken.clone())) {
            Ok(_) => panic!("malformed JSON must not load"),
            Err(e) => e,
        };
        assert!(
            !is_no_config(&err),
            "a present-but-malformed config is NOT 'no config present': {err}"
        );

        // Present but an unsupported version → also NOT NoConfig.
        let badver = dir.join("badver.json");
        std::fs::write(&badver, r#"{"version":"beta9"}"#).unwrap();
        let err = match load(&ConfigSource::File(badver.clone())) {
            Ok(_) => panic!("an unsupported version must not load"),
            Err(e) => e,
        };
        assert!(!is_no_config(&err), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `vm:user-data` is RECOGNIZED (not treated as a filename) and reports absence, the branch Go
    /// takes on a build without cloud-metadata support (`feature.ErrUnavailable`, wrapped in
    /// `ErrNoConfig`). So the sentinel no longer dies with a bogus "no such file" and, behind
    /// `optional:`, does not fail startup at all.
    #[test]
    fn vm_user_data_source_reports_no_config_naming_the_missing_support() {
        let err = match load(&ConfigSource::VmUserData) {
            Ok(_) => panic!("this build cannot read the VM user-data"),
            Err(e) => e,
        };
        assert!(is_no_config(&err), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("vm:user-data"), "{msg}");
        assert!(
            msg.contains("not supported by this build"),
            "the error must name what is missing, not pretend it was a file: {msg}"
        );
    }

    /// The `optional:` contract end-to-end, through the production `ConfigFlag::load`:
    /// absent + optional → boot unconfigured; absent + required → fail; present + malformed → fail
    /// EVEN when optional; present + valid → load.
    #[test]
    fn optional_prefix_tolerates_an_absent_source_but_never_a_broken_one() {
        let dir = std::env::temp_dir().join(format!("tailnetd-conf-opt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("absent.json");
        let missing_s = missing.display().to_string();

        // `Config` has no `Debug`, so `Result<Option<Config>>` cannot be unwrapped — match by hand.
        let loaded = |value: &str| {
            let flag = ConfigFlag::parse(value).expect("a non-empty --config value parses");
            match flag.load() {
                Ok(Some(_)) => Ok(true),
                Ok(None) => Ok(false),
                Err(e) => Err(e.to_string()),
            }
        };

        // Absent + optional → Ok(None): the node boots unconfigured.
        assert_eq!(
            loaded(&format!("optional:{missing_s}")),
            Ok(false),
            "an absent optional source must not fail startup"
        );
        // Same for the cloud-init form this bead is named after.
        assert_eq!(loaded("optional:vm:user-data"), Ok(false));
        // Absent + required → error (unchanged fail-fast contract).
        match loaded(&missing_s) {
            Err(e) => assert!(e.contains("no config present"), "{e}"),
            Ok(_) => panic!("a required but absent config must fail"),
        }
        match loaded("vm:user-data") {
            Err(e) => assert!(e.contains("not supported by this build"), "{e}"),
            Ok(_) => panic!("a required vm:user-data source must fail on this build"),
        }

        // Present but malformed → fails EVEN with `optional:` (the whole point: optional means
        // "may be absent", never "may be broken").
        let broken = dir.join("broken.json");
        std::fs::write(&broken, r#"{"version":"beta9"}"#).unwrap();
        let broken_s = broken.display().to_string();
        match loaded(&format!("optional:{broken_s}")) {
            Err(e) => assert!(e.contains("unsupported") && e.contains("beta9"), "{e}"),
            Ok(_) => panic!("an optional-but-present-and-invalid config must still fail"),
        }

        // Present and valid → loaded, optional or not.
        let good = dir.join("good.json");
        std::fs::write(&good, r#"{"version":"alpha0","Hostname":"node-a"}"#).unwrap();
        let good_s = good.display().to_string();
        assert_eq!(loaded(&good_s), Ok(true));
        assert_eq!(loaded(&format!("optional:{good_s}")), Ok(true));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
